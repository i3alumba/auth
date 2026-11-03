"""Explicit isolated exact-MinIO protocol probe; no production endpoints.

Run only with /fixture on tmpfs and a network-none shared loopback namespace.
Credentials, JWTs and native response bodies remain in memory, never in proof.
"""

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import base64
import hmac
import json
import os
from pathlib import Path
import ssl
import sys
import time
from urllib.parse import quote, urlencode
from uuid import uuid4
import xml.etree.ElementTree as ET

import django
import jwt

from .oidc import ISSUER, runtime_directory


def presigned_get(credentials, path, now):
    """Fixture-only SigV4 GET; never return/log the URL outside this process."""
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    day = now.strftime("%Y%m%d")
    scope = day + "/us-east-1/s3/aws4_request"
    query = urlencode(
        sorted(
            {
                "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
                "X-Amz-Credential": credentials["AccessKeyId"] + "/" + scope,
                "X-Amz-Date": timestamp,
                "X-Amz-Expires": "900",
                "X-Amz-Security-Token": credentials["SessionToken"],
                "X-Amz-SignedHeaders": "host",
            }.items()
        ),
        quote_via=quote,
        safe="-_.~",
    )
    encoded_path = quote(path, safe="/-_.~")
    canonical = "\n".join(
        [
            "GET",
            encoded_path,
            query,
            "host:localhost:9443\n",
            "host",
            "UNSIGNED-PAYLOAD",
        ]
    )
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            timestamp,
            scope,
            hashlib.sha256(canonical.encode()).hexdigest(),
        ]
    )
    key = ("AWS4" + credentials["SecretAccessKey"]).encode()
    for part in [day, "us-east-1", "s3", "aws4_request"]:
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    return encoded_path + "?" + query + "&X-Amz-Signature=" + signature


class ProbeFailure(Exception):
    """Only a fixed fixture-stage code, never native exception text."""


def probe(runtime):
    if os.environ.get("DJANGO_SETTINGS_MODULE") != "auth.test_settings":
        raise ValueError("synthetic_settings_required")
    django.setup()
    from ..adapters import Command
    from ..native.http import NativeHTTP
    from ..native.minio import MinioAdapter
    from ..native.minio_policy import _normalized, policy_stamp
    from ..native.sigv4 import sign_s3
    from .console import console_request

    context = ssl.create_default_context(cafile=str(runtime / "tls/public.crt"))

    class RecordingHTTP(NativeHTTP):
        last_response = None

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.shapes = {}

        def request(self, method, target, **kwargs):
            # Query strings may carry temporary credentials (presigned URLs).
            self.last_response = {
                "method": method,
                "target": target.split("?", 1)[0],
                "status": None,
            }
            response = super().request(method, target, **kwargs)
            self.last_response.update(
                {"status": response.status, "content_type": response.content_type[:80]}
            )
            if (
                method == "GET"
                and target
                in {"/minio/admin/v3/info", "/minio/admin/v3/site-replication/info"}
                and response.status == 200
            ):
                try:
                    data = json.loads(response.body)
                    if type(data) is dict:
                        if "site-replication" not in target:
                            self.shapes["server_info"] = {
                                "keys": sorted(data.keys()),
                                "mode": data.get("mode"),
                                "region_present": "region" in data,
                                "region": data.get("region"),
                                "server_versions": [
                                    item.get("version")
                                    for item in data.get("servers", [])
                                    if type(item) is dict
                                ],
                            }
                        else:
                            self.shapes["site_info"] = {
                                "keys": sorted(data.keys()),
                                "enabled": data.get("enabled"),
                                "Enabled": data.get("Enabled"),
                                "sites_empty": not bool(
                                    data.get("sites", data.get("Sites"))
                                ),
                            }
                except (ValueError, TypeError):
                    pass
            return response

    client = RecordingHTTP("https://localhost:9443", context=context, timeout=5)
    access = (runtime / "root-user").read_text().strip()
    secret = (runtime / "root-password").read_text().strip()
    private = (runtime / "tls/private.key").read_bytes()
    owned, records, receipts = set(), {}, {}
    adapter = MinioAdapter(
        client=client,
        access_key=access,
        secret_key=secret,
        instance="local-fixture",
        ownership=lambda cmd: cmd.target_id in owned,
        receipts=lambda cmd: receipts.get(cmd.target_id, ""),
        policy_receipts=lambda cmd, op, gen, blocked: (op, gen, blocked)
        in records.get(cmd.target_id, set()),
        policy_history=lambda cmd: bool(records.get(cmd.target_id)),
        exclusive_authority=True,
        claim_policy_only=True,
        standalone_without_federation=True,
    )

    def require(value, code):
        if not value:
            raise ProbeFailure(code)

    def native(label, cmd):
        try:
            result = adapter.apply(cmd)
        except Exception as error:
            from ..engine import ControlError

            code = (
                error.code if isinstance(error, ControlError) else type(error).__name__
            )
            raise ProbeFailure(
                "native_" + label + "_" + code,
                {
                    "last_response": client.last_response,
                    "public_response_shapes": client.shapes,
                },
            ) from None
        if cmd.action == "create":
            owned.add(cmd.target_id)
        else:
            stamp = policy_stamp(adapter._policy(cmd), cmd.target_id)
            records.setdefault(cmd.target_id, set()).add(stamp)
            if cmd.action == "block":
                receipts[cmd.target_id] = result.block_receipt
        return result

    def provision(subject):
        cmd = Command(
            target_id=uuid4(),
            operation_id=uuid4(),
            user_id=subject,
            service="minio",
            instance="local-fixture",
            generation=1,
            action="create",
            native_id="",
        )
        created = native("create", cmd)
        cmd = replace(
            cmd, native_id=created.native_id, action="bind", operation_id=uuid4()
        )
        binding = native("bind", cmd)
        require(binding.binding is not None, "binding_missing")
        return cmd, binding.binding.minio_policy

    def token(subject, policy):
        now = int(time.time())
        return jwt.encode(
            {
                "iss": ISSUER,
                "sub": str(subject),
                "aud": "synthetic-client",
                "iat": now,
                "exp": now + 900,
                "policy": policy,
                "preferred_username": "synthetic-user-" + str(subject),
            },
            private,
            algorithm="RS256",
            headers={"kid": "synthetic-fixture"},
        )

    def sts(identity_token):
        body = urlencode(
            {
                "Action": "AssumeRoleWithWebIdentity",
                "Version": "2011-06-15",
                "WebIdentityToken": identity_token,
                "DurationSeconds": "900",
            }
        ).encode()
        reply = client.request(
            "POST",
            "/",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )
        if reply.status != 200:
            return reply.status, None
        root = ET.fromstring(reply.body)
        values = {}
        for element in root.iter():
            name = element.tag.rsplit("}", 1)[-1]
            if name in {"AccessKeyId", "SecretAccessKey", "SessionToken"}:
                values[name] = element.text
        require(
            all(
                type(values.get(name)) is str and values[name]
                for name in ["AccessKeyId", "SecretAccessKey", "SessionToken"]
            ),
            "sts_credentials_missing",
        )
        return reply.status, values

    def s3(credentials, method, path, body=b""):
        headers = sign_s3(
            access_key=credentials["AccessKeyId"],
            secret_key=credentials["SecretAccessKey"],
            authority=client.authority,
            method=method,
            target=path,
            body=body,
            now=datetime.now(timezone.utc),
            headers=(
                {"x-amz-security-token": credentials["SessionToken"]}
                if "SessionToken" in credentials
                else {}
            ),
        )
        return client.request(method, path, headers=headers, body=body)

    def console_login(keys):
        reply = console_request(
            context,
            "POST",
            "/api/v1/login",
            body=json.dumps(
                {
                    "accessKey": keys["AccessKeyId"],
                    "secretKey": keys["SecretAccessKey"],
                    "sts": keys["SessionToken"],
                }
            ).encode(),
        )
        require(reply.status == 204, "console_login_status_" + str(reply.status))
        require(bool(reply.cookie), "console_login_cookie_missing")
        return reply

    def console_download(bucket, cookie):
        target = (
            "/api/v1/buckets/"
            + bucket
            + "/objects/download?"
            + urlencode({"prefix": base64.b64encode(b"probe.txt").decode()})
        )
        return console_request(context, "GET", target, cookie=cookie)

    def service_account(cookie):
        reply = console_request(
            context,
            "POST",
            "/api/v1/service-accounts",
            cookie=cookie,
            body=b'{"policy":""}',
        )
        require(
            reply.status == 201, "service_account_create_status_" + str(reply.status)
        )
        data = reply.json()
        require(
            type(data) is dict
            and all(
                type(data.get(key)) is str and data[key]
                for key in ["accessKey", "secretKey"]
            ),
            "service_account_keys_missing",
        )
        return {"AccessKeyId": data["accessKey"], "SecretAccessKey": data["secretKey"]}

    proof = {
        "scope": "isolated loopback exact-image fixture only",
        "browser_and_oauth_redirect": "not_tested",
        "native_login_revocation": "not_claimed",
    }
    first, policy_a = provision(1003)
    second, policy_b = provision(1004)
    jwt_a, jwt_b = token(1003, policy_a), token(1004, policy_b)
    status_a, key_a = sts(jwt_a)
    status_b, key_b = sts(jwt_b)
    require(status_a == status_b == 200, "initial_sts_failed")
    path_a, path_b = (
        "/" + first.native_id + "/probe.txt",
        "/" + second.native_id + "/probe.txt",
    )
    payload_a, payload_b = b"synthetic-owned-data-a", b"synthetic-control-data-b"
    require(s3(key_a, "PUT", path_a, payload_a).status == 200, "own_put_failed")
    require(s3(key_b, "PUT", path_b, payload_b).status == 200, "control_put_failed")
    require(s3(key_a, "GET", path_a).body == payload_a, "own_get_failed")
    presigned = presigned_get(key_a, path_a, datetime.now(timezone.utc))
    require(client.request("GET", presigned).body == payload_a, "presigned_get_failed")
    require(s3(key_a, "GET", path_b).status == 403, "foreign_bucket_not_denied")
    require(s3(key_b, "GET", path_a).status == 403, "control_foreign_bucket_not_denied")
    require(s3(key_a, "GET", "/minio/admin/v3/info").status == 403, "admin_not_denied")
    listing = s3(key_a, "GET", "/")
    if listing.status == 200:
        names = [
            node.text
            for node in ET.fromstring(listing.body).iter()
            if node.tag.rsplit("}", 1)[-1] == "Name"
        ]
        require(set(names) == {first.native_id}, "bucket_listing_not_exactly_owned")
    else:
        require(listing.status == 403, "unexpected_listing_response")
    login_a, login_b = console_login(key_a), console_login(key_b)
    cookie_a, cookie_b = login_a.cookie, login_b.cookie
    require(
        console_download(first.native_id, cookie_a).body == payload_a,
        "console_owned_download_failed",
    )
    require(
        console_download(second.native_id, cookie_a).status == 403,
        "console_foreign_download_not_denied",
    )
    require(
        console_download(second.native_id, cookie_b).body == payload_b,
        "console_control_download_failed",
    )
    service_a, service_b = service_account(cookie_a), service_account(cookie_b)
    require(
        s3(service_a, "GET", path_a).body == payload_a, "service_account_own_get_failed"
    )
    require(
        s3(service_a, "PUT", path_a, payload_a).status == 200,
        "service_account_own_put_failed",
    )
    require(
        s3(service_a, "GET", path_b).status == 403, "service_account_foreign_not_denied"
    )
    require(
        s3(service_a, "GET", "/minio/admin/v3/info").status == 403,
        "service_account_admin_info_not_denied",
    )
    require(
        s3(service_b, "GET", path_b).body == payload_b,
        "service_account_control_get_failed",
    )
    policy_b_before = hashlib.sha256(
        json.dumps(_normalized(adapter._policy(second))).encode()
    ).hexdigest()
    blocked = replace(first, action="block", generation=2, operation_id=uuid4())
    native("block", blocked)
    require(s3(key_a, "GET", path_a).status == 403, "old_sts_read_not_blocked")
    require(
        client.request("GET", presigned).status == 403, "old_presigned_get_not_blocked"
    )
    require(
        s3(key_a, "PUT", path_a, b"must-not-replace").status == 403,
        "old_sts_write_not_blocked",
    )
    require(s3(key_b, "GET", path_b).body == payload_b, "control_user_affected")
    require(
        console_download(first.native_id, cookie_a).status == 403,
        "old_console_cookie_s3_not_blocked",
    )
    require(
        console_download(second.native_id, cookie_b).body == payload_b,
        "console_control_user_affected",
    )
    require(
        s3(service_a, "GET", path_a).status == 403,
        "old_service_account_read_not_blocked",
    )
    require(
        s3(service_a, "PUT", path_a, b"must-not-replace").status == 403,
        "old_service_account_write_not_blocked",
    )
    require(
        s3(service_b, "GET", path_b).body == payload_b,
        "control_service_account_affected",
    )
    blocked_session_status = console_request(
        context, "GET", "/api/v1/session", cookie=cookie_a
    ).status
    blocked_login = console_request(
        context,
        "POST",
        "/api/v1/login",
        body=json.dumps(
            {
                "accessKey": key_a["AccessKeyId"],
                "secretKey": key_a["SecretAccessKey"],
                "sts": key_a["SessionToken"],
            }
        ).encode(),
    )
    stale_status, stale_credentials = sts(jwt_a)
    if stale_status == 200:
        require(
            s3(stale_credentials, "GET", path_a).status == 403,
            "stale_jwt_restored_access",
        )
        require(
            s3(stale_credentials, "PUT", path_a, b"must-not-replace").status == 403,
            "stale_jwt_write_not_blocked",
        )
    else:
        require(stale_status in {400, 403}, "unexpected_stale_sts_response")
    enabled = replace(first, action="enable", generation=3, operation_id=uuid4())
    native("enable", enabled)
    require(s3(key_a, "GET", path_a).body == payload_a, "restored_data_mismatch")
    require(
        client.request("GET", presigned).body == payload_a,
        "restored_presigned_data_mismatch",
    )
    require(s3(key_b, "GET", path_b).body == payload_b, "control_data_mismatch")
    require(
        console_download(first.native_id, cookie_a).body == payload_a,
        "restored_original_console_cookie_data_mismatch",
    )
    require(
        console_download(second.native_id, cookie_b).body == payload_b,
        "restored_console_control_data_mismatch",
    )
    require(
        s3(service_a, "GET", path_a).body == payload_a,
        "restored_original_service_account_data_mismatch",
    )
    require(
        s3(service_b, "GET", path_b).body == payload_b,
        "restored_control_service_account_data_mismatch",
    )
    require(
        hashlib.sha256(
            json.dumps(_normalized(adapter._policy(second))).encode()
        ).hexdigest()
        == policy_b_before,
        "control_policy_changed",
    )
    proof.update(
        {
            "own_bucket_read_write": True,
            "foreign_bucket_denied": True,
            "native_admin_info_denied": True,
            "console_cookie_s3_denied_while_blocked": True,
            "same_console_cookie_restores_preserved_data": True,
            "console_cookie_secure_httponly": login_a.secure_httponly
            and login_b.secure_httponly,
            "console_session_status_while_blocked": blocked_session_status,
            "console_login_status_while_blocked": blocked_login.status,
            "console_cookie_issued_while_blocked": bool(blocked_login.cookie),
            "existing_service_account_read_write_denied_while_blocked": True,
            "same_service_account_keys_restore_preserved_data": True,
            "bucket_listing": "own_only" if listing.status == 200 else "denied",
            "existing_sts_read_write_denied_while_blocked": True,
            "existing_presigned_get_denied_while_blocked": True,
            "stale_jwt_sts_issuance": (
                "possible_but_s3_denied" if stale_status == 200 else "denied"
            ),
            "enable_restores_preserved_data": True,
            "control_user_and_policy_preserved": True,
            "owned_data_sha256": hashlib.sha256(payload_a).hexdigest(),
            "ok": True,
        }
    )
    return proof


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("synthetic_runtime_required")
        result = probe(runtime_directory(sys.argv[1]))
    except Exception as error:
        # Never stringify native exceptions, credentials, tokens or bodies.
        print(
            json.dumps(
                {
                    "ok": False,
                    "error_type": type(error).__name__,
                    "code": (
                        error.args[0]
                        if type(error) is ProbeFailure
                        else "native_probe_failed"
                    ),
                    "diagnostic": (
                        error.args[1]
                        if type(error) is ProbeFailure and len(error.args) > 1
                        else None
                    ),
                }
            )
        )
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))
