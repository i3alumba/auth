"""Explicit loopback-only exact-Synapse fixture; native secrets remain in RAM.

No browser/OAuth/federation/crash-recovery acceptance is implied. Never imported
by a worker or web startup. The only endpoint is the new fixture namespace.
"""

from dataclasses import replace
import hashlib
import base64
import hmac
import json
import os
import re
import ssl
import sys
from urllib.parse import quote
from uuid import uuid4

import django

from .oidc import runtime_directory


class ProbeFailure(Exception):
    """Only a nonsecret fixed stage code and selected status metadata."""


def device_bundle(user_id, device_id):
    """Real synthetic signed public device keys; no encrypted-chat claim."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

    signer = ed25519.Ed25519PrivateKey.generate()
    curve = x25519.X25519PrivateKey.generate()

    def encoded(key):
        return (
            base64.b64encode(
                key.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
            )
            .decode()
            .rstrip("=")
        )

    document = {
        "user_id": user_id,
        "device_id": device_id,
        "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
        "keys": {
            "curve25519:" + device_id: encoded(curve.public_key()),
            "ed25519:" + device_id: encoded(signer.public_key()),
        },
    }
    canonical = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    signature = base64.b64encode(signer.sign(canonical)).decode().rstrip("=")
    document["signatures"] = {user_id: {"ed25519:" + device_id: signature}}
    return document


def probe(runtime):
    if os.environ.get("DJANGO_SETTINGS_MODULE") != "auth.test_settings":
        raise ProbeFailure("synthetic_settings_required")
    django.setup()
    from ..adapters import Command
    from ..engine import ControlError
    from ..native.http import NativeHTTP
    from ..native.synapse import SynapseAdapter

    class FixtureHTTP(NativeHTTP):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.created_passwords = {}
            self.last = None

        def request(self, method, target, **kwargs):
            response = super().request(method, target, **kwargs)
            self.last = {
                "method": method,
                "path": target.split("?", 1)[0],
                "status": response.status,
            }
            if response.status >= 400:
                try:
                    code = response.json().get("errcode")
                    if type(code) is str and re.fullmatch(r"M_[A-Z_]{1,64}", code):
                        self.last["errcode"] = code
                except Exception:
                    pass
            if (
                method == "POST"
                and target == "/_synapse/admin/v1/register"
                and response.status == 200
            ):
                # Only our own synthetic CREATE request, never a production password.
                body = json.loads(kwargs["body"])
                if body.get("admin") is False and re.fullmatch(
                    r"ua_[0-9a-f]{32}", body.get("username", "")
                ):
                    self.created_passwords[body["username"]] = body["password"]
            return response

    client = FixtureHTTP(
        "https://localhost:18448",
        context=ssl.create_default_context(cafile=str(runtime / "tls/public.crt")),
        timeout=5,
    )
    registration_secret = (runtime / "registration-secret").read_text()

    def require(condition, code):
        if not condition:
            raise ProbeFailure(code, client.last)

    def request(method, path, payload=None, token="", expected=(200,)):
        headers = {"Authorization": "Bearer " + token} if token else {}
        body = b""
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode()
        reply = client.request(method, path, headers=headers, body=body)
        if expected is not None:
            require(reply.status in expected, "http_status_unexpected")
        return reply

    nonce = request("GET", "/_synapse/admin/v1/register").json()["nonce"]
    root_name, root_password = (
        "synthetic_admin",
        (runtime / "admin-password").read_text(),
    )
    message = b"\x00".join(
        [nonce.encode(), root_name.encode(), root_password.encode(), b"admin"]
    )
    mac = hmac.new(registration_secret.encode(), message, hashlib.sha1).hexdigest()
    root = request(
        "POST",
        "/_synapse/admin/v1/register",
        {
            "nonce": nonce,
            "username": root_name,
            "password": root_password,
            "admin": True,
            "mac": mac,
        },
    ).json()
    admin_token = root["access_token"]
    owned, receipts = set(), {}
    adapter = SynapseAdapter(
        client=client,
        token=admin_token,
        registration_secret=registration_secret,
        instance="local-fixture",
        server_name="fixture.invalid",
        ownership=lambda cmd: cmd.target_id in owned,
        receipts=lambda cmd: receipts.get(cmd.target_id, ""),
    )

    def native(cmd):
        try:
            result = adapter.apply(cmd)
        except Exception as error:
            code = (
                error.code if isinstance(error, ControlError) else type(error).__name__
            )
            raise ProbeFailure(
                "native_" + cmd.action + "_" + code, client.last
            ) from None
        if cmd.action == "create":
            owned.add(cmd.target_id)
        if cmd.action == "block":
            receipts[cmd.target_id] = result.block_receipt
        return result

    def provision(subject):
        create = Command(
            uuid4(), uuid4(), subject, "matrix", "local-fixture", 1, "create", ""
        )
        created = native(create)
        bind = replace(
            create, native_id=created.native_id, operation_id=uuid4(), action="bind"
        )
        bound = native(bind)
        require(bound.binding is not None, "native_binding_missing")
        password = client.created_passwords[adapter.localpart(bind)]
        return bind, password

    def login(command, password, device, *, refresh=False, expected=(200,)):
        return request(
            "POST",
            "/_matrix/client/v3/login",
            {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": command.native_id},
                "password": password,
                "device_id": device,
                "refresh_token": refresh,
            },
            expected=expected,
        )

    def stable_user(command):
        data = request(
            "GET",
            "/_synapse/admin/v2/users/" + quote(command.native_id, safe=""),
            token=admin_token,
        ).json()
        return {
            key: data.get(key)
            for key in [
                "name",
                "admin",
                "deactivated",
                "is_guest",
                "appservice_id",
                "external_ids",
                "threepids",
                "displayname",
                "avatar_url",
            ]
        }

    def devices(command):
        rows = request(
            "GET",
            "/_synapse/admin/v2/users/"
            + quote(command.native_id, safe="")
            + "/devices",
            token=admin_token,
        ).json()["devices"]
        return sorted((row["device_id"], row.get("display_name")) for row in rows)

    first, password_a = provision(1003)
    control, password_b = provision(1004)
    login_a = login(first, password_a, "FIXTURE_A").json()
    login_b = login(control, password_b, "FIXTURE_B").json()
    token_a, token_b = login_a["access_token"], login_b["access_token"]
    refresh_session = login(first, password_a, "FIXTURE_REFRESH", refresh=True).json()
    require(type(refresh_session.get("refresh_token")) is str, "refresh_token_missing")
    request("GET", "/_matrix/client/v3/sync?timeout=0", token=token_a)
    user_a_before, user_b_before, devices_before = (
        stable_user(first),
        stable_user(control),
        devices(first),
    )
    room = request(
        "POST",
        "/_matrix/client/v3/createRoom",
        {
            "visibility": "private",
            "preset": "private_chat",
            "invite": [control.native_id],
        },
        token_a,
    ).json()["room_id"]
    room_path = "/_matrix/client/v3/rooms/" + quote(room, safe="")
    request("POST", "/_matrix/client/v3/join/" + quote(room, safe=""), {}, token_b)
    event = request(
        "PUT",
        room_path + "/send/m.room.message/synthetic1",
        {"msgtype": "m.text", "body": "synthetic-preserved-message"},
        token_a,
    ).json()["event_id"]
    event_path = room_path + "/event/" + quote(event, safe="")
    content_before = request("GET", event_path, token=token_b).json()["content"]
    bundle = device_bundle(first.native_id, "FIXTURE_A")
    request("POST", "/_matrix/client/v3/keys/upload", {"device_keys": bundle}, token_a)

    def queried_keys():
        data = request(
            "POST",
            "/_matrix/client/v3/keys/query",
            {"device_keys": {first.native_id: ["FIXTURE_A"]}},
            token_b,
        ).json()
        stored = data["device_keys"][first.native_id]["FIXTURE_A"]
        return {
            key: stored[key]
            for key in ["user_id", "device_id", "algorithms", "keys", "signatures"]
        }

    require(queried_keys() == bundle, "baseline_signed_device_keys_mismatch")
    member_path = room_path + "/state/m.room.member/" + quote(first.native_id, safe="")
    require(
        request("GET", member_path, token=token_b).json()["membership"] == "join",
        "baseline_room_membership_missing",
    )
    blocked = replace(first, action="block", generation=2, operation_id=uuid4())
    native(blocked)
    denied_sync = request(
        "GET", "/_matrix/client/v3/sync?timeout=0", token=token_a, expected=None
    )
    require(
        denied_sync.status in {401, 403}
        and denied_sync.json().get("errcode") == "M_USER_LOCKED",
        "old_access_token_not_locked",
    )
    denied_login = login(first, password_a, "MUST_NOT_LOGIN", expected=None)
    require(
        denied_login.status in {401, 403}
        and denied_login.json().get("errcode") == "M_USER_LOCKED",
        "password_login_not_locked",
    )
    require(
        request("GET", event_path, token=token_b).json()["content"] == content_before,
        "control_room_data_changed",
    )
    require(
        request("GET", member_path, token=token_b).json()["membership"] == "join",
        "locked_user_room_membership_removed",
    )
    request("GET", "/_matrix/client/v3/sync?timeout=0", token=token_b)
    second_event = request(
        "PUT",
        room_path + "/send/m.room.message/control2",
        {"msgtype": "m.text", "body": "synthetic-control-while-locked"},
        token_b,
    ).json()["event_id"]
    second_event_path = room_path + "/event/" + quote(second_event, safe="")
    require(
        stable_user(first) == user_a_before and stable_user(control) == user_b_before,
        "stable_user_fields_changed",
    )
    require(devices(first) == devices_before, "devices_changed_while_locked")
    require(queried_keys() == bundle, "signed_device_keys_changed_while_locked")
    refreshed = request(
        "POST",
        "/_matrix/client/v3/refresh",
        {"refresh_token": refresh_session["refresh_token"]},
        expected=None,
    )
    refreshed_denied = None
    if refreshed.status == 200:
        fresh = refreshed.json()["access_token"]
        fresh_sync = request(
            "GET", "/_matrix/client/v3/sync?timeout=0", token=fresh, expected=None
        )
        require(
            fresh_sync.status in {401, 403}
            and fresh_sync.json().get("errcode") == "M_USER_LOCKED",
            "refresh_restored_locked_access",
        )
        refreshed_denied = True
    else:
        require(refreshed.status in {400, 401, 403}, "unexpected_refresh_failure")
    enabled = replace(first, action="enable", generation=3, operation_id=uuid4())
    native(enabled)
    request("GET", "/_matrix/client/v3/sync?timeout=0", token=token_a)
    require(devices(first) == devices_before, "original_devices_not_preserved")
    require(
        request("GET", member_path, token=token_b).json()["membership"] == "join",
        "original_room_membership_not_preserved",
    )
    require(queried_keys() == bundle, "original_signed_device_keys_not_preserved")
    require(
        stable_user(first) == user_a_before and stable_user(control) == user_b_before,
        "original_profiles_not_preserved",
    )
    require(
        request("GET", event_path, token=token_a).json()["content"] == content_before,
        "original_room_data_not_preserved",
    )
    require(
        request("GET", second_event_path, token=token_a).json()["content"]["body"]
        == "synthetic-control-while-locked",
        "control_message_not_preserved",
    )
    require(
        login(first, password_a, "FIXTURE_A").status == 200,
        "original_password_not_preserved",
    )
    return {
        "ok": True,
        "scope": "isolated exact-image Synapse HTTP API fixture only",
        "create_and_external_binding": True,
        "password_login_denied_while_locked": True,
        "original_access_token_denied_while_locked": True,
        "original_access_token_works_after_unlock": True,
        "original_password_devices_profiles_room_membership_and_message_preserved": True,
        "control_user_preserved": True,
        "refresh_status_while_locked": refreshed.status,
        "refreshed_token_still_denied": refreshed_denied,
        "signed_e2ee_device_keys_preserved": True,
        "browser_oidc_encrypted_chat_and_federation": "not_tested",
        "permanent_credential_revocation": "not_claimed",
    }


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ProbeFailure("synthetic_runtime_required")
        outcome = probe(runtime_directory(sys.argv[1]))
    except Exception as error:
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
    print(json.dumps(outcome, sort_keys=True))
