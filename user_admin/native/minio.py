"""Pinned MinIO candidate: own UUID bucket + stable per-subject OIDC policy.

Never creates/disables IAM users, deletes buckets/objects/credentials, adopts an
existing bucket, or edits shared policies. Required operator declarations are
assumptions, not runtime acceptance. No web registration or automatic execution.
"""

from datetime import datetime, timezone
import json
from typing import Callable

from ..adapters import Binding, Capabilities, Command, Observation
from ..engine import ControlError
from .http import NativeHTTP, NativeTransportError, Reply
from .minio_policy import bucket_policy, policy_stamp, resource_name
from .sigv4 import sign_s3


class MinioAdapter:
    def __init__(
        self,
        *,
        client: NativeHTTP,
        access_key: str,
        secret_key: str,
        instance: str,
        ownership: Callable[[Command], bool],
        receipts: Callable[[Command], str],
        policy_receipts: Callable,
        policy_history: Callable[[Command], bool],
        exclusive_authority: bool,
        claim_policy_only: bool,
        standalone_without_federation: bool,
        clock=lambda: datetime.now(timezone.utc),
    ):
        if (
            exclusive_authority is not True
            or claim_policy_only is not True
            or standalone_without_federation is not True
        ):
            raise ValueError("minio_protocol_not_certified")
        self.client, self._access_key, self._secret_key = client, access_key, secret_key
        self.ownership, self.receipts = ownership, receipts
        self.policy_receipts, self.policy_history, self.clock = (
            policy_receipts,
            policy_history,
            clock,
        )
        self.capabilities = Capabilities(
            "minio",
            instance,
            frozenset({"create", "bind", "enable", "block"}),
            create_only=True,
        )
        # Validate signing configuration without network or credential output.
        sign_s3(
            access_key=access_key,
            secret_key=secret_key,
            authority=client.authority,
            method="GET",
            target="/",
            now=self.clock(),
        )

    def _check(self, command):
        if command.service != "minio" or command.instance != self.capabilities.instance:
            raise ControlError("instance_conflict")
        if command.action not in self.capabilities.actions:
            raise ControlError("unsupported_action")
        if command.action == "create":
            if command.native_id:
                raise ControlError("creation_not_authorized")
        elif (
            command.native_id != resource_name(command.target_id)
            or self.ownership(command) is not True
        ):
            raise ControlError("ownership_unverified")

    def _request(self, method, target, data=None, expected=(200,)):
        body = (
            json.dumps(data, separators=(",", ":")).encode()
            if data is not None
            else b""
        )
        headers = sign_s3(
            access_key=self._access_key,
            secret_key=self._secret_key,
            authority=self.client.authority,
            method=method,
            target=target,
            body=body,
            now=self.clock(),
            headers={"Content-Type": "application/json"} if data is not None else None,
        )
        reply = self.client.request(method, target, headers=headers, body=body)
        if reply.status not in expected:
            raise NativeTransportError()
        return reply

    @staticmethod
    def _legacy_admin_json(reply):
        # Exact-release policy/site-info handlers write JSON without setting a
        # MIME type. Normalize only those known endpoints, never arbitrary
        # responses; strict JSON and caller-specific shape checks still apply.
        if reply.content_type.split(";", 1)[0].strip().lower() not in {
            "application/json",
            "text/plain",
        }:
            raise NativeTransportError()
        return Reply(reply.status, reply.body, "application/json").json()

    def _preflight(self):
        info = self._request("GET", "/minio/admin/v3/info").json()
        replicas = self._legacy_admin_json(
            self._request("GET", "/minio/admin/v3/site-replication/info")
        )
        servers = info.get("servers") if type(info) is dict else None
        accepted_versions = {"2023-05-18T00:05:36Z", "RELEASE.2023-05-18T00-05-36Z"}
        if (
            type(info) is not dict
            or info.get("mode") != "online"
            # Exact-release InfoMessage omits an empty/default region. An
            # explicit null/other region remains unsupported.
            or info.get("region", "") not in {"", "us-east-1"}
            or type(servers) is not list
            or len(servers) != 1
            or type(servers[0]) is not dict
            or servers[0].get("version") not in accepted_versions
            or type(replicas) is not dict
            or replicas.get("enabled") is not False
        ):
            raise ControlError("unsupported_action")

    def _policy(self, command):
        name = resource_name(command.target_id)
        reply = self._request(
            "GET",
            "/minio/admin/v3/info-canned-policy?name=" + name,
            expected=(200, 404),
        )
        if reply.status == 404:
            data = reply.json()
            if type(data) is not dict or data.get("Code") != "XMinioAdminNoSuchPolicy":
                raise NativeTransportError()
            return None
        return self._legacy_admin_json(reply)

    def _verified_policy(self, command, document, *, just_written=False):
        try:
            stamp = policy_stamp(document, command.target_id)
        except (ValueError, TypeError):
            raise ControlError("ownership_unverified") from None
        operation, generation, blocked = stamp
        if just_written:
            if operation != command.operation_id or generation != command.generation:
                raise ControlError("ownership_unverified")
        elif self.policy_receipts(command, operation, generation, blocked) is not True:
            # A valid-looking Sid/name is not confirmed creation evidence.
            raise ControlError("ownership_unverified")
        return stamp

    def _observation(self, command, document, *, just_written=False):
        if document is None:
            return Observation(
                native_id=command.native_id,
                subject=str(command.user_id),
                instance=command.instance,
                owner=command.target_id,
                state="unbound",
            )
        operation, generation, blocked = self._verified_policy(
            command, document, just_written=just_written
        )
        receipt = ""
        if blocked:
            if just_written:
                receipt = str(command.operation_id)
            elif self.receipts(command) == str(operation):
                receipt = str(operation)
        name = resource_name(command.target_id)
        binding = (
            Binding(str(command.user_id), name, name)
            if command.action == "bind"
            else None
        )
        return Observation(
            native_id=command.native_id,
            subject=str(command.user_id),
            instance=command.instance,
            owner=command.target_id,
            state="blocked" if blocked else "enabled",
            # Exact fixture: named-policy deny blocks S3, not STS/Console
            # credential or cookie issuance. Never call that login revocation.
            new_login="unsupported" if blocked else "unknown",
            block_receipt=receipt,
            binding=binding,
        )

    def inspect(self, command):
        self._check(command)
        if (
            self._request("HEAD", "/" + command.native_id, expected=(200, 404)).status
            != 200
        ):
            raise ControlError("ownership_unverified")
        document = self._policy(command)
        if document is None and (
            self.policy_history(command) or command.action == "enable"
        ):
            # Never recreate a policy removed during manual handoff, or assume
            # that missing authorization means permission to restore access.
            raise ControlError("ownership_unverified")
        return self._observation(command, document)

    def apply(self, command):
        self._check(command)
        self._preflight()
        if command.action == "create":
            name = resource_name(command.target_id)
            if self._request("HEAD", "/" + name, expected=(200, 404)).status != 404:
                raise ControlError("ownership_unverified")
            # Exact release MakeBucket reports existing buckets as an error.
            # No force-create/retry/delete; collision must not become ownership.
            self._request("PUT", "/" + name)
            return Observation(
                native_id=name,
                subject=str(command.user_id),
                instance=command.instance,
                owner=command.target_id,
                state="unbound",
            )
        current = self.inspect(command)
        if current.state == "blocked" and not current.block_receipt:
            raise ControlError("foreign_block")
        if command.action == "bind" and current.state != "unbound":
            return current  # Known policy: read-only binding, no overwrite.
        if command.action == "enable" and current.state == "enabled":
            return current
        if command.action == "block" and current.state == "blocked":
            return current
        blocked = command.action == "block"
        if command.action not in {"bind", "block", "enable"}:
            raise ControlError("unsupported_action")
        document = bucket_policy(
            owner=command.target_id,
            operation=command.operation_id,
            generation=command.generation,
            blocked=blocked,
        )
        name = resource_name(command.target_id)
        self._request(
            "PUT",
            "/minio/admin/v3/add-canned-policy?name=" + name,
            document,
            expected=(200, 204),
        )
        observed = self._policy(command)
        if observed is None:
            raise NativeTransportError()
        result = self._observation(command, observed, just_written=True)
        if (result.state == "blocked") != blocked:
            raise NativeTransportError()
        return result
