"""Synapse 1.164.1 candidate: staged registration/binding, reversible lock only.

No deactivate/logout/device deletion/password reset. Registration is create-only;
UUID-shaped existence is never ownership without a confirmed local receipt.
Not registered/enabled by the web app; exact vendor acceptance remains required.
"""

import hashlib
import hmac
import json
import re
import secrets
from typing import Callable
from urllib.parse import quote

from ..adapters import Binding, Capabilities, Command, Observation
from ..engine import ControlError
from .http import NativeHTTP, NativeTransportError


class SynapseAdapter:
    def __init__(
        self,
        *,
        client: NativeHTTP,
        token: str,
        registration_secret: str,
        instance: str,
        server_name: str,
        ownership: Callable[[Command], bool],
        receipts: Callable[[Command], str],
    ):
        if (
            type(token) is not str
            or not token
            or any(ord(c) < 33 or ord(c) > 126 for c in token)
            or type(registration_secret) is not str
            or len(registration_secret) < 16
        ):
            raise ValueError("invalid_synapse_credentials")
        if type(server_name) is not str or not re.fullmatch(
            r"[a-z0-9.-]+(?::[1-9][0-9]{0,4})?", server_name
        ):
            raise ValueError("invalid_matrix_server_name")
        self.client, self._token, self._registration_secret = (
            client,
            token,
            registration_secret,
        )
        self.server_name, self.ownership, self.receipts = (
            server_name,
            ownership,
            receipts,
        )
        self.capabilities = Capabilities(
            "matrix",
            instance,
            frozenset({"create", "bind", "block", "enable"}),
            create_only=True,
        )

    @staticmethod
    def localpart(command):
        return "ua_" + command.target_id.hex

    def native_id(self, command):
        return "@" + self.localpart(command) + ":" + self.server_name

    def _check(self, command):
        if (
            command.service != "matrix"
            or command.instance != self.capabilities.instance
        ):
            raise ControlError("instance_conflict")
        if command.action not in self.capabilities.actions:
            raise ControlError("unsupported_action")
        if command.action == "create":
            if command.native_id:
                raise ControlError("creation_not_authorized")
        elif (
            command.native_id != self.native_id(command)
            or self.ownership(command) is not True
        ):
            raise ControlError("ownership_unverified")

    def _request(self, method, path, data=None, *, admin=True, expected=(200,)):
        headers = {"Authorization": "Bearer " + self._token} if admin else {}
        body = b""
        if data is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data, separators=(",", ":")).encode("utf-8")
        reply = self.client.request(
            method, "/_synapse/admin/" + path, headers=headers, body=body
        )
        if reply.status not in expected:
            raise NativeTransportError()
        return reply

    def _preflight(self):
        version = self._request("GET", "v1/server_version").json()
        if type(version) is not dict or version.get("server_version") != "1.164.1":
            raise ControlError("unsupported_action")

    @staticmethod
    def external_ids(command):
        return [
            {"auth_provider": "oidc-common-auth", "external_id": str(command.user_id)}
        ]

    def _path(self, command):
        return "v2/users/" + quote(command.native_id, safe="")

    def _read(self, command):
        user = self._request("GET", self._path(command)).json()
        if (
            type(user) is not dict
            or user.get("name") != command.native_id
            or user.get("admin") is not False
            or user.get("deactivated") is not False
            or type(user.get("locked")) is not bool
            or user.get("external_ids") not in [[], self.external_ids(command)]
        ):
            raise ControlError("ownership_unverified")
        if command.action == "enable" and user["external_ids"] != self.external_ids(
            command
        ):
            raise ControlError("binding_required")
        return user

    def _observation(self, command, user, *, receipt=""):
        if user["locked"] and not receipt:
            receipt = self.receipts(command)
        binding = None
        if command.action == "bind":
            if user["external_ids"] != self.external_ids(command):
                raise ControlError("ownership_unverified")
            binding = Binding(command.native_id, self.localpart(command))
        return Observation(
            native_id=command.native_id,
            subject=str(command.user_id),
            instance=command.instance,
            owner=command.target_id,
            state="blocked" if user["locked"] else "enabled",
            block_receipt=receipt,
            binding=binding,
        )

    def inspect(self, command):
        self._check(command)
        user = self._read(command)
        # Unbound is a real phase, not successful native admission.
        if command.action == "bind" and not user["external_ids"]:
            return Observation(
                native_id=command.native_id,
                subject=str(command.user_id),
                instance=command.instance,
                owner=command.target_id,
                state="blocked" if user["locked"] else "unbound",
                block_receipt=self.receipts(command) if user["locked"] else "",
            )
        return self._observation(command, user)

    def apply(self, command):
        self._check(command)
        self._preflight()
        if command.action == "create":
            data = self._request("GET", "v1/register", admin=False).json()
            nonce = data.get("nonce") if type(data) is dict else None
            if type(nonce) is not str or not 0 < len(nonce) <= 256 or "\x00" in nonce:
                raise NativeTransportError()
            password = secrets.token_urlsafe(48)
            username = self.localpart(command)
            message = b"\x00".join(
                [nonce.encode(), username.encode(), password.encode(), b"notadmin"]
            )
            mac = hmac.new(
                self._registration_secret.encode(), message, hashlib.sha1
            ).hexdigest()
            result = self._request(
                "POST",
                "v1/register",
                {
                    "nonce": nonce,
                    "username": username,
                    "password": password,
                    "admin": False,
                    "inhibit_login": True,
                    "mac": mac,
                },
                admin=False,
            ).json()
            if (
                type(result) is not dict
                or result.get("user_id") != self.native_id(command)
                or any(
                    key in result
                    for key in ["access_token", "refresh_token", "device_id"]
                )
            ):
                raise NativeTransportError()
            return Observation(
                native_id=self.native_id(command),
                subject=str(command.user_id),
                instance=command.instance,
                owner=command.target_id,
                state="unbound",
            )
        user = self._read(command)
        if user["locked"] and not self.receipts(command):
            raise ControlError("foreign_block")
        receipt = ""
        if command.action == "bind":
            if not user["external_ids"]:
                # Never pass deactivated/admin/password/logout_devices. Exact
                # v1.164.1 changes deactivation only when that key is present.
                self._request(
                    "PUT",
                    self._path(command),
                    {"external_ids": self.external_ids(command)},
                )
                user = self._read(command)
        elif command.action in {"block", "enable"}:
            locked = command.action == "block"
            if user["locked"] != locked:
                self._request("PUT", self._path(command), {"locked": locked})
                user = self._read(command)
                if user["locked"] != locked:
                    raise NativeTransportError()
                if locked:
                    receipt = str(command.operation_id)
        return self._observation(command, user, receipt=receipt)
