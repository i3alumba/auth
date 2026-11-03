"""GitLab 18.1.0 CE candidate. Not registered/enabled by Auth web.

Exact-version fixture acceptance is still mandatory. Uses ban/unban, NEVER the
block endpoint that changes CI. A confirmed local block receipt is meaningful
only within the approved exclusive authority epoch; it is not a native CAS.
"""

from dataclasses import dataclass, field
import json
import re
from typing import Callable

from ..adapters import Binding, Capabilities, Command, Observation
from ..engine import ControlError
from .http import NativeHTTP, NativeTransportError


@dataclass(frozen=True)
class Profile:
    username: str
    email: str = field(repr=False)
    name: str


class GitlabAdapter:
    def __init__(
        self,
        *,
        client: NativeHTTP,
        token: str,
        instance: str,
        profiles: Callable[[Command], Profile],
        receipts: Callable[[Command], str],
    ):
        if (
            type(token) is not str
            or not token
            or any(ord(c) < 33 or ord(c) > 126 for c in token)
        ):
            raise ValueError("invalid_gitlab_credentials")
        self.client, self._token = client, token
        self.profiles, self.receipts = profiles, receipts
        self.capabilities = Capabilities(
            "gitlab",
            instance,
            frozenset({"create", "bind", "enable", "block"}),
            create_only=True,
        )

    @staticmethod
    def marker(command):
        return "user-admin-v1:" + json.dumps(
            {
                "owner": str(command.target_id),
                "subject": str(command.user_id),
                "instance": command.instance,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def _check(self, command):
        if (
            command.service != "gitlab"
            or command.instance != self.capabilities.instance
        ):
            raise ControlError("instance_conflict")
        if command.action not in self.capabilities.actions:
            raise ControlError("unsupported_action")
        if command.action == "create" and command.native_id:
            raise ControlError("creation_not_authorized")
        if command.action != "create" and not re.fullmatch(
            r"[1-9][0-9]*", command.native_id
        ):
            raise ControlError("ownership_unverified")

    def _request(self, method, path, data=None, expected=(200,)):
        headers = {"PRIVATE-TOKEN": self._token}
        body = b""
        if data is not None:
            body = json.dumps(data, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        reply = self.client.request(
            method, "/api/v4" + path, headers=headers, body=body
        )
        if reply.status not in expected:
            raise NativeTransportError()
        return reply

    def _preflight(self):
        version = self._request("GET", "/version").json()
        settings = self._request("GET", "/application/settings").json()
        if type(version) is not dict or version.get("version") != "18.1.0":
            raise ControlError("unsupported_action")
        # BanDuplicateUsersWorker can otherwise affect unrelated accounts.
        # Missing/unknown settings are NOT interpreted as safe defaults.
        if (
            type(settings) is not dict
            or settings.get("enforce_email_subaddress_restrictions") is not False
        ):
            raise ControlError("unsupported_action")

    def _user(self, command, user):
        if (
            type(user) is not dict
            or type(user.get("id")) is not int
            or user["id"] <= 0
            or (command.native_id and str(user["id"]) != command.native_id)
            or user.get("note") != self.marker(command)
            or user.get("is_admin") is not False
            or type(user.get("username")) is not str
            or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}", user["username"])
            or not self._identity_matches(command, user.get("identities"))
        ):
            raise ControlError("ownership_unverified")
        return user

    @staticmethod
    def _identity_matches(command, identities):
        return (
            type(identities) is list
            and len(identities) == 1
            and type(identities[0]) is dict
            and identities[0].get("provider") == "openid_connect"
            and identities[0].get("extern_uid") == str(command.user_id)
            and identities[0].get("saml_provider_id") is None
        )

    def _read(self, command):
        return self._user(
            command, self._request("GET", "/users/" + command.native_id).json()
        )

    def _observation(self, command, user, *, receipt="", create=False):
        if create:
            state = "unbound"
        elif user.get("state") == "active":
            state = "enabled"
        elif user.get("state") in {
            "banned",
            "blocked",
            "blocked_pending_approval",
            "ldap_blocked",
            "deactivated",
        }:
            state = "blocked"
        else:
            raise ControlError("ownership_unverified")
        if state == "blocked" and user.get("state") == "banned" and not receipt:
            receipt = self.receipts(command)
        binding = (
            Binding(str(user["id"]), user["username"])
            if command.action == "bind"
            else None
        )
        return Observation(
            native_id=str(user["id"]),
            subject=str(command.user_id),
            instance=command.instance,
            owner=command.target_id,
            state=state,
            block_receipt=receipt,
            binding=binding,
        )

    def inspect(self, command):
        self._check(command)
        return self._observation(command, self._read(command))

    def apply(self, command):
        self._check(command)
        # BIND is read-only remotely, but enables central issuance; it requires
        # the same accepted-version/config gate as native mutations.
        self._preflight()
        if command.action == "create":
            profile = self.profiles(command)
            if (
                type(profile) is not Profile
                or type(profile.username) is not str
                or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", profile.username)
                or type(profile.email) is not str
                or not 0 < len(profile.email) <= 254
                or type(profile.name) is not str
                or not 0 < len(profile.name) <= 255
            ):
                raise ControlError("invalid_request")
            user = self._user(
                command,
                self._request(
                    "POST",
                    "/users",
                    {
                        "username": profile.username,
                        "email": profile.email,
                        "name": profile.name,
                        "admin": False,
                        "force_random_password": True,
                        "skip_confirmation": True,
                        "provider": "openid_connect",
                        "extern_uid": str(command.user_id),
                        "note": self.marker(command),
                    },
                    expected=(201,),
                ).json(),
            )
            return self._observation(command, user, create=True)
        user = self._read(command)
        if command.action == "bind":
            return self._observation(command, user)
        receipt = ""
        if command.action == "block":
            if user.get("state") == "active":
                self._request(
                    "POST", f"/users/{command.native_id}/ban", expected=(200, 201, 204)
                )
                user = self._read(command)
                if user.get("state") != "banned":
                    raise NativeTransportError()
                receipt = str(command.operation_id)
            elif user.get("state") == "banned" and self.receipts(command):
                receipt = self.receipts(command)
            else:
                raise ControlError("foreign_block")
        elif command.action == "enable":
            if user.get("state") == "banned" and self.receipts(command):
                self._request(
                    "POST",
                    f"/users/{command.native_id}/unban",
                    expected=(200, 201, 204),
                )
                user = self._read(command)
            if user.get("state") != "active":
                raise ControlError("foreign_block")
        return self._observation(command, user, receipt=receipt)
