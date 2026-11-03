"""Synthetic Synapse REST; no real homeserver/account/device operations."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import hmac
import json
from urllib.parse import unquote
from uuid import uuid4

from django.test import SimpleTestCase

from .adapters import Command
from .engine import ControlError
from .native.http import NativeTransportError, Reply
from .native.synapse import SynapseAdapter

SECRET = "synthetic-registration-secret-only"


class SynapseFixture:
    def __init__(self):
        self.user = None
        self.calls = []
        self.version = "1.164.1"
        self.lose_registration = False

    def request(self, method, target, *, headers=None, body=b""):
        data = json.loads(body) if body else None
        self.calls.append((method, target, data))
        if target == "/_synapse/admin/v1/server_version":
            assert headers["Authorization"] == "Bearer synthetic-admin-token"
            return self.reply({"server_version": self.version})
        if target == "/_synapse/admin/v1/register":
            assert "Authorization" not in headers
            if method == "GET":
                return self.reply({"nonce": "synthetic-nonce"})
            if self.user is not None:
                return self.reply({"error": "private-collision-body"}, 409)
            expected = hmac.new(
                SECRET.encode(),
                (
                    "synthetic-nonce\0"
                    + data["username"]
                    + "\0"
                    + data["password"]
                    + "\0notadmin"
                ).encode(),
                hashlib.sha1,
            ).hexdigest()
            assert hmac.compare_digest(expected, data["mac"])
            assert data["inhibit_login"] is True
            assert data["admin"] is False
            self.user = {
                "name": "@" + data["username"] + ":matrix.example.test",
                "admin": False,
                "deactivated": False,
                "locked": False,
                "external_ids": [],
                "password_hash": "synthetic-preserved-hash",
                "devices": ["preserved-device"],
                "rooms": ["preserved-room"],
            }
            if self.lose_registration:
                raise NativeTransportError()
            return self.reply(
                {"user_id": self.user["name"], "home_server": "matrix.example.test"}
            )
        assert headers["Authorization"] == "Bearer synthetic-admin-token"
        if target.startswith("/_synapse/admin/v2/users/"):
            assert unquote(target.rsplit("/", 1)[1]) == self.user["name"]
            if method == "GET":
                return self.reply(self.user)
            assert set(data) in [{"external_ids"}, {"locked"}]
            self.user.update(data)
            return self.reply({})
        raise AssertionError("unexpected fixture endpoint")

    @staticmethod
    def reply(data, status=200):
        return Reply(status, json.dumps(data).encode(), "application/json")


class SynapseCandidateTests(SimpleTestCase):
    def setUp(self):
        self.client = SynapseFixture()
        self.owned = False
        self.receipt = ""
        self.adapter = SynapseAdapter(
            client=self.client,
            token="synthetic-admin-token",
            registration_secret=SECRET,
            instance="fixture",
            server_name="matrix.example.test",
            ownership=lambda command: self.owned,
            receipts=lambda command: self.receipt,
        )
        self.command = Command(
            target_id=uuid4(),
            operation_id=uuid4(),
            user_id=1002,
            service="matrix",
            instance="fixture",
            generation=1,
            action="create",
            native_id="",
        )

    def created(self):
        observation = self.adapter.apply(self.command)
        self.owned = True  # Represents confirmed, durable engine creation receipt.
        return replace(self.command, action="bind", native_id=observation.native_id)

    def bound(self):
        command = self.created()
        self.adapter.apply(command)
        return command

    def test_registration_is_create_only_nonadmin_without_devices_or_auth_password_copy(
        self,
    ):
        observation = self.adapter.apply(self.command)
        writes = [(m, path, data) for m, path, data in self.client.calls if m != "GET"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1], "/_synapse/admin/v1/register")
        self.assertIs(writes[0][2]["inhibit_login"], True)
        self.assertIs(writes[0][2]["admin"], False)
        self.assertGreaterEqual(len(writes[0][2]["password"]), 48)
        self.assertNotEqual(writes[0][2]["password"], SECRET)
        self.assertEqual(observation.state, "unbound")
        self.assertEqual(
            observation.native_id,
            "@ua_" + self.command.target_id.hex + ":matrix.example.test",
        )
        self.assertIsNone(observation.binding)

    def test_binding_is_separate_and_changes_only_external_ids_on_owned_user(self):
        command = self.created()
        original = deepcopy(self.client.user)
        inspected = self.adapter.inspect(command)
        self.assertEqual(inspected.state, "unbound")
        self.client.calls.clear()
        observation = self.adapter.apply(command)
        writes = [data for method, path, data in self.client.calls if method == "PUT"]
        self.assertEqual(
            writes,
            [
                {
                    "external_ids": [
                        {"auth_provider": "oidc-common-auth", "external_id": "1002"}
                    ]
                }
            ],
        )
        self.assertEqual(observation.binding.external_id, command.native_id)
        self.assertEqual(
            observation.binding.external_username, "ua_" + command.target_id.hex
        )
        self.assertEqual(
            {k: v for k, v in self.client.user.items() if k != "external_ids"},
            {k: v for k, v in original.items() if k != "external_ids"},
        )

    def test_lock_unlock_preserve_password_devices_rooms_admin_and_binding(self):
        command = self.bound()
        original = deepcopy(self.client.user)
        block = replace(command, action="block", operation_id=uuid4())
        observation = self.adapter.apply(block)
        self.assertEqual(observation.state, "blocked")
        self.receipt = observation.block_receipt
        self.assertEqual(self.receipt, str(block.operation_id))
        observation = self.adapter.apply(replace(command, action="enable"))
        self.assertEqual(observation.state, "enabled")
        self.assertEqual(self.client.user, original)
        for method, path, data in self.client.calls:
            if method == "PUT":
                self.assertNotIn("deactivated", data)
                self.assertNotIn("password", data)
                self.assertNotIn("admin", data)
                self.assertNotIn("logout_devices", data)
        self.assertFalse(
            any(
                "logout" in path or "deactivate" in path or "devices" in path
                for _, path, _ in self.client.calls
            )
        )
        self.assertEqual(observation.existing_sessions, "unknown")

    def test_existing_deactivated_admin_or_foreign_binding_never_gets_mutated(self):
        command = self.created()
        original = deepcopy(self.client.user)
        for fields in [
            {"deactivated": True},
            {"admin": True},
            {"locked": 1},
            {
                "external_ids": [
                    {"auth_provider": "oidc-common-auth", "external_id": "foreign"}
                ]
            },
        ]:
            self.client.user = {**original, **fields}
            self.client.calls.clear()
            with (
                self.subTest(fields=fields),
                self.assertRaisesMessage(ControlError, "ownership_unverified"),
            ):
                self.adapter.apply(command)
            self.assertFalse(
                any(method == "PUT" for method, path, data in self.client.calls)
            )

    def test_uuid_shaped_remote_user_without_confirmed_receipt_is_not_adopted(self):
        command = self.created()
        self.owned = False
        self.client.calls.clear()
        with self.assertRaisesMessage(ControlError, "ownership_unverified"):
            self.adapter.inspect(command)
        self.assertEqual(self.client.calls, [])

    def test_lost_registration_response_does_not_auto_retry_or_authorize_binding(self):
        self.client.lose_registration = True
        with self.assertRaisesRegex(NativeTransportError, "^native_transport_failed$"):
            self.adapter.apply(self.command)
        self.assertEqual(
            sum(method == "POST" for method, path, data in self.client.calls), 1
        )
        with self.assertRaisesMessage(ControlError, "ownership_unverified"):
            self.adapter.inspect(
                replace(
                    self.command,
                    action="bind",
                    native_id=self.adapter.native_id(self.command),
                )
            )
        self.assertFalse(
            any(method == "PUT" for method, path, data in self.client.calls)
        )

    def test_foreign_lock_is_not_cleared_and_bind_does_not_unlock_our_lock(self):
        command = self.created()
        self.client.user["locked"] = True
        with self.assertRaisesMessage(ControlError, "foreign_block"):
            self.adapter.apply(command)
        self.receipt = "confirmed-exclusive-authority-receipt"
        observation = self.adapter.apply(command)
        self.assertEqual(observation.state, "blocked")
        self.assertTrue(self.client.user["locked"])
        self.assertEqual(observation.block_receipt, self.receipt)
        self.assertIsNotNone(observation.binding)

    def test_wrong_version_or_excluded_service_never_registers_or_changes_user(self):
        self.client.version = "1.165.0"
        with self.assertRaisesMessage(ControlError, "unsupported_action"):
            self.adapter.apply(self.command)
        self.assertFalse(
            any(method != "GET" for method, path, data in self.client.calls)
        )
        self.client.calls.clear()
        with self.assertRaises(ControlError):
            self.adapter.apply(replace(self.command, service="jenkins"))
        self.assertEqual(self.client.calls, [])
