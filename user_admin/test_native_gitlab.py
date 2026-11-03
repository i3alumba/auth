"""Synthetic GitLab REST shapes; not exact-version vendor acceptance."""

from dataclasses import replace
import json
from uuid import uuid4

from django.test import SimpleTestCase

from .adapters import Command
from .engine import ControlError
from .native.gitlab import GitlabAdapter, Profile
from .native.http import NativeTransportError, Reply


class GitlabFixture:
    def __init__(self):
        self.user = None
        self.calls = []
        self.version = "18.1.0"
        self.duplicate_setting = False
        self.fail_write = False

    def request(self, method, target, *, headers=None, body=b""):
        self.calls.append((method, target, headers, body))
        assert headers["PRIVATE-TOKEN"] == "synthetic-native-token"
        if target == "/api/v4/version":
            return self.reply({"version": self.version})
        if target == "/api/v4/application/settings":
            return self.reply(
                {"enforce_email_subaddress_restrictions": self.duplicate_setting}
            )
        if method == "POST" and self.fail_write:
            raise NativeTransportError()
        if method == "POST" and target == "/api/v4/users":
            if self.user is not None:
                return self.reply({"error": "synthetic-private-body"}, 409)
            data = json.loads(body)
            self.user = {
                "id": 42,
                "username": data["username"],
                "note": data["note"],
                "is_admin": data["admin"],
                "state": "active",
                "identities": [
                    {
                        "provider": data["provider"],
                        "extern_uid": data["extern_uid"],
                        "saml_provider_id": None,
                    }
                ],
            }
            return self.reply(self.user, 201)
        if method == "GET" and target == "/api/v4/users/42":
            return self.reply(self.user)
        if method == "POST" and target in {
            "/api/v4/users/42/ban",
            "/api/v4/users/42/unban",
        }:
            self.user["state"] = "banned" if target.endswith("/ban") else "active"
            return self.reply({}, 201)
        raise AssertionError("unexpected fixture endpoint")

    @staticmethod
    def reply(data, status=200):
        return Reply(status, json.dumps(data).encode(), "application/json")


class GitlabCandidateTests(SimpleTestCase):
    def setUp(self):
        self.client = GitlabFixture()
        self.receipt = ""
        self.adapter = GitlabAdapter(
            client=self.client,
            token="synthetic-native-token",
            instance="fixture",
            profiles=lambda command: Profile(
                "candidate-user", "candidate@example.test", "Candidate User"
            ),
            receipts=lambda command: self.receipt,
        )
        self.command = Command(
            target_id=uuid4(),
            operation_id=uuid4(),
            user_id=1001,
            service="gitlab",
            instance="fixture",
            generation=1,
            action="create",
            native_id="",
        )

    def created(self):
        observation = self.adapter.apply(self.command)
        return replace(self.command, action="bind", native_id=observation.native_id)

    def test_create_is_one_create_only_request_with_atomic_provider_and_owner_no_password_copy(
        self,
    ):
        observation = self.adapter.apply(self.command)
        mutations = [c for c in self.client.calls if c[0] != "GET"]
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0][1], "/api/v4/users")
        data = json.loads(mutations[0][3])
        self.assertIs(data["admin"], False)
        self.assertIs(data["force_random_password"], True)
        self.assertNotIn("password", data)
        self.assertEqual(data["extern_uid"], "1001")
        self.assertEqual(data["provider"], "openid_connect")
        self.assertEqual(data["note"], self.adapter.marker(self.command))
        self.assertEqual(observation.native_id, "42")
        self.assertEqual(observation.state, "unbound")
        self.assertIsNone(observation.binding)
        self.assertEqual(observation.existing_sessions, "unknown")

    def test_bind_is_readonly_and_returns_exact_remote_identity_not_profile_guess(self):
        command = self.created()
        self.client.calls.clear()
        observation = self.adapter.apply(command)
        self.assertEqual(
            [c[:2] for c in self.client.calls],
            [
                ("GET", "/api/v4/version"),
                ("GET", "/api/v4/application/settings"),
                ("GET", "/api/v4/users/42"),
            ],
        )
        self.assertEqual(observation.binding.external_id, "42")
        self.assertEqual(observation.binding.external_username, "candidate-user")
        self.assertEqual(observation.binding.minio_policy, "")

    def test_version_change_after_create_refuses_binding_publication_proof(self):
        command = self.created()
        self.client.version = "18.2.0"
        self.client.calls.clear()
        with self.assertRaisesMessage(ControlError, "unsupported_action"):
            self.adapter.apply(command)
        self.assertFalse(
            any(method != "GET" for method, target, headers, body in self.client.calls)
        )

    def test_only_ban_unban_are_used_and_unban_requires_confirmed_own_receipt(self):
        command = self.created()
        block = replace(command, action="block", operation_id=uuid4())
        observation = self.adapter.apply(block)
        self.assertEqual(observation.state, "blocked")
        self.assertEqual(observation.block_receipt, str(block.operation_id))
        self.assertEqual(observation.api_credentials, "unknown")
        with self.assertRaisesMessage(ControlError, "foreign_block"):
            self.adapter.apply(replace(command, action="enable"))
        self.receipt = observation.block_receipt
        observation = self.adapter.apply(replace(command, action="enable"))
        self.assertEqual(observation.state, "enabled")
        paths = [c[1] for c in self.client.calls]
        self.assertIn("/api/v4/users/42/ban", paths)
        self.assertIn("/api/v4/users/42/unban", paths)
        self.assertFalse(
            any(path.endswith("/block") or path.endswith("/unblock") for path in paths)
        )

    def test_owner_subject_native_id_and_native_admin_changes_are_refused(self):
        command = self.created()
        original = dict(self.client.user)
        variants = [
            {"note": "foreign"},
            {"id": 43},
            {"is_admin": True},
            {"identities": [{"provider": "openid_connect", "extern_uid": "foreign"}]},
            {"identities": [{"provider": "ldapmain", "extern_uid": "1001"}]},
        ]
        for change in variants:
            self.client.user = {**original, **change}
            before = len([c for c in self.client.calls if c[0] != "GET"])
            with (
                self.subTest(change=change),
                self.assertRaisesMessage(ControlError, "ownership_unverified"),
            ):
                self.adapter.inspect(command)
            self.assertEqual(
                len([c for c in self.client.calls if c[0] != "GET"]), before
            )

    def test_unknown_or_enabled_duplicate_ban_setting_and_wrong_version_fail_before_write(
        self,
    ):
        for setting in [None, True, "false", 0]:
            self.client.duplicate_setting = setting
            with (
                self.subTest(setting=setting),
                self.assertRaisesMessage(ControlError, "unsupported_action"),
            ):
                self.adapter.apply(self.command)
        self.client.duplicate_setting = False
        self.client.version = "18.2.0"
        with self.assertRaisesMessage(ControlError, "unsupported_action"):
            self.adapter.apply(self.command)
        self.assertFalse(any(c[0] != "GET" for c in self.client.calls))

    def test_foreign_block_state_never_becomes_our_ban(self):
        command = self.created()
        self.client.user["state"] = "blocked"
        self.receipt = "old-local-receipt"
        observation = self.adapter.inspect(command)
        self.assertEqual(observation.block_receipt, "")
        with self.assertRaisesMessage(ControlError, "foreign_block"):
            self.adapter.apply(replace(command, action="enable"))
        self.assertEqual(self.client.user["state"], "blocked")

    def test_collision_or_lost_response_does_not_update_foreign_user_or_retry(self):
        self.created()
        original = dict(self.client.user)
        with self.assertRaisesRegex(NativeTransportError, "^native_transport_failed$"):
            self.adapter.apply(self.command)
        self.assertEqual(self.client.user, original)
        self.client.fail_write = True
        with self.assertRaisesRegex(NativeTransportError, "^native_transport_failed$"):
            self.adapter.apply(replace(self.command, action="block", native_id="42"))
        self.assertEqual(self.client.user["state"], "active")

    def test_excluded_provider_or_wrong_instance_never_receives_credentials(self):
        for command in [
            replace(self.command, service="jenkins"),
            replace(self.command, instance="other"),
            replace(self.command, native_id="42"),
        ]:
            with self.subTest(command=command), self.assertRaises(ControlError):
                self.adapter.apply(command)
        self.assertEqual(self.client.calls, [])
