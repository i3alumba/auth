"""Synthetic MinIO S3/admin REST shapes, not STS/Console/vendor acceptance."""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
from uuid import uuid4

from django.test import SimpleTestCase

from .adapters import Command
from .engine import ControlError
from .native.http import NativeTransportError, Reply
from .native.minio import MinioAdapter
from .native.minio_policy import bucket_policy, policy_stamp, resource_name


class MinioFixture:
    authority = "minio.example.test:9443"

    def __init__(self):
        self.buckets = set()
        self.policies = {}
        self.calls = []
        self.site_replication = False
        self.site_content_type = "application/json"
        self.version = "2023-05-18T00:05:36Z"
        self.region_override = "omitted"
        self.lose_write = False
        self.collide_bucket_write = False
        self.policy_content_type = "application/json"

    def request(self, method, target, *, headers=None, body=b""):
        assert headers["host"] == self.authority
        assert headers["authorization"].startswith(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"
        )
        self.calls.append((method, target, body))
        if target == "/minio/admin/v3/info":
            data = {"mode": "online", "servers": [{"version": self.version}]}
            if self.region_override != "omitted":
                data["region"] = self.region_override
            return self.reply(data)
        if target == "/minio/admin/v3/site-replication/info":
            return replace(
                self.reply({"enabled": self.site_replication}),
                content_type=self.site_content_type,
            )
        if target.startswith("/minio/admin/v3/info-canned-policy?name="):
            name = target.split("=", 1)[1]
            return (
                replace(
                    self.reply(self.policies[name]),
                    content_type=self.policy_content_type,
                )
                if name in self.policies
                else self.reply({"Code": "XMinioAdminNoSuchPolicy"}, 404)
            )
        if target.startswith("/minio/admin/v3/add-canned-policy?name="):
            assert method == "PUT"
            name = target.split("=", 1)[1]
            self.policies[name] = json.loads(body)
            if self.lose_write:
                raise NativeTransportError()
            return self.reply({})
        name = target.removeprefix("/")
        if method == "HEAD":
            return Reply(200 if name in self.buckets else 404, b"")
        if method == "PUT":
            if name in self.buckets or self.collide_bucket_write:
                return self.reply({"Code": "BucketAlreadyOwnedByYou"}, 409)
            self.buckets.add(name)
            if self.lose_write:
                raise NativeTransportError()
            return Reply(200, b"")
        raise AssertionError("unexpected fixture endpoint")

    @staticmethod
    def reply(data, status=200):
        return Reply(status, json.dumps(data).encode(), "application/json")


class MinioCandidateTests(SimpleTestCase):
    def setUp(self):
        self.client = MinioFixture()
        self.owned = False
        self.receipt = ""
        self.known = set()
        self.adapter = MinioAdapter(
            client=self.client,
            access_key="AKIDEXAMPLE",
            secret_key="synthetic-minio-signing-secret",
            instance="fixture",
            ownership=lambda command: self.owned,
            receipts=lambda command: self.receipt,
            policy_receipts=lambda command, op, generation, blocked: (
                op,
                generation,
                blocked,
            )
            in self.known,
            policy_history=lambda command: bool(self.known),
            exclusive_authority=True,
            claim_policy_only=True,
            standalone_without_federation=True,
            clock=lambda: datetime(2025, 1, 2, tzinfo=timezone.utc),
        )
        self.command = Command(
            target_id=uuid4(),
            operation_id=uuid4(),
            user_id=1003,
            service="minio",
            instance="fixture",
            generation=1,
            action="create",
            native_id="",
        )
        self.name = resource_name(self.command.target_id)

    def created(self):
        observation = self.adapter.apply(self.command)
        self.owned = True
        return replace(
            self.command,
            native_id=observation.native_id,
            action="bind",
            operation_id=uuid4(),
        )

    def bound(self):
        command = self.created()
        observation = self.adapter.apply(command)
        self.known.add(
            policy_stamp(self.client.policies[self.name], self.command.target_id)
        )
        return command, observation

    def test_create_is_one_fixed_new_bucket_with_no_policy_iam_or_object_mutation(self):
        observation = self.adapter.apply(self.command)
        writes = [
            (method, target)
            for method, target, body in self.client.calls
            if method not in {"GET", "HEAD"}
        ]
        self.assertEqual(writes, [("PUT", "/" + self.name)])
        self.assertEqual(self.client.buckets, {self.name})
        self.assertEqual(self.client.policies, {})
        self.assertEqual(observation.state, "unbound")
        self.assertIsNone(observation.binding)
        self.assertEqual(observation.native_id, self.name)

    def test_collision_even_already_owned_or_intervening_creation_never_becomes_ownership(
        self,
    ):
        self.client.buckets.add(self.name)
        with self.assertRaisesMessage(ControlError, "ownership_unverified"):
            self.adapter.apply(self.command)
        self.assertFalse(
            any(method == "PUT" for method, target, body in self.client.calls)
        )
        self.client.buckets.clear()
        self.client.collide_bucket_write = True
        with self.assertRaisesRegex(NativeTransportError, "^native_transport_failed$"):
            self.adapter.apply(self.command)
        self.assertFalse(self.client.policies)

    def test_bind_creates_only_own_policy_and_uses_oidc_subject_not_iam_account(self):
        command = self.created()
        self.client.calls.clear()
        observation = self.adapter.apply(command)
        writes = [
            (method, target)
            for method, target, body in self.client.calls
            if method == "PUT"
        ]
        self.assertEqual(
            writes, [("PUT", "/minio/admin/v3/add-canned-policy?name=" + self.name)]
        )
        self.assertEqual(observation.binding.external_id, "1003")
        self.assertEqual(observation.binding.external_username, self.name)
        self.assertEqual(observation.binding.minio_policy, self.name)
        self.assertNotEqual(observation.binding.external_id, observation.native_id)
        self.assertEqual(observation.existing_sessions, "unknown")
        self.assertFalse(
            any(
                "add-user" in target or "set-user-status" in target
                for method, target, body in self.client.calls
            )
        )

    def test_block_enable_preserve_bucket_and_other_policy_and_require_our_block_receipt(
        self,
    ):
        command, observation = self.bound()
        self.client.buckets.add("original-data")
        foreign = {"Version": "2012-10-17", "Statement": []}
        self.client.policies["existing-shared-policy"] = deepcopy(foreign)
        block = replace(command, action="block", operation_id=uuid4(), generation=2)
        blocked = self.adapter.apply(block)
        self.known.add(
            policy_stamp(self.client.policies[self.name], self.command.target_id)
        )
        self.assertEqual(blocked.state, "blocked")
        self.assertEqual(blocked.block_receipt, str(block.operation_id))
        self.assertEqual(blocked.new_login, "unsupported")
        self.assertEqual(blocked.existing_sessions, "unknown")
        self.assertEqual(blocked.api_credentials, "unknown")
        with self.assertRaisesMessage(ControlError, "foreign_block"):
            self.adapter.apply(
                replace(command, action="enable", operation_id=uuid4(), generation=3)
            )
        self.receipt = blocked.block_receipt
        enabled = self.adapter.apply(
            replace(command, action="enable", operation_id=uuid4(), generation=3)
        )
        self.assertEqual(enabled.state, "enabled")
        self.assertEqual(self.client.buckets, {self.name, "original-data"})
        self.assertEqual(self.client.policies["existing-shared-policy"], foreign)
        self.assertFalse(
            any(method == "DELETE" for method, target, body in self.client.calls)
        )

    def test_valid_looking_policy_without_confirmed_ack_is_not_adopted(self):
        command = self.created()
        self.client.policies[self.name] = bucket_policy(
            owner=command.target_id, operation=uuid4(), generation=1, blocked=False
        )
        self.client.calls.clear()
        with self.assertRaisesMessage(ControlError, "ownership_unverified"):
            self.adapter.apply(command)
        self.assertFalse(
            any(method == "PUT" for method, target, body in self.client.calls)
        )

    def test_known_policy_tampering_or_manual_deletion_is_not_silently_restored(self):
        command, _ = self.bound()
        original = deepcopy(self.client.policies[self.name])
        self.client.policies[self.name]["Statement"][0]["Resource"] = ["*"]
        with self.assertRaisesMessage(ControlError, "ownership_unverified"):
            self.adapter.inspect(command)
        self.client.policies[self.name] = original
        del self.client.policies[self.name]
        self.client.calls.clear()
        with self.assertRaisesMessage(ControlError, "ownership_unverified"):
            self.adapter.apply(command)
        self.assertFalse(
            any(method == "PUT" for method, target, body in self.client.calls)
        )

    def test_legacy_raw_json_policy_content_type_is_endpoint_specific_and_not_html(
        self,
    ):
        self.client.site_content_type = "text/plain; charset=utf-8"
        command = self.created()
        self.client.policy_content_type = "text/plain; charset=utf-8"
        observation = self.adapter.apply(command)
        self.assertEqual(observation.state, "enabled")
        self.known.add(policy_stamp(self.client.policies[self.name], command.target_id))
        self.assertEqual(self.adapter.inspect(command).state, "enabled")
        self.client.policy_content_type = "text/html"
        with self.assertRaisesRegex(NativeTransportError, "^native_transport_failed$"):
            self.adapter.inspect(command)
        self.client.policy_content_type = "application/json"
        self.client.site_content_type = "text/html"
        writes = sum(method == "PUT" for method, target, body in self.client.calls)
        with self.assertRaisesRegex(NativeTransportError, "^native_transport_failed$"):
            self.adapter.apply(command)
        self.assertEqual(
            sum(method == "PUT" for method, target, body in self.client.calls), writes
        )

    def test_explicit_null_or_nondefault_region_is_not_coerced_to_default(self):
        for value in [None, "eu-west-1", True]:
            self.client.region_override = value
            with (
                self.subTest(region=value),
                self.assertRaisesMessage(ControlError, "unsupported_action"),
            ):
                self.adapter.apply(self.command)
        self.assertFalse(
            any(method == "PUT" for method, target, body in self.client.calls)
        )

    def test_lost_policy_response_does_not_retry_publish_or_erase_bucket(self):
        command = self.created()
        self.client.lose_write = True
        with self.assertRaisesRegex(NativeTransportError, "^native_transport_failed$"):
            self.adapter.apply(command)
        self.assertIn(self.name, self.client.policies)
        self.assertIn(self.name, self.client.buckets)
        self.assertEqual(
            sum(
                method == "PUT" and "add-canned-policy" in target
                for method, target, body in self.client.calls
            ),
            1,
        )
        self.assertFalse(self.known)

    def test_locking_owned_but_unbound_bucket_installs_deny_without_publishing_identity(
        self,
    ):
        command = self.created()
        observation = self.adapter.apply(
            replace(command, action="block", operation_id=uuid4())
        )
        self.assertEqual(observation.state, "blocked")
        self.assertIsNone(observation.binding)
        self.assertTrue(
            policy_stamp(self.client.policies[self.name], command.target_id)[2]
        )

    def test_wrong_version_replication_or_missing_local_ownership_refuse_before_mutation(
        self,
    ):
        self.client.site_replication = True
        with self.assertRaisesMessage(ControlError, "unsupported_action"):
            self.adapter.apply(self.command)
        self.client.site_replication = False
        self.client.version = "2025-01-01T00:00:00Z"
        with self.assertRaisesMessage(ControlError, "unsupported_action"):
            self.adapter.apply(self.command)
        self.assertFalse(
            any(method == "PUT" for method, target, body in self.client.calls)
        )
        self.client.calls.clear()
        with self.assertRaisesMessage(ControlError, "ownership_unverified"):
            self.adapter.inspect(
                replace(self.command, native_id=self.name, action="bind")
            )
        self.assertEqual(self.client.calls, [])
        with self.assertRaises(ControlError):
            self.adapter.apply(replace(self.command, service="jenkins"))
        self.assertEqual(self.client.calls, [])
