"""Synthetic fake-native tests. No credentials, HTTP or production fixtures."""

from dataclasses import replace
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import transaction
from django.test import TestCase, override_settings

from sso.models import Service, ServiceIdentity

from .adapters import Capabilities, Observation
from .engine import ControlError, execute, schedule
from .models import AdministrationLock, AuditEvent, Operation, Target, UserControl


class FakeNative:
    capabilities = Capabilities(
        service="gitlab",
        instance="fixture",
        actions=frozenset({"create", "enable", "block"}),
        create_only=True,
    )

    def __init__(self):
        self.calls = []
        self.after_inspect = None
        self.after_apply = None
        self.response = None
        self.inspect_response = None
        self.current = None

    def proof(self, command):
        return Observation(
            native_id=command.native_id or "native-42",
            subject=str(command.user_id),
            instance=command.instance,
            owner=command.target_id,
            state="blocked" if command.action == "block" else "enabled",
            new_login="confirmed",
            existing_sessions="confirmed",
            api_credentials="confirmed",
            block_receipt=(
                str(command.operation_id) if command.action == "block" else ""
            ),
        )

    def inspect(self, command):
        proof = self.inspect_response or self.current or self.proof(command)
        if self.after_inspect:
            self.after_inspect(command)
        return proof

    def apply(self, command):
        self.calls.append(command.action)
        if self.after_apply:
            self.after_apply(command)
        self.current = self.response or self.proof(command)
        return self.current


@override_settings(USER_ADMIN_NATIVE_EXECUTION_ENABLED=True)
class NativeOutboxTests(TestCase):
    def setUp(self):
        # TransactionTestCase flushes migration data in PostgreSQL-only tests.
        AdministrationLock.objects.get_or_create(pk=1)
        User = get_user_model()
        self.actor = User.objects.create_user(
            username="fixture-admin", is_superuser=True, is_staff=True
        )
        self.user = User.objects.create_user(username="fixture-user")
        group = Group.objects.create(name="fixture-gitlab")
        self.service = Service.objects.create(slug="gitlab", group=group)
        self.user.groups.add(group)
        UserControl.objects.create(user=self.user, creation_receipt=uuid4())
        self.adapter = FakeNative()

    def request(self, action="create", version=0, key=None, **kwargs):
        return schedule(
            actor_id=self.actor.pk,
            user_id=self.user.pk,
            service="gitlab",
            instance="fixture",
            action=action,
            expected_version=version,
            idempotency_key=key or uuid4(),
            **kwargs,
        )

    def created(self):
        op = self.request()
        self.assertEqual(execute(op.pk, self.adapter), "succeeded")
        return Target.objects.get(pk=op.target_id)

    def test_default_execution_disabled_keeps_durable_intent_untouched(self):
        op = self.request()
        with override_settings(USER_ADMIN_NATIVE_EXECUTION_ENABLED=False):
            with self.assertRaisesMessage(ControlError, "execution_disabled"):
                execute(op.pk, self.adapter)
        op.refresh_from_db()
        self.assertEqual(op.status, "pending")
        self.assertEqual(self.adapter.calls, [])

    def test_outer_transaction_rollback_includes_goal_outbox_version_audit(self):
        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                self.request()
                raise RuntimeError("synthetic failure")
        self.assertEqual(Target.objects.count(), 0)
        self.assertEqual(Operation.objects.count(), 0)
        self.assertEqual(AuditEvent.objects.count(), 0)
        self.assertEqual(UserControl.objects.get(user=self.user).version, 0)

    def test_live_superuser_required_staff_is_not_enough(self):
        get_user_model().objects.filter(pk=self.actor.pk).update(is_superuser=False)
        with self.assertRaisesMessage(ControlError, "administrator_required"):
            self.request()
        self.assertFalse(Operation.objects.exists())

    def test_inactive_administrator_denied(self):
        get_user_model().objects.filter(pk=self.actor.pk).update(is_active=False)
        with self.assertRaisesMessage(ControlError, "administrator_required"):
            self.request()

    def test_idempotent_request_and_duplicate_delivery_do_not_repeat_create(self):
        key = uuid4()
        first = self.request(key=key)
        self.assertEqual(first.pk, self.request(key=key).pk)
        self.assertEqual(execute(first.pk, self.adapter), "succeeded")
        self.assertEqual(execute(first.pk, self.adapter), "succeeded")
        self.assertEqual(self.adapter.calls, ["create"])
        self.assertEqual(Operation.objects.count(), 1)

    def test_same_key_different_request_is_conflict(self):
        key = uuid4()
        self.request(key=key)
        with self.assertRaisesMessage(ControlError, "idempotency_conflict"):
            self.request(action="block", key=key)
        with self.assertRaisesMessage(ControlError, "idempotency_conflict"):
            self.request(version=1, key=key)

    def test_stale_and_noninteger_versions_rejected(self):
        self.request()
        with self.assertRaisesMessage(ControlError, "stale_version"):
            self.request()
        with self.assertRaisesMessage(ControlError, "invalid_request"):
            self.request(version=True)
        self.assertEqual(Operation.objects.count(), 1)

    def test_existing_unmanaged_user_cannot_be_silently_provisioned(self):
        UserControl.objects.filter(user=self.user).update(creation_receipt=None)
        with self.assertRaisesMessage(ControlError, "creation_not_authorized"):
            self.request()
        self.assertFalse(Target.objects.exists())

    def test_existing_binding_does_not_authorize_creation_or_adoption(self):
        ServiceIdentity.objects.create(
            user=self.user,
            service=self.service,
            external_id="old-native",
            external_username="old-name",
        )
        with self.assertRaisesMessage(ControlError, "creation_not_authorized"):
            self.request()
        with self.assertRaisesMessage(ControlError, "ownership_required"):
            self.request(action="block")
        self.assertFalse(Target.objects.exists())

    def test_read_then_upsert_provider_is_not_create_only(self):
        self.adapter.capabilities = replace(
            self.adapter.capabilities, create_only=False
        )
        self.assertEqual(execute(self.request().pk, self.adapter), "unsupported")
        self.assertEqual(self.adapter.calls, [])

    def test_wrong_provider_instance_never_receives_a_call(self):
        self.adapter.capabilities = replace(self.adapter.capabilities, instance="other")
        self.assertEqual(execute(self.request().pk, self.adapter), "unsupported")
        self.assertEqual(self.adapter.calls, [])

    def test_unknown_create_holds_reservation_and_never_replays(self):
        op = self.request()

        def fail(_):
            raise RuntimeError("SYNTHETIC_PRIVATE_CREDENTIAL_DO_NOT_PERSIST")

        self.adapter.after_apply = fail
        self.assertEqual(execute(op.pk, self.adapter), "outcome_unknown")
        self.assertEqual(execute(op.pk, self.adapter), "outcome_unknown")
        newer = self.request(action="block", version=1)
        self.assertEqual(execute(newer.pk, self.adapter), "target_reserved")
        self.assertEqual(self.adapter.calls, ["create"])
        op.refresh_from_db()
        self.assertEqual(op.error_code, "outcome_unknown")
        self.assertNotIn("PRIVATE_CREDENTIAL", repr(list(Operation.objects.values())))
        self.assertNotIn("PRIVATE_CREDENTIAL", repr(list(AuditEvent.objects.values())))

    def test_unverified_native_account_is_not_adopted_from_response(self):
        op = self.request()
        self.adapter.response = replace(
            self.adapter.proof(OperationCommand(op)), owner=uuid4()
        )
        self.assertEqual(execute(op.pk, self.adapter), "outcome_unknown")
        target = Target.objects.get(pk=op.target_id)
        self.assertEqual(target.native_id, "")
        self.assertEqual(target.ownership, "unmanaged")

    def test_running_reservations_have_no_expiry_takeover(self):
        op = self.request()
        Operation.objects.filter(pk=op.pk).update(
            status="running", execution_token=uuid4()
        )
        self.assertEqual(execute(op.pk, self.adapter), "running")
        newer = self.request(action="block", version=1)
        self.assertEqual(execute(newer.pk, self.adapter), "target_reserved")
        self.assertEqual(self.adapter.calls, [])

    def test_revocation_during_create_retains_id_and_serializes_next_block(self):
        block = []

        def revoke(_):
            block.append(self.request(action="block", version=1))

        self.adapter.after_apply = revoke
        op = self.request()
        self.assertEqual(execute(op.pk, self.adapter), "superseded")
        target = Target.objects.get(pk=op.target_id)
        self.assertEqual(target.native_id, "native-42")
        self.assertEqual(target.ownership, "created")
        self.assertEqual(target.desired, "blocked")
        self.adapter.after_apply = None
        self.assertEqual(execute(block[0].pk, self.adapter), "succeeded")
        target.refresh_from_db()
        self.assertEqual(target.observed, "blocked")
        self.assertEqual(self.adapter.calls, ["create", "block"])

    def test_foreign_native_block_is_never_cleared(self):
        target = self.created()
        op = self.request(action="enable", version=1)
        self.adapter.inspect_response = replace(
            self.adapter.proof(OperationCommand(op)),
            state="blocked",
            block_receipt="operator-owned-block",
        )
        self.assertEqual(execute(op.pk, self.adapter), "failed")
        op.refresh_from_db()
        self.assertEqual(op.error_code, "foreign_block")
        self.assertEqual(self.adapter.calls, ["create"])
        target.refresh_from_db()
        self.assertEqual(target.block_receipt, "")

    def test_unknown_session_or_api_revocation_is_partial_not_success(self):
        self.created()
        op = self.request(action="block", version=1)
        self.adapter.response = replace(
            self.adapter.proof(OperationCommand(op)), existing_sessions="unknown"
        )
        self.assertEqual(execute(op.pk, self.adapter), "partial")
        op.refresh_from_db()
        self.assertEqual(op.evidence["existing_sessions"], "unknown")

    def test_actor_revoked_after_inspection_prevents_enable_write(self):
        self.created()
        op = self.request(action="enable", version=1)
        self.adapter.after_inspect = (
            lambda _: get_user_model()
            .objects.filter(pk=self.actor.pk)
            .update(is_superuser=False)
        )
        self.assertEqual(execute(op.pk, self.adapter), "failed")
        self.assertEqual(self.adapter.calls, ["create"])

    def test_actor_revoked_during_create_cannot_report_completed_grant(self):
        op = self.request()
        self.adapter.after_apply = (
            lambda _: get_user_model()
            .objects.filter(pk=self.actor.pk)
            .update(is_superuser=False)
        )
        self.assertEqual(execute(op.pk, self.adapter), "partial")
        op.refresh_from_db()
        self.assertEqual(op.error_code, "grant_revoked_in_flight")

    def test_user_group_revoked_before_native_write(self):
        op = self.request()
        self.user.groups.clear()
        self.assertEqual(execute(op.pk, self.adapter), "failed")
        self.assertEqual(self.adapter.calls, [])

    def test_block_does_not_depend_on_requesting_admin_remaining_active(self):
        self.created()
        op = self.request(action="block", version=1)
        get_user_model().objects.filter(pk=self.actor.pk).update(is_active=False)
        self.assertEqual(execute(op.pk, self.adapter), "succeeded")

    def test_block_cannot_take_ownership_of_an_operator_imposed_block(self):
        self.created()
        op = self.request(action="block", version=1)
        self.adapter.inspect_response = replace(
            self.adapter.proof(OperationCommand(op)),
            state="blocked",
            block_receipt="foreign-operator-block",
        )
        self.assertEqual(execute(op.pk, self.adapter), "failed")
        self.assertEqual(self.adapter.calls, ["create"])
        self.assertEqual(Target.objects.get(pk=op.target_id).block_receipt, "")

    def test_stale_enable_never_runs_after_a_newer_block(self):
        self.created()
        enable = self.request(action="enable", version=1)
        block = self.request(action="block", version=2)
        self.assertEqual(execute(enable.pk, self.adapter), "superseded")
        self.assertEqual(execute(block.pk, self.adapter), "succeeded")
        self.assertEqual(execute(enable.pk, self.adapter), "superseded")
        self.assertEqual(self.adapter.calls, ["create", "block"])

    def test_only_our_confirmed_block_can_be_reenabled(self):
        self.created()
        block = self.request(action="block", version=1)
        self.assertEqual(execute(block.pk, self.adapter), "succeeded")
        enable = self.request(action="enable", version=2)
        self.assertEqual(execute(enable.pk, self.adapter), "succeeded")
        self.assertEqual(self.adapter.calls, ["create", "block", "enable"])

    def test_adapter_exception_cannot_inject_private_error_codes(self):
        def fail(_):
            raise ControlError("SYNTHETIC_PRIVATE_EXCEPTION_BODY")

        self.adapter.after_apply = fail
        op = self.request()
        self.assertEqual(execute(op.pk, self.adapter), "outcome_unknown")
        op.refresh_from_db()
        self.assertEqual(op.error_code, "outcome_unknown")
        self.assertNotIn("PRIVATE_EXCEPTION", repr(list(Operation.objects.values())))

    def test_malformed_post_apply_evidence_is_unknown_without_private_persistence(self):
        cases = [
            ("state", {"secret": "SYNTHETIC_PRIVATE_NATIVE_BODY"}),
            ("new_login", ["SYNTHETIC_PRIVATE_NATIVE_BODY"]),
            ("existing_sessions", {"secret": "SYNTHETIC_PRIVATE_NATIVE_BODY"}),
            ("api_credentials", None),
        ]
        for index, (field, value) in enumerate(cases):
            with self.subTest(field=field):
                self.user = get_user_model().objects.create_user(
                    username=f"malformed-{index}"
                )
                self.user.groups.add(self.service.group)
                UserControl.objects.create(user=self.user, creation_receipt=uuid4())
                adapter = FakeNative()
                op = self.request()
                adapter.response = replace(
                    adapter.proof(OperationCommand(op)), **{field: value}
                )
                self.assertEqual(execute(op.pk, adapter), "outcome_unknown")
                op.refresh_from_db()
                self.assertEqual(op.evidence, {})
                target = Target.objects.get(pk=op.target_id)
                self.assertEqual(target.native_id, "")
                self.assertEqual(target.ownership, "unmanaged")
                self.assertNotIn(
                    "PRIVATE_NATIVE_BODY", repr(list(Operation.objects.values()))
                )

    def test_queued_second_create_cannot_create_again_after_first_receipt(self):
        newer = []
        self.adapter.after_apply = lambda _: newer.append(self.request(version=1))
        first = self.request()
        self.assertEqual(execute(first.pk, self.adapter), "superseded")
        self.adapter.after_apply = None
        self.assertEqual(execute(newer[0].pk, self.adapter), "failed")
        self.assertEqual(self.adapter.calls, ["create"])
        self.assertEqual(Target.objects.get(pk=first.target_id).native_id, "native-42")

    def test_block_cancels_unstarted_creation_without_native_revocation_claims(self):
        create = self.request()
        block = self.request(action="block", version=1)
        self.assertEqual(execute(create.pk, self.adapter), "superseded")
        self.assertEqual(execute(block.pk, self.adapter), "not_required")
        target = Target.objects.get(pk=create.target_id)
        self.assertEqual(target.desired, "blocked")
        self.assertEqual(target.observed, "not_created")
        self.assertEqual(target.native_id, "")
        block.refresh_from_db()
        self.assertEqual(block.evidence, {})
        self.assertEqual(self.adapter.calls, [])

    def test_read_only_inspection_failure_does_not_poison_later_block(self):
        self.created()
        enable = self.request(action="enable", version=1)

        def fail(_):
            raise RuntimeError("SYNTHETIC_PRIVATE_INSPECT_BODY")

        self.adapter.after_inspect = fail
        self.assertEqual(execute(enable.pk, self.adapter), "failed")
        enable.refresh_from_db()
        self.assertEqual(enable.error_code, "inspection_failed")
        self.adapter.after_inspect = None
        block = self.request(action="block", version=2)
        self.assertEqual(execute(block.pk, self.adapter), "succeeded")
        self.assertEqual(self.adapter.calls, ["create", "block"])
        self.assertNotIn("PRIVATE_INSPECT_BODY", repr(list(Operation.objects.values())))

    def test_jenkins_requests_are_rejected_without_changing_existing_access(self):
        group = Group.objects.create(name="existing-jenkins")
        service = Service.objects.create(slug="jenkins", group=group)
        self.user.groups.add(group)
        ServiceIdentity.objects.create(
            user=self.user,
            service=service,
            external_id="existing-jenkins-id",
            external_username="existing-user",
        )
        users = list(get_user_model().objects.order_by("pk").values())
        memberships = list(
            get_user_model().groups.through.objects.order_by("pk").values()
        )
        identities = list(ServiceIdentity.objects.order_by("pk").values())
        for action in Operation.Action.values:
            with self.subTest(action=action):
                with self.assertRaisesMessage(ControlError, "invalid_request"):
                    schedule(
                        actor_id=self.actor.pk,
                        user_id=self.user.pk,
                        service="jenkins",
                        instance="fixture",
                        action=action,
                        idempotency_key=uuid4(),
                        expected_version=0,
                    )
        self.assertEqual(users, list(get_user_model().objects.order_by("pk").values()))
        self.assertEqual(
            memberships,
            list(get_user_model().groups.through.objects.order_by("pk").values()),
        )
        self.assertEqual(
            identities, list(ServiceIdentity.objects.order_by("pk").values())
        )
        self.assertFalse(Target.objects.exists())
        self.assertFalse(Operation.objects.exists())
        self.assertFalse(AuditEvent.objects.exists())
        self.assertEqual(UserControl.objects.get(user=self.user).version, 0)

    def test_legacy_jenkins_outbox_never_reaches_an_adapter(self):
        # choices are not a database constraint: guard imported/old queue rows too.
        target = Target.objects.create(
            user=self.user,
            service="jenkins",
            instance="fixture",
            native_id="legacy-native-id",
            ownership="created",
            generation=1,
            desired="blocked",
        )
        operation = Operation.objects.create(
            target=target,
            actor_id=self.actor.pk,
            base_version=0,
            generation=1,
            action="block",
            idempotency_key=uuid4(),
        )

        class ForbiddenAdapter:
            @property
            def capabilities(self):
                raise AssertionError("Excluded service reached adapter")

            def inspect(self, command):
                raise AssertionError("Excluded service inspected")

            def apply(self, command):
                raise AssertionError("Excluded service mutated")

        self.assertEqual(execute(operation.pk, ForbiddenAdapter()), "unsupported")
        operation.refresh_from_db()
        self.assertEqual(operation.error_code, "service_excluded")
        target.refresh_from_db()
        self.assertEqual(target.native_id, "legacy-native-id")
        self.assertEqual(target.ownership, "created")

    def test_creation_never_changes_existing_auth_credentials_or_groups(self):
        before = list(get_user_model().objects.order_by("pk").values())
        memberships = list(
            get_user_model().groups.through.objects.order_by("pk").values()
        )
        self.created()
        self.assertEqual(before, list(get_user_model().objects.order_by("pk").values()))
        self.assertEqual(
            memberships,
            list(get_user_model().groups.through.objects.order_by("pk").values()),
        )
        self.assertFalse(ServiceIdentity.objects.exists())


def OperationCommand(operation):
    # Same immutable adapter envelope, no native payload or secret fixture.
    from .engine import _command

    return _command(operation, operation.target)
