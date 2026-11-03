"""Durable creation is distinct from binding and issuing an Auth identity."""

from dataclasses import replace
from uuid import uuid4, uuid5

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings

from sso.models import Service, ServiceIdentity
from .adapters import Binding
from .engine import ControlError, execute, schedule
from .models import AdministrationLock, Operation, Target, UserControl
from .service import row
from .tests import FakeNative


class StagedNative(FakeNative):
    capabilities = replace(
        FakeNative.capabilities,
        actions=frozenset({"create", "bind", "enable", "block"}),
    )

    def proof(self, command):
        observation = replace(
            super().proof(command), native_id=command.native_id or "42"
        )
        if command.action == "create":
            return replace(
                observation,
                state="unbound",
                new_login="unknown",
                existing_sessions="unknown",
                api_credentials="unknown",
            )
        if command.action == "bind":
            return replace(
                observation, binding=Binding(command.native_id, "stages-user")
            )
        return observation


@override_settings(USER_ADMIN_NATIVE_EXECUTION_ENABLED=True)
class NativeStagingTests(TestCase):
    def setUp(self):
        AdministrationLock.objects.get_or_create(pk=1)
        User = get_user_model()
        self.actor = User.objects.create_user(
            username="stages-admin", is_superuser=True, is_staff=True
        )
        self.user = User.objects.create_user(username="stages-user")
        self.service = Service.objects.create(
            slug="gitlab", group=Group.objects.create(name="stages-gitlab")
        )
        self.user.groups.add(self.service.group)
        UserControl.objects.create(user=self.user, creation_receipt=uuid4())
        self.adapter = StagedNative()

    def request(self, action="create"):
        return schedule(
            actor_id=self.actor.pk,
            user_id=self.user.pk,
            service="gitlab",
            instance="fixture",
            action=action,
            idempotency_key=uuid4(),
            expected_version=UserControl.objects.get(user=self.user).version,
        )

    def created(self):
        create = self.request()
        self.assertEqual(execute(create.pk, self.adapter), "succeeded")
        return create, Operation.objects.get(target=create.target, action="bind")

    def test_confirmed_creation_saves_id_and_queues_one_bind_without_new_intent_generation(
        self,
    ):
        create, bind = self.created()
        target = Target.objects.get(pk=create.target_id)
        self.assertEqual(target.native_id, "42")
        self.assertEqual(target.observed, "unbound")
        self.assertEqual(target.creation_operation_id, create.pk)
        self.assertFalse(ServiceIdentity.objects.filter(user=self.user).exists())
        self.assertEqual(bind.generation, create.generation)
        self.assertEqual(target.generation, create.generation)
        self.assertEqual(UserControl.objects.get(user=self.user).version, 1)
        Operation.objects.filter(pk=bind.pk).update(created_at=create.created_at)
        progress = row(self.user)["native"]["gitlab"]
        self.assertEqual(progress["phase"], "bind")
        self.assertEqual(progress["status"], "pending")
        execute(create.pk, self.adapter)
        self.assertEqual(
            Operation.objects.filter(target=target, action="bind").count(), 1
        )

    def test_verified_bind_publishes_identity_once_and_links_provenance_atomically(
        self,
    ):
        create, bind = self.created()
        self.assertEqual(execute(bind.pk, self.adapter), "succeeded")
        target = Target.objects.get(pk=create.target_id)
        identity = ServiceIdentity.objects.get(user=self.user, service=self.service)
        self.assertEqual(target.identity_id, identity.pk)
        self.assertEqual(identity.external_id, "42")
        self.assertEqual(identity.external_username, "stages-user")
        self.assertEqual(identity.minio_policy, "")
        self.assertFalse(identity.jenkins_admin)
        self.assertEqual(execute(bind.pk, self.adapter), "succeeded")
        self.assertEqual(self.adapter.calls, ["create", "bind"])
        self.assertEqual(ServiceIdentity.objects.count(), 1)

    def test_revocation_during_create_retains_native_id_without_bind_continuation(self):
        create = self.request()
        self.adapter.after_apply = lambda command: self.request("block")
        self.assertEqual(execute(create.pk, self.adapter), "superseded")
        target = Target.objects.get(pk=create.target_id)
        self.assertEqual(target.native_id, "42")
        self.assertEqual(target.creation_operation_id, create.pk)
        self.assertFalse(
            Operation.objects.filter(target=target, action="bind").exists()
        )
        self.assertFalse(ServiceIdentity.objects.exists())

    def test_revocation_during_bind_never_publishes_stale_identity(self):
        create, bind = self.created()
        self.adapter.after_apply = lambda command: self.request("block")
        self.assertEqual(execute(bind.pk, self.adapter), "superseded")
        self.assertFalse(ServiceIdentity.objects.exists())
        target = Target.objects.get(pk=create.target_id)
        self.assertEqual(target.native_id, "42")
        self.assertEqual(target.ownership, "created")
        self.assertIsNone(target.identity_id)

    def test_known_create_survives_lost_bind_response_and_unknown_blocks_new_writes(
        self,
    ):
        create, bind = self.created()

        def lose_response(command):
            raise RuntimeError("synthetic-private-body-never-store")

        self.adapter.after_apply = lose_response
        self.assertEqual(execute(bind.pk, self.adapter), "outcome_unknown")
        self.assertEqual(Target.objects.get(pk=create.target_id).native_id, "42")
        block = self.request("block")
        self.assertEqual(execute(block.pk, self.adapter), "target_reserved")
        self.assertEqual(self.adapter.calls, ["create", "bind"])
        self.assertFalse(ServiceIdentity.objects.exists())
        bind.refresh_from_db()
        self.assertEqual(bind.error_code, "outcome_unknown")

    def test_foreign_existing_identity_is_not_adopted_or_overwritten(self):
        create, bind = self.created()
        identity = ServiceIdentity.objects.create(
            user=self.user,
            service=self.service,
            external_id="foreign",
            external_username="foreign",
        )
        self.assertEqual(execute(bind.pk, self.adapter), "failed")
        identity.refresh_from_db()
        self.assertEqual(identity.external_id, "foreign")
        target = Target.objects.get(pk=create.target_id)
        self.assertEqual(target.native_id, "42")
        self.assertIsNone(target.identity_id)
        bind.refresh_from_db()
        self.assertEqual(bind.error_code, "binding_conflict")

    def test_external_id_collision_does_not_rollback_known_native_ownership(self):
        create, bind = self.created()
        other = get_user_model().objects.create_user(username="foreign-owner")
        ServiceIdentity.objects.create(
            user=other,
            service=self.service,
            external_id="42",
            external_username="foreign",
        )
        self.assertEqual(execute(bind.pk, self.adapter), "failed")
        self.assertEqual(
            Target.objects.get(pk=create.target_id).creation_operation_id, create.pk
        )
        self.assertFalse(ServiceIdentity.objects.filter(user=self.user).exists())

    def test_enable_cannot_bypass_unbound_owned_resource(self):
        create, bind = self.created()
        enable = self.request("enable")
        self.assertEqual(execute(enable.pk, self.adapter), "failed")
        enable.refresh_from_db()
        self.assertEqual(enable.error_code, "binding_required")
        self.assertEqual(self.adapter.calls, ["create"])
        self.assertEqual(execute(bind.pk, self.adapter), "superseded")

    def test_invalid_binding_never_publishes_or_relabels_native_failure_success(self):
        create, bind = self.created()
        self.adapter.response = replace(
            self.adapter.current,
            state="enabled",
            binding=Binding("42", "stages-user", "consoleAdmin"),
        )
        self.assertEqual(execute(bind.pk, self.adapter), "outcome_unknown")
        self.assertFalse(ServiceIdentity.objects.exists())

    def test_bind_of_our_blocked_resource_queues_enable_as_another_same_intent_phase(
        self,
    ):
        create, original_bind = self.created()
        block = self.request("block")
        self.assertEqual(execute(block.pk, self.adapter), "succeeded")
        bind = self.request("bind")
        self.adapter.response = replace(
            self.adapter.current, binding=Binding("42", "stages-user")
        )
        self.assertEqual(execute(bind.pk, self.adapter), "partial")
        target = Target.objects.get(pk=create.target_id)
        self.assertIsNotNone(target.identity_id)
        enable = Operation.objects.get(
            target=target, generation=bind.generation, action="enable"
        )
        self.assertEqual(enable.generation, bind.generation)
        self.adapter.response = None
        self.assertEqual(execute(enable.pk, self.adapter), "succeeded")
        self.assertEqual(row(self.user)["native"]["gitlab"]["phase"], "enable")

    def test_foreign_ban_is_not_removed_or_bound_even_with_matching_owner(self):
        create, bind = self.created()
        self.adapter.current = replace(
            self.adapter.current, state="blocked", block_receipt="foreign-ban"
        )
        self.assertEqual(execute(bind.pk, self.adapter), "failed")
        bind.refresh_from_db()
        self.assertEqual(bind.error_code, "foreign_block")
        self.assertEqual(self.adapter.calls, ["create"])
        self.assertFalse(ServiceIdentity.objects.exists())

    def test_actor_revocation_during_bind_retains_id_without_publishing(self):
        create, bind = self.created()
        self.adapter.after_apply = (
            lambda command: get_user_model()
            .objects.filter(pk=self.actor.pk)
            .update(is_superuser=False)
        )
        self.assertEqual(execute(bind.pk, self.adapter), "partial")
        self.assertFalse(ServiceIdentity.objects.exists())
        self.assertEqual(Target.objects.get(pk=create.target_id).native_id, "42")

    def test_unknown_creation_never_enqueues_bind_or_guesses_id(self):
        create = self.request()

        def lose_response(command):
            raise RuntimeError("synthetic-unknown-create")

        self.adapter.after_apply = lose_response
        self.assertEqual(execute(create.pk, self.adapter), "outcome_unknown")
        self.assertEqual(Target.objects.get(pk=create.target_id).native_id, "")
        self.assertFalse(Operation.objects.filter(action="bind").exists())
        self.assertFalse(ServiceIdentity.objects.exists())

    def test_provision_only_runs_original_create_bind_but_defers_block(self):
        create = self.request()
        self.assertEqual(
            execute(create.pk, self.adapter, execution_scope="provision_only"),
            "succeeded",
        )
        bind = Operation.objects.get(target=create.target, action="bind")
        self.assertEqual(
            execute(bind.pk, self.adapter, execution_scope="provision_only"),
            "succeeded",
        )
        block = self.request("block")
        self.assertEqual(
            execute(block.pk, None, execution_scope="provision_only"), "unsupported"
        )
        block.refresh_from_db()
        self.assertEqual(block.error_code, "revocation_deferred")
        self.assertIsNone(block.execution_token)
        self.assertEqual(block.evidence, {})
        self.assertEqual(Target.objects.get(pk=create.target_id).observed, "enabled")
        self.assertEqual(self.adapter.calls, ["create", "bind"])

    def test_provision_only_does_not_rebind_or_reenable_after_deny_intent(self):
        create, bind = self.created()
        block = self.request("block")
        execute(block.pk, None, execution_scope="provision_only")
        later_bind = self.request("bind")
        self.assertEqual(
            execute(later_bind.pk, None, execution_scope="provision_only"),
            "unsupported",
        )
        later_bind.refresh_from_db()
        self.assertEqual(later_bind.error_code, "reenable_not_supported")
        self.assertFalse(ServiceIdentity.objects.exists())
        self.assertEqual(self.adapter.calls, ["create"])

    def test_provision_only_stale_phase_is_superseded_before_scope_refusal(self):
        create, bind = self.created()
        self.request("block")
        self.assertEqual(
            execute(bind.pk, None, execution_scope="provision_only"), "superseded"
        )
        self.assertEqual(self.adapter.calls, ["create"])

    def test_provision_only_unknown_still_reserves_target(self):
        create, bind = self.created()
        Operation.objects.filter(pk=bind.pk).update(status=Operation.Status.UNKNOWN)
        block = self.request("block")
        self.assertEqual(
            execute(block.pk, None, execution_scope="provision_only"), "target_reserved"
        )
        block.refresh_from_db()
        self.assertEqual(block.status, "pending")

    def test_provision_only_cannot_enable_using_arbitrary_same_generation_row(self):
        create, bind = self.created()
        enable = Operation.objects.create(
            target=create.target,
            actor_id=self.actor.pk,
            base_version=1,
            generation=create.generation,
            action="enable",
            idempotency_key=uuid4(),
        )
        self.assertEqual(
            execute(enable.pk, None, execution_scope="provision_only"), "unsupported"
        )
        self.assertEqual(self.adapter.calls, ["create"])

    def test_provision_only_deny_during_create_never_publishes_binding(self):
        create = self.request()
        self.adapter.after_apply = lambda command: self.request("block")
        self.assertEqual(
            execute(create.pk, self.adapter, execution_scope="provision_only"),
            "superseded",
        )
        target = Target.objects.get(pk=create.target_id)
        self.assertEqual(target.native_id, "42")
        self.assertFalse(ServiceIdentity.objects.exists())
        self.assertFalse(Operation.objects.filter(action="bind").exists())

    def test_provision_only_accepts_initial_enable_with_exact_bind_continuation(self):
        create, bind = self.created()
        execute(bind.pk, self.adapter, execution_scope="provision_only")
        Operation.objects.filter(pk=bind.pk).update(
            status="partial", error_code="native_enable_pending", observed="blocked"
        )
        target = Target.objects.get(pk=create.target_id)
        target.observed = "blocked"
        target.block_receipt = "synthetic-owned-initial-close"
        target.save(update_fields=["observed", "block_receipt"])
        self.adapter.current = replace(
            self.adapter.current, state="blocked", block_receipt=target.block_receipt
        )
        enable = Operation.objects.create(
            target=target,
            actor_id=self.actor.pk,
            base_version=1,
            generation=create.generation,
            action="enable",
            idempotency_key=uuid5(bind.pk, "enable"),
        )
        self.assertEqual(
            execute(enable.pk, self.adapter, execution_scope="provision_only"),
            "succeeded",
        )
        self.assertEqual(self.adapter.calls, ["create", "bind", "enable"])

    def test_provision_only_paused_target_is_not_finalized_as_deferred(self):
        create, bind = self.created()
        block = self.request("block")
        Target.objects.filter(pk=create.target_id).update(management_paused=True)
        self.assertEqual(
            execute(block.pk, None, execution_scope="provision_only"),
            "management_paused",
        )
        block.refresh_from_db()
        self.assertEqual(block.status, "pending")

    def test_current_blocked_intent_denies_create_even_with_live_group(self):
        create = self.request()
        Target.objects.filter(pk=create.target_id).update(desired="blocked")
        self.assertEqual(
            execute(create.pk, self.adapter, execution_scope="provision_only"), "failed"
        )
        create.refresh_from_db()
        self.assertEqual(create.error_code, "grant_revoked")
        self.assertEqual(self.adapter.calls, [])

    def test_bind_without_confirmed_create_provenance_is_refused(self):
        target = Target.objects.create(
            user=self.user,
            service="gitlab",
            instance="fixture",
            native_id="42",
            ownership="created",
            desired="enabled",
        )
        with self.assertRaisesMessage(ControlError, "creation_provenance_required"):
            self.request("bind")
        self.assertFalse(Operation.objects.exists())
