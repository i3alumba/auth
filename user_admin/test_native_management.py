"""A requested pause is not quiescence; UNKNOWN never permits manual handoff."""

from uuid import uuid4

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken

from sso.models import Service, ServiceIdentity
from .engine import execute, schedule
from .management import management_state, set_management
from .models import AdministrationLock, ManagementEvent, Operation, Target, UserControl
from .service import ChangeError
from .test_native_stages import StagedNative


@override_settings(
    USER_ADMIN_NATIVE_EXECUTION_ENABLED=True,
    USER_ADMIN_API_ENABLED=True,
    USER_ADMIN_NATIVE_SCHEDULING_ENABLED=True,
)
class NativeManagementTests(TestCase):
    def setUp(self):
        AdministrationLock.objects.get_or_create(pk=1)
        User = get_user_model()
        self.actor = User.objects.create_user(
            username="handoff-admin", is_superuser=True, is_staff=True
        )
        self.user = User.objects.create_user(username="handoff-user")
        service = Service.objects.create(
            slug="gitlab", group=Group.objects.create(name="handoff-gitlab")
        )
        self.user.groups.add(service.group)
        UserControl.objects.create(user=self.user, creation_receipt=uuid4())
        self.proof = AccessToken.for_user(self.actor)
        self.adapter = StagedNative()
        self.create = self.request()
        self.target = self.create.target

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

    def control(self, paused=True, *, epoch=None, key=None, proof=None):
        self.target.refresh_from_db()
        return set_management(
            proof=proof or self.proof,
            key=key or uuid4(),
            target_id=self.target.pk,
            expected_epoch=self.target.authority_epoch if epoch is None else epoch,
            paused=paused,
        )

    def created(self):
        self.assertEqual(execute(self.create.pk, self.adapter), "succeeded")
        return Operation.objects.get(target=self.target, action="bind")

    @override_settings(USER_ADMIN_NATIVE_SCHEDULING_ENABLED=False)
    def test_central_only_api_cannot_resume_paused_native_work(self):
        self.control()
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Bearer " + str(self.proof))
        self.target.refresh_from_db()
        epoch = self.target.authority_epoch
        response = client.post(
            f"/api/user-admin/users/{self.user.pk}/native/gitlab/resume/",
            {"expected_epoch": epoch},
            format="json",
            HTTP_IDEMPOTENCY_KEY=str(uuid4()),
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["code"], "native_provisioning_deferred")
        self.target.refresh_from_db()
        self.assertTrue(self.target.management_paused)
        self.assertEqual(self.target.authority_epoch, epoch)
        self.assertEqual(self.adapter.calls, [])

    def test_pause_before_claim_does_not_consult_adapter_or_claim_operation(self):
        state, replayed = self.control()
        self.assertTrue(state["safe_for_manual_changes"])
        self.assertEqual(execute(self.create.pk, self.adapter), "management_paused")
        self.create.refresh_from_db()
        self.assertEqual(self.create.status, "pending")
        self.assertIsNone(self.create.execution_token)
        self.assertEqual(self.adapter.calls, [])
        state, _ = self.control(False)
        self.assertFalse(state["paused"])
        self.assertEqual(execute(self.create.pk, self.adapter), "superseded")
        self.target.refresh_from_db()
        latest = Operation.objects.get(
            target=self.target, generation=self.target.generation
        )
        self.assertEqual(latest.action, "create")

    def test_pause_between_inspection_and_dispatch_defers_without_native_write(self):
        bind = self.created()
        responses = []
        self.adapter.after_inspect = lambda command: responses.append(self.control()[0])
        self.assertEqual(execute(bind.pk, self.adapter), "pending")
        self.assertFalse(responses[0]["safe_for_manual_changes"])
        self.assertEqual(self.adapter.calls, ["create"])
        bind.refresh_from_db()
        self.assertIsNone(bind.execution_token)
        self.target.refresh_from_db()
        self.assertTrue(management_state(self.target)["safe_for_manual_changes"])
        self.assertFalse(ServiceIdentity.objects.exists())

    def test_pause_during_creation_retains_receipt_without_continuation_or_publication(
        self,
    ):
        responses = []
        self.adapter.after_apply = lambda command: responses.append(self.control()[0])
        self.assertEqual(execute(self.create.pk, self.adapter), "partial")
        self.assertFalse(responses[0]["safe_for_manual_changes"])
        self.target.refresh_from_db()
        self.assertEqual(self.target.native_id, "42")
        self.assertEqual(self.target.creation_operation_id, self.create.pk)
        self.assertFalse(Operation.objects.filter(action="bind").exists())
        self.assertTrue(management_state(self.target)["safe_for_manual_changes"])
        self.adapter.after_apply = None
        self.control(False)
        self.target.refresh_from_db()
        bind = Operation.objects.get(
            target=self.target, generation=self.target.generation, action="bind"
        )
        self.assertEqual(execute(bind.pk, self.adapter), "succeeded")
        self.assertTrue(ServiceIdentity.objects.filter(user=self.user).exists())

    def test_unknown_remote_outcome_never_becomes_safe_or_auto_expires(self):
        def lost(command):
            raise RuntimeError("synthetic-private-unknown")

        self.adapter.after_apply = lost
        self.assertEqual(execute(self.create.pk, self.adapter), "outcome_unknown")
        state, _ = self.control()
        self.assertFalse(state["safe_for_manual_changes"])
        with self.assertRaisesMessage(ChangeError, "native_target_reserved"):
            self.control(False)
        self.target.refresh_from_db()
        self.assertTrue(self.target.management_paused)
        self.create.refresh_from_db()
        self.assertEqual(self.create.status, "outcome_unknown")
        self.assertEqual(self.adapter.calls, ["create"])

    def test_control_is_versioned_idempotent_and_cannot_be_resumed_by_another_admin(
        self,
    ):
        key = uuid4()
        first, _ = self.control(key=key)
        again, replayed = self.control(key=key, epoch=0)
        self.assertTrue(replayed)
        self.assertEqual(first, again)
        self.assertEqual(ManagementEvent.objects.count(), 1)
        with self.assertRaisesMessage(ChangeError, "stale_authority_epoch"):
            self.control(False, epoch=0)
        with self.assertRaisesMessage(ChangeError, "idempotency_conflict"):
            self.control(False, key=key, epoch=0)
        other = get_user_model().objects.create_user(
            username="handoff-other-admin", is_superuser=True
        )
        with self.assertRaisesMessage(ChangeError, "pause_owner_required"):
            self.control(False, proof=AccessToken.for_user(other))
        self.target.refresh_from_db()
        self.assertTrue(self.target.management_paused)

    def test_prior_epoch_block_receipt_cannot_authorize_unban_after_manual_handoff(
        self,
    ):
        bind = self.created()
        self.assertEqual(execute(bind.pk, self.adapter), "succeeded")
        block = self.request("block")
        self.assertEqual(execute(block.pk, self.adapter), "succeeded")
        self.target.refresh_from_db()
        old_receipt = self.target.block_receipt
        self.control()
        self.control(False)
        enable = self.request("enable")
        self.assertEqual(execute(enable.pk, self.adapter), "failed")
        enable.refresh_from_db()
        self.assertEqual(enable.error_code, "foreign_block")
        self.target.refresh_from_db()
        self.assertEqual(self.target.block_receipt, old_receipt)
        self.assertEqual(self.adapter.calls, ["create", "bind", "block"])

    def test_bearer_only_control_api_and_readonly_matrix_report_authoritative_pause(
        self,
    ):
        api = APIClient()
        url = f"/api/user-admin/users/{self.user.pk}/native/gitlab/pause/"
        api.force_login(self.actor)
        self.assertEqual(
            api.post(url, {"expected_epoch": 0}, format="json").status_code, 401
        )
        api.credentials(HTTP_AUTHORIZATION="Bearer " + str(self.proof))
        response = api.post(
            url, {"expected_epoch": 0}, format="json", HTTP_IDEMPOTENCY_KEY=str(uuid4())
        )
        self.assertEqual(response.status_code, 202, response.content)
        self.assertIs(response.json()["management"]["safe_for_manual_changes"], True)
        matrix = api.get("/api/user-admin/users/").json()["results"]
        state = next(u for u in matrix if u["id"] == self.user.pk)["native"]["gitlab"][
            "management"
        ]
        self.assertIs(state["paused"], True)
        self.assertEqual(state["authority_epoch"], 1)
        self.assertEqual(state["pause_actor_id"], self.actor.pk)

    def test_no_legacy_identity_adoption_jenkins_control_or_boolean_epoch_coercion(
        self,
    ):
        self.target.service = "jenkins"
        self.target.save(update_fields=["service"])
        with self.assertRaisesMessage(ChangeError, "invalid_services"):
            self.control()
        self.target.service = "gitlab"
        self.target.save(update_fields=["service"])
        UserControl.objects.filter(user=self.user).update(creation_receipt=None)
        with self.assertRaisesMessage(ChangeError, "ownership_required"):
            self.control()
        with self.assertRaisesMessage(ChangeError, "invalid_native_control"):
            self.control(epoch=True)
        self.assertFalse(ManagementEvent.objects.exists())
        self.assertEqual(self.adapter.calls, [])
