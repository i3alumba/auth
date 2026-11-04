"""Central API contract; native adapters remain disabled and never contacted."""

from dataclasses import replace
import json
from unittest.mock import patch
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from sso.access import services_for
from sso.models import Service, ServiceIdentity

from .models import AdministrationLock, Operation, Target, UserChange, UserControl
from .service import etag

BASE = "/api/user-admin/"
PASSWORD = "Synthetic-Central-Password-84!"


@override_settings(
    USER_ADMIN_API_ENABLED=True, USER_ADMIN_NATIVE_SCHEDULING_ENABLED=True
)
class AdministrationAPITests(TestCase):
    def setUp(self):
        AdministrationLock.objects.get_or_create(pk=1)
        User = get_user_model()
        self.admin = User.objects.create_user(
            username="central-admin",
            password=PASSWORD,
            is_superuser=True,
            is_staff=True,
        )
        self.user = User.objects.create_user(
            username="existing-member", password=PASSWORD
        )
        for slug in ["drive", "matrix", "gitlab", "minio", "jenkins"]:
            Service.objects.create(
                slug=slug, group=Group.objects.create(name="api-" + slug)
            )
        self.client = APIClient()
        self.token = str(AccessToken.for_user(self.admin))
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + self.token)

    def create(self, data=None, key=None):
        payload = {
            "username": "new-member",
            "email": "new@example.test",
            "password": PASSWORD,
        }
        payload.update(data or {})
        return self.client.post(
            BASE + "users/",
            payload,
            format="json",
            HTTP_IDEMPOTENCY_KEY=str(key or uuid4()),
        )

    def change(self, data=None, action="", expected=None, key=None, user=None):
        user = user or self.user
        user.refresh_from_db()
        headers = {
            "HTTP_IDEMPOTENCY_KEY": str(key or uuid4()),
            "HTTP_IF_MATCH": expected or etag(user),
        }
        url = BASE + f"users/{user.pk}/" + action
        if action:
            return self.client.post(url, data or {}, format="json", **headers)
        return self.client.patch(url, data or {}, format="json", **headers)

    @override_settings(USER_ADMIN_NATIVE_SCHEDULING_ENABLED=False)
    def test_central_only_creation_records_deferred_intents_not_executable_work(self):
        with patch("user_admin.engine.execute") as execute:
            response = self.create(
                {"services": {"gitlab": True, "matrix": True, "minio": True}}
            )
        self.assertEqual(response.status_code, 202)
        self.assertIn("deferred", response.json()["detail"])
        user = get_user_model().objects.get(pk=response.json()["user"]["id"])
        self.assertTrue(user.check_password(PASSWORD))
        operations = Operation.objects.filter(target__user=user)
        self.assertEqual(operations.count(), 3)
        self.assertEqual(
            set(operations.values_list("status", "error_code")),
            {("held", "native_provisioning_deferred")},
        )
        self.assertFalse(operations.filter(status__in=["pending", "running"]).exists())
        self.assertFalse(ServiceIdentity.objects.filter(user=user).exists())
        execute.assert_not_called()
        capabilities = self.client.get(BASE + "capabilities/").json()
        self.assertIs(capabilities["native_scheduling_enabled"], False)
        self.assertIs(capabilities["native_adapters_accepted"], False)

    def test_central_only_idempotent_replay_does_not_activate_deferred_native_work(
        self,
    ):
        key = uuid4()
        payload = {"services": {"gitlab": True}}
        with override_settings(USER_ADMIN_NATIVE_SCHEDULING_ENABLED=False):
            response = self.create(payload, key=key)
        self.assertEqual(response.status_code, 202)
        replay = self.create(payload, key=key)
        self.assertEqual(replay.status_code, 202)
        self.assertTrue(replay.json()["replayed"])
        operations = Operation.objects.filter(
            target__user_id=response.json()["user"]["id"]
        )
        self.assertEqual(operations.count(), 1)
        self.assertEqual(operations.get().status, "held")
        self.assertEqual(operations.get().error_code, "native_provisioning_deferred")

    @override_settings(USER_ADMIN_NATIVE_SCHEDULING_ENABLED="true")
    def test_native_scheduling_capability_does_not_coerce_untyped_settings(self):
        self.assertIs(
            self.client.get(BASE + "capabilities/").json()["native_scheduling_enabled"],
            False,
        )

    def test_anonymous_cookie_only_and_staff_only_denied_no_store(self):
        self.client.credentials()
        response = self.client.get(BASE + "users/")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(BASE + "users/").status_code, 401)
        self.user.is_staff = True
        self.user.save(update_fields=["is_staff"])
        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer " + str(AccessToken.for_user(self.user))
        )
        self.assertEqual(self.client.get(BASE + "users/").status_code, 403)

    def test_feature_default_off_preserves_capability_metadata_without_user_list(self):
        with override_settings(USER_ADMIN_API_ENABLED=False):
            self.assertEqual(self.client.get(BASE + "users/").status_code, 503)
            response = self.client.get(BASE + "capabilities/")
            self.assertIs(response.json()["enabled"], False)
            self.assertIs(services_for(self.admin)["users"]["enabled"], False)

    def test_users_origin_host_serves_api_and_reports_current_actor(self):
        response = self.client.get(
            BASE + "capabilities/", HTTP_HOST="users.i3alumba.ru"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["actor_id"], self.admin.pk)
        self.assertIs(response.json()["administrator"], True)
        self.assertNotIn("hosting", response.json()["editable_services"])
        self.assertIn("jenkins", response.json()["readonly_services"])

    def test_matrix_pagination_boolean_cells_and_readonly_jenkins_hosting(self):
        response = self.client.get(BASE + "users/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["page_size"], 50)
        data = response.json()["results"][1]
        self.assertEqual(data["id"], self.user.pk)
        self.assertIs(data["services"]["jenkins"]["readonly"], True)
        self.assertIs(data["services"]["hosting"]["readonly"], True)
        self.assertNotIn("password", data)
        self.assertNotIn("is_staff", data)
        self.assertNotIn("is_superuser", data)
        self.assertFalse(UserControl.objects.exists())
        self.assertEqual(self.client.get(BASE + "users/?page=-1").status_code, 400)

    @override_settings(USER_ADMIN_HOSTING_GRANTS_READY=True)
    def test_independent_hosting_permission_profile_and_same_bearer_revocation(self):
        token = str(AccessToken.for_user(self.user))
        member = APIClient()
        member.credentials(HTTP_AUTHORIZATION="Bearer " + token)
        granted = self.change({"services": {"hosting": True}})
        self.assertEqual(granted.status_code, 202, granted.content)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_staff or self.user.is_superuser)
        profile = member.get("/api/user/")
        self.assertEqual(profile.status_code, 200)
        data = profile.json()[0]
        self.assertIs(data["is_active"], True)
        self.assertIs(data["is_staff"], False)
        self.assertIs(data["services"]["hosting"], True)
        self.assertIs(data["services"]["monitor"], False)
        self.assertIs(data["services"]["jenkins"], False)
        self.assertEqual(member.get(BASE + "users/").status_code, 403)
        denied = self.change({"services": {"hosting": False}})
        self.assertEqual(denied.status_code, 202, denied.content)
        self.assertIs(member.get("/api/user/").json()[0]["services"]["hosting"], False)

    def test_disabling_hosting_readiness_never_revives_an_explicit_deny(self):
        self.user.is_staff = True
        self.user.save(update_fields=["is_staff"])
        self.assertIs(services_for(self.user)["hosting"]["enabled"], True)
        with override_settings(USER_ADMIN_HOSTING_GRANTS_READY=True):
            response = self.change({"services": {"hosting": False}})
            self.assertEqual(response.status_code, 202, response.content)
            self.assertIs(services_for(self.user)["hosting"]["enabled"], False)
        self.assertIs(services_for(self.user)["hosting"]["enabled"], False)
        rows = self.client.get(BASE + "users/").json()["results"]
        cell = next(u for u in rows if u["id"] == self.user.pk)["services"]["hosting"]
        self.assertIs(cell["granted"], False)
        self.assertIs(cell["readonly"], True)

    def test_hosting_global_admin_override_starts_only_after_consumer_readiness(self):
        self.admin.is_staff = False
        self.admin.save(update_fields=["is_staff"])
        self.assertIs(services_for(self.admin)["hosting"]["enabled"], False)
        with override_settings(USER_ADMIN_HOSTING_GRANTS_READY=True):
            self.assertIs(services_for(self.admin)["hosting"]["enabled"], True)

    @override_settings(USER_ADMIN_NATIVE_EXECUTION_ENABLED=True)
    def test_staged_progress_reports_bind_not_completed_create(self):
        from .engine import execute
        from .test_native_stages import StagedNative

        response = self.create({"services": {"gitlab": True}})
        self.assertEqual(response.status_code, 202)
        native = StagedNative()
        native.capabilities = replace(native.capabilities, instance="primary")
        create = Operation.objects.get(action="create")
        self.assertEqual(execute(create.pk, native), "succeeded")
        change = self.client.get(BASE + "changes/" + response.json()["change_id"] + "/")
        self.assertEqual(change.status_code, 200, change.content)
        self.assertEqual(change.json()["native"][0]["phase"], "bind")
        self.assertEqual(change.json()["native"][0]["status"], "pending")
        bind = Operation.objects.get(action="bind")
        self.assertEqual(execute(bind.pk, native), "succeeded")
        change = self.client.get(BASE + "changes/" + response.json()["change_id"] + "/")
        self.assertEqual(change.json()["native"][0]["phase"], "bind")
        self.assertEqual(change.json()["native"][0]["status"], "succeeded")

    @override_settings(USER_ADMIN_NATIVE_EXECUTION_ENABLED=True)
    def test_regrant_of_unbound_owned_resource_uses_bind_not_enable(self):
        from .engine import execute
        from .test_native_stages import StagedNative

        response = self.create({"services": {"gitlab": True}})
        self.assertEqual(response.status_code, 202)
        user = get_user_model().objects.get(pk=response.json()["user"]["id"])
        native = StagedNative()
        native.capabilities = replace(native.capabilities, instance="primary")
        self.assertEqual(
            execute(Operation.objects.get(action="create").pk, native), "succeeded"
        )
        self.assertEqual(
            self.change({"services": {"gitlab": False}}, user=user).status_code, 202
        )
        regrant = self.change({"services": {"gitlab": True}}, user=user)
        self.assertEqual(regrant.status_code, 202, regrant.content)
        target = Target.objects.get(user=user, service="gitlab")
        latest = Operation.objects.get(target=target, generation=target.generation)
        self.assertEqual(latest.action, "bind")
        self.assertIsNone(target.identity_id)

    def test_create_password_hashed_native_queued_and_response_redacted(self):
        response = self.create({"services": {"gitlab": True, "drive": True}})
        self.assertEqual(response.status_code, 202, response.content)
        user = get_user_model().objects.get(username="new-member")
        self.assertTrue(user.check_password(PASSWORD))
        self.assertNotEqual(user.password, PASSWORD)
        self.assertEqual(Operation.objects.get().status, "pending")
        self.assertEqual(Target.objects.get().native_id, "")
        self.assertTrue(
            ServiceIdentity.objects.filter(user=user, service__slug="drive").exists()
        )
        self.assertFalse(
            ServiceIdentity.objects.filter(user=user, service__slug="gitlab").exists()
        )
        self.assertNotIn(PASSWORD, response.content.decode())
        self.assertNotIn(PASSWORD, repr(list(UserChange.objects.values())))
        self.assertNotIn(PASSWORD, repr(list(Operation.objects.values())))
        self.assertIs(response.json()["user"]["services"]["gitlab"]["effective"], False)

    def test_create_idempotency_does_not_repeat_user_intents_or_password_write(self):
        key = uuid4()
        first = self.create({"services": {"gitlab": True}}, key)
        second = self.create({"services": {"gitlab": True}}, key)
        self.assertEqual(first.status_code, 202)
        self.assertEqual(second.status_code, 202, second.content)
        self.assertEqual(first.json()["user"]["id"], second.json()["user"]["id"])
        self.assertIs(second.json()["replayed"], True)
        self.assertEqual(Operation.objects.count(), 1)
        self.assertEqual(UserChange.objects.count(), 1)
        self.assertEqual(
            self.create(
                {
                    "password": "Other-Synthetic-Secret-84!",
                    "services": {"gitlab": True},
                },
                key,
            ).status_code,
            409,
        )

    def test_replay_after_password_change_never_resets_password(self):
        key = uuid4()
        self.assertEqual(self.create(key=key).status_code, 202)
        user = get_user_model().objects.get(username="new-member")
        user.set_password("Changed-Synthetic-Secret-96!")
        user.save(update_fields=["password"])
        password_hash = user.password
        self.assertEqual(self.create(key=key).status_code, 409)
        replay = self.create({"password": "Changed-Synthetic-Secret-96!"}, key)
        self.assertEqual(replay.status_code, 202)
        self.assertIs(replay.json()["replayed"], True)
        user.refresh_from_db()
        self.assertEqual(user.password, password_hash)
        self.assertEqual(UserChange.objects.count(), 1)

    def test_unknown_flags_strict_booleans_and_jenkins_are_rejected(self):
        for data in [
            {"is_staff": True},
            {"is_superuser": True},
            {"groups": [1]},
            {"is_admin": "true"},
            {"services": {"matrix": "true"}},
            {"services": {"jenkins": True}},
            {"username": "renamed"},
        ]:
            with self.subTest(data=data):
                self.assertEqual(self.change(data).status_code, 400)
        self.assertFalse(UserChange.objects.exists())
        self.assertEqual(self.change({"services": {"hosting": False}}).status_code, 409)

    def test_hosting_changes_unavailable_until_controller_contract_is_ready(self):
        self.user.is_staff = True
        self.user.save(update_fields=["is_staff"])
        self.assertEqual(self.change({"services": {"hosting": False}}).status_code, 409)
        self.assertIs(services_for(self.user)["hosting"]["enabled"], True)
        self.assertFalse(UserControl.objects.exists())

    def test_missing_precondition_and_stale_form_do_not_overwrite_changes(self):
        url = BASE + f"users/{self.user.pk}/"
        self.assertEqual(
            self.client.patch(
                url,
                {"email": "new@example.test"},
                format="json",
                HTTP_IDEMPOTENCY_KEY=str(uuid4()),
            ).status_code,
            428,
        )
        old = etag(self.user)
        self.assertEqual(self.change({"email": "first@example.test"}).status_code, 202)
        self.assertEqual(
            self.change({"email": "stale@example.test"}, expected=old).status_code, 412
        )
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "first@example.test")
        self.assertEqual(UserChange.objects.count(), 1)

    def test_profile_only_update_does_not_materialize_preferences_or_normalize_staff(
        self,
    ):
        self.user.is_staff = True
        self.user.save(update_fields=["is_staff"])
        self.assertEqual(self.change({"first_name": "Changed"}).status_code, 202)
        self.user.refresh_from_db()
        self.assertIs(self.user.is_staff, True)
        self.assertEqual(
            UserControl.objects.get(user=self.user).service_preferences, {}
        )
        self.assertFalse(Operation.objects.exists())

    def test_promote_demote_restores_pre_admin_memberships_and_preserves_jenkins(self):
        matrix = Service.objects.get(slug="matrix")
        jenkins = Service.objects.get(slug="jenkins")
        unrelated = Group.objects.create(name="unrelated")
        self.user.groups.add(matrix.group, jenkins.group, unrelated)
        identity = ServiceIdentity.objects.create(
            user=self.user,
            service=jenkins,
            external_id="legacy-id",
            external_username="legacy-name",
            jenkins_admin=True,
        )
        original_identity = dict(
            ServiceIdentity.objects.filter(pk=identity.pk).values().get()
        )
        self.assertEqual(self.change({"is_admin": True}).status_code, 202)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_superuser and self.user.is_staff)
        self.assertTrue(
            self.user.groups.filter(
                pk=Service.objects.get(slug="gitlab").group_id
            ).exists()
        )
        self.assertEqual(self.change({"is_admin": False}).status_code, 202)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_superuser or self.user.is_staff)
        self.assertSetEqual(
            set(self.user.groups.values_list("pk", flat=True)),
            {matrix.group_id, jenkins.group_id, unrelated.pk},
        )
        self.assertEqual(
            original_identity,
            ServiceIdentity.objects.filter(pk=identity.pk).values().get(),
        )
        self.assertFalse(Target.objects.filter(service="jenkins").exists())

    def test_monitor_preference_does_not_require_staff_or_change_hosting(self):
        response = self.change({"services": {"monitor": True}})
        self.assertEqual(response.status_code, 202)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_staff)
        self.assertTrue(services_for(self.user)["monitor"]["enabled"])
        self.assertFalse(services_for(self.user)["hosting"]["enabled"])

    def test_self_demotion_or_deactivation_rejected(self):
        self.assertEqual(
            self.change({"is_admin": False}, user=self.admin).status_code, 409
        )
        self.assertEqual(
            self.change(action="deactivate/", user=self.admin).status_code, 409
        )
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active and self.admin.is_superuser)
        self.assertFalse(UserChange.objects.exists())

    def test_deactivation_commits_held_native_deny_without_guessing_ownership(self):
        service = Service.objects.get(slug="gitlab")
        self.user.groups.add(service.group)
        ServiceIdentity.objects.create(
            user=self.user,
            service=service,
            external_id="old-native",
            external_username="old-name",
        )
        response = self.change(action="deactivate/")
        self.assertEqual(response.status_code, 202, response.content)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)
        op = Operation.objects.get()
        self.assertEqual((op.status, op.error_code), ("held", "adoption_required"))
        target = Target.objects.get()
        self.assertEqual(
            (target.desired, target.ownership, target.native_id),
            ("blocked", "unmanaged", ""),
        )
        change = self.client.get(
            BASE + f"changes/{response.json()['change_id']}/"
        ).json()
        self.assertEqual(change["native"][0]["status"], "held")

    def test_reactivation_does_not_resurrect_old_access_refresh_or_session(self):
        old = RefreshToken.for_user(self.user)
        self.assertEqual(self.change(action="deactivate/").status_code, 202)
        self.assertEqual(self.change(action="reactivate/").status_code, 202)
        other = APIClient()
        other.credentials(HTTP_AUTHORIZATION="Bearer " + str(old.access_token))
        self.assertEqual(other.get("/api/user/").status_code, 401)
        self.assertEqual(
            other.post(
                "/api/token/refresh/", {"refresh": str(old)}, format="json"
            ).status_code,
            401,
        )
        self.assertEqual(
            other.post(
                "/api/token/verify/", {"token": str(old.access_token)}, format="json"
            ).status_code,
            401,
        )
        self.assertEqual(UserControl.objects.get(user=self.user).auth_epoch, 1)

    def test_native_persistence_failure_rolls_back_central_creation(self):
        with patch(
            "user_admin.service.schedule",
            side_effect=RuntimeError("synthetic persistence failure"),
        ):
            with self.assertRaises(RuntimeError):
                self.create({"services": {"gitlab": True}})
        self.assertFalse(
            get_user_model().objects.filter(username="new-member").exists()
        )
        self.assertFalse(UserChange.objects.exists())
        self.assertFalse(Target.objects.exists())

    def test_requesting_bearer_epoch_rechecked_inside_mutation_transaction(self):
        from .authentication import credential_lock

        def revoke_then_lock():
            control, _ = UserControl.objects.get_or_create(user=self.admin)
            control.auth_epoch += 1
            control.save(update_fields=["auth_epoch"])
            credential_lock()

        with patch("user_admin.service.credential_lock", side_effect=revoke_then_lock):
            self.assertEqual(
                self.change({"email": "not-saved@example.test"}).status_code, 401
            )
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "")

    def test_role_revocation_same_bearer_immediate(self):
        get_user_model().objects.filter(pk=self.admin.pk).update(is_superuser=False)
        self.assertEqual(self.client.get(BASE + "users/").status_code, 403)

    def test_shared_managed_group_cannot_turn_explicit_deny_into_allow(self):
        matrix = Service.objects.get(slug="matrix")
        gitlab = Service.objects.get(slug="gitlab")
        gitlab.group = matrix.group
        gitlab.save(update_fields=["group"])
        self.user.groups.add(matrix.group)
        for service in [matrix, gitlab]:
            ServiceIdentity.objects.create(
                user=self.user,
                service=service,
                external_id="existing-" + service.slug,
                external_username="existing",
            )
        self.assertTrue(services_for(self.user)["matrix"]["enabled"])
        response = self.change({"services": {"matrix": False, "gitlab": True}})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["code"], "service_group_conflict")
        self.assertTrue(services_for(self.user)["matrix"]["enabled"])
        self.assertFalse(UserControl.objects.exists())
        self.assertFalse(UserChange.objects.exists())

    def test_jenkins_group_alias_cannot_add_or_remove_jenkins_access(self):
        matrix = Service.objects.get(slug="matrix")
        jenkins = Service.objects.get(slug="jenkins")
        matrix.group = jenkins.group
        matrix.save(update_fields=["group"])
        ServiceIdentity.objects.create(
            user=self.user,
            service=jenkins,
            external_id="existing-jenkins",
            external_username="legacy",
            jenkins_admin=True,
        )
        for had_access in [False, True]:
            with self.subTest(had_access=had_access):
                if had_access:
                    self.user.groups.add(jenkins.group)
                before = list(self.user.groups.values_list("pk", flat=True))
                response = self.change({"services": {"matrix": not had_access}})
                self.assertEqual(response.status_code, 409)
                self.assertEqual(response.json()["code"], "service_group_conflict")
                self.assertEqual(
                    before, list(self.user.groups.values_list("pk", flat=True))
                )
                self.assertEqual(
                    services_for(self.user)["jenkins"]["enabled"], had_access
                )
        self.assertFalse(UserControl.objects.exists())
        self.assertFalse(UserChange.objects.exists())

    def test_no_hard_delete_endpoint(self):
        self.assertEqual(
            self.client.delete(BASE + f"users/{self.user.pk}/").status_code, 405
        )
        self.assertTrue(get_user_model().objects.filter(pk=self.user.pk).exists())
