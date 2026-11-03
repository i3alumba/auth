"""Both legacy password forms persist passwords only, never stale role flags."""

from types import SimpleNamespace
from unittest.mock import patch

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory, TestCase, override_settings

from .authentication import credential_lock
from .models import AdministrationLock, UserControl
from .passwords import SafeOtherPasswordForm, SafeOwnPasswordForm

OLD = "Synthetic-Original-Password-46!"
NEW = "Synthetic-Changed-Password-58!"


@override_settings(USER_ADMIN_API_ENABLED=True)
class LegacyPasswordBoundaryTests(TestCase):
    def setUp(self):
        AdministrationLock.objects.get_or_create(pk=1)
        User = get_user_model()
        self.admin = User.objects.create_user(
            username="password-admin", password=OLD, is_staff=True, is_superuser=True
        )
        self.target = User.objects.create_user(
            username="password-target", password=OLD, is_staff=True, is_superuser=True
        )
        self.client = Client()
        self.client.force_login(self.admin)

    def test_both_password_forms_preserve_deactivated_demoted_flags(self):
        for form_class in [SafeOtherPasswordForm, SafeOwnPasswordForm]:
            with self.subTest(form=form_class.__name__):
                self.target.refresh_from_db()
                self.target.set_password(OLD)
                self.target.is_active = self.target.is_superuser = (
                    self.target.is_staff
                ) = True
                self.target.save()
                stale = get_user_model().objects.get(pk=self.target.pk)
                data = (
                    {"password1": NEW, "password2": NEW}
                    if form_class is SafeOtherPasswordForm
                    else {
                        "old_password": OLD,
                        "new_password1": NEW,
                        "new_password2": NEW,
                    }
                )
                form = form_class(stale, data)
                self.assertTrue(form.is_valid(), form.errors)
                get_user_model().objects.filter(pk=stale.pk).update(
                    is_active=False, is_superuser=False, is_staff=False
                )
                form.save()
                fresh = get_user_model().objects.get(pk=stale.pk)
                self.assertFalse(
                    fresh.is_active or fresh.is_superuser or fresh.is_staff
                )
                self.assertTrue(fresh.check_password(NEW))

    def test_disable_password_preserves_django_unusable_branch_and_commit_semantics(
        self,
    ):
        original = self.target.password
        form = SafeOtherPasswordForm(
            self.target, {"usable_password": "false", "password1": "", "password2": ""}
        )
        self.assertTrue(form.is_valid(), form.errors)
        unsaved = form.save(commit=False)
        self.assertFalse(unsaved.has_usable_password())
        self.assertEqual(
            get_user_model().objects.get(pk=self.target.pk).password, original
        )
        unsaved.save(update_fields=["password"])
        self.target.refresh_from_db()
        self.assertFalse(self.target.has_usable_password())
        self.assertFalse(self.target.check_password(""))

    def test_legacy_password_route_can_disable_password_without_changing_flags(self):
        response = self.client.post(
            f"/admin/auth/user/{self.target.pk}/password/",
            {
                "usable_password": "false",
                "password1": "",
                "password2": "",
                "unset-password": "1",
            },
        )
        self.assertEqual(response.status_code, 302, response.content)
        self.target.refresh_from_db()
        self.assertFalse(self.target.has_usable_password())
        self.assertTrue(
            self.target.is_active and self.target.is_superuser and self.target.is_staff
        )
        anonymous = Client()
        login = anonymous.post(
            "/api/session/login/",
            {"username": self.target.username, "password": ""},
            content_type="application/json",
        )
        self.assertEqual(login.status_code, 401)
        self.assertFalse(anonymous.get("/api/session/").json()["authenticated"])

    def test_legitimate_other_password_route_remains_functional(self):
        response = self.client.post(
            f"/admin/auth/user/{self.target.pk}/password/",
            {"password1": NEW, "password2": NEW},
        )
        self.assertEqual(response.status_code, 302, response.content)
        self.target.refresh_from_db()
        self.assertTrue(self.target.check_password(NEW))
        self.assertTrue(self.target.is_superuser and self.target.is_active)

    def test_legitimate_own_password_route_updates_session_hash(self):
        response = self.client.post(
            "/admin/password_change/",
            {"old_password": OLD, "new_password1": NEW, "new_password2": NEW},
        )
        self.assertEqual(response.status_code, 302, response.content)
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.check_password(NEW))
        self.assertTrue(self.client.get("/api/session/").json()["authenticated"])

    def test_both_password_posts_recheck_original_actor_epoch_inside_lock(self):
        routes = [
            (
                "/admin/password_change/",
                "user_admin.passwords.credential_lock",
                {"old_password": OLD, "new_password1": NEW, "new_password2": NEW},
            ),
            (
                f"/admin/auth/user/{self.target.pk}/password/",
                "user_admin.admin.credential_lock",
                {"password1": NEW, "password2": NEW},
            ),
        ]
        for route, seam, data in routes:
            with self.subTest(route=route):

                def revoke_then_lock():
                    control, _ = UserControl.objects.get_or_create(user=self.admin)
                    control.auth_epoch += 1
                    control.save(update_fields=["auth_epoch"])
                    credential_lock()

                with patch(seam, side_effect=revoke_then_lock):
                    self.assertEqual(self.client.post(route, data).status_code, 403)
                self.admin.refresh_from_db()
                self.target.refresh_from_db()
                self.assertTrue(self.admin.check_password(OLD))
                self.assertTrue(self.target.check_password(OLD))

    def test_both_password_posts_recheck_original_actor_password_hash(self):
        for route, seam, data in [
            (
                "/admin/password_change/",
                "user_admin.passwords.credential_lock",
                {"old_password": OLD, "new_password1": NEW, "new_password2": NEW},
            ),
            (
                f"/admin/auth/user/{self.target.pk}/password/",
                "user_admin.admin.credential_lock",
                {"password1": NEW, "password2": NEW},
            ),
        ]:
            with self.subTest(route=route):

                def changed_then_lock():
                    fresh = get_user_model().objects.get(pk=self.admin.pk)
                    fresh.set_password("Concurrent-Synthetic-Password-69!")
                    fresh.save(update_fields=["password"])
                    credential_lock()

                with patch(seam, side_effect=changed_then_lock):
                    self.assertEqual(self.client.post(route, data).status_code, 403)
                self.target.refresh_from_db()
                self.assertTrue(self.target.check_password(OLD))

    def test_stale_legacy_profile_save_cannot_restore_target_flags(self):
        stale = get_user_model().objects.get(pk=self.target.pk)
        stale.email = "profile@example.test"
        get_user_model().objects.filter(pk=stale.pk).update(
            is_active=False, is_staff=False, is_superuser=False
        )
        request = RequestFactory().post("/admin/auth/user/")
        request.user = self.admin
        admin.site._registry[get_user_model()].save_model(
            request, stale, SimpleNamespace(changed_data=["email"]), True
        )
        self.target.refresh_from_db()
        self.assertFalse(
            self.target.is_active or self.target.is_superuser or self.target.is_staff
        )
        self.assertEqual(self.target.email, "profile@example.test")
