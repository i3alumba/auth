"""Credential compatibility and non-resurrection, no native service requests."""

import json
from unittest.mock import patch

from django.contrib.auth import authenticate, get_user_model
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpRequest
from django.contrib.sessions.backends.db import SessionStore
from django.test import Client, TestCase, override_settings
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken

from .authentication import (
    EPOCH,
    EpochModelBackend,
    credential_lock,
    issue_refresh,
    stamp_session_epoch,
)
from .models import AdministrationLock, UserControl
from .service import _revoke

PASSWORD = "Synthetic-Authentication-Password-47!"


class CredentialEpochTests(TestCase):
    def setUp(self):
        AdministrationLock.objects.get_or_create(pk=1)
        self.user = get_user_model().objects.create_user(
            username="epoch-user", password=PASSWORD, is_staff=True, is_superuser=True
        )

    def revoke_and_reactivate(self):
        with transaction.atomic():
            credential_lock()
            control, _ = UserControl.objects.get_or_create(user=self.user)
            get_user_model().objects.filter(pk=self.user.pk).update(is_active=False)
            _revoke(self.user, control)
            get_user_model().objects.filter(pk=self.user.pk).update(is_active=True)

    def test_legacy_epoch_zero_bearer_remains_compatible_without_creating_control(self):
        token = str(AccessToken.for_user(self.user))
        response = self.client.get("/api/user/", HTTP_AUTHORIZATION="Bearer " + token)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(UserControl.objects.exists())

    def test_old_backend_session_alias_does_not_upgrade_its_epoch(self):
        self.client.force_login(self.user)
        session = self.client.session
        session["_auth_user_backend"] = "django.contrib.auth.backends.ModelBackend"
        session.pop(EPOCH, None)
        session.save()
        self.assertTrue(self.client.get("/api/session/").json()["authenticated"])
        self.assertNotIn(EPOCH, self.client.session)
        self.revoke_and_reactivate()
        self.assertFalse(self.client.get("/api/session/").json()["authenticated"])

    def test_malformed_and_missing_epochs_never_match_a_revoked_user(self):
        self.revoke_and_reactivate()
        for value in [False, "1", -1, {}, None]:
            with self.subTest(value=value):
                token = AccessToken.for_user(self.user)
                if value is not None:
                    token[EPOCH] = value
                self.assertEqual(
                    self.client.get(
                        "/api/user/", HTTP_AUTHORIZATION="Bearer " + str(token)
                    ).status_code,
                    401,
                )

    def test_authentication_event_cannot_upgrade_to_a_new_epoch(self):
        user = authenticate(username=self.user.username, password=PASSWORD)
        self.revoke_and_reactivate()
        with self.assertRaises(AuthenticationFailed):
            issue_refresh(user)
        request = HttpRequest()
        request.session = SessionStore()
        with self.assertRaises(PermissionDenied):
            stamp_session_epoch(None, request, user)
        self.assertNotIn(EPOCH, request.session)

    def test_password_change_between_verification_and_issuance_is_rejected(self):
        user = authenticate(username=self.user.username, password=PASSWORD)
        self.user.set_password("Changed-Synthetic-Password-59!")
        self.user.save(update_fields=["password"])
        with self.assertRaises(AuthenticationFailed):
            issue_refresh(user)

    def test_old_session_cannot_mint_a_new_epoch_even_if_authenticated_before_revoke(
        self,
    ):
        self.revoke_and_reactivate()
        with self.assertRaises(AuthenticationFailed):
            issue_refresh(self.user, session_epoch=0)

    def test_all_password_login_entrypoints_reject_cross_epoch_authentication(self):
        original = EpochModelBackend.authenticate
        for route in [
            "/api/token/",
            "/api/session/login/",
            "/sso/login/",
            "/admin/login/",
        ]:
            with self.subTest(route=route):
                client = Client()

                def authenticate_then_revoke(backend, *args, **kwargs):
                    user = original(backend, *args, **kwargs)
                    if user:
                        self.revoke_and_reactivate()
                    return user

                with patch.object(
                    EpochModelBackend, "authenticate", authenticate_then_revoke
                ):
                    payload = {"username": self.user.username, "password": PASSWORD}
                    if route == "/api/session/login/":
                        response = client.post(
                            route, json.dumps(payload), content_type="application/json"
                        )
                    else:
                        response = client.post(route, payload)
                self.assertIn(response.status_code, [401, 403])
                self.assertNotIn('"access"', response.content.decode())
                self.assertFalse(client.get("/api/session/").json()["authenticated"])

    def test_fresh_login_after_reactivation_gets_new_epoch(self):
        self.revoke_and_reactivate()
        response = self.client.post(
            "/api/session/login/",
            json.dumps({"username": self.user.username, "password": PASSWORD}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        token = AccessToken(response.json()["access"])
        self.assertEqual(token[EPOCH], 1)
        self.assertEqual(self.client.session[EPOCH], 1)
        self.assertEqual(
            self.client.get(
                "/api/user/", HTTP_AUTHORIZATION="Bearer " + str(token)
            ).status_code,
            200,
        )

    def test_disabling_new_api_does_not_disable_epoch_enforcement(self):
        old = str(AccessToken.for_user(self.user))
        self.revoke_and_reactivate()
        with override_settings(USER_ADMIN_API_ENABLED=False):
            self.assertEqual(
                self.client.get(
                    "/api/user/", HTTP_AUTHORIZATION="Bearer " + old
                ).status_code,
                401,
            )
