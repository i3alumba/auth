"""Pinned DOT hook lifecycle: revoked validation cannot escape in a 200 token."""

from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from django.contrib.auth import get_user_model
from django.db import transaction
from oauth2_provider.models import get_access_token_model, get_grant_model

from sso import tests as fixtures
from sso.validator import SSOValidator

from .authentication import credential_lock
from .models import AdministrationLock, UserControl
from .service import _revoke


class OIDCEpochTests(fixtures.SSOFixture):
    authorization = fixtures.OIDCTests.authorization
    code = fixtures.OIDCTests.code
    exchange = fixtures.OIDCTests.exchange
    verifier = fixtures.OIDCTests.verifier

    def setUp(self):
        super().setUp()
        AdministrationLock.objects.get_or_create(pk=1)

    def revoke_and_reactivate(self):
        with transaction.atomic():
            credential_lock()
            control, _ = UserControl.objects.get_or_create(user=self.user)
            get_user_model().objects.filter(pk=self.user.pk).update(is_active=False)
            _revoke(self.user, control)
            get_user_model().objects.filter(pk=self.user.pk).update(is_active=True)

    def assert_no_successful_token(self, response):
        self.assertEqual(response.status_code, 400, response.content)
        for key in ["access_token", "refresh_token", "id_token"]:
            self.assertNotIn(key, response.json())
        self.assertFalse(
            get_access_token_model().objects.filter(user=self.user).exists()
        )

    def test_code_validated_before_revocation_cannot_issue_after_reactivation(self):
        code = self.code()
        original = SSOValidator.save_bearer_token

        def revoke_before_save(validator, token, request, *args, **kwargs):
            self.revoke_and_reactivate()
            return original(validator, token, request, *args, **kwargs)

        with patch.object(SSOValidator, "save_bearer_token", revoke_before_save):
            response = self.exchange(code)
        self.assert_no_successful_token(response)

    def test_refresh_validated_before_revocation_cannot_issue_after_reactivation(self):
        tokens = self.exchange(self.code()).json()
        original = SSOValidator.save_bearer_token

        def revoke_before_save(validator, token, request, *args, **kwargs):
            self.revoke_and_reactivate()
            return original(validator, token, request, *args, **kwargs)

        with patch.object(SSOValidator, "save_bearer_token", revoke_before_save):
            response = self.client.post(
                "/o/token/",
                {
                    "grant_type": "refresh_token",
                    "refresh_token": tokens["refresh_token"],
                    "client_id": "matrix",
                    "client_secret": "x" * 40,
                },
            )
        self.assert_no_successful_token(response)

    def test_authorization_preserves_original_session_epoch_until_grant_save(self):
        original = SSOValidator.save_authorization_code

        def revoke_before_save(validator, client_id, code, request, *args, **kwargs):
            self.revoke_and_reactivate()
            return original(validator, client_id, code, request, *args, **kwargs)

        with patch.object(SSOValidator, "save_authorization_code", revoke_before_save):
            response = self.authorization()
        self.assertNotEqual(response.status_code, 200)
        query = parse_qs(urlsplit(response.get("Location", "")).query)
        self.assertNotIn("code", query)
        self.assertFalse(get_grant_model().objects.filter(user=self.user).exists())
