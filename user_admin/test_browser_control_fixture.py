import os
import ssl
from types import SimpleNamespace
from unittest.mock import Mock, patch
from wsgiref.simple_server import WSGIRequestHandler

from django.test import SimpleTestCase

from .vendor_fixtures.browser_control import (
    binding_matches,
    fixture_service,
    phase_outcome,
    setup,
)
from .vendor_fixtures.browser_idp import SilentTLSHandler


class BrowserControlFixtureTests(SimpleTestCase):
    def outcome(
        self,
        *,
        action="block",
        status="partial",
        reason="capability_unconfirmed",
        observed="blocked",
        identity=1,
        target_observed=None,
    ):
        operation = SimpleNamespace(
            action=action,
            status=status,
            error_code=reason,
            observed=observed,
            evidence={
                name: "unknown"
                for name in ["new_login", "existing_sessions", "api_credentials"]
            },
        )
        target = SimpleNamespace(
            observed=observed if target_observed is None else target_observed,
            identity_id=identity,
        )
        return phase_outcome(operation, target)

    def test_fixture_service_is_fixed_allowlist_with_gitlab_compatibility(self):
        for data, expected in [
            ({}, "gitlab"),
            ({"service": "gitlab"}, "gitlab"),
            ({"service": "matrix"}, "matrix"),
            ({"service": "minio"}, "minio"),
        ]:
            with patch(
                "user_admin.vendor_fixtures.browser_control.inputs", return_value=data
            ):
                self.assertEqual(fixture_service(), expected)
        for value in [True, None, [], "../matrix", "jenkins", "other"]:
            with (
                self.subTest(value=value),
                patch(
                    "user_admin.vendor_fixtures.browser_control.inputs",
                    return_value={"service": value},
                ),
                self.assertRaisesMessage(
                    RuntimeError, "browser_fixture_service_invalid"
                ),
            ):
                fixture_service()

    def test_minio_binding_checks_auth_subject_and_owned_policy_not_bucket_as_subject(
        self,
    ):
        from uuid import UUID
        from .native.minio_policy import resource_name

        owner = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        bucket = resource_name(owner)
        user = SimpleNamespace(pk=12)
        identity = SimpleNamespace(
            user_id=12,
            service=SimpleNamespace(slug="minio"),
            external_id="12",
            external_username=bucket,
            minio_policy=bucket,
        )
        target = SimpleNamespace(
            pk=owner, user_id=12, service="minio", native_id=bucket, identity=identity
        )
        self.assertTrue(binding_matches(target, user))
        for changes in [
            {"external_id": bucket},
            {"minio_policy": "consoleAdmin"},
            {"user_id": 13},
            {"service": SimpleNamespace(slug="gitlab")},
        ]:
            with self.subTest(changes=list(changes)):
                target.identity = SimpleNamespace(**{**vars(identity), **changes})
                self.assertFalse(binding_matches(target, user))

    def test_authority_and_revocation_partials_are_not_success(self):
        for reason in [
            "authority_changed",
            "grant_revoked_in_flight",
            "grant_revoked",
            "outcome_unknown",
        ]:
            with (
                self.subTest(reason=reason),
                self.assertRaisesMessage(
                    RuntimeError, "browser_fixture_native_outcome_unaccepted"
                ),
            ):
                self.outcome(reason=reason)

    def test_wrong_native_state_or_missing_binding_rejected(self):
        for options in [
            {"observed": "enabled"},
            {"target_observed": "enabled"},
            {"identity": None},
            {"action": "enable", "observed": "blocked"},
        ]:
            with self.subTest(options=options), self.assertRaises(RuntimeError):
                self.outcome(**options)

    def test_expected_state_partial_preserves_unknown_channel_evidence(self):
        result = self.outcome()
        self.assertTrue(result["phase_complete"])
        self.assertFalse(result["ready_for_browser"])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["reason"], "capability_unconfirmed")
        self.assertEqual(set(result["evidence"].values()), {"unknown"})

    def test_bind_intermediate_is_explicitly_incomplete_not_browser_ready(self):
        result = self.outcome(action="bind", reason="native_enable_pending")
        self.assertFalse(result["phase_complete"])
        self.assertFalse(result["ready_for_browser"])
        self.assertEqual(result["observed"], "blocked")
        result = self.outcome(action="bind", observed="enabled")
        self.assertTrue(result["phase_complete"])
        self.assertTrue(result["ready_for_browser"])

    def test_create_unbound_is_not_fabricated_readiness(self):
        result = self.outcome(
            action="create",
            status="succeeded",
            reason="",
            observed="unbound",
            identity=None,
        )
        self.assertTrue(result["phase_complete"])
        self.assertFalse(result["ready_for_browser"])
        with self.assertRaises(RuntimeError):
            self.outcome(action="create", observed="unbound", identity=None)

    def test_nonfixture_settings_stop_before_django_or_database(self):
        with (
            patch.dict(os.environ, {"DJANGO_SETTINGS_MODULE": "auth.settings"}),
            patch("django.setup") as initialize,
            self.assertRaisesMessage(RuntimeError, "browser_fixture_settings_required"),
        ):
            setup()
        initialize.assert_not_called()

    def test_wsgi_https_comes_from_transport_not_forwarded_header(self):
        handler = SilentTLSHandler.__new__(SilentTLSHandler)
        handler.connection = Mock(spec=ssl.SSLSocket)
        with patch.object(
            WSGIRequestHandler,
            "get_environ",
            return_value={"HTTP_X_FORWARDED_PROTO": "http", "wsgi.url_scheme": "http"},
        ):
            environ = handler.get_environ()
        self.assertEqual(environ["wsgi.url_scheme"], "https")
        self.assertEqual(environ["HTTPS"], "on")
        handler.connection = object()
        with self.assertRaisesMessage(RuntimeError, "browser_fixture_tls_required"):
            handler.get_environ()
