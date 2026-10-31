import json
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from django.test import Client, TestCase, override_settings
from django.utils import timezone

from .minio_guard import CALLBACK, COOKIE, LOGIN
from .models import MinioLoginChallenge

PUBLIC = "https://minio.i3alumba.ru"
ORIGINAL_STATE = "constant-console-hmac-state"


@override_settings(
    SSO_MINIO_GUARD_ENABLED=True,
    SSO_MINIO_PKCE_EXCEPTION_CLIENT_ID="minio-client",
    ALLOWED_HOSTS=["minio.i3alumba.ru", "auth.i3alumba.ru", "testserver"],
)
class MinioGuardTests(TestCase):
    def setUp(self):
        self.mock = patch("sso.minio_guard.backend").start()
        self.addCleanup(patch.stopall)
        self.client = Client(enforce_csrf_checks=True)
        self.mock.return_value = self.metadata()

    def metadata(self):
        query = urlencode(
            {
                "client_id": "minio-client",
                "redirect_uri": PUBLIC + "/oauth_callback",
                "response_type": "code",
                "scope": "openid",
                "state": ORIGINAL_STATE,
            }
        )
        return (
            200,
            json.dumps(
                {
                    "redirectRules": [
                        {"redirect": "https://auth.i3alumba.ru/o/authorize/?" + query}
                    ]
                }
            ).encode(),
            [],
        )

    def begin(self, client=None):
        client = client or self.client
        self.mock.return_value = self.metadata()
        response = client.get(LOGIN, secure=True, HTTP_HOST="minio.i3alumba.ru")
        self.assertEqual(response.status_code, 200)
        state = parse_qs(
            urlsplit(response.json()["redirectRules"][0]["redirect"]).query
        )["state"][0]
        return state, response

    def finish(self, state, client=None, origin=PUBLIC, path=CALLBACK):
        return (client or self.client).post(
            path,
            json.dumps({"code": "fixture-code", "state": state}),
            content_type="application/json",
            secure=True,
            HTTP_HOST="minio.i3alumba.ru",
            HTTP_ORIGIN=origin,
        )

    def test_wraps_even_constant_console_state_and_restores_only_to_backend(self):
        state, response = self.begin()
        self.assertNotEqual(state, ORIGINAL_STATE)
        cookie = response.cookies[COOKIE]
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Lax")
        self.assertEqual(cookie["domain"], "")
        self.assertEqual(cookie["path"], "/")
        self.mock.return_value = (
            204,
            b"",
            ["token=fixture-session; Path=/; HttpOnly; Domain=.i3alumba.ru"],
        )
        result = self.finish(state)
        self.assertEqual(result.status_code, 204)
        self.assertEqual(
            json.loads(self.mock.call_args.args[2]),
            {"code": "fixture-code", "state": ORIGINAL_STATE},
        )
        self.assertTrue(result.cookies["token"]["secure"])
        self.assertTrue(result.cookies["token"]["httponly"])
        self.assertFalse(result.cookies["token"]["domain"])
        self.assertIn("no-store", result["Cache-Control"])

    def test_code_and_state_from_browser_a_are_rejected_by_browser_b(self):
        a, b = Client(), Client()
        state_a, _ = self.begin(a)
        state_b, _ = self.begin(b)
        self.assertNotEqual(state_a, state_b)
        before = self.mock.call_count
        self.assertEqual(self.finish(state_a, b).status_code, 403)
        self.assertEqual(self.mock.call_count, before)
        self.mock.return_value = (204, b"", [])
        self.assertEqual(self.finish(state_a, a).status_code, 204)

    def test_replay_is_rejected_without_second_exchange(self):
        state, _ = self.begin()
        self.mock.return_value = (204, b"", [])
        self.assertEqual(self.finish(state).status_code, 204)
        before = self.mock.call_count
        self.assertEqual(self.finish(state).status_code, 403)
        self.assertEqual(self.mock.call_count, before)

    def test_expired_or_missing_browser_cookie_is_rejected(self):
        state, _ = self.begin()
        self.assertEqual(self.finish(state, Client()).status_code, 403)
        MinioLoginChallenge.objects.update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
        before = self.mock.call_count
        self.assertEqual(self.finish(state).status_code, 403)
        self.assertEqual(self.mock.call_count, before)

    def test_two_tabs_in_same_browser_keep_distinct_valid_challenges(self):
        first, _ = self.begin()
        second, _ = self.begin()
        self.mock.return_value = (204, b"", [])
        self.assertEqual(self.finish(first).status_code, 204)
        self.assertEqual(self.finish(second).status_code, 204)

    def test_invalid_state_and_foreign_or_missing_origin_are_rejected(self):
        state, _ = self.begin()
        before = self.mock.call_count
        for origin in ["https://evil.example", "https://main.i3alumba.ru", "null", ""]:
            self.assertEqual(self.finish(state, origin=origin).status_code, 403)
        for bad in [ORIGINAL_STATE, "", "x" * 43]:
            self.assertEqual(self.finish(bad).status_code, 403)
        self.assertEqual(self.mock.call_count, before)

    def test_callback_variants_never_bypass_guard(self):
        state, _ = self.begin()
        before = self.mock.call_count
        for path in [CALLBACK + "/", CALLBACK + "/extra", LOGIN + "/unknown"]:
            self.assertEqual(self.finish(state, path=path).status_code, 404)
        self.assertEqual(self.mock.call_count, before)

    def test_emergency_credential_login_preserved_but_needs_same_origin(self):
        body = json.dumps(
            {"accessKey": "fixture-admin", "secretKey": "fixture-password"}
        )
        self.mock.return_value = (204, b"", ["token=fixture; Path=/; HttpOnly"])
        response = self.client.post(
            LOGIN,
            body,
            content_type="application/json",
            secure=True,
            HTTP_HOST="minio.i3alumba.ru",
            HTTP_ORIGIN=PUBLIC,
        )
        self.assertEqual(response.status_code, 204)
        self.assertEqual(self.mock.call_args.args, (LOGIN, "POST", body.encode()))
        before = self.mock.call_count
        response = self.client.post(
            LOGIN,
            body,
            content_type="application/json",
            secure=True,
            HTTP_HOST="minio.i3alumba.ru",
            HTTP_ORIGIN="https://evil.example",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.mock.call_count, before)

    def test_redirect_to_other_issuer_or_client_is_not_returned(self):
        status, body, cookies = self.metadata()
        for old, new in [
            ("auth.i3alumba.ru", "evil.example"),
            ("minio-client", "other-client"),
        ]:
            self.mock.return_value = (
                status,
                body.replace(old.encode(), new.encode()),
                cookies,
            )
            response = self.client.get(
                LOGIN, secure=True, HTTP_HOST="minio.i3alumba.ru"
            )
            self.assertEqual(response.status_code, 502)
            self.assertEqual(MinioLoginChallenge.objects.count(), 0)

    def test_non_minio_host_cannot_use_proxy(self):
        response = self.client.get(LOGIN, secure=True, HTTP_HOST="auth.i3alumba.ru")
        self.assertEqual(response.status_code, 403)
        self.mock.assert_not_called()

    @override_settings(SSO_MINIO_GUARD_ENABLED=False)
    def test_unconfigured_guard_fails_closed(self):
        self.assertEqual(
            self.client.get(
                LOGIN, secure=True, HTTP_HOST="minio.i3alumba.ru"
            ).status_code,
            503,
        )
        self.mock.assert_not_called()

    def test_failed_exchange_still_consumes_challenge(self):
        state, _ = self.begin()
        self.mock.side_effect = TimeoutError()
        self.assertEqual(self.finish(state).status_code, 502)
        self.mock.side_effect = None
        self.mock.return_value = (204, b"", [])
        before = self.mock.call_count
        self.assertEqual(self.finish(state).status_code, 403)
        self.assertEqual(self.mock.call_count, before)
