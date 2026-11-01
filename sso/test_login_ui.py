"""Native UI must remain a server-owned form without a JavaScript dependency."""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase


class NativeLoginUITests(TestCase):
    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        get_user_model().objects.create_user(
            username="native", password="test-password"
        )

    def form(self, target="/o/authorize/?client_id=example&state=synthetic"):
        response = self.client.get("/sso/login/", {"next": target})
        self.assertEqual(response.status_code, 200)
        return response, response.context["csrf_token"]

    def test_fallback_has_native_fields_and_self_hosted_assets(self):
        response, _ = self.form()
        for fragment in (
            '<form method="post">',
            'name="csrfmiddlewaretoken"',
            'name="next"',
            'class="fallback-submit" type="submit">Sign in',
            "/static/sso/ui/login.js",
            "/static/sso/ui/login.css",
        ):
            self.assertContains(response, fragment)
        for field in (
            '<input name="username" maxlength="150" autocomplete="username" required>',
            '<input type="password" name="password" autocomplete="current-password" required>',
        ):
            self.assertContains(response, field, html=True)
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_native_post_preserves_next_and_session(self):
        _, csrf = self.form()
        response = self.client.post(
            "/sso/login/",
            {
                "csrfmiddlewaretoken": csrf,
                "username": "native",
                "password": "test-password",
                "next": "/o/authorize/?state=synthetic",
            },
        )
        self.assertRedirects(
            response, "/o/authorize/?state=synthetic", fetch_redirect_response=False
        )
        self.assertIn("_auth_user_id", self.client.session)

    def test_csrf_still_required(self):
        self.assertEqual(
            self.client.post(
                "/sso/login/", {"username": "native", "password": "test-password"}
            ).status_code,
            403,
        )

    def test_untrusted_next_still_rejected(self):
        response, csrf = self.form("https://untrusted.example/")
        self.assertEqual(response.context["next"], "/")
        response = self.client.post(
            "/sso/login/",
            {
                "csrfmiddlewaretoken": csrf,
                "username": "native",
                "password": "test-password",
                "next": "https://untrusted.example/",
            },
        )
        self.assertRedirects(response, "/", fetch_redirect_response=False)

    def test_errors_and_limits_remain_native(self):
        _, csrf = self.form()
        response = self.client.post(
            "/sso/login/",
            {
                "csrfmiddlewaretoken": csrf,
                "username": "x" * 151,
                "password": "bad",
                "next": "/retained/",
            },
        )
        self.assertContains(
            response, '<p role="alert">Invalid credentials or rate limit</p>'
        )
        self.assertEqual(response.context["next"], "/retained/")
        self.assertNotIn("_auth_user_id", self.client.session)
