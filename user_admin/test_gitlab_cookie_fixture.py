"""No-network login-CSRF and origin-boundary checks for local GitLab fixture."""

from http.cookiejar import Cookie
from urllib.request import Request
from unittest.mock import patch
import ssl

from django.test import SimpleTestCase

from .vendor_fixtures.gitlab_cookie import LocalGitlabSession, LocalRedirect, csrf_token


class GitlabCookieFixtureTests(SimpleTestCase):
    def test_csrf_is_only_from_the_login_form(self):
        body = b'<form action="/other"><input name="authenticity_token" value="wrong"></form><form action="/users/sign_in"><input name="authenticity_token" value="right&amp;token"></form><form action="/other"><input name="authenticity_token" value="wrong-again"></form>'
        self.assertEqual(csrf_token(body), "right&token")
        with self.assertRaisesRegex(ValueError, "fixture_csrf_token_missing"):
            csrf_token(
                b'<form action="/other"><input name="authenticity_token" value="wrong"></form>'
            )

    def test_redirect_cannot_leave_fixed_tls_origin(self):
        redirect = LocalRedirect()
        for target in [
            "http://localhost:19443/",
            "https://localhost:443/",
            "https://other.invalid:19443/",
        ]:
            with (
                self.subTest(target=target),
                self.assertRaisesRegex(ValueError, "fixture_redirect_outside_origin"),
            ):
                redirect.redirect_request(
                    Request("https://localhost:19443/users/sign_in"),
                    None,
                    302,
                    "",
                    {},
                    target,
                )

    def test_original_cookie_snapshot_does_not_follow_response_rotation(self):
        with patch("user_admin.vendor_fixtures.gitlab_cookie.build_opener"):
            session = LocalGitlabSession(ssl.create_default_context())
            cookie = Cookie(
                0,
                "session",
                "public-fixture-original",
                None,
                False,
                "localhost",
                False,
                False,
                "/",
                True,
                True,
                None,
                True,
                None,
                None,
                {},
                False,
            )
            session.cookies.set_cookie(cookie)
            frozen = session.frozen_copy()
            cookie.value = "public-fixture-rotated"
            self.assertEqual(
                next(iter(frozen.cookies)).value, "public-fixture-original"
            )
            session.cookies.clear()
            self.assertEqual(
                next(iter(frozen.cookies)).value, "public-fixture-original"
            )

    def test_bad_tls_or_absolute_path_is_refused(self):
        context = ssl.create_default_context()
        with patch("user_admin.vendor_fixtures.gitlab_cookie.build_opener"):
            session = LocalGitlabSession(context)
            for path in ["https://elsewhere.invalid/", "//elsewhere.invalid/"]:
                with self.assertRaises(ValueError):
                    session.request(path)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with self.assertRaisesRegex(
                ValueError, "fixture_tls_verification_required"
            ):
                LocalGitlabSession(context)
