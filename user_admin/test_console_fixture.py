"""No-network checks for the isolated Console-cookie fixture transport."""

import ssl
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from .vendor_fixtures.console import console_request


class ConsoleFixtureTransportTests(SimpleTestCase):
    def test_opaque_cookie_and_body_are_never_in_reply_repr(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = b"synthetic-data"
        response.getheader.return_value = "application/octet-stream"
        response.getheaders.return_value = [
            (
                "Set-Cookie",
                "token=public-fixture-cookie; Secure; HttpOnly; SameSite=Lax; Path=/",
            )
        ]
        context = ssl.create_default_context()
        with patch(
            "user_admin.vendor_fixtures.console.HTTPSConnection",
            return_value=connection,
        ) as factory:
            reply = console_request(
                context,
                "GET",
                "/api/v1/buckets/synthetic/objects",
                cookie="token=public-request-cookie",
            )
        self.assertEqual(reply.cookie, "token=public-fixture-cookie")
        self.assertTrue(reply.secure_httponly)
        self.assertNotIn("public-fixture-cookie", repr(reply))
        self.assertNotIn("synthetic-data", repr(reply))
        factory.assert_called_once_with("localhost", 9444, context=context, timeout=5)
        connection.close.assert_called_once()

    def test_bad_tls_or_non_console_target_never_opens_connection(self):
        context = ssl.create_default_context()
        with patch("user_admin.vendor_fixtures.console.HTTPSConnection") as factory:
            for target in [
                "https://elsewhere.invalid/api/v1/",
                "/wrong-api",
                "/api/v1/x\r\nHost:other",
            ]:
                with self.subTest(target=target), self.assertRaises(ValueError):
                    console_request(context, "GET", target)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with self.assertRaisesRegex(
                ValueError, "fixture_tls_verification_required"
            ):
                console_request(context, "GET", "/api/v1/session")
        factory.assert_not_called()

    def test_redirect_is_returned_not_followed(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 302
        response.read.return_value = b""
        response.getheader.return_value = "text/html"
        response.getheaders.return_value = [("Location", "https://elsewhere.invalid/")]
        with patch(
            "user_admin.vendor_fixtures.console.HTTPSConnection",
            return_value=connection,
        ):
            reply = console_request(
                ssl.create_default_context(), "GET", "/api/v1/session"
            )
        self.assertEqual(reply.status, 302)
        self.assertEqual(connection.request.call_count, 1)
