"""No vendor/production endpoints: bounded HTTPS transport unit fixtures."""

import http.client
import os
import ssl
import threading
from unittest.mock import patch

from django.test import SimpleTestCase

from .native.http import NativeHTTP, NativeTransportError, Reply


class Wire:
    def __init__(self):
        self.closed = threading.Event()

    def shutdown(self, how):
        self.closed.set()

    def close(self):
        self.closed.set()


class Response:
    status = 200

    def __init__(self, body=b"{}", content_type="application/json", wire=None):
        self.body, self.content_type, self.wire = body, content_type, wire

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, maximum):
        if self.wire is not None:
            self.wire.closed.wait(1)
        return self.body[:maximum]

    def getheader(self, name, default=""):
        return self.content_type


class Connection:
    def __init__(self, response=None):
        self.sock = Wire()
        self.response = response or Response()
        self.calls = []

    def connect(self):
        pass

    def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))

    def getresponse(self):
        return self.response

    def close(self):
        self.sock.close()


class NativeHTTPTests(SimpleTestCase):
    def test_only_https_origins_without_credential_query_or_fragment_are_allowed(self):
        for origin in [
            "http://localhost",
            "https://user:password@vendor.invalid",
            "https://vendor.invalid/api",
            "https://vendor.invalid/?token=secret",
            "https://vendor.invalid/#secret",
            "https://vendor.invalid:bad",
            "https://vendor.invalid:0",
            "https://vendor.invalid\r\n",
            None,
        ]:
            with (
                self.subTest(origin=origin),
                self.assertRaisesRegex(ValueError, "invalid_native_endpoint"),
            ):
                NativeHTTP(origin)
        with self.assertRaisesRegex(ValueError, "native_tls_verification_required"):
            NativeHTTP(
                "https://vendor.invalid", context=ssl._create_unverified_context()
            )

    def test_direct_connection_ignores_proxy_environment_and_does_not_follow_redirects(
        self,
    ):
        connection = Connection()
        connection.response.status = 302
        with (
            patch.dict(os.environ, {"HTTPS_PROXY": "http://untrusted-proxy.invalid"}),
            patch("http.client.HTTPSConnection", return_value=connection) as factory,
        ):
            reply = NativeHTTP("https://vendor.invalid:9443").request(
                "POST",
                "/fixed",
                headers={"Authorization": "Bearer synthetic-token"},
                body=b"{}",
            )
        self.assertEqual(reply.status, 302)
        self.assertEqual(factory.call_args.args, ("vendor.invalid", 9443))
        self.assertEqual(len(connection.calls), 1)
        self.assertEqual(connection.calls[0][0], ("POST", "/fixed"))
        self.assertEqual(connection.calls[0][1]["headers"]["Connection"], "close")
        self.assertTrue(connection.sock.closed.is_set())

    def test_response_limit_failure_and_private_transport_error_are_sanitized(self):
        connection = Connection(Response(b"DO_NOT_LOG_NATIVE_RESPONSE"))
        with (
            patch("http.client.HTTPSConnection", return_value=connection),
            self.assertRaisesRegex(NativeTransportError, "^native_transport_failed$"),
        ):
            NativeHTTP("https://vendor.invalid", max_response=8).request(
                "GET", "/fixed"
            )
        connection.request = lambda *args, **kwargs: (_ for _ in ()).throw(
            http.client.HTTPException("DO_NOT_LOG_NATIVE_RESPONSE")
        )
        with (
            patch("http.client.HTTPSConnection", return_value=connection),
            self.assertRaisesRegex(NativeTransportError, "^native_transport_failed$"),
        ):
            NativeHTTP("https://vendor.invalid").request("POST", "/fixed")
        self.assertNotIn("DO_NOT_LOG", repr(Reply(400, b"DO_NOT_LOG_NATIVE_RESPONSE")))

    def test_connected_deadline_interrupts_stalled_response_not_only_idle_timeout(self):
        connection = Connection()
        connection.response = Response(b"", wire=connection.sock)
        with (
            patch("http.client.HTTPSConnection", return_value=connection),
            self.assertRaisesRegex(NativeTransportError, "native_transport_failed"),
        ):
            NativeHTTP("https://vendor.invalid", timeout=0.02).request("PUT", "/fixed")
        self.assertTrue(connection.sock.closed.is_set())

    def test_invalid_request_or_headers_never_open_a_connection(self):
        transport = NativeHTTP("https://vendor.invalid")
        with patch("http.client.HTTPSConnection") as factory:
            for target in [
                "https://other.invalid/",
                "//other.invalid",
                "/foo\r\nAuthorization:secret",
                "/foo#token",
            ]:
                with self.subTest(target=target), self.assertRaises(ValueError):
                    transport.request("GET", target)
            for headers in [
                [],
                {"Host": "other.invalid"},
                {"Authorization": "secret\r\n"},
                {"Proxy-Authorization": "secret"},
                {"Transfer-Encoding": "chunked"},
                {"Content-Length": "4"},
                {"Authorization": "one", "authorization": "two"},
            ]:
                with self.subTest(headers=headers), self.assertRaises(ValueError):
                    transport.request("POST", "/fixed", headers=headers)
            factory.assert_not_called()

    def test_json_rejects_duplicate_keys_nonfinite_numbers_and_unexpected_content_types(
        self,
    ):
        for body, content_type in [
            (b'{"id":1,"id":2}', "application/json"),
            (b'{"id":NaN}', "application/json"),
            (b"private-not-json", "application/json"),
            (b"{}", "text/html"),
        ]:
            with (
                self.subTest(body=body),
                self.assertRaisesRegex(
                    NativeTransportError, "^native_transport_failed$"
                ),
            ):
                Reply(200, body, content_type).json()
        self.assertEqual(
            Reply(200, b'{"id":1}', "application/json; charset=utf-8").json(), {"id": 1}
        )

    def test_limits_cannot_be_disabled_or_coerced(self):
        for kwargs in [
            {"timeout": True},
            {"timeout": float("nan")},
            {"timeout": 0},
            {"timeout": 1000},
            {"max_response": True},
            {"max_response": 0},
            {"max_response": 10**9},
        ]:
            with (
                self.subTest(kwargs=kwargs),
                self.assertRaisesRegex(ValueError, "invalid_native_limits"),
            ):
                NativeHTTP("https://vendor.invalid", **kwargs)
