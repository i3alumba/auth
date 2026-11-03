"""Synthetic, in-memory router tests; never bind sockets or contact services."""

import json
import time
from unittest.mock import Mock, patch
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import SimpleTestCase
import jwt

from .vendor_fixtures.minio_browser_router import (
    AUTH,
    HEADER_LIMIT,
    Handler,
    LOGIN,
    MINIO,
    ORIGIN,
    REQUEST_LIMIT,
    SMALL_LIMIT,
    TokenObserver,
    Wire,
    body_length,
    clean_headers,
    parse_headers,
    read_response,
    reply,
    request_limit,
    route_request,
)

POLICY_A = "ua-" + "a" * 32
POLICY_B = "ua-" + "b" * 32


class MinioBrowserRouterFixtureTests(SimpleTestCase):
    def route(self, method="GET", target=LOGIN, origin=None, host=MINIO, sni=MINIO):
        return route_request(host, sni, method, target, origin)

    def test_exact_method_routes_keep_native_login_independent_of_auth(self):
        self.assertEqual(self.route(), "auth")
        self.assertEqual(self.route("POST", LOGIN + "/oauth2/auth"), "auth")
        self.assertEqual(self.route("POST", origin=ORIGIN), "console")
        for path in [
            "/",
            "/login",
            "/oauth_callback?code=synthetic",
            "/api/v1/session",
        ]:
            self.assertEqual(self.route(target=path), "console")
        for path in ["/o/token/", "/o/authorize/?state=synthetic", LOGIN]:
            self.assertEqual(self.route(target=path, host=AUTH, sni=AUTH), "auth")
        self.assertEqual(self.route(target="/_fixture/status"), "status")
        self.assertEqual(self.route(target="/_fixture/attacker"), "attacker")

    def test_login_variants_never_fall_through(self):
        for path in [
            LOGIN + "/",
            LOGIN + "?x=1",
            LOGIN + "/oauth2/auth/",
            LOGIN + "/oauth2/auth?x=1",
            LOGIN + "/authcallback",
            LOGIN + ";suffix",
            LOGIN.upper(),
            "/api/v1/%6cogin",
            "/api/v1/log%69n",
            "/api//v1/login",
            "/api/v1/./login",
            "/api/v1/x/../login",
            "/api/v1/login%2f",
            "/%2561pi/v1/login",
        ]:
            for method in ["GET", "POST", "PUT", "OPTIONS"]:
                with self.subTest(path=path, method=method), self.assertRaises(
                    ValueError
                ):
                    self.route(method, path, ORIGIN)
        for method in ["PUT", "HEAD", "OPTIONS", "DELETE"]:
            with self.subTest(method=method), self.assertRaises(ValueError):
                self.route(method)
        for origin in [
            None,
            "null",
            ORIGIN + "/",
            "http://" + MINIO,
            "https://attacker.invalid",
            ORIGIN + ":443",
        ]:
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                self.route("POST", origin=origin)

    def test_authority_and_target_rejections(self):
        for host, sni in [
            (MINIO, AUTH),
            (AUTH, MINIO),
            (None, MINIO),
            (MINIO, None),
            (MINIO + ":443", MINIO),
            ("unknown.invalid", "unknown.invalid"),
        ]:
            with self.subTest(host=host, sni=sni), self.assertRaises(ValueError):
                self.route(host=host, sni=sni)
        for target in [
            "https://" + MINIO + LOGIN,
            "//" + MINIO + LOGIN,
            "/\\api",
            "/x#fragment",
            "/x\r\n",
            "*",
            "/x%00",
        ]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.route(target=target)
        with self.assertRaises(ValueError):
            self.route("CONNECT", "/")
        for method, path in [
            ("POST", "/_fixture/status"),
            ("GET", "/_fixture/status?x=1"),
            ("GET", "/_fixture/unknown"),
        ]:
            with self.assertRaises(ValueError):
                self.route(method, path)

    def test_header_and_body_boundaries(self):
        first, headers = parse_headers(
            b"GET / HTTP/1.1\r\nHost: minio.i3alumba.ru\r\n\r\n"
        )
        self.assertEqual(first, "GET / HTTP/1.1")
        self.assertEqual(dict(headers)["host"], MINIO)
        exact = b"GET / HTTP/1.1\r\nX: " + b"a" * (HEADER_LIMIT - 23) + b"\r\n\r\n"
        self.assertEqual(len(exact), HEADER_LIMIT)
        parse_headers(exact)
        for block in [
            exact[:-4] + b"a\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            b"GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
            b"GET / HTTP/1.1\r\n folded: value\r\n\r\n",
            b"GET / HTTP/1.1\r\nX: a\x00b\r\n\r\n",
            b"GET / HTTP/1.1\nHost: a\n\n",
        ]:
            with self.subTest(block_length=len(block)), self.assertRaises(ValueError):
                parse_headers(block)
        self.assertEqual(request_limit(LOGIN), SMALL_LIMIT)
        self.assertEqual(request_limit("/o/token/"), SMALL_LIMIT)
        self.assertEqual(request_limit("/api/v1/other"), REQUEST_LIMIT)
        for limit in [SMALL_LIMIT, REQUEST_LIMIT]:
            self.assertEqual(
                body_length([("content-length", str(limit))], limit), limit
            )
            for headers in [
                [("content-length", str(limit + 1))],
                [("content-length", "-1")],
                [("content-length", "+1")],
                [("content-length", "1,1")],
                [("transfer-encoding", "chunked")],
                [("expect", "100-continue")],
            ]:
                with self.assertRaises(ValueError):
                    body_length(headers, limit)

    def test_strip_forwarding_and_hop_headers_preserve_separate_cookies(self):
        headers = [
            ("connection", "x-remove"),
            ("x-remove", "bad"),
            ("x-forwarded-for", "bad"),
            ("x-forwarded-proto", "http"),
            ("forwarded", "bad"),
            ("proxy-authorization", "bad"),
            ("host", "bad"),
            ("set-cookie", "a=one; Secure"),
            ("set-cookie", "b=two; Secure"),
        ]
        self.assertEqual(clean_headers(headers), headers[-2:])
        wire = Mock()
        reply(wire, 204, headers, b"")
        output = wire.send.call_args_list[0].args[0]
        self.assertEqual(output.count(b"set-cookie:"), 2)
        self.assertNotIn(b"bad", output)

    def test_status_probe_ignores_browser_cookie_without_forwarding_or_exposing_it(
        self,
    ):
        handler = object.__new__(Handler)
        connection = Mock(fixture_sni=MINIO)
        observer = Mock()
        observer.exportSafe.return_value = {
            "claims_verified": False,
            "token_request_count": 0,
        }
        handler.request = Mock()
        handler.server = SimpleNamespace(context=Mock(), observer=observer)
        handler.server.context.wrap_socket.return_value = connection
        wire = Mock()
        wire.headers.return_value = (
            "GET /_fixture/status HTTP/1.1",
            [("host", MINIO), ("cookie", "token=PUBLIC_SYNTHETIC_COOKIE")],
        )
        wire.read.return_value = b""
        with patch(
            "user_admin.vendor_fixtures.minio_browser_router.Wire", return_value=wire
        ), patch(
            "user_admin.vendor_fixtures.minio_browser_router.socket.create_connection"
        ) as upstream:
            handler.handle()
        upstream.assert_not_called()
        output = b"".join(call.args[0] for call in wire.send.call_args_list)
        self.assertIn(b"HTTP/1.1 200", output)
        self.assertNotIn(b"PUBLIC_SYNTHETIC_COOKIE", output)

    def test_bounded_response_and_finite_wire_deadline(self):
        wire = Mock()
        wire.headers.return_value = (
            "HTTP/1.1 200 OK",
            [("content-length", str(SMALL_LIMIT + 1))],
        )
        with self.assertRaises(ValueError):
            read_response(wire, "POST", SMALL_LIMIT)
        wire.read.assert_not_called()
        wire.headers.return_value = (
            "HTTP/1.1 200 OK",
            [("transfer-encoding", "chunked")],
        )
        wire.line.return_value = b"10001\r\n"
        with self.assertRaises(ValueError):
            read_response(wire, "POST", SMALL_LIMIT)
        wire.headers.return_value = (
            "HTTP/1.1 200 OK",
            [("transfer-encoding", "chunked"), ("content-length", "1")],
        )
        with self.assertRaises(ValueError):
            read_response(wire, "POST", SMALL_LIMIT)
        connection = Mock()
        with self.assertRaises(TimeoutError):
            Wire(connection, time.monotonic() - 1).read(1)
        connection.recv.assert_not_called()


class MinioBrowserTokenObserverFixtureTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def setUp(self):
        self.expected = {
            "client_id": "synthetic-minio-client",
            "subjects": {"2": POLICY_A, "3": POLICY_B},
        }
        self.observer = TokenObserver(self.public_key, lambda: self.expected)

    def response(self, **changes):
        now = int(time.time())
        claims = {
            "iss": "https://auth.i3alumba.ru/o",
            "aud": "synthetic-minio-client",
            "sub": "2",
            "iat": now - 1,
            "exp": now + 300,
            "policy": POLICY_A,
        }
        claims.update(changes)
        token = jwt.encode(claims, self.private_key, algorithm="RS256")
        return json.dumps(
            {"id_token": token, "access_token": "synthetic-not-retained"}
        ).encode()

    def test_real_signed_claims_count_only_verified_subjects_and_safe_integers(self):
        self.observer.attempt()
        self.observer.observe(self.response())
        self.observer.observe(self.response())
        self.observer.observe(self.response(sub="3", policy=POLICY_B))
        safe = self.observer.exportSafe()
        self.assertEqual(
            safe,
            {
                "token_exchange_count": 3,
                "verified_subject_count": 2,
                "claims_verified": True,
                "observer_failed": False,
                "token_request_count": 1,
            },
        )
        self.assertTrue(all(type(value) in {int, bool} for value in safe.values()))
        self.assertNotIn("synthetic", json.dumps(safe))
        self.assertNotIn("ua-ownBucket", json.dumps(safe))

    def test_invalid_claims_fail_observer_without_throwing_or_counting(self):
        for changes in [
            {"aud": "wrong"},
            {"aud": ["synthetic-minio-client", "wrong"]},
            {"policy": "wrong"},
            {"sub": "3"},
            {"sub": "4"},
            {"exp": int(time.time()) - 1},
            {"iat": int(time.time()) + 100},
            {"iss": "https://auth.i3alumba.ru/o/"},
            {"iat": True},
        ]:
            with self.subTest(changes=changes):
                observer = TokenObserver(self.public_key, lambda: self.expected)
                observer.observe(self.response(**changes))
                self.assertTrue(observer.exportSafe()["observer_failed"])
                self.assertEqual(observer.exportSafe()["token_exchange_count"], 0)
        for body in [
            b"not-json",
            b"{}",
            b'{"id_token":"bad"}',
            b"x" * (SMALL_LIMIT + 1),
        ]:
            observer = TokenObserver(self.public_key, lambda: self.expected)
            observer.observe(body)
            self.assertTrue(observer.exportSafe()["observer_failed"])

    def test_wrong_signature_and_missing_expected_file_fail_closed(self):
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        observer = TokenObserver(wrong_key.public_key(), lambda: self.expected)
        observer.observe(self.response())
        self.assertTrue(observer.exportSafe()["observer_failed"])

        def missing():
            raise FileNotFoundError

        observer = TokenObserver(self.public_key, missing)
        self.assertFalse(observer.exportSafe()["observer_failed"])
        observer.observe(self.response())
        self.assertTrue(observer.exportSafe()["observer_failed"])

    def test_expectations_are_runtime_subjects_not_hardcoded_fixture_ids(self):
        expected = {
            "client_id": "synthetic-minio-client",
            "subjects": {"12": POLICY_A, "88": POLICY_B},
        }
        observer = TokenObserver(self.public_key, lambda: expected)
        observer.observe(self.response(sub="12"))
        self.assertTrue(observer.exportSafe()["claims_verified"])
        for subjects in [
            {"12": POLICY_A, "88": POLICY_A},
            {"12": "consoleAdmin", "88": POLICY_B},
            {"admin": POLICY_A, "88": POLICY_B},
        ]:
            observer = TokenObserver(
                self.public_key,
                lambda: {"client_id": "synthetic-minio-client", "subjects": subjects},
            )
            observer.observe(self.response(sub="12"))
            self.assertTrue(observer.exportSafe()["observer_failed"])

    def test_failed_flag_is_sticky_even_after_valid_observation(self):
        self.observer.observe(b"malformed")
        self.observer.observe(self.response())
        self.assertEqual(self.observer.exportSafe()["token_exchange_count"], 1)
        self.assertFalse(self.observer.exportSafe()["claims_verified"])
        self.assertTrue(self.observer.exportSafe()["observer_failed"])
