"""Synthetic-only tests of the explicitly approved private cluster HTTP mode."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from .models import Operation
from .native.endpoints import CLUSTER_HTTP_ORIGINS
from .native.http import NativeHTTP, NativeTransportError
from .worker_config import WorkerError, load_config
from .worker_runtime import admission, make_adapter
from .test_native_http import Connection, Response

PROFILES = {
    "gitlab": "gitlab-18.1.0-ce-ban-v1",
    "matrix": "synapse-1.164.1-lock-v1",
    "minio": "minio-2023-05-18-owned-s3-v1",
}


class ClusterHTTPConfigTests(SimpleTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir="/dev/shm")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.path = self.root / "config.json"

    def instance(self, service):
        credentials = {
            "gitlab": {"token_file": "token"},
            "matrix": {
                "token_file": "token",
                "registration_secret_file": "registration",
            },
            "minio": {"access_key_file": "access", "secret_key_file": "secret"},
        }
        result = {
            "service": service,
            "instance": "primary",
            "origin": CLUSTER_HTTP_ORIGINS[service],
            "transport": "cluster_http",
            "acceptance_profile": PROFILES[service],
            "credentials": credentials[service],
        }
        if service == "matrix":
            result["server_name"] = "matrix.example.invalid"
        return result

    def load(self, instance):
        self.path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "private_root": str(self.private),
                    "instances": [instance],
                }
            )
        )
        return load_config(str(self.path))

    def test_only_three_exact_service_origins_are_explicitly_accepted(self):
        for service in CLUSTER_HTTP_ORIGINS:
            with self.subTest(service=service):
                config = self.load(self.instance(service))
                self.assertEqual(config.instances[0].transport, "cluster_http")
                self.assertEqual(config.execution_scope, "provision_only")
                self.assertFalse(list(self.private.iterdir()))

    def test_http_is_never_default_or_an_unknown_coerced_transport(self):
        for value in [None, True, [], "http", "auto", "", "https"]:
            instance = self.instance("gitlab")
            instance["transport"] = value
            with self.subTest(value=value), self.assertRaises(WorkerError):
                self.load(instance)
        instance = self.instance("gitlab")
        del instance["transport"]
        with self.assertRaises(WorkerError):
            self.load(instance)

    def test_private_mode_rejects_every_noncanonical_or_cross_service_origin(self):
        for service in CLUSTER_HTTP_ORIGINS:
            for origin in [
                "http://127.0.0.1",
                "http://169.254.169.254",
                "http://gitlab.i3alumba.ru",
                "http://gitlab",
                "http://gitlab.public-page.svc.cluster.local:80",
                "http://minio.public-page.svc.cluster.local:9001",
                "http://user:password@gitlab.public-page.svc.cluster.local",
                CLUSTER_HTTP_ORIGINS[service] + "/",
                CLUSTER_HTTP_ORIGINS[service] + "/path",
                CLUSTER_HTTP_ORIGINS[service] + "?x=1",
                CLUSTER_HTTP_ORIGINS[service] + "#fragment",
                CLUSTER_HTTP_ORIGINS[service].upper(),
                CLUSTER_HTTP_ORIGINS[service].replace("http:", "https:"),
                *[o for s, o in CLUSTER_HTTP_ORIGINS.items() if s != service],
            ]:
                instance = self.instance(service)
                instance["origin"] = origin
                with (
                    self.subTest(service=service, origin=origin),
                    self.assertRaises(WorkerError),
                ):
                    self.load(instance)

    def test_cluster_http_rejects_ca_or_other_instance_not_ignored_security_options(
        self,
    ):
        for change in [{"ca_file": "ca.pem"}, {"instance": "other"}]:
            instance = self.instance("gitlab")
            instance.update(change)
            with self.subTest(change=change), self.assertRaises(WorkerError):
                self.load(instance)

    def test_factory_uses_plain_http_only_for_the_selected_service(self):
        for service in CLUSTER_HTTP_ORIGINS:
            instance = self.load(self.instance(service)).instances[0]
            secrets = {
                name: "SYNTHETIC_NOT_A_SECRET" for name, _ in instance.credentials
            }
            adapter = make_adapter(
                instance, secrets, SimpleNamespace(action=Operation.Action.BIND)
            )
            self.assertEqual(adapter.client.scheme, "http")
            self.assertIsNone(adapter.client.context)
            self.assertEqual(
                adapter.client.authority, CLUSTER_HTTP_ORIGINS[service][7:]
            )

    def test_transport_selection_does_not_open_activation_gates(self):
        config = self.load(self.instance("gitlab"))
        with (
            override_settings(
                SETTINGS_MODULE="auth.worker_settings",
                USER_ADMIN_WORKER_ENABLED=True,
                USER_ADMIN_NATIVE_EXECUTION_ENABLED=True,
            ),
            self.assertRaises(WorkerError) as caught,
        ):
            admission(config)
        self.assertEqual(caught.exception.code, "profile_activation_blocked")


class ClusterHTTPTransportTests(SimpleTestCase):
    def test_direct_constructor_cannot_turn_http_on_generically_or_for_other_service(
        self,
    ):
        for service in CLUSTER_HTTP_ORIGINS:
            origin = CLUSTER_HTTP_ORIGINS[service]
            with self.assertRaises(ValueError):
                NativeHTTP(origin)
            for selector in [
                None,
                True,
                [],
                "http",
                "jenkins",
                *[s for s in CLUSTER_HTTP_ORIGINS if s != service],
            ]:
                with self.subTest(selector=selector), self.assertRaises(ValueError):
                    NativeHTTP(origin, cluster_http_service=selector)
            for origin in [
                origin + "/",
                origin + "?x=1",
                "http://127.0.0.1",
                "https://public.example.invalid",
            ]:
                with self.subTest(origin=origin), self.assertRaises(ValueError):
                    NativeHTTP(origin, cluster_http_service=service)

    def test_https_verification_is_not_disabled_or_ignored(self):
        with self.assertRaisesRegex(ValueError, "native_tls_verification_required"):
            NativeHTTP(
                "https://public.example.invalid",
                context=ssl._create_unverified_context(),
            )
        with self.assertRaises(ValueError):
            NativeHTTP(
                CLUSTER_HTTP_ORIGINS["gitlab"],
                cluster_http_service="gitlab",
                context=ssl.create_default_context(),
            )

    def test_http_retains_response_limit_deadline_and_sanitized_errors(self):
        for connection, kwargs in [
            (Connection(Response(b"SYNTHETIC_PRIVATE_RESPONSE")), {"max_response": 2}),
            (Connection(), {"timeout": 0.02}),
        ]:
            if "timeout" in kwargs:
                connection.response = Response(b"", wire=connection.sock)
            with (
                patch("http.client.HTTPConnection", return_value=connection),
                self.assertRaisesRegex(
                    NativeTransportError, "^native_transport_failed$"
                ),
            ):
                NativeHTTP(
                    CLUSTER_HTTP_ORIGINS["minio"],
                    cluster_http_service="minio",
                    **kwargs,
                ).request("GET", "/fixed")
            self.assertTrue(connection.sock.closed.is_set())

    def test_http_failure_never_falls_back_to_https_and_invalid_host_never_connects(
        self,
    ):
        connection = Connection()
        connection.connect = lambda: (_ for _ in ()).throw(
            OSError("SYNTHETIC_PRIVATE_FAILURE")
        )
        transport = NativeHTTP(
            CLUSTER_HTTP_ORIGINS["minio"], cluster_http_service="minio"
        )
        with (
            patch("http.client.HTTPConnection", return_value=connection) as plain,
            patch("http.client.HTTPSConnection") as tls,
        ):
            with self.assertRaisesRegex(
                NativeTransportError, "^native_transport_failed$"
            ):
                transport.request("POST", "/fixed")
            self.assertEqual(plain.call_count, 1)
            tls.assert_not_called()
            with self.assertRaises(ValueError):
                transport.request(
                    "POST", "/fixed", headers={"Host": "minio.i3alumba.ru"}
                )
            self.assertEqual(plain.call_count, 1)

    def test_real_plain_http_keeps_host_path_no_proxy_no_redirect_and_no_logs(self):
        calls = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append(
                    (self.path, self.headers["Host"], self.headers.get("Authorization"))
                )
                self.send_response(302)
                self.send_header("Content-Type", "application/json")
                self.send_header(
                    "Location", "http://untrusted.example.invalid/redirect"
                )
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        original = socket.getaddrinfo

        def fixture_dns(host, port, *args, **kwargs):
            self.assertEqual(
                (host, port), ("minio.public-page.svc.cluster.local", 9000)
            )
            return original("127.0.0.1", server.server_port, *args, **kwargs)

        try:
            with (
                patch("socket.getaddrinfo", side_effect=fixture_dns),
                patch.dict(
                    "os.environ",
                    {
                        "HTTP_PROXY": "http://untrusted.example.invalid",
                        "ALL_PROXY": "http://untrusted.example.invalid",
                    },
                ),
            ):
                reply = NativeHTTP(
                    CLUSTER_HTTP_ORIGINS["minio"], cluster_http_service="minio"
                ).request(
                    "GET",
                    "/owned?version=1",
                    headers={"Authorization": "SYNTHETIC_NOT_A_SECRET"},
                )
            self.assertEqual(reply.status, 302)
            self.assertEqual(
                calls,
                [
                    (
                        "/owned?version=1",
                        "minio.public-page.svc.cluster.local:9000",
                        "SYNTHETIC_NOT_A_SECRET",
                    )
                ],
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
