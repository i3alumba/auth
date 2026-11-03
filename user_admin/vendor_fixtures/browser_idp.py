"""Actual Django URLs over fixture-only loopback TLS, without request logging."""

import os
from pathlib import Path
import signal
from socketserver import ThreadingMixIn
import ssl
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server


class LoopbackServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class SilentTLSHandler(WSGIRequestHandler):
    error_stream = None

    def log_message(self, *args):
        pass

    def get_environ(self):
        if not isinstance(self.connection, ssl.SSLSocket):
            raise RuntimeError("browser_fixture_tls_required")
        environ = super().get_environ()
        environ["HTTPS"] = "on"
        environ["wsgi.url_scheme"] = "https"
        return environ

    def get_stderr(self):
        return self.error_stream


def stop(signum, frame):
    raise SystemExit(0)


def main():
    if os.environ.get("DJANGO_SETTINGS_MODULE") not in {
        "user_admin.vendor_fixtures.browser_settings",
        "user_admin.vendor_fixtures.minio_browser_settings",
    }:
        raise RuntimeError("browser_fixture_settings_required")
    from django.core.wsgi import get_wsgi_application

    application = get_wsgi_application()
    root = Path("/fixture-idp")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "tls.crt", root / "tls.key")
    signal.signal(signal.SIGTERM, stop)
    with open(os.devnull, "w") as errors:
        SilentTLSHandler.error_stream = errors
        with make_server(
            "127.0.0.1",
            19445,
            application,
            server_class=LoopbackServer,
            handler_class=SilentTLSHandler,
        ) as server:
            server.socket = context.wrap_socket(server.socket, server_side=True)
            server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("browser_fixture_idp_failed") from None
