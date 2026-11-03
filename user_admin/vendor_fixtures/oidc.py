"""Synthetic loopback-only OIDC discovery/JWKS for an isolated vendor namespace.

No login/token/userinfo API, production keys, logs or external calls. The private
key and TLS certificate are supplied only from an ephemeral tmpfs fixture.
"""

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import sys

from cryptography.hazmat.primitives import serialization

ISSUER = "https://localhost:19445"
MARKER = "PUBLIC_PAGE_SYNTHETIC_FIXTURE_V1"


def runtime_directory(value):
    runtime = Path(value).resolve()
    if runtime.name != "fixture" or (runtime / "marker").read_text() != MARKER:
        raise ValueError("synthetic_fixture_marker_required")
    return runtime


def serve(runtime):
    private = serialization.load_pem_private_key(
        (runtime / "tls/private.key").read_bytes(), password=None
    )
    numbers = private.public_key().public_numbers()

    def encoded(number):
        return (
            base64.urlsafe_b64encode(
                number.to_bytes((number.bit_length() + 7) // 8, "big")
            )
            .rstrip(b"=")
            .decode()
        )

    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "synthetic-fixture",
                "use": "sig",
                "alg": "RS256",
                "n": encoded(numbers.n),
                "e": encoded(numbers.e),
            }
        ]
    }
    discovery = {
        "issuer": ISSUER,
        "jwks_uri": ISSUER + "/jwks",
        "authorization_endpoint": ISSUER + "/unused-authorize",
        "token_endpoint": ISSUER + "/unused-token",
        "userinfo_endpoint": ISSUER + "/unused-userinfo",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "policy"],
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            document = (
                discovery
                if self.path == "/.well-known/openid-configuration"
                else jwks if self.path == "/jwks" else None
            )
            payload = json.dumps(
                document
                if document is not None
                else {"error": "fixture_endpoint_not_found"}
            ).encode()
            self.send_response(200 if document is not None else 404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 19445), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(runtime / "tls/public.crt", runtime / "tls/private.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("synthetic_runtime_directory_required")
    serve(runtime_directory(sys.argv[1]))
