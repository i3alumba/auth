"""Owned, isolated browser-fixture TLS router; importing performs no I/O."""

import json
import os
from pathlib import Path
import re
import socket
import socketserver
import ssl
import threading
import time
from uuid import UUID

import jwt

AUTH = "auth.i3alumba.ru"
MINIO = "minio.i3alumba.ru"
ORIGIN = "https://" + MINIO
LOGIN = "/api/v1/login"
TOKEN = "/o/token/"
HEADER_LIMIT = 16 * 1024
SMALL_LIMIT = 64 * 1024
REQUEST_LIMIT = 1024 * 1024
RESPONSE_LIMIT = 16 * 1024 * 1024
TOTAL_SECONDS = 30
HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
}
ATTACKER = (
    b"<!doctype html><title>Owned fixture probe</title><body>Owned fixture probe</body>"
)


def route_request(host, sni, method, target, origin):
    """Return auth/console/status/attacker, or a fixed rejection code."""
    if not isinstance(host, str) or host not in {AUTH, MINIO} or sni != host:
        raise ValueError("router_authority_rejected")
    if (
        not isinstance(method, str)
        or not re.fullmatch(r"[A-Z]+", method)
        or method == "CONNECT"
        or not isinstance(target, str)
        or not target.startswith("/")
        or "//" in target
        or "\\" in target
        or "#" in target
        or any(ord(char) < 33 or ord(char) > 126 for char in target)
    ):
        raise ValueError("router_target_rejected")
    path = target.split("?", 1)[0]
    # Reject alternate path normalization rather than depend on either upstream.
    if "%" in path or any(part in {".", ".."} for part in path.split("/")):
        raise ValueError("router_target_rejected")
    if host == AUTH:
        return "auth"
    if path.startswith("/_fixture/"):
        if method == "GET" and target == "/_fixture/status":
            return "status"
        if method == "GET" and target == "/_fixture/attacker":
            return "attacker"
        raise ValueError("router_route_rejected")
    if path.lower().startswith(LOGIN):
        if target == LOGIN and method == "GET":
            return "auth"
        if target == LOGIN and method == "POST" and origin == ORIGIN:
            return "console"
        if target == LOGIN + "/oauth2/auth" and method == "POST":
            return "auth"
        raise ValueError("router_login_rejected")
    return "console"


def request_limit(target):
    return (
        SMALL_LIMIT
        if target.split("?", 1)[0].startswith((LOGIN, TOKEN))
        else REQUEST_LIMIT
    )


def parse_headers(block):
    """Parse bounded headers without duplicate fields or ambiguous framing."""
    if len(block) > HEADER_LIMIT or not block.endswith(b"\r\n\r\n"):
        raise ValueError("router_headers_rejected")
    lines = block[:-4].split(b"\r\n")
    first = lines.pop(0).decode("ascii")
    headers = []
    seen = set()
    for line in lines:
        name, separator, value = line.partition(b":")
        if not separator or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ValueError("router_headers_rejected")
        value = value.strip(b" \t")
        if any(char < 32 or char == 127 for char in value):
            raise ValueError("router_headers_rejected")
        key = name.decode("ascii").lower()
        # Separate Set-Cookie is mandatory on upstream responses only.
        if key in seen and key != "set-cookie":
            raise ValueError("router_headers_rejected")
        seen.add(key)
        headers.append((key, value.decode("latin1")))
    return first, headers


def body_length(headers, limit):
    values = dict(headers)
    if "transfer-encoding" in values or "expect" in values:
        raise ValueError("router_framing_rejected")
    raw = values.get("content-length", "0")
    if not re.fullmatch(r"[0-9]{1,10}", raw) or int(raw) > limit:
        raise ValueError("router_body_rejected")
    return int(raw)


def clean_headers(headers):
    connection = dict(headers).get("connection", "")
    excluded = HOP | {item.strip().lower() for item in connection.split(",")}
    excluded |= {"host", "content-length", "forwarded", "via", "x-real-ip"}
    return [
        (key, value)
        for key, value in headers
        if key not in excluded and not key.startswith(("x-forwarded-", "proxy-"))
    ]


class TokenObserver:
    """Only verified counters survive observation; response bytes are never changed."""

    def __init__(self, public_key, expected):
        self._public_key = public_key
        self._expected = expected
        self._lock = threading.Lock()
        self._counts = {}
        self._failed = False
        self._attempts = 0

    def attempt(self):
        with self._lock:
            self._attempts += 1

    def observe(self, body):
        try:
            expected = self._expected()
            if (
                set(expected) != {"client_id", "subjects"}
                or not isinstance(expected["client_id"], str)
                or not expected["client_id"]
                or type(expected["subjects"]) is not dict
                or len(expected["subjects"]) != 2
                or any(
                    type(subject) is not str
                    or not re.fullmatch(r"[1-9][0-9]*", subject)
                    or type(policy) is not str
                    or not re.fullmatch(r"ua-[0-9a-f]{32}", policy)
                    for subject, policy in expected["subjects"].items()
                )
                or len(set(expected["subjects"].values())) != 2
                or len(body) > SMALL_LIMIT
            ):
                raise ValueError("observer_rejected")
            token = json.loads(body)["id_token"]
            claims = jwt.decode(
                token,
                self._public_key,
                algorithms=["RS256"],
                issuer="https://auth.i3alumba.ru/o",
                audience=expected["client_id"],
                options={
                    "require": ["iss", "aud", "exp", "iat", "sub"],
                    "strict_aud": True,
                },
            )
            subject = claims["sub"]
            if (
                not isinstance(subject, str)
                or subject not in expected["subjects"]
                or claims.get("policy") != expected["subjects"][subject]
                or type(claims["iat"]) is not int
                or type(claims["exp"]) is not int
                or claims["iat"] >= claims["exp"]
            ):
                raise ValueError("observer_rejected")
            with self._lock:
                self._counts[subject] = self._counts.get(subject, 0) + 1
        except Exception:
            # A real exchange may already have mutated state: never replace its response.
            with self._lock:
                self._failed = True

    def exportSafe(self):
        with self._lock:
            return {
                "token_exchange_count": sum(self._counts.values()),
                "verified_subject_count": len(self._counts),
                "claims_verified": bool(self._counts) and not self._failed,
                "observer_failed": self._failed,
                "token_request_count": self._attempts,
            }


class Wire:
    def __init__(self, connection, deadline):
        self.connection = connection
        self.deadline = deadline

    def timeout(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("router_deadline")
        self.connection.settimeout(min(5, remaining))

    def read(self, length):
        chunks = bytearray()
        while len(chunks) < length:
            self.timeout()
            data = self.connection.recv(min(65536, length - len(chunks)))
            if not data:
                raise ValueError("router_truncated")
            chunks.extend(data)
        return bytes(chunks)

    def line(self, limit):
        data = bytearray()
        while not data.endswith(b"\r\n"):
            if len(data) >= limit:
                raise ValueError("router_headers_rejected")
            data.extend(self.read(1))
        return bytes(data)

    def headers(self):
        data = bytearray()
        while not data.endswith(b"\r\n\r\n"):
            data.extend(self.line(HEADER_LIMIT - len(data)))
        return parse_headers(bytes(data))

    def send(self, data):
        for offset in range(0, len(data), 65536):
            self.timeout()
            self.connection.sendall(data[offset : offset + 65536])


def read_response(wire, method, limit):
    first, headers = wire.headers()
    if not re.fullmatch(r"HTTP/1\.[01] [2-5][0-9]{2}(?: [\x20-\x7e]*)?", first):
        raise ValueError("router_response_rejected")
    status = int(first.split(" ")[1])
    values = dict(headers)
    if "transfer-encoding" in values and "content-length" in values:
        raise ValueError("router_framing_rejected")
    if method == "HEAD" or status in {204, 304}:
        return status, headers, b""
    if "transfer-encoding" in values:
        if values["transfer-encoding"].lower() != "chunked":
            raise ValueError("router_framing_rejected")
        body = bytearray()
        while True:
            line = wire.line(128)[:-2]
            if not re.fullmatch(rb"[0-9a-fA-F]{1,8}", line):
                raise ValueError("router_framing_rejected")
            size = int(line, 16)
            if size > limit - len(body):
                raise ValueError("router_body_rejected")
            if size == 0:
                if wire.read(2) != b"\r\n":
                    raise ValueError("router_framing_rejected")
                break
            body.extend(wire.read(size))
            if wire.read(2) != b"\r\n":
                raise ValueError("router_framing_rejected")
        return status, headers, bytes(body)
    if "content-length" in values:
        return status, headers, wire.read(body_length(headers, limit))
    body = bytearray()
    while True:
        wire.timeout()
        chunk = wire.connection.recv(min(65536, limit + 1 - len(body)))
        if not chunk:
            return status, headers, bytes(body)
        body.extend(chunk)
        if len(body) > limit:
            raise ValueError("router_body_rejected")


def reply(wire, status, headers, body):
    fields = clean_headers(headers)
    fields.extend([("content-length", str(len(body))), ("connection", "close")])
    head = (
        f"HTTP/1.1 {status} Fixture\r\n"
        + "".join(f"{key}: {value}\r\n" for key, value in fields)
        + "\r\n"
    )
    wire.send(head.encode("latin1"))
    wire.send(body)


class Router(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, context, upstream_context, observer):
        self.context = context
        self.upstream_context = upstream_context
        self.observer = observer
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(("127.0.0.1", 443), Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            request.close()

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        deadline = time.monotonic() + TOTAL_SECONDS
        connection = None
        try:
            self.request.settimeout(5)
            connection = self.server.context.wrap_socket(self.request, server_side=True)
            wire = Wire(connection, deadline)
            first, headers = wire.headers()
            parts = first.split(" ")
            if len(parts) != 3 or parts[2] != "HTTP/1.1":
                raise ValueError("router_request_rejected")
            method, target, _ = parts
            values = dict(headers)
            if any(key == "set-cookie" for key, _ in headers):
                raise ValueError("router_headers_rejected")
            host = values.get("host")
            route = route_request(
                host,
                getattr(connection, "fixture_sni", None),
                method,
                target,
                values.get("origin"),
            )
            body = wire.read(body_length(headers, request_limit(target)))
            if route in {"status", "attacker"}:
                # Same-origin browser probes naturally carry HttpOnly cookies.
                # Ignore them here: never forward or expose their contents.
                if body or "authorization" in values:
                    raise ValueError("router_probe_rejected")
                payload = (
                    json.dumps(self.server.observer.exportSafe()).encode()
                    if route == "status"
                    else ATTACKER
                )
                reply(
                    wire,
                    200,
                    [
                        (
                            "content-type",
                            "application/json" if route == "status" else "text/html",
                        ),
                        ("cache-control", "no-store"),
                    ],
                    payload,
                )
                return
            observed = host == AUTH and method == "POST" and target == TOKEN
            if observed:
                self.server.observer.attempt()
            port = 19445 if route == "auth" else 19001
            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=min(5, max(0.001, deadline - time.monotonic())),
            ) as raw:
                with self.server.upstream_context.wrap_socket(
                    raw, server_hostname="localhost"
                ) as upstream:
                    backend = Wire(upstream, deadline)
                    fields = clean_headers(headers) + [
                        ("host", host),
                        ("x-forwarded-proto", "https"),
                        ("content-length", str(len(body))),
                        ("connection", "close"),
                    ]
                    request = (
                        f"{method} {target} HTTP/1.1\r\n"
                        + "".join(f"{key}: {value}\r\n" for key, value in fields)
                        + "\r\n"
                    )
                    backend.send(request.encode("latin1"))
                    backend.send(body)
                    limit = (
                        SMALL_LIMIT
                        if target.split("?", 1)[0].startswith((LOGIN, TOKEN))
                        else RESPONSE_LIMIT
                    )
                    status, response_headers, response_body = read_response(
                        backend, method, limit
                    )
            if observed and status == 200:
                self.server.observer.observe(response_body)
            reply(wire, status, response_headers, response_body)
        except Exception:
            if connection is not None:
                try:
                    reply(
                        Wire(connection, deadline),
                        502,
                        [("content-type", "text/plain")],
                        b"fixture_router_rejected",
                    )
                except Exception:
                    pass
        finally:
            if connection is not None:
                connection.close()


def startup_files(root):
    uid = os.getuid()
    if uid == 0:
        raise ValueError("router_fixture_required")
    for name in ("marker", "run-id"):
        file = root / name
        if (
            file.is_symlink()
            or file.stat().st_uid not in {0, uid}
            or file.stat().st_mode & 0o022
        ):
            raise ValueError("router_fixture_required")
    if (root / "marker").read_text() != "PUBLIC_PAGE_SYNTHETIC_FIXTURE_V1":
        raise ValueError("router_fixture_required")
    run_id = (root / "run-id").read_text().strip()
    if run_id not in {UUID(run_id).hex, str(UUID(run_id))}:
        raise ValueError("router_fixture_required")
    for host in (AUTH, MINIO):
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        if not addresses or any(item[4][0] != "127.0.0.1" for item in addresses):
            raise ValueError("router_loopback_required")


def main():
    root = Path("/fixture-router")
    startup_files(root)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(root / "tls.crt", root / "tls.key")

    def sni(connection, name, tls_context):
        if name not in {AUTH, MINIO}:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        connection.fixture_sni = name

    context.set_servername_callback(sni)
    upstream = ssl.create_default_context(cafile=str(root / "ca.crt"))
    upstream.minimum_version = ssl.TLSVersion.TLSv1_2
    observer = TokenObserver(
        (root / "issuer-public.pem").read_bytes(),
        lambda: json.loads((root / "expected.json").read_text()),
    )
    with Router(context, upstream, observer) as server:
        server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("fixture_router_failed") from None
