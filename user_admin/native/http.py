"""Small HTTPS-only vendor transport. No redirects, proxies, cookies or body logs.

Socket connect/TLS timeouts are bounded; DNS resolution remains a platform
facility, not a claimed hard-deadline guarantee. Once connected, a deadline
interrupts header/body IO. Any uncertain write is left to the outbox UNKNOWN
reservation; transport failures never authorize replay.
"""

from dataclasses import dataclass, field
import http.client
import json
import math
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit


class NativeTransportError(Exception):
    def __init__(self):
        super().__init__("native_transport_failed")


@dataclass(frozen=True)
class Reply:
    status: int
    body: bytes = field(repr=False)
    content_type: str = ""

    def json(self):
        try:
            if self.content_type.split(";", 1)[0].strip().lower() != "application/json":
                raise ValueError
            return json.loads(
                self.body,
                object_pairs_hook=_unique_pairs,
                parse_constant=_invalid_constant,
            )
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise NativeTransportError() from None


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError


class NativeHTTP:
    def __init__(
        self,
        origin: str,
        *,
        context: ssl.SSLContext | None = None,
        timeout: float = 3,
        max_response: int = 1024 * 1024,
    ):
        try:
            parsed = urlsplit(origin)
            port = 443 if parsed.port is None else parsed.port
            host = parsed.hostname
            if (
                parsed.scheme != "https"
                or not host
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
                or not 1 <= port <= 65535
                or any(ord(c) <= 32 or ord(c) >= 127 for c in origin)
            ):
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise ValueError("invalid_native_endpoint") from None
        if (
            type(timeout) not in {int, float}
            or not math.isfinite(timeout)
            or not 0 < timeout <= 30
            or type(max_response) is not int
            or not 0 < max_response <= 4 * 1024 * 1024
        ):
            raise ValueError("invalid_native_limits")
        self.context = context if context is not None else ssl.create_default_context()
        if (
            not self.context.check_hostname
            or self.context.verify_mode != ssl.CERT_REQUIRED
        ):
            raise ValueError("native_tls_verification_required")
        self.host, self.port = host, port
        bracketed = f"[{host}]" if ":" in host else host
        self.authority = bracketed if port == 443 else f"{bracketed}:{port}"
        self.timeout, self.max_response = timeout, max_response

    def request(
        self,
        method: str,
        target: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> Reply:
        if (
            method not in {"GET", "HEAD", "POST", "PUT"}
            or type(target) is not str
            or not target.startswith("/")
            or target.startswith("//")
            or any(ord(c) <= 32 or ord(c) >= 127 for c in target)
            or "#" in target
            or type(body) is not bytes
            or len(body) > 1024 * 1024
        ):
            raise ValueError("invalid_native_request")
        if headers is not None and type(headers) is not dict:
            raise ValueError("invalid_native_headers")
        safe_headers = {}
        for key, value in (headers or {}).items():
            if (
                type(key) is not str
                or not re.fullmatch(r"[A-Za-z0-9-]+", key)
                or type(value) is not str
                or not value
                or any(ord(c) < 32 or ord(c) >= 127 for c in value)
                or key.lower()
                in {
                    "proxy-authorization",
                    "connection",
                    "transfer-encoding",
                    "content-length",
                }
                or (key.lower() == "host" and value != self.authority)
                or key.lower() in {k.lower() for k in safe_headers}
            ):
                raise ValueError("invalid_native_headers")
            safe_headers[key] = value
        safe_headers["Connection"] = "close"
        conn = http.client.HTTPSConnection(
            self.host, self.port, timeout=self.timeout, context=self.context
        )
        expired = threading.Event()
        timer = None
        deadline = time.monotonic() + self.timeout
        try:
            conn.connect()
            wire = conn.sock
            if wire is None:
                raise NativeTransportError()

            def interrupt():
                expired.set()
                try:
                    wire.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                finally:
                    wire.close()

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NativeTransportError()
            timer = threading.Timer(remaining, interrupt)
            timer.daemon = True
            timer.start()
            conn.request(method, target, body=body, headers=safe_headers)
            with conn.getresponse() as response:
                payload = response.read(self.max_response + 1)
                if (
                    len(payload) > self.max_response
                    or expired.is_set()
                    or time.monotonic() >= deadline
                ):
                    raise NativeTransportError()
                return Reply(
                    response.status, payload, response.getheader("Content-Type", "")
                )
        except (OSError, ValueError, http.client.HTTPException, TimeoutError):
            raise NativeTransportError() from None
        finally:
            if timer is not None:
                timer.cancel()
            conn.close()
