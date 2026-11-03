"""Fixture-only HTTPS cookie path to the exact embedded loopback Console.

No redirects, proxy, logging, persistence or configurable remote origins. This
proves HTTP cookie authorization, not browser or OAuth redirect/callback behavior.
"""

from dataclasses import dataclass, field
from http.client import HTTPSConnection
from http.cookies import SimpleCookie
import ssl

from ..native.http import Reply


@dataclass(frozen=True)
class ConsoleReply(Reply):
    cookie: str = field(default="", repr=False)
    secure_httponly: bool = False


def console_request(
    context: ssl.SSLContext,
    method: str,
    target: str,
    *,
    body: bytes = b"",
    cookie: str = "",
) -> ConsoleReply:
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise ValueError("fixture_tls_verification_required")
    if not target.startswith("/api/v1/") or any(
        ord(char) <= 32 or ord(char) >= 127 for char in target
    ):
        raise ValueError("fixture_console_target_invalid")
    connection = HTTPSConnection("localhost", 9444, context=context, timeout=5)
    headers = {"Content-Type": "application/json", "Origin": "https://localhost:9444"}
    if cookie:
        headers["Cookie"] = cookie
    try:
        connection.request(method, target, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read(1024 * 1024 + 1)
        if len(payload) > 1024 * 1024:
            raise ValueError("fixture_console_response_too_large")
        jar = SimpleCookie()
        for name, value in response.getheaders():
            if name.lower() == "set-cookie":
                jar.load(value)
        token = jar.get("token")
        return ConsoleReply(
            response.status,
            payload,
            response.getheader("Content-Type", ""),
            "token=" + token.coded_value if token is not None else "",
            bool(token is not None and token["secure"] and token["httponly"]),
        )
    finally:
        connection.close()
