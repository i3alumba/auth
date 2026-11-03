"""Fixture-only GitLab password/opaque HTTP-cookie path, never browser evidence."""

from copy import deepcopy
from html.parser import HTMLParser
from http.cookiejar import CookieJar
import ssl
from urllib.error import HTTPError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import (
    Request,
    build_opener,
    ProxyHandler,
    HTTPSHandler,
    HTTPCookieProcessor,
    HTTPRedirectHandler,
)

from ..native.http import Reply

ORIGIN = "https://localhost:19443"


class TokenParser(HTMLParser):
    token = None
    in_login_form = False

    def handle_endtag(self, tag):
        if tag == "form":
            self.in_login_form = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "form":
            self.in_login_form = values.get("action") == "/users/sign_in"
        if (
            tag == "input"
            and self.in_login_form
            and values.get("name") == "authenticity_token"
        ):
            self.token = values.get("value")


def csrf_token(body):
    parser = TokenParser()
    parser.feed(body.decode())
    if type(parser.token) is not str or not parser.token:
        raise ValueError("fixture_csrf_token_missing")
    return parser.token


class LocalRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, newurl):
        value = urlsplit(urljoin(request.full_url, newurl))
        if (value.scheme, value.hostname, value.port) != ("https", "localhost", 19443):
            raise ValueError("fixture_redirect_outside_origin")
        return super().redirect_request(request, file, code, message, headers, newurl)


class LocalGitlabSession:
    def __init__(self, context: ssl.SSLContext):
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("fixture_tls_verification_required")
        self.context = context
        self.cookies = CookieJar()
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=context),
            HTTPCookieProcessor(self.cookies),
            LocalRedirect(),
        )

    def frozen_copy(self):
        """Replay unchanged original cookies in a new client, never manufacture them."""
        other = LocalGitlabSession(self.context)
        for cookie in self.cookies:
            other.cookies.set_cookie(deepcopy(cookie))
        return other

    def request(self, path, fields=None):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("fixture_path_required")
        body = urlencode(fields).encode() if fields is not None else None
        headers = {"Origin": ORIGIN, "Referer": ORIGIN + "/users/sign_in"}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = Request(ORIGIN + path, data=body, headers=headers)
        try:
            response = self.opener.open(request, timeout=10)
        except HTTPError as error:
            response = error
        with response:
            payload = response.read(1024 * 1024 + 1)
            if len(payload) > 1024 * 1024:
                raise ValueError("fixture_cookie_response_too_large")
            return Reply(
                response.status, payload, response.headers.get("Content-Type", "")
            )

    def login(self, username, password):
        form = self.request("/users/sign_in")
        return self.request(
            "/users/sign_in",
            {
                "authenticity_token": csrf_token(form.body),
                "user[login]": username,
                "user[password]": password,
                "user[remember_me]": "0",
            },
        )
