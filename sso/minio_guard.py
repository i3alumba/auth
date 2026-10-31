"""Bind the legacy Console OAuth state to its initiating browser.

Only the two small login APIs are proxied. Object/S3 traffic never passes here.
The opaque public state is replaced with Console's original signed state only
once, after the browser binding is consumed. No code or credential is persisted.
"""

import hashlib
import json
import re
import secrets
from datetime import timedelta
from http.cookies import SimpleCookie
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from django.conf import settings
from django.db import transaction
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_variables, sensitive_post_parameters

from .models import MinioLoginChallenge

COOKIE = "__Host-minio-sso-browser"
LOGIN = "/api/v1/login"
CALLBACK = LOGIN + "/oauth2/auth"
LIMIT = 64 * 1024
TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@sensitive_variables("body", "request", "data")
def backend(path, method, body=None):
    # This endpoint is operator configuration, never a URL from the request.
    base = settings.SSO_MINIO_CONSOLE_URL.rstrip("/")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Host": urlsplit(settings.SSO_MINIO_PUBLIC_URL).netloc,
        "X-Forwarded-Proto": "https",
        "User-Agent": "CommonAuthMinioGuard/1",
    }
    request = Request(base + path, data=body, method=method, headers=headers)
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(request, timeout=10)
    except HTTPError as error:
        response = error
    with response:
        data = response.read(LIMIT + 1)
        if len(data) > LIMIT or 300 <= response.status < 400:
            raise ValueError("Unexpected Console response")
        return response.status, data, response.headers.get_all("Set-Cookie", [])


def result(status, body, cookies):
    response = HttpResponse(body, status=status, content_type="application/json")
    for header in cookies:
        parsed = SimpleCookie()
        parsed.load(header)
        for name, morsel in parsed.items():
            if name == COOKIE:
                continue
            response.cookies[name] = morsel
            response.cookies[name]["secure"] = True
            response.cookies[name]["domain"] = ""
    return response


def new_login(request):
    status, body, cookies = backend(LOGIN, "GET")
    if status != 200:
        return result(status, body, cookies)
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("Invalid Console response")
    rules = data.get("redirectRules", [])
    if not isinstance(rules, list) or len(rules) > 10:
        raise ValueError("Unexpected redirect rules")
    browser = request.COOKIES.get(COOKIE, "")
    if not TOKEN.fullmatch(browser):
        browser = secrets.token_urlsafe(32)
    now = timezone.now()
    MinioLoginChallenge.objects.filter(expires_at__lte=now).delete()
    if MinioLoginChallenge.objects.filter(browser_hash=digest(browser)).count() >= 30:
        return JsonResponse({"detail": "Too many login attempts"}, status=429)
    for rule in rules:
        original = rule.get("redirect") if isinstance(rule, dict) else None
        if not isinstance(original, str):
            raise ValueError("Missing redirect")
        url = urlsplit(original)
        pairs = parse_qsl(url.query, keep_blank_values=True)
        values = {}
        for key, value in pairs:
            values.setdefault(key, []).append(value)
        if (
            url.scheme != "https"
            or url.netloc != "auth.i3alumba.ru"
            or url.path != "/o/authorize/"
            or url.fragment
            or values.get("client_id") != [settings.SSO_MINIO_PKCE_EXCEPTION_CLIENT_ID]
            or values.get("redirect_uri")
            != [settings.SSO_MINIO_PUBLIC_URL + "/oauth_callback"]
            or values.get("response_type") != ["code"]
            or len(values.get("state", [])) != 1
            or not 1 <= len(values["state"][0]) <= 4096
        ):
            raise ValueError("Unexpected authorization destination")
        public_state = secrets.token_urlsafe(32)
        MinioLoginChallenge.objects.create(
            state_hash=digest(public_state),
            browser_hash=digest(browser),
            original_state=values["state"][0],
            expires_at=now + timedelta(minutes=10),
        )
        rewritten = [
            (key, public_state if key == "state" else value) for key, value in pairs
        ]
        rule["redirect"] = urlunsplit(
            (url.scheme, url.netloc, url.path, urlencode(rewritten), "")
        )
    response = result(status, json.dumps(data).encode(), cookies)
    if rules:
        response.set_cookie(
            COOKIE, browser, secure=True, httponly=True, samesite="Lax", path="/"
        )
    return response


@sensitive_variables("body", "data", "code")
def callback(request, body):
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("Invalid callback")
    state, code = data.get("state"), data.get("code")
    browser = request.COOKIES.get(COOKIE, "")
    if (
        not isinstance(state, str)
        or not TOKEN.fullmatch(state)
        or not TOKEN.fullmatch(browser)
        or not isinstance(code, str)
        or not 1 <= len(code) <= 4096
    ):
        return JsonResponse({"detail": "Login rejected"}, status=403)
    now = timezone.now()
    with transaction.atomic():
        matches = MinioLoginChallenge.objects.filter(
            state_hash=digest(state),
            browser_hash=digest(browser),
            consumed_at__isnull=True,
            expires_at__gt=now,
        )
        challenge = matches.first()
        if challenge is None or matches.update(consumed_at=now) != 1:
            return JsonResponse({"detail": "Login rejected"}, status=403)
        data["state"] = challenge.original_state
    # A failed exchange remains consumed: restart login rather than reuse a code.
    status, response_body, cookies = backend(
        CALLBACK, "POST", json.dumps(data).encode()
    )
    return result(status, response_body, cookies)


@never_cache
@csrf_exempt
@sensitive_variables("body", "data")
@sensitive_post_parameters("accessKey", "secretKey", "code", "state")
def console_login(request, suffix=""):
    """Own state + exact Origin validation replace Django CSRF for this legacy API."""
    if not settings.SSO_MINIO_GUARD_ENABLED:
        return JsonResponse({"detail": "Login guard unavailable"}, status=503)
    expected = settings.SSO_MINIO_PUBLIC_URL
    if request.get_host() != urlsplit(expected).netloc:
        return JsonResponse({"detail": "Login rejected"}, status=403)
    path = request.path
    if path not in {LOGIN, CALLBACK}:
        return JsonResponse({"detail": "Unknown login API"}, status=404)
    try:
        if request.method == "GET" and path == LOGIN:
            return new_login(request)
        if request.method != "POST":
            return HttpResponse(status=405)
        if request.headers.get("Origin") != expected:
            return JsonResponse({"detail": "Login rejected"}, status=403)
        if request.content_type != "application/json":
            return HttpResponse(status=415)
        body = request.read(LIMIT + 1)
        if len(body) > LIMIT:
            return HttpResponse(status=413)
        if path == CALLBACK:
            return callback(request, body)
        # Local credential login remains available for emergency/machine access.
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError("Invalid login")
        status, response_body, cookies = backend(LOGIN, "POST", body)
        return result(status, response_body, cookies)
    except (ValueError, TypeError, KeyError, URLError, TimeoutError, OSError):
        return JsonResponse({"detail": "MinIO login unavailable"}, status=502)
