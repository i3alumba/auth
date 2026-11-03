"""Explicit loopback-only Auth IdP fixture; never web/worker default settings."""

import os
from pathlib import Path

RUNTIME = Path("/fixture-idp")
if (
    not (RUNTIME / "marker").is_file()
    or (RUNTIME / "marker").read_text() != "PUBLIC_PAGE_SYNTHETIC_FIXTURE_V1"
):
    raise RuntimeError("browser_fixture_runtime_required")

# Set before importing production's key validation, using only fresh tmpfs files.
os.environ["SSO_ENABLED"] = "true"
os.environ["SSO_RSA_PRIVATE_KEY_FILE"] = str(RUNTIME / "oidc-rsa.pem")
os.environ.pop("SSO_RSA_PRIVATE_KEY", None)
os.environ["SSO_MINIO_GUARD_ENABLED"] = "false"
os.environ["SSO_MINIO_PKCE_EXCEPTION_CLIENT_ID"] = ""
os.environ.pop("OAUTHLIB_INSECURE_TRANSPORT", None)

from auth.settings import *  # noqa: F403,E402

SECRET_KEY = (RUNTIME / "django-secret").read_text()
DEBUG = False
ALLOWED_HOSTS = ["localhost"]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "user_admin_browser_fixture",
        "USER": "user_admin_browser_fixture",
        "PASSWORD": (RUNTIME / "postgres-password").read_text(),
        "HOST": "127.0.0.1",
        "PORT": "15432",
    }
}
ROOT_URLCONF = "auth.urls"
OAUTH2_PROVIDER = {
    **OAUTH2_PROVIDER,
    "OIDC_ISS_ENDPOINT": "https://localhost:19445/o",
}  # noqa: F405
SIMPLE_JWT = {**SIMPLE_JWT, "SIGNING_KEY": SECRET_KEY}  # noqa: F405
SSO_ENABLED = True
SSO_MINIO_GUARD_ENABLED = False
SSO_MINIO_PKCE_EXCEPTION_CLIENT_ID = ""
USER_ADMIN_API_ENABLED = False
USER_ADMIN_NATIVE_EXECUTION_ENABLED = False
USER_ADMIN_HOSTING_GRANTS_READY = False
SECURE_PROXY_SSL_HEADER = None
SESSION_COOKIE_NAME = "__Host-fixture-auth-session"
CSRF_COOKIE_NAME = "__Host-fixture-auth-csrf"
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_DOMAIN = None
CSRF_COOKIE_DOMAIN = None
SESSION_COOKIE_PATH = "/"
CSRF_COOKIE_PATH = "/"
CSRF_TRUSTED_ORIGINS = ["https://localhost:19445"]
CORS_ALLOWED_ORIGINS = ["https://localhost:19445"]
CORS_ALLOW_ALL_ORIGINS = False
LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
    "handlers": {"null": {"class": "logging.NullHandler"}},
    "root": {"handlers": ["null"], "level": "CRITICAL"},
    "loggers": {
        "django": {"handlers": ["null"], "propagate": False},
        "oauthlib": {"handlers": ["null"], "propagate": False},
    },
}
