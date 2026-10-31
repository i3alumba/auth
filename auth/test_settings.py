"""Isolated SQLite tests; ephemeral signing key, never production credentials."""

from .settings import *  # noqa: F403
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)

SECRET_KEY = "isolated-test-secret-at-least-32-characters"
DEBUG = True
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
ALLOWED_HOSTS = ["testserver", "auth.i3alumba.ru"]
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SSO_ENABLED = True
OAUTH2_PROVIDER = {
    **OAUTH2_PROVIDER,  # noqa: F405
    "OIDC_ENABLED": True,
    "OIDC_RSA_PRIVATE_KEY": rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    .private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    .decode(),
}
