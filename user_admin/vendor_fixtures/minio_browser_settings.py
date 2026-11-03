"""Exact-name MinIO guard fixture, isolated by owned loopback-only hosts/TLS."""

import os
import re

from .browser_settings import *  # noqa: F403

# The base module validates the fresh fixture marker before importing production.
# Exact canonical names exercise the unchanged guard, never host DNS/production.
os.environ["SSL_CERT_FILE"] = str(RUNTIME / "ca.crt")  # noqa: F405
ALLOWED_HOSTS = ["auth.i3alumba.ru", "minio.i3alumba.ru"]
OAUTH2_PROVIDER = {
    **OAUTH2_PROVIDER,
    "OIDC_ISS_ENDPOINT": "https://auth.i3alumba.ru/o",
}  # noqa: F405
SSO_MINIO_GUARD_ENABLED = True
SSO_MINIO_PKCE_EXCEPTION_CLIENT_ID = (
    RUNTIME / "minio-client-id"
).read_text()  # noqa: F405
if not re.fullmatch(r"fixture-minio-[0-9a-f]{32}", SSO_MINIO_PKCE_EXCEPTION_CLIENT_ID):
    raise RuntimeError("minio_browser_fixture_client_required")
SSO_MINIO_PUBLIC_URL = "https://minio.i3alumba.ru"
SSO_MINIO_CONSOLE_URL = "https://localhost:19001"
CSRF_TRUSTED_ORIGINS = ["https://auth.i3alumba.ru"]
CORS_ALLOWED_ORIGINS = ["https://auth.i3alumba.ru"]
