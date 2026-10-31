"""Synthetic PostgreSQL fixture on loopback in an isolated container namespace."""

from .test_settings import *  # noqa: F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "common_auth_guard_fixture",
        "USER": "common_auth_guard_fixture",
        "PASSWORD": "synthetic-test-password-only",
        "HOST": "127.0.0.1",
        "PORT": "5432",
    }
}
