"""Explicit managed-service preferences; untouched users keep legacy behavior."""

from django.conf import settings

from sso.models import Service
from .models import UserControl

MANAGED = ("drive", "matrix", "gitlab", "minio", "monitor", "hosting")
PORTAL = ("monitor", "hosting")
GROUP_SERVICES = ("drive", "matrix", "gitlab", "minio")


def preferences(user):
    value = (
        UserControl.objects.filter(user_id=user.pk)
        .values_list("service_preferences", flat=True)
        .first()
    )
    return value if isinstance(value, dict) else {}


def assigned(user, slug, values=None):
    values = preferences(user) if values is None else values
    if slug in MANAGED and slug in values:
        return values[slug] is True
    if slug in PORTAL:
        return bool(user.is_staff)
    service = Service.objects.filter(slug=slug).first()
    return bool(service and user.groups.filter(pk=service.group_id).exists())


def wanted(user, slug, values=None):
    # Jenkins is intentionally NOT a global-administrator override.
    return bool((slug in MANAGED and user.is_superuser) or assigned(user, slug, values))


def portal_allowed(user, slug):
    if not user or not user.is_authenticated or not user.is_active:
        return False
    values = preferences(user)
    if slug == "hosting" and not getattr(
        settings, "USER_ADMIN_HOSTING_GRANTS_READY", False
    ):
        # Disabling readiness must never revive a previously explicit deny.
        # Untouched users retain legacy staff access; nonstaff grants remain
        # ineffective until the consumer is verified.
        if slug in values:
            if type(values[slug]) is not bool:
                return False
            return bool(user.is_staff and (user.is_superuser or values[slug]))
        return bool(user.is_staff)
    if slug in values:
        if type(values[slug]) is not bool:
            return False
        return bool(user.is_superuser or values[slug])
    # Before Hosting readiness the early return preserves legacy staff access.
    # Afterwards the canonical global administrator also has a Hosting grant.
    return bool(user.is_staff or (slug == "hosting" and user.is_superuser))
