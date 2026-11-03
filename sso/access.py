from django.conf import settings
from user_admin.grants import portal_allowed

from .models import Service, ServiceIdentity

PORTAL_URLS = {
    "drive": "https://drive.i3alumba.ru",
    "matrix": "https://matrix.i3alumba.ru",
    "gitlab": "https://gitlab.i3alumba.ru",
    "minio": "https://minio.i3alumba.ru",
    "jenkins": "https://jenkins.i3alumba.ru",
    "monitor": "https://monitor.i3alumba.ru",
    "hosting": "https://hosting.i3alumba.ru",
    "users": "https://users.i3alumba.ru",
}


def identity_for(user, service):
    if not user or not user.is_authenticated or not user.is_active or not service:
        return None
    if not user.groups.filter(pk=service.group_id).exists():
        return None
    return ServiceIdentity.objects.filter(user=user, service=service).first()


def services_for(user):
    services = {s.slug: s for s in Service.objects.all()}
    users_allowed = bool(
        getattr(settings, "USER_ADMIN_API_ENABLED", False)
        and user
        and user.is_authenticated
        and user.is_active
        and user.is_superuser
    )
    return {
        slug: {
            "enabled": (
                users_allowed
                if slug == "users"
                else (
                    portal_allowed(user, slug)
                    if slug in {"monitor", "hosting"}
                    else bool(identity_for(user, services.get(slug)))
                )
            ),
            "url": url,
        }
        for slug, url in PORTAL_URLS.items()
    }
