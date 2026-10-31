from .models import Service, ServiceIdentity

PORTAL_URLS = {
    "drive": "https://drive.i3alumba.ru",
    "matrix": "https://matrix.i3alumba.ru",
    "gitlab": "https://gitlab.i3alumba.ru",
    "minio": "https://minio.i3alumba.ru",
    "jenkins": "https://jenkins.i3alumba.ru",
}


def identity_for(user, service):
    if not user or not user.is_authenticated or not user.is_active or not service:
        return None
    if not user.groups.filter(pk=service.group_id).exists():
        return None
    return ServiceIdentity.objects.filter(user=user, service=service).first()


def services_for(user):
    services = {s.slug: s for s in Service.objects.all()}
    return {
        slug: {"enabled": bool(identity_for(user, services.get(slug))), "url": url}
        for slug, url in PORTAL_URLS.items()
    }
