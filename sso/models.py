from django.conf import settings
from django.contrib.auth.models import Group
from django.db import models


class Service(models.Model):
    class Slug(models.TextChoices):
        DRIVE = "drive"
        MATRIX = "matrix"
        GITLAB = "gitlab"
        MINIO = "minio"
        JENKINS = "jenkins"

    slug = models.CharField(max_length=16, choices=Slug.choices, unique=True)
    group = models.ForeignKey(Group, on_delete=models.PROTECT)
    oidc_client_id = models.CharField(
        max_length=100, unique=True, null=True, blank=True
    )


class ServiceIdentity(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    service = models.ForeignKey(Service, on_delete=models.PROTECT)
    external_id = models.CharField(max_length=255)
    external_username = models.CharField(max_length=255)
    minio_policy = models.CharField(max_length=255, blank=True)
    jenkins_admin = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "service"], name="sso_user_service"
            ),
            models.UniqueConstraint(
                fields=["service", "external_id"], name="sso_service_external"
            ),
        ]


class LoginAttempt(models.Model):
    key = models.CharField(max_length=64, unique=True)
    failures = models.PositiveIntegerField(default=0)
    expires_at = models.DateTimeField(db_index=True)


class MinioLoginChallenge(models.Model):
    state_hash = models.CharField(max_length=64, unique=True)
    browser_hash = models.CharField(max_length=64, db_index=True)
    original_state = models.TextField()
    expires_at = models.DateTimeField(db_index=True)
    consumed_at = models.DateTimeField(null=True, blank=True)


class ProvisionRun(models.Model):
    fingerprint = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_ids = models.JSONField(default=dict)
