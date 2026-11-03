"""Additive native-lifecycle bookkeeping. No provisioning at migration/startup."""

import uuid

from django.conf import settings
from django.db import models


class AdministrationLock(models.Model):
    """Singleton serialization point, seeded by the schema migration."""

    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)


class UserControl(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    version = models.PositiveBigIntegerField(default=0)
    auth_epoch = models.PositiveBigIntegerField(default=0)
    api_version = models.PositiveBigIntegerField(default=0)
    # Empty means untouched legacy entitlements, not an implicit mass migration.
    service_preferences = models.JSONField(default=dict)
    # Set only by the transactional create-user flow, never backfilled.
    creation_receipt = models.UUIDField(null=True, editable=False)


class UserChange(models.Model):
    id = models.UUIDField(primary_key=True, editable=False)
    actor_id = models.PositiveBigIntegerField()
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    action = models.CharField(max_length=16)
    fingerprint = models.CharField(max_length=64)
    changed_fields = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)


class Target(models.Model):
    class Service(models.TextChoices):
        GITLAB = "gitlab"
        MATRIX = "matrix"
        MINIO = "minio"

    class Desired(models.TextChoices):
        ENABLED = "enabled"
        BLOCKED = "blocked"

    class Ownership(models.TextChoices):
        UNMANAGED = "unmanaged"
        CREATED = "created"
        ADOPTED = "adopted"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    service = models.CharField(max_length=16, choices=Service.choices)
    instance = models.CharField(max_length=100)
    native_id = models.CharField(max_length=255, blank=True)
    ownership = models.CharField(
        max_length=16, choices=Ownership.choices, default=Ownership.UNMANAGED
    )
    generation = models.PositiveBigIntegerField(default=0)
    desired = models.CharField(max_length=16, choices=Desired.choices)
    observed = models.CharField(max_length=16, default="unknown")
    # Receipt of our own block, never inferred from a native 'disabled' boolean.
    block_receipt = models.CharField(max_length=100, blank=True)
    block_authority_epoch = models.PositiveBigIntegerField(default=0)
    authority_epoch = models.PositiveBigIntegerField(default=0)
    management_paused = models.BooleanField(default=False)
    pause_actor_id = models.PositiveBigIntegerField(null=True, editable=False)
    creation_operation = models.ForeignKey(
        "Operation",
        null=True,
        on_delete=models.PROTECT,
        related_name="created_targets",
        editable=False,
    )
    identity = models.OneToOneField(
        "sso.ServiceIdentity",
        null=True,
        on_delete=models.PROTECT,
        related_name="managed_target",
        editable=False,
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "service"], name="ua_user_service")
        ]


class Operation(models.Model):
    class Action(models.TextChoices):
        CREATE = "create"
        BIND = "bind"
        ENABLE = "enable"
        BLOCK = "block"

    class Status(models.TextChoices):
        PENDING = "pending"
        RUNNING = "running"
        SUCCEEDED = "succeeded"
        PARTIAL = "partial"
        FAILED = "failed"
        UNKNOWN = "outcome_unknown"
        UNSUPPORTED = "unsupported"
        SUPERSEDED = "superseded"
        NOT_REQUIRED = "not_required"
        HELD = "held"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    idempotency_key = models.UUIDField(unique=True)
    target = models.ForeignKey(Target, on_delete=models.PROTECT)
    actor_id = models.PositiveBigIntegerField()
    base_version = models.PositiveBigIntegerField()
    generation = models.PositiveBigIntegerField()
    action = models.CharField(max_length=16, choices=Action.choices)
    status = models.CharField(
        max_length=24, choices=Status.choices, default=Status.PENDING
    )
    execution_token = models.UUIDField(null=True, editable=False)
    authority_epoch = models.PositiveBigIntegerField(null=True, editable=False)
    error_code = models.CharField(max_length=40, blank=True)
    evidence = models.JSONField(default=dict)
    # Confirmed native effect, independent of superseded/partial publication.
    observed = models.CharField(max_length=16, blank=True, default="", editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["target", "generation", "action"],
                name="ua_target_generation_action",
            )
        ]


class ManagementEvent(models.Model):
    """Idempotent manual-handoff audit; never contains native bodies/secrets."""

    id = models.UUIDField(primary_key=True, editable=False)
    target = models.ForeignKey(Target, on_delete=models.PROTECT)
    actor_id = models.PositiveBigIntegerField()
    paused = models.BooleanField()
    before_epoch = models.PositiveBigIntegerField()
    after_epoch = models.PositiveBigIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)


class AuditEvent(models.Model):
    # Stable IDs, not credentials or copies of mutable private user profiles.
    actor_id = models.PositiveBigIntegerField()
    user_id = models.PositiveBigIntegerField()
    operation = models.ForeignKey(Operation, on_delete=models.PROTECT)
    event = models.CharField(max_length=24)
    created_at = models.DateTimeField(auto_now_add=True)
