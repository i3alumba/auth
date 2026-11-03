"""Queue selection and factories only; the engine owns all claims and writes."""

import base64
import ssl
from dataclasses import dataclass

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db.models import Exists, OuterRef, Q

from .engine import execute
from .models import Operation
from .native.gitlab import GitlabAdapter, Profile
from .native.http import NativeHTTP
from .native.minio import MinioAdapter
from .native.receipts import (
    confirmed_block_receipt,
    confirmed_ownership,
    confirmed_policy,
    policy_history,
)
from .native.synapse import SynapseAdapter
from .worker_config import WorkerError
from .worker_profiles import PROFILES


@dataclass(frozen=True)
class Cursor:
    created_at: object
    operation_id: object


def candidates(config, *, limit, cursor=None, operation_id=None):
    pairs = Q(pk__in=[])
    for instance in config.instances:
        pairs |= Q(target__service=instance.service, target__instance=instance.instance)
    reserved = Operation.objects.filter(
        target_id=OuterRef("target_id"),
        status__in=[Operation.Status.RUNNING, Operation.Status.UNKNOWN],
    )
    query = (
        Operation.objects.filter(
            pairs, status=Operation.Status.PENDING, target__management_paused=False
        )
        .annotate(reserved=Exists(reserved))
        .filter(reserved=False)
    )
    if operation_id is not None:
        query = query.filter(pk=operation_id)
    elif cursor is not None:
        query = query.filter(
            Q(created_at__gt=cursor.created_at)
            | Q(created_at=cursor.created_at, id__gt=cursor.operation_id)
        )
    return list(
        query.select_related("target", "target__user")
        .defer("target__user__password")
        .order_by("created_at", "id")[:limit]
    )


def gitlab_profile(operation):
    # Never consume the related-user object cached during batch selection.
    # Fresh local validation is not a cross-system uniqueness transaction.
    try:
        user = (
            get_user_model()
            .objects.only("id", "username", "email", "first_name", "last_name")
            .get(pk=operation.target.user_id)
        )
    except get_user_model().DoesNotExist:
        raise WorkerError("invalid_gitlab_profile") from None
    try:
        validate_email(user.email)
    except ValidationError:
        raise WorkerError("gitlab_email_required") from None
    if not user.email or len(user.email) > 254:
        raise WorkerError("gitlab_email_required")
    if (
        get_user_model()
        .objects.filter(email__iexact=user.email)
        .exclude(pk=user.pk)
        .exists()
    ):
        raise WorkerError("gitlab_email_conflict")
    username = "ua_" + base64.b32encode(operation.target_id.bytes).decode(
        "ascii"
    ).lower().rstrip("=")
    name = (user.get_full_name().strip() or user.username)[:255]
    if not name or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise WorkerError("invalid_gitlab_profile")
    return Profile(username, user.email, name)


def make_adapter(instance, secrets, operation):
    if instance.service not in {"gitlab", "matrix", "minio"}:
        raise WorkerError("service_excluded")
    if instance.transport == "cluster_http":
        if instance.instance != "primary" or instance.ca_file or "ca_pem" in secrets:
            raise WorkerError("invalid_worker_transport")
        client = NativeHTTP(instance.origin, cluster_http_service=instance.service)
    elif instance.transport == "https":
        context = ssl.create_default_context()
        if "ca_pem" in secrets:
            try:
                context.load_verify_locations(cadata=secrets["ca_pem"])
            except (ValueError, ssl.SSLError):
                raise WorkerError("invalid_worker_ca") from None
        client = NativeHTTP(instance.origin, context=context)
    else:
        raise WorkerError("invalid_worker_transport")
    common = {
        "client": client,
        "instance": instance.instance,
        "receipts": confirmed_block_receipt,
    }
    if instance.service == "gitlab":
        if operation.action == Operation.Action.CREATE:
            gitlab_profile(operation)  # Fail before claiming when already invalid.

        def profiles(command):
            if (
                command.target_id != operation.target_id
                or command.user_id != operation.target.user_id
            ):
                raise WorkerError("invalid_gitlab_profile")
            # Re-read immediately before adapter CREATE, not a factory snapshot.
            return gitlab_profile(operation)

        return GitlabAdapter(**common, token=secrets["token_file"], profiles=profiles)
    if instance.service == "matrix":
        return SynapseAdapter(
            **common,
            token=secrets["token_file"],
            registration_secret=secrets["registration_secret_file"],
            server_name=instance.server_name,
            ownership=confirmed_ownership,
        )
    if instance.service == "minio":
        # These are the versioned protocol's requirements, NOT observations.
        # Source profiles remain activation-blocked pending deployment proof.
        return MinioAdapter(
            **common,
            access_key=secrets["access_key_file"],
            secret_key=secrets["secret_key_file"],
            ownership=confirmed_ownership,
            policy_receipts=confirmed_policy,
            policy_history=policy_history,
            exclusive_authority=True,
            claim_policy_only=True,
            standalone_without_federation=True,
        )
    raise WorkerError("service_excluded")


def admission(config, profiles=PROFILES):
    """Scope restricts actions; it never clears independent acceptance gates."""
    if config.execution_scope not in {"provision_only", "lifecycle"}:
        raise WorkerError("invalid_worker_scope")
    if (
        settings.SETTINGS_MODULE != "auth.worker_settings"
        or getattr(settings, "USER_ADMIN_WORKER_ENABLED", False) is not True
        or getattr(settings, "USER_ADMIN_NATIVE_EXECUTION_ENABLED", False) is not True
    ):
        raise WorkerError("worker_execution_disabled")
    for instance in config.instances:
        profile = profiles.get(instance.acceptance_profile)
        if (
            profile is None
            or profile.service != instance.service
            or len(profile.proof_sha256) != 64
            or not profile.fixture_run
            or not profile.image.startswith("sha256:")
            or (
                profile.provisioning_blockers
                if config.execution_scope == "provision_only"
                else profile.blockers
            )
        ):
            raise WorkerError("profile_activation_blocked")


def run_pass(
    config,
    *,
    limit=20,
    cursor=None,
    operation_id=None,
    dry_run=True,
    snapshot=None,
    stopping=lambda: False,
    report=lambda event: None,
    factory=make_adapter,
    profiles=PROFILES,
):
    """One bounded pass. Invalid local profiles advance the keyset, not the DB."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise WorkerError("invalid_worker_limit")
    if config.execution_scope not in {"provision_only", "lifecycle"}:
        raise WorkerError("invalid_worker_scope")
    if not dry_run:
        admission(config, profiles)
    rows = candidates(config, limit=limit, cursor=cursor, operation_id=operation_id)
    instances = {(i.service, i.instance): i for i in config.instances}
    last = cursor
    incomplete = False
    processed = 0
    for operation in rows:
        if stopping():
            break
        last = Cursor(operation.created_at, operation.pk)
        instance = instances[(operation.target.service, operation.target.instance)]
        code = "preview_pending"
        if instance.service == "gitlab" and operation.action == Operation.Action.CREATE:
            try:
                gitlab_profile(operation)
            except WorkerError as error:
                code = error.code
        if dry_run or code != "preview_pending":
            report(
                {
                    "operation": str(operation.pk),
                    "service": instance.service,
                    "instance": instance.instance,
                    "execution_scope": config.execution_scope,
                    "status": (
                        "revocation_deferred"
                        if config.execution_scope == "provision_only"
                        and operation.action == Operation.Action.BLOCK
                        else code
                    ),
                }
            )
            processed += 1
            incomplete |= code != "preview_pending"
            continue
        # Deferred revocation is finalized by the engine without credentials or
        # an adapter. It remains terminal/truthful and cannot starve CREATE.
        adapter = None
        if not (
            config.execution_scope == "provision_only"
            and operation.action == Operation.Action.BLOCK
        ):
            adapter = factory(
                instance, snapshot[(instance.service, instance.instance)], operation
            )
        if stopping():
            break
        # No runtime transaction, claim, retry or evidence rewriting here.
        status = execute(operation.pk, adapter, execution_scope=config.execution_scope)
        if status not in set(Operation.Status.values) | {
            "management_paused",
            "target_reserved",
        }:
            raise WorkerError("invalid_engine_result")
        report(
            {
                "operation": str(operation.pk),
                "service": instance.service,
                "instance": instance.instance,
                "execution_scope": config.execution_scope,
                "status": status,
            }
        )
        incomplete |= status not in {
            Operation.Status.SUCCEEDED,
            Operation.Status.NOT_REQUIRED,
            Operation.Status.SUPERSEDED,
        }
        processed += 1
    # The next watch pass wraps only after reaching the end, preventing bad
    # profiles or held rows at the queue head from monopolizing every batch.
    return (last if rows else None), processed, incomplete
