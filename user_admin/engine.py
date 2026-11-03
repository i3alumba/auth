"""Offline-first outbox foundation; never called from web startup/migrations.

Native execution is disabled by default. No production adapter is registered
here. RUNNING/UNKNOWN reservations never expire: a dead client does not prove
that its remote request stopped. Resolving them needs a provider-specific,
reviewed recovery protocol, not an automatic retry or lease takeover.
"""

from dataclasses import asdict
import re
from uuid import UUID, uuid4, uuid5

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from sso.models import Service, ServiceIdentity

from .adapters import Command, NativeAdapter, Observation
from .bindings import BindingConflict, publish_binding, valid_binding
from .models import AdministrationLock, AuditEvent, Operation, Target, UserControl


class ControlError(Exception):
    """Only this bounded code may cross API/log boundaries, never native bodies."""

    CODES = frozenset(
        {
            "administrator_required",
            "invalid_request",
            "idempotency_conflict",
            "stale_version",
            "instance_conflict",
            "creation_not_authorized",
            "grant_revoked",
            "ownership_required",
            "execution_disabled",
            "stale_generation",
            "unsupported_action",
            "instance_unconfigured",
            "ownership_unverified",
            "foreign_block",
            "outcome_unknown",
            "execution_ownership_lost",
            "inspection_failed",
            "binding_required",
            "binding_conflict",
            "creation_provenance_required",
            "management_paused",
            "authority_changed",
        }
    )

    def __init__(self, code: str):
        self.code = (
            code if isinstance(code, str) and code in self.CODES else "outcome_unknown"
        )
        super().__init__(self.code)


def _serialize():
    AdministrationLock.objects.select_for_update().get(pk=1)


def _administrator(user_id: int):
    actor = get_user_model().objects.select_for_update().get(pk=user_id)
    if not actor.is_active or not actor.is_superuser:
        raise ControlError("administrator_required")
    return actor


def schedule(
    *,
    actor_id: int,
    user_id: int,
    service: str,
    instance: str,
    action: str,
    idempotency_key: UUID,
    expected_version: int,
) -> Operation:
    """Persist an authorized native goal/outbox/audit atomically.

    Intended to run INSIDE the future central user-mutation transaction. This
    function does not itself change User, Groups, ServiceIdentity or passwords.
    Existing native-account adoption is deliberately not implemented by guessing
    username/email or merely trusting the presence of a ServiceIdentity.
    """
    if (
        service not in Target.Service.values
        or action not in Operation.Action.values
        or not isinstance(idempotency_key, UUID)
        or type(expected_version) is not int
        or expected_version < 0
        or not isinstance(instance, str)
        or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", instance)
    ):
        raise ControlError("invalid_request")
    with transaction.atomic():
        _serialize()
        _administrator(actor_id)
        previous = Operation.objects.filter(idempotency_key=idempotency_key).first()
        if previous:
            target = previous.target
            if (
                previous.actor_id != actor_id
                or target.user_id != user_id
                or target.service != service
                or target.instance != instance
                or previous.action != action
                or previous.base_version != expected_version
            ):
                raise ControlError("idempotency_conflict")
            return previous
        user = get_user_model().objects.select_for_update().get(pk=user_id)
        control, _ = UserControl.objects.get_or_create(user=user)
        if control.version != expected_version:
            raise ControlError("stale_version")
        target, _ = Target.objects.get_or_create(
            user=user,
            service=service,
            defaults={"instance": instance, "desired": Target.Desired.BLOCKED},
        )
        if target.instance != instance:
            raise ControlError("instance_conflict")
        cancel_pending_creation = False
        if action == Operation.Action.CREATE:
            if not _creation_allowed(target, control):
                raise ControlError("creation_not_authorized")
        elif not target.native_id or target.ownership == Target.Ownership.UNMANAGED:
            creates = Operation.objects.filter(
                target=target, action=Operation.Action.CREATE
            )
            in_flight_create = creates.filter(
                status__in=[Operation.Status.RUNNING, Operation.Status.UNKNOWN]
            ).exists()
            pending_creates = list(creates.filter(status=Operation.Status.PENDING))
            cancel_pending_creation = (
                bool(pending_creates)
                and not Operation.objects.filter(
                    target=target, execution_token__isnull=False
                ).exists()
            )
            if (
                action != Operation.Action.BLOCK
                or control.creation_receipt is None
                or not (in_flight_create or cancel_pending_creation)
            ):
                raise ControlError("ownership_required")
            if cancel_pending_creation:
                for pending in pending_creates:
                    _finish(
                        pending, Operation.Status.SUPERSEDED, "cancelled_before_create"
                    )
                target.observed = "not_created"
                target.save(update_fields=["observed"])
        if action == Operation.Action.BIND and not _binding_allowed(target):
            raise ControlError("creation_provenance_required")
        if action != Operation.Action.BLOCK and not _grant_allowed(user, service):
            raise ControlError("grant_revoked")
        target.generation += 1
        target.desired = (
            Target.Desired.BLOCKED
            if action == Operation.Action.BLOCK
            else Target.Desired.ENABLED
        )
        target.save(update_fields=["generation", "desired"])
        operation = Operation.objects.create(
            idempotency_key=idempotency_key,
            target=target,
            actor_id=actor_id,
            base_version=expected_version,
            generation=target.generation,
            action=action,
        )
        control.version += 1
        control.save(update_fields=["version"])
        AuditEvent.objects.create(
            actor_id=actor_id, user_id=user_id, operation=operation, event="requested"
        )
        if cancel_pending_creation:
            _finish(
                operation, Operation.Status.NOT_REQUIRED, "no_native_account_created"
            )
        return operation


def _creation_allowed(target: Target, control: UserControl | None) -> bool:
    return bool(
        control is not None
        and control.creation_receipt is not None
        and not target.native_id
        and target.ownership == Target.Ownership.UNMANAGED
        and not ServiceIdentity.objects.filter(
            user_id=target.user_id, service__slug=target.service
        ).exists()
    )


def _binding_allowed(target: Target) -> bool:
    return bool(
        target.ownership == Target.Ownership.CREATED
        and target.native_id
        and target.creation_operation_id
        and Operation.objects.filter(
            pk=target.creation_operation_id,
            target=target,
            action=Operation.Action.CREATE,
        ).exists()
    )


def _queue_phase(operation: Operation, target: Target, action: str):
    # Continuation is a phase of THIS intent, not a new user goal/version.
    Operation.objects.get_or_create(
        target=target,
        generation=operation.generation,
        action=action,
        defaults={
            "idempotency_key": uuid5(operation.pk, action),
            "actor_id": operation.actor_id,
            "base_version": operation.base_version,
        },
    )


def _grant_allowed(user, service: str) -> bool:
    return bool(
        user.is_active
        and (
            user.is_superuser
            or Service.objects.filter(
                slug=service, group__in=user.groups.all()
            ).exists()
        )
    )


def _grant_current(operation: Operation, target: Target) -> bool:
    actor = (
        get_user_model()
        .objects.filter(pk=operation.actor_id, is_active=True, is_superuser=True)
        .exists()
    )
    user = get_user_model().objects.get(pk=target.user_id)
    return (
        target.desired == Target.Desired.ENABLED
        and actor
        and _grant_allowed(user, target.service)
    )


def _command(operation: Operation, target: Target) -> Command:
    return Command(
        target_id=target.pk,
        operation_id=operation.pk,
        user_id=target.user_id,
        service=target.service,
        instance=target.instance,
        generation=operation.generation,
        action=operation.action,
        native_id=target.native_id,
        authority_epoch=operation.authority_epoch or 0,
    )


def _verified(command: Command, observation: Observation, *, applied=False) -> bool:
    return (
        type(observation) is Observation
        and type(observation.owner) is UUID
        and all(
            type(value) is str
            for value in (
                observation.native_id,
                observation.subject,
                observation.instance,
                observation.state,
                observation.block_receipt,
                observation.new_login,
                observation.existing_sessions,
                observation.api_credentials,
            )
        )
        and observation.owner == command.target_id
        and observation.subject == str(command.user_id)
        and observation.instance == command.instance
        and isinstance(observation.native_id, str)
        and 0 < len(observation.native_id) <= 255
        and (not command.native_id or observation.native_id == command.native_id)
        and observation.state in {"enabled", "blocked", "unbound"}
        and (observation.binding is None or valid_binding(command, observation.binding))
        and (
            not applied
            or command.action != Operation.Action.BIND
            or (
                observation.binding is not None
                and observation.state in {"enabled", "blocked"}
            )
        )
        and isinstance(observation.block_receipt, str)
        and len(observation.block_receipt) <= 100
        and all(
            value in {"confirmed", "unknown", "unsupported"}
            for value in (
                observation.new_login,
                observation.existing_sessions,
                observation.api_credentials,
            )
        )
    )


def provisioning_refusal(operation: Operation, target: Target) -> str:
    """Only the original CREATE's deterministic continuations can grant access.

    Called again under the engine lock, never an adapter capability or an
    operator-controlled bypass. A newer intent cannot reuse old CREATE evidence.
    """
    if operation.action == Operation.Action.BLOCK:
        return "revocation_deferred"
    if operation.action == Operation.Action.CREATE:
        return ""
    creation = Operation.objects.filter(
        pk=target.creation_operation_id,
        target=target,
        generation=operation.generation,
        action=Operation.Action.CREATE,
        status=Operation.Status.SUCCEEDED,
        observed="unbound",
    ).first()
    if creation is None or target.ownership != Target.Ownership.CREATED:
        return "reenable_not_supported"
    if operation.action == Operation.Action.BIND:
        return (
            ""
            if operation.idempotency_key == uuid5(creation.pk, "bind")
            else "reenable_not_supported"
        )
    if operation.action == Operation.Action.ENABLE:
        binding = Operation.objects.filter(
            target=target,
            generation=operation.generation,
            action=Operation.Action.BIND,
            status=Operation.Status.PARTIAL,
            error_code="native_enable_pending",
            observed="blocked",
            idempotency_key=uuid5(creation.pk, "bind"),
        ).first()
        if (
            binding is not None
            and target.identity_id is not None
            and operation.idempotency_key == uuid5(binding.pk, "enable")
        ):
            return ""
    return "reenable_not_supported"


def execute(
    operation_id: UUID, adapter: NativeAdapter | None, *, execution_scope="lifecycle"
) -> str:
    """Run one explicitly selected operation, once; no remote IO under DB locks."""
    if execution_scope not in {"lifecycle", "provision_only"}:
        raise ControlError("invalid_execution_scope")
    if not getattr(settings, "USER_ADMIN_NATIVE_EXECUTION_ENABLED", False):
        raise ControlError("execution_disabled")
    with transaction.atomic():
        _serialize()
        operation = Operation.objects.select_for_update().get(pk=operation_id)
        target = Target.objects.select_for_update().get(pk=operation.target_id)
        if operation.status != Operation.Status.PENDING:
            return operation.status
        # Enforce the scope even for imported/legacy rows; Django choices alone
        # are not a database-level constraint. Never reach an excluded adapter.
        if target.service not in Target.Service.values:
            return _finish(operation, Operation.Status.UNSUPPORTED, "service_excluded")
        if target.management_paused:
            return "management_paused"
        if Operation.objects.filter(
            target=target,
            status__in=[Operation.Status.RUNNING, Operation.Status.UNKNOWN],
        ).exists():
            return "target_reserved"
        if operation.generation != target.generation:
            return _finish(operation, Operation.Status.SUPERSEDED, "stale_generation")
        if execution_scope == "provision_only":
            refusal = provisioning_refusal(operation, target)
            if refusal:
                return _finish(operation, Operation.Status.UNSUPPORTED, refusal)
        if operation.action != Operation.Action.BLOCK and not _grant_current(
            operation, target
        ):
            return _finish(operation, Operation.Status.FAILED, "grant_revoked")
        if operation.action == Operation.Action.CREATE and not _creation_allowed(
            target, UserControl.objects.filter(user_id=target.user_id).first()
        ):
            return _finish(
                operation, Operation.Status.FAILED, "creation_not_authorized"
            )
        if operation.action != Operation.Action.CREATE and (
            not target.native_id or target.ownership == Target.Ownership.UNMANAGED
        ):
            return _finish(operation, Operation.Status.FAILED, "ownership_required")
        caps = adapter.capabilities
        if caps.service != target.service or caps.instance != target.instance:
            return _finish(
                operation, Operation.Status.UNSUPPORTED, "instance_unconfigured"
            )
        if operation.action not in caps.actions or (
            operation.action == Operation.Action.CREATE and not caps.create_only
        ):
            return _finish(
                operation, Operation.Status.UNSUPPORTED, "unsupported_action"
            )
        if operation.action == Operation.Action.BIND and not _binding_allowed(target):
            return _finish(
                operation, Operation.Status.FAILED, "creation_provenance_required"
            )
        if (
            operation.action == Operation.Action.ENABLE
            and Operation.Action.BIND in caps.actions
            and target.identity_id is None
        ):
            return _finish(operation, Operation.Status.FAILED, "binding_required")
        operation.status = Operation.Status.RUNNING
        operation.execution_token = uuid4()
        operation.authority_epoch = target.authority_epoch
        operation.save(update_fields=["status", "execution_token", "authority_epoch"])
        command = _command(operation, target)
        token = operation.execution_token
        expected_receipt = (
            target.block_receipt
            if target.block_authority_epoch == command.authority_epoch
            else ""
        )

    # Any unexpected adapter exception is ambiguous and is NOT saved verbatim.
    observation = None
    error = ""
    apply_started = False
    try:
        if command.action != Operation.Action.CREATE:
            inspected = adapter.inspect(command)
            if not _verified(command, inspected):
                raise ControlError("ownership_unverified")
            if (
                command.action
                in {
                    Operation.Action.ENABLE,
                    Operation.Action.BLOCK,
                    Operation.Action.BIND,
                }
                and inspected.state == "blocked"
                and (
                    not expected_receipt or inspected.block_receipt != expected_receipt
                )
            ):
                raise ControlError("foreign_block")
        with transaction.atomic():
            _serialize()
            current = Target.objects.get(pk=command.target_id)
            if current.generation != command.generation:
                raise ControlError("stale_generation")
            if current.management_paused:
                raise ControlError("management_paused")
            if current.authority_epoch != command.authority_epoch:
                raise ControlError("authority_changed")
            if command.action == Operation.Action.CREATE and not _creation_allowed(
                current, UserControl.objects.filter(user_id=current.user_id).first()
            ):
                raise ControlError("creation_not_authorized")
            if command.action != Operation.Action.BLOCK and not _grant_current(
                operation, current
            ):
                raise ControlError("grant_revoked")
        apply_started = True
        candidate = adapter.apply(command)
        if _verified(command, candidate, applied=True):
            observation = candidate
        else:
            error = "outcome_unknown"
    except ControlError as exc:
        observation = None
        error = (
            "outcome_unknown"
            if apply_started
            else "inspection_failed" if exc.code == "outcome_unknown" else exc.code
        )
    except Exception:
        observation = None
        # Handled read-only failures are not uncertain writes. A crashed RUNNING
        # process is still reserved: this does not introduce lease takeover.
        error = "outcome_unknown" if apply_started else "inspection_failed"

    with transaction.atomic():
        _serialize()
        operation = Operation.objects.select_for_update().get(pk=operation_id)
        target = Target.objects.select_for_update().get(pk=command.target_id)
        if (
            operation.status != Operation.Status.RUNNING
            or operation.execution_token != token
        ):
            raise ControlError("execution_ownership_lost")
        if observation is None:
            if not apply_started and error in {
                "management_paused",
                "authority_changed",
            }:
                # Inspection completed, but no mutation was dispatched. This is
                # not UNKNOWN and may be claimed after an explicit safe resume.
                operation.status = Operation.Status.PENDING
                operation.execution_token = None
                operation.authority_epoch = None
                operation.error_code = error
                operation.save(
                    update_fields=[
                        "status",
                        "execution_token",
                        "authority_epoch",
                        "error_code",
                    ]
                )
                AuditEvent.objects.create(
                    actor_id=operation.actor_id,
                    user_id=target.user_id,
                    operation=operation,
                    event="deferred",
                )
                return operation.status
            status = (
                Operation.Status.UNKNOWN
                if error == "outcome_unknown"
                else (
                    Operation.Status.SUPERSEDED
                    if error == "stale_generation"
                    else Operation.Status.FAILED
                )
            )
            return _finish(operation, status, error)
        # Retain a verified created ID even if revocation arrived in flight: the
        # next block must target THIS account, never create a replacement.
        target.native_id = observation.native_id
        if command.action == Operation.Action.CREATE:
            target.ownership = Target.Ownership.CREATED
            target.creation_operation = operation
        target.observed = observation.state
        staged = Operation.Action.BIND in caps.actions
        if (
            staged
            and target.identity_id is None
            and command.action != Operation.Action.BLOCK
        ):
            target.observed = "unbound"
        if command.action == Operation.Action.BLOCK and observation.state == "blocked":
            target.block_receipt = observation.block_receipt
            target.block_authority_epoch = command.authority_epoch
        target.save(
            update_fields=[
                "native_id",
                "ownership",
                "observed",
                "block_receipt",
                "block_authority_epoch",
                "creation_operation",
            ]
        )
        evidence = {
            key: value
            for key, value in asdict(observation).items()
            if key in {"new_login", "existing_sessions", "api_credentials"}
        }
        operation.evidence = evidence
        operation.observed = observation.state
        operation.save(update_fields=["evidence", "observed"])
        if operation.generation != target.generation:
            return _finish(operation, Operation.Status.SUPERSEDED, "stale_generation")
        if (
            target.management_paused
            or target.authority_epoch != command.authority_epoch
        ):
            return _finish(operation, Operation.Status.PARTIAL, "authority_changed")
        if command.action != Operation.Action.BLOCK and not _grant_current(
            operation, target
        ):
            return _finish(
                operation, Operation.Status.PARTIAL, "grant_revoked_in_flight"
            )
        if command.action == Operation.Action.BIND:
            try:
                publish_binding(command, target, observation.binding)
            except BindingConflict:
                return _finish(operation, Operation.Status.FAILED, "binding_conflict")
            target.observed = observation.state
            target.save(update_fields=["observed"])
        if staged and command.action == Operation.Action.CREATE:
            status = _finish(operation, Operation.Status.SUCCEEDED, "")
            if target.identity_id is None and _binding_allowed(target):
                _queue_phase(operation, target, Operation.Action.BIND)
            return status
        if command.action == Operation.Action.BIND and observation.state == "blocked":
            status = _finish(
                operation, Operation.Status.PARTIAL, "native_enable_pending"
            )
            _queue_phase(operation, target, Operation.Action.ENABLE)
            return status
        desired = "blocked" if command.action == Operation.Action.BLOCK else "enabled"
        complete = observation.state == desired and all(
            value == "confirmed" for value in evidence.values()
        )
        return _finish(
            operation,
            Operation.Status.SUCCEEDED if complete else Operation.Status.PARTIAL,
            "" if complete else "capability_unconfirmed",
        )


def _finish(operation: Operation, status: str, code: str) -> str:
    operation.status = status
    operation.error_code = code
    operation.finished_at = timezone.now()
    operation.save(update_fields=["status", "error_code", "finished_at"])
    AuditEvent.objects.create(
        actor_id=operation.actor_id,
        user_id=operation.target.user_id,
        operation=operation,
        event=status,
    )
    return status
