"""Durable per-target pause/handoff. No native IO, lease expiry or forced resume."""

from uuid import UUID

from django.contrib.auth import get_user_model
from django.db import transaction

from sso.models import ServiceIdentity
from ..authentication import credential_lock
from ..engine import _binding_allowed, _grant_allowed, schedule
from ..models import ManagementEvent, Operation, Target, UserControl
from ..service import ChangeError, _actor


def can_manage(target):
    if target.service not in Target.Service.values:
        return False
    if _binding_allowed(target):
        return True
    return bool(
        not target.native_id
        and target.ownership == Target.Ownership.UNMANAGED
        and UserControl.objects.filter(
            user_id=target.user_id, creation_receipt__isnull=False
        ).exists()
        and not ServiceIdentity.objects.filter(
            user_id=target.user_id, service__slug=target.service
        ).exists()
    )


def management_state(target):
    managed = can_manage(target)
    reserved = Operation.objects.filter(
        target=target, status__in=[Operation.Status.RUNNING, Operation.Status.UNKNOWN]
    ).exists()
    return {
        "can_manage": managed,
        "paused": target.management_paused,
        "authority_epoch": target.authority_epoch,
        "pause_actor_id": target.pause_actor_id,
        # Accepted adapters must retain reservations until all possible native
        # writes have a known outcome. Process death/idle time never prove this.
        "safe_for_manual_changes": bool(
            managed and target.management_paused and not reserved
        ),
    }


def set_management(*, proof, key, target_id, expected_epoch, paused):
    if (
        type(key) is not UUID
        or type(target_id) is not UUID
        or type(expected_epoch) is not int
        or not 0 <= expected_epoch < 2**63
        or type(paused) is not bool
    ):
        raise ChangeError("invalid_native_control")
    with transaction.atomic():
        credential_lock()
        actor = _actor(proof)
        previous = ManagementEvent.objects.filter(pk=key).first()
        if previous:
            if (
                previous.actor_id != actor.pk
                or previous.target_id != target_id
                or previous.paused != paused
                or previous.before_epoch != expected_epoch
            ):
                raise ChangeError("idempotency_conflict", 409)
            return management_state(previous.target), True
        target = Target.objects.select_for_update().filter(pk=target_id).first()
        if target is None:
            raise ChangeError("native_target_not_found", 404)
        if target.service not in Target.Service.values:
            raise ChangeError("invalid_services")
        if not can_manage(target):
            raise ChangeError("ownership_required", 409)
        if target.authority_epoch != expected_epoch:
            raise ChangeError("stale_authority_epoch", 412)
        changed = target.management_paused != paused
        if changed and not paused:
            if target.pause_actor_id != actor.pk:
                raise ChangeError("pause_owner_required", 403)
            if not management_state(target)["safe_for_manual_changes"]:
                raise ChangeError("native_target_reserved", 409)
        if changed:
            target.authority_epoch += 1
            target.management_paused = paused
            target.pause_actor_id = actor.pk if paused else None
            target.save(
                update_fields=["authority_epoch", "management_paused", "pause_actor_id"]
            )
            if not paused:
                _resume_intent(actor, target)
        ManagementEvent.objects.create(
            id=key,
            target=target,
            actor_id=actor.pk,
            paused=paused,
            before_epoch=expected_epoch,
            after_epoch=target.authority_epoch,
        )
        return management_state(target), False


def _resume_intent(actor, target):
    # Resuming manual authority is an explicit NEW intent, unlike automatic
    # CREATE->BIND continuation. Every non-create action will inspect ownership
    # again; old block receipts cannot authorize an unban in the new epoch.
    user = get_user_model().objects.get(pk=target.user_id)
    control = UserControl.objects.get(user=user)
    blocked = target.desired == Target.Desired.BLOCKED or not _grant_allowed(
        user, target.service
    )
    if blocked:
        pending_create = Operation.objects.filter(
            target=target,
            action=Operation.Action.CREATE,
            status=Operation.Status.PENDING,
        ).exists()
        if not target.native_id and not pending_create:
            return
        action = Operation.Action.BLOCK
    else:
        action = (
            Operation.Action.CREATE
            if not target.native_id
            else (
                Operation.Action.BIND
                if target.identity_id is None
                else Operation.Action.ENABLE
            )
        )
    from uuid import uuid4

    schedule(
        actor_id=actor.pk,
        user_id=target.user_id,
        service=target.service,
        instance=target.instance,
        action=action,
        idempotency_key=uuid4(),
        expected_version=control.version,
    )
