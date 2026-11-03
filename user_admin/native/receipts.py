"""Local confirmed block evidence, scoped to approved exclusive authority.

This is not a native CAS and must not be used for unmanaged/adopted accounts or
outside accepted exclusive-writer protocols. Manual handoff invalidates epochs.
"""

from ..engine import _binding_allowed
from ..models import Operation, Target


def _confirmed_target(command):
    if command.service not in Target.Service.values:
        return None
    target = Target.objects.filter(
        pk=command.target_id,
        user_id=command.user_id,
        service=command.service,
        instance=command.instance,
        native_id=command.native_id,
        authority_epoch=command.authority_epoch,
        management_paused=False,
    ).first()
    return target if target is not None and _binding_allowed(target) else None


def confirmed_ownership(command) -> bool:
    return _confirmed_target(command) is not None


def confirmed_block_receipt(command) -> str:
    target = _confirmed_target(command)
    if target is None or target.block_authority_epoch != command.authority_epoch:
        return ""
    return target.block_receipt


def confirmed_policy(command, operation_id, generation, blocked) -> bool:
    target = _confirmed_target(command)
    if target is None or command.service != "minio":
        return False
    # Ownership history survives a manual epoch; the right to UNBAN does not.
    # The adapter must also verify the entire fixed scoped policy document.
    return Operation.objects.filter(
        pk=operation_id,
        target=target,
        generation=generation,
        observed="blocked" if blocked else "enabled",
        action__in=[
            Operation.Action.BIND,
            Operation.Action.ENABLE,
            Operation.Action.BLOCK,
        ],
    ).exists()


def policy_history(command) -> bool:
    target = _confirmed_target(command)
    return bool(
        target
        and command.service == "minio"
        and Operation.objects.filter(
            target=target,
            observed__in=["enabled", "blocked"],
            action__in=[
                Operation.Action.BIND,
                Operation.Action.ENABLE,
                Operation.Action.BLOCK,
            ],
        ).exists()
    )
