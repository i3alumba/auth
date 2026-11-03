"""Validate worker binding evidence and publish only a NEW owned identity.

Call publication under AdministrationLock in the final native transaction.
No network, adoption, membership changes, role promotion or identity updates.
"""

import re

from django.db import IntegrityError, transaction

from sso.models import Service, ServiceIdentity
from .adapters import Binding, Command
from .native.minio_policy import resource_name


class BindingConflict(Exception):
    def __init__(self):
        super().__init__("binding_conflict")


def valid_binding(command: Command, binding: Binding) -> bool:
    if type(binding) is not Binding or any(
        type(value) is not str or len(value) > 255
        for value in (
            binding.external_id,
            binding.external_username,
            binding.minio_policy,
        )
    ):
        return False
    if not binding.external_id or not binding.external_username:
        return False
    if command.service == "minio":
        name = resource_name(command.target_id)
        return (
            command.native_id == name
            and binding.external_id == str(command.user_id)
            and binding.external_username == name
            and binding.minio_policy == name
        )
    if binding.minio_policy or binding.external_id != command.native_id:
        return False
    if command.service == "gitlab":
        return bool(
            re.fullmatch(r"[1-9][0-9]*", command.native_id)
            and re.fullmatch(
                r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}", binding.external_username
            )
        )
    if command.service == "matrix":
        localpart = "ua_" + command.target_id.hex
        return bool(
            binding.external_username == localpart
            and re.fullmatch(
                r"@" + localpart + r":[A-Za-z0-9.-]+(?::[0-9]+)?", command.native_id
            )
        )
    return False


def publish_binding(command, target, binding):
    if not valid_binding(command, binding):
        raise BindingConflict()
    service = Service.objects.filter(slug=command.service).first()
    if not service:
        raise BindingConflict()
    fields = {
        "user_id": command.user_id,
        "service": service,
        "external_id": binding.external_id,
        "external_username": binding.external_username,
        "minio_policy": binding.minio_policy,
        "jenkins_admin": False,
    }
    if target.identity_id:
        existing = ServiceIdentity.objects.filter(pk=target.identity_id).first()
        if existing and all(getattr(existing, k) == v for k, v in fields.items()):
            return
        raise BindingConflict()
    # Even an identical existing identity is NOT silently adopted. Capture a
    # uniqueness race inside a savepoint so native creation evidence survives.
    if ServiceIdentity.objects.filter(
        user_id=command.user_id, service=service
    ).exists():
        raise BindingConflict()
    try:
        with transaction.atomic():
            identity = ServiceIdentity.objects.create(**fields)
    except IntegrityError:
        raise BindingConflict() from None
    target.identity = identity
    target.save(update_fields=["identity"])
