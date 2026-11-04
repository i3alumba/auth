"""Central mutations: one transaction, no native IO and no Jenkins writes."""

import hashlib
import json
from uuid import UUID, uuid5

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils.crypto import constant_time_compare, salted_hmac
from oauth2_provider.models import (
    get_access_token_model,
    get_grant_model,
    get_refresh_token_model,
)

from sso.access import services_for
from sso.models import Service, ServiceIdentity

from .authentication import check_epoch, credential_lock
from .engine import ControlError, schedule
from .grants import GROUP_SERVICES, MANAGED, assigned, wanted
from .models import AuditEvent, Operation, Target, UserChange, UserControl
from .phases import latest_phase


class ChangeError(Exception):
    def __init__(self, code, status=400):
        self.code, self.status = code, status
        super().__init__(code)


def native_scheduling_enabled():
    return getattr(settings, "USER_ADMIN_NATIVE_SCHEDULING_ENABLED", False) is True


def hosting_ready():
    return getattr(settings, "USER_ADMIN_HOSTING_GRANTS_READY", False)


def editable_services():
    return tuple(slug for slug in MANAGED if slug != "hosting" or hosting_ready())


def etag(user):
    control = UserControl.objects.filter(user=user).first()
    state = {
        "id": user.pk,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "active": user.is_active,
        "admin": user.is_superuser,
        "staff": user.is_staff,
        "groups": list(user.groups.order_by("pk").values_list("pk", flat=True)),
        "permissions": list(
            user.user_permissions.order_by("pk").values_list("pk", flat=True)
        ),
        "version": control.api_version if control else 0,
        "preferences": control.service_preferences if control else {},
        "epoch": control.auth_epoch if control else 0,
    }
    encoded = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
    return '"' + hashlib.sha256(encoded).hexdigest() + '"'


def row(user):
    from .management import management_state

    control = UserControl.objects.filter(user=user).first()
    values = control.service_preferences if control else {}
    effective = services_for(user)
    cells = {}
    for slug in (*MANAGED, "jenkins"):
        readonly = slug == "jenkins" or (slug == "hosting" and not hosting_ready())
        legacy_hosting = (
            slug == "hosting" and not hosting_ready() and slug not in values
        )
        cells[slug] = {
            "assigned": (
                bool(user.is_staff) if legacy_hosting else assigned(user, slug, values)
            ),
            "granted": (
                bool(user.is_staff) if legacy_hosting else wanted(user, slug, values)
            ),
            "effective": effective[slug]["enabled"],
            "readonly": readonly,
        }
    native = {}
    for target in Target.objects.filter(user=user, service__in=Target.Service.values):
        operation = latest_phase(target)
        native[target.service] = {
            "desired": target.desired,
            "observed": target.observed,
            "status": operation.status if operation else "unmanaged",
            "phase": operation.action if operation else "",
            "management": management_state(target),
            "reason": operation.error_code if operation else "",
        }
    return {
        "id": user.pk,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "is_admin": bool(user.is_superuser),
        "is_active": bool(user.is_active),
        "version": control.api_version if control else 0,
        "etag": etag(user),
        "services": cells,
        "native": native,
    }


def validate_changes(data, create=False):
    if type(data) is not dict:
        raise ChangeError("invalid_body")
    allowed = {"email", "first_name", "last_name", "is_admin", "services"}
    if create:
        allowed |= {"username", "password"}
    if set(data) - allowed:
        raise ChangeError("unknown_fields")
    if create and not {"username", "password", "email"} <= data.keys():
        raise ChangeError("required_fields")
    for name, maximum in [
        ("username", 32),
        ("email", 254),
        ("first_name", 150),
        ("last_name", 150),
        ("password", 256),
    ]:
        if name in data and (type(data[name]) is not str or len(data[name]) > maximum):
            raise ChangeError("invalid_" + name)
    if "is_admin" in data and type(data["is_admin"]) is not bool:
        raise ChangeError("invalid_admin")
    if "services" in data:
        grants = data["services"]
        if type(grants) is not dict or set(grants) - set(MANAGED):
            raise ChangeError("invalid_services")
        if any(type(value) is not bool for value in grants.values()):
            raise ChangeError("invalid_services")
        if "hosting" in grants and not hosting_ready():
            raise ChangeError("hosting_consumer_pending", 409)
    return data


def _fingerprint(action, user_id, data, expected):
    safe = {key: value for key, value in data.items() if key != "password"}
    return salted_hmac(
        "user_admin.change",
        json.dumps(
            [action, user_id, expected, safe], sort_keys=True, separators=(",", ":")
        ),
        algorithm="sha256",
    ).hexdigest()


def _actor(proof):
    actor = check_epoch(proof)
    actor = get_user_model().objects.select_for_update().get(pk=actor.pk)
    if not actor.is_active or not actor.is_superuser:
        raise ChangeError("administrator_required", 403)
    return actor


def _revoke(user, control):
    control.auth_epoch += 1
    control.save(update_fields=["auth_epoch"])
    # These are Auth-issued OAuth credentials, never native vendor sessions,
    # Jenkins API tokens, machine/runner credentials or user passwords.
    get_refresh_token_model().objects.filter(user=user).delete()
    get_access_token_model().objects.filter(user=user).delete()
    get_grant_model().objects.filter(user=user).delete()


def _sync_groups(user, preferences):
    # Service.group is a non-unique FK. Aliases would turn an explicit deny
    # into an allow, or mutate excluded Jenkins admission via a shared group.
    mappings = list(Service.objects.values_list("slug", "group_id"))
    for slug, group_id in mappings:
        if slug in GROUP_SERVICES and any(
            other != slug and other_group == group_id for other, other_group in mappings
        ):
            raise ChangeError("service_group_conflict", 409)
    for slug in GROUP_SERVICES:
        service = Service.objects.filter(slug=slug).first()
        if not service:
            continue
        if user.is_superuser or preferences.get(slug) is True:
            user.groups.add(service.group_id)
        else:
            user.groups.remove(service.group_id)
    # Drive uses the canonical Auth subject, not a separate vendor account.
    drive = Service.objects.filter(slug="drive").first()
    if drive and (user.is_superuser or preferences.get("drive") is True):
        if not ServiceIdentity.objects.filter(user=user, service=drive).exists():
            if ServiceIdentity.objects.filter(
                service=drive, external_id=str(user.pk)
            ).exists():
                raise ChangeError("drive_binding_conflict", 409)
            ServiceIdentity.objects.create(
                user=user,
                service=drive,
                external_id=str(user.pk),
                external_username=user.username,
            )


def _native_intents(actor, user, control, change, before, force_block=False):
    for slug in Target.Service.values:
        desired = bool(
            user.is_active and wanted(user, slug, control.service_preferences)
        )
        target = Target.objects.filter(user=user, service=slug).first()
        binding = ServiceIdentity.objects.filter(user=user, service__slug=slug).exists()
        if desired == before[slug] and not (force_block and (target or binding)):
            continue
        if not desired and not target and not binding:
            continue
        instance = target.instance if target else "primary"
        action = (
            Operation.Action.BLOCK
            if not desired
            else (
                Operation.Action.ENABLE
                if binding or (target and target.native_id)
                else Operation.Action.CREATE
            )
        )
        if (
            desired
            and target
            and target.native_id
            and target.ownership == Target.Ownership.CREATED
            and target.creation_operation_id
            and target.identity_id is None
        ):
            action = Operation.Action.BIND
        held = None
        if not Service.objects.filter(slug=slug).exists():
            held = "service_unconfigured"
        elif (not target or target.ownership == Target.Ownership.UNMANAGED) and (
            control.creation_receipt is None or binding
        ):
            held = "adoption_required"
        if (
            not held
            and not desired
            and target
            and not target.native_id
            and target.ownership == Target.Ownership.UNMANAGED
            and not Operation.objects.filter(
                target=target,
                action=Operation.Action.CREATE,
                status__in=[
                    Operation.Status.PENDING,
                    Operation.Status.RUNNING,
                    Operation.Status.UNKNOWN,
                ],
            ).exists()
        ):
            held = "native_not_provisioned"
        if not held and not native_scheduling_enabled():
            held = "native_provisioning_deferred"
        if held:
            target, _ = Target.objects.get_or_create(
                user=user,
                service=slug,
                defaults={"instance": instance, "desired": Target.Desired.BLOCKED},
            )
            target.generation += 1
            target.desired = (
                Target.Desired.ENABLED if desired else Target.Desired.BLOCKED
            )
            target.save(update_fields=["generation", "desired"])
            operation = Operation.objects.create(
                idempotency_key=uuid5(change.pk, slug),
                target=target,
                actor_id=actor.pk,
                base_version=control.version,
                generation=target.generation,
                action=action,
                status=Operation.Status.HELD,
                error_code=held,
            )
            AuditEvent.objects.create(
                actor_id=actor.pk, user_id=user.pk, operation=operation, event="held"
            )
        else:
            schedule(
                actor_id=actor.pk,
                user_id=user.pk,
                service=slug,
                instance=instance,
                action=action,
                idempotency_key=uuid5(change.pk, slug),
                expected_version=control.version,
            )
            control.refresh_from_db()


def apply_change(*, proof, key, action, data, user_id=None, expected=None):
    """All central flags, preferences, deny epoch, intents and audit commit once."""
    if not isinstance(key, UUID):
        raise ChangeError("idempotency_key_required")
    create = action == "create"
    if action not in {"create", "update", "deactivate", "reactivate"}:
        raise ChangeError("invalid_action")
    if action in {"deactivate", "reactivate"}:
        if data != {}:
            raise ChangeError("unknown_fields")
    else:
        validate_changes(data, create)
    fingerprint = _fingerprint(action, user_id, data, expected)
    # Validate/hash the new password before taking the global serialization row.
    candidate = None
    if create:
        import re

        if not re.fullmatch(r"[a-z][a-z0-9_-]{2,31}", data["username"]):
            raise ChangeError("invalid_username")
        candidate = get_user_model()(
            **{
                name: data[name]
                for name in ("username", "email", "first_name", "last_name")
                if name in data
            }
        )
        try:
            if not data["email"]:
                raise ValidationError("Email required")
            candidate.full_clean(
                exclude=["password"], validate_unique=False, validate_constraints=False
            )
            validate_password(data["password"], candidate)
        except ValidationError:
            raise ChangeError("invalid_profile_or_password") from None
        candidate.set_password(data["password"])
    with transaction.atomic():
        credential_lock()
        actor = _actor(proof)
        prior = UserChange.objects.filter(pk=key).first()
        if prior:
            if (
                prior.actor_id != actor.pk
                or prior.action != action
                or not constant_time_compare(prior.fingerprint, fingerprint)
                or (
                    create and not check_password(data["password"], prior.user.password)
                )
            ):
                raise ChangeError("idempotency_conflict", 409)
            return prior.user, prior, True
        if create:
            user = candidate
            user.is_active = True
            user.is_superuser = data.get("is_admin", False)
            user.is_staff = user.is_superuser
            try:
                with transaction.atomic():
                    user.save(force_insert=True)
            except IntegrityError:
                raise ChangeError("username_conflict", 409) from None
            control = UserControl.objects.create(user=user, creation_receipt=key)
            preferences = {slug: False for slug in editable_services()}
            before = {slug: False for slug in Target.Service.values}
        else:
            user = (
                get_user_model().objects.select_for_update().filter(pk=user_id).first()
            )
            if not user:
                raise ChangeError("user_not_found", 404)
            if expected is None:
                raise ChangeError("if_match_required", 428)
            if not constant_time_compare(expected, etag(user)):
                raise ChangeError("stale_version", 412)
            control, _ = UserControl.objects.get_or_create(user=user)
            before = {
                slug: bool(user.is_active and wanted(user, slug))
                for slug in Target.Service.values
            }
            preferences = dict(control.service_preferences)
            role_or_services = "is_admin" in data or "services" in data
            if role_or_services and not preferences:
                preferences = {
                    slug: assigned(user, slug) for slug in editable_services()
                }
            new_active = (
                False
                if action == "deactivate"
                else True if action == "reactivate" else user.is_active
            )
            new_admin = data.get("is_admin", user.is_superuser)
            if user.pk == actor.pk and (not new_active or not new_admin):
                raise ChangeError("self_lockout", 409)
            if (
                user.is_active
                and user.is_superuser
                and (not new_active or not new_admin)
            ):
                if (
                    get_user_model()
                    .objects.filter(is_active=True, is_superuser=True)
                    .count()
                    <= 1
                ):
                    raise ChangeError("last_administrator", 409)
            if user.is_active and not new_active:
                _revoke(user, control)
            user.is_active = new_active
            if "is_admin" in data:
                user.is_superuser = new_admin
                user.is_staff = new_admin
            for name in ("email", "first_name", "last_name"):
                if name in data:
                    setattr(user, name, data[name])
            try:
                user.full_clean(exclude=["password"])
            except ValidationError:
                raise ChangeError("invalid_profile") from None
            user.save(
                update_fields=[
                    "email",
                    "first_name",
                    "last_name",
                    "is_active",
                    "is_superuser",
                    "is_staff",
                ]
            )
        preferences.update(data.get("services", {}))
        if create or "services" in data or "is_admin" in data:
            control.service_preferences = preferences
            control.save(update_fields=["service_preferences"])
            _sync_groups(user, preferences)
        change = UserChange.objects.create(
            id=key,
            actor_id=actor.pk,
            user=user,
            action=action,
            fingerprint=fingerprint,
            changed_fields=sorted(
                (set(data) - {"password"})
                | ({"is_active"} if action in {"deactivate", "reactivate"} else set())
            ),
        )
        if create or action != "update" or "services" in data or "is_admin" in data:
            _native_intents(
                actor, user, control, change, before, action == "deactivate"
            )
        control.refresh_from_db()
        control.api_version += 1
        control.save(update_fields=["api_version"])
        return user, change, False
