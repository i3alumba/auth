"""Private, one-shot MinIO fixture runtime DI; never production CLI acceptance.

Import is inert. The controller supplies read-only ROOT and private writable
STATUS in a fresh network-none fixture. No issuer/browser inputs are consumed.
"""

from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
from uuid import UUID, uuid5

ROOT = Path("/fixture-worker")
STATUS = Path("/fixture-worker-status")
PROFILE = "minio-2023-05-18-owned-s3-v1"
ORIGIN = "https://localhost:19000"
MARKER = "PUBLIC_PAGE_SYNTHETIC_FIXTURE_V1"


def require(condition: bool) -> None:
    if condition is not True:
        raise RuntimeError("worker_fixture_rejected")


def validate_environment(environ, uid: int) -> None:
    require(uid != 0)
    for key, value in {
        "DJANGO_SETTINGS_MODULE": "auth.worker_settings",
        "DJANGO_DEBUG": "false",
        "SSO_ENABLED": "false",
        "USER_ADMIN_WORKER_ENABLED": "1",
    }.items():
        require(environ.get(key) == value)
    require(not {"SSO_RSA_PRIVATE_KEY", "SSO_RSA_PRIVATE_KEY_FILE"} & environ.keys())


def validate_settings(settings, urlpatterns) -> None:
    require(settings.SETTINGS_MODULE == "auth.worker_settings")
    require(settings.DEBUG is False and settings.SSO_ENABLED is False)
    require(settings.USER_ADMIN_API_ENABLED is False)
    require(settings.USER_ADMIN_WORKER_ENABLED is True)
    require(settings.USER_ADMIN_NATIVE_EXECUTION_ENABLED is True)
    require(settings.OAUTH2_PROVIDER.get("OIDC_RSA_PRIVATE_KEY") == "")
    require(settings.OAUTH2_PROVIDER.get("OIDC_ENABLED") is False)
    require(settings.ROOT_URLCONF == "auth.worker_urls" and urlpatterns == [])
    database = settings.DATABASES["default"]
    # This is the existing dedicated settings' Django PostgreSQL alias.
    for key, value in {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": "user_admin_browser_fixture",
        "USER": "user_admin_browser_fixture",
        "HOST": "127.0.0.1",
        "PORT": "15432",
    }.items():
        require(database.get(key) == value)


def reserve_started() -> None:
    """Reserve before Django/DB/native work. Never retry or remove this marker."""
    from user_admin.worker_config import _directory

    directory = _directory(str(STATUS), private=True)
    try:
        info = os.fstat(directory)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        fd = os.open(
            "started",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        os.close(fd)
    finally:
        os.close(directory)


def canonical_uuid(value) -> UUID:
    require(type(value) is str)
    parsed = UUID(value)
    require(str(parsed) == value)
    return parsed


def validate_record(record, run: str) -> None:
    require(type(run) is str and re.fullmatch(r"[0-9a-f]{32}", run) is not None)
    require(UUID(hex=run).hex == run)
    require(
        type(record) is dict
        and set(record)
        == {
            "run",
            "service",
            "user_id",
            "actor_id",
            "change_id",
            "target_id",
            "operation_id",
            "before",
            "controls",
        }
    )
    require(record["run"] == run and record["service"] == "minio")
    for key in ("user_id", "actor_id"):
        require(type(record[key]) is int and record[key] > 0)
    require(record["user_id"] != record["actor_id"])
    for key in ("change_id", "target_id", "operation_id"):
        canonical_uuid(record[key])
    require(type(record["before"]) is dict)
    require(type(record["controls"]) is dict and set(record["controls"]) == {"a", "b"})
    users = {record["user_id"], record["actor_id"]}
    targets = {record["target_id"]}
    for control in record["controls"].values():
        require(
            type(control) is dict
            and set(control)
            == {
                "user_id",
                "target_id",
                "native_id",
                "canary_sha256",
            }
        )
        require(type(control["user_id"]) is int and control["user_id"] > 0)
        require(control["user_id"] not in users)
        users.add(control["user_id"])
        target = canonical_uuid(control["target_id"])
        require(control["target_id"] not in targets)
        targets.add(control["target_id"])
        require(control["native_id"] == "ua-" + target.hex)
        require(
            type(control["canary_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", control["canary_sha256"]) is not None
        )


def read_record():
    from user_admin.worker_config import (
        _directory,
        _read_at,
        _pairs,
        _invalid_constant,
    )

    directory = _directory(str(ROOT))
    try:
        require(bool(os.fstatvfs(directory).f_flag & os.ST_RDONLY))
        require(_read_at(directory, "marker", 128, private=False).decode() == MARKER)
        run = _read_at(directory, "run-id", 32, private=False).decode("ascii")
        record = json.loads(
            _read_at(directory, "subject.json", 1048576, private=True),
            object_pairs_hook=_pairs,
            parse_constant=_invalid_constant,
        )
    finally:
        os.close(directory)
    validate_record(record, run)
    return record


def validate_config(config) -> None:
    require(config.execution_scope == "provision_only")
    require(config.private_root == str(ROOT / "private") and len(config.instances) == 1)
    instance = config.instances[0]
    require(
        (
            instance.service,
            instance.instance,
            instance.acceptance_profile,
            instance.origin,
        )
        == ("minio", "primary", PROFILE, ORIGIN)
    )
    require(instance.server_name == "" and bool(instance.ca_file))
    require(
        dict(instance.credentials)
        == {
            "access_key_file": "root-user",
            "secret_key_file": "root-password",
        }
    )
    require(instance.ca_file not in {"root-user", "root-password"})


def load_fixture_config():
    from user_admin.worker_config import (
        _directory,
        _read_at,
        _pairs,
        _invalid_constant,
        load_config,
    )

    directory = _directory(str(ROOT / "config"))
    try:
        document = json.loads(
            _read_at(directory, "worker.json", 65536, private=False),
            object_pairs_hook=_pairs,
            parse_constant=_invalid_constant,
        )
    finally:
        os.close(directory)
    # The fixture must declare scope, not rely on the loader's default.
    require(
        type(document) is dict and document.get("execution_scope") == "provision_only"
    )
    config = load_config(str(ROOT / "config/worker.json"))
    validate_config(config)
    return config


def validate_private_metadata(config) -> None:
    from user_admin.worker_config import _directory

    directory = _directory(config.private_root, private=True)
    try:
        require(stat.S_IMODE(os.fstat(directory).st_mode) == 0o700)
        instance = config.instances[0]
        for name in ["root-user", "root-password", instance.ca_file]:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            require(
                info.st_uid in {0, os.getuid()} and stat.S_IMODE(info.st_mode) == 0o600
            )
    finally:
        os.close(directory)


def fixture_profiles(profiles):
    """Only an explicit fixture DI copy; lifecycle and global gates stay sealed."""
    require(
        all(
            profile.provisioning_blockers and profile.blockers
            for profile in profiles.values()
        )
    )
    base = profiles[PROFILE]
    require(base.service == "minio" and bool(base.provisioning_blockers))
    return {PROFILE: replace(base, provisioning_blockers=())}


def snapshot_state(exclude_user_id=None):
    """JSON-safe nonsecret controller baseline; never read passwords or tokens."""
    from django.contrib.auth import get_user_model
    from sso.models import ServiceIdentity
    from user_admin.models import Operation, Target, UserControl

    def rows(model, fields, user_path="user_id"):
        query = model.objects.all()
        if exclude_user_id is not None:
            query = query.exclude(**{user_path: exclude_user_id})
        return list(query.order_by("pk").values(*fields))

    users = rows(
        get_user_model(),
        ["id", "username", "is_active", "is_staff", "is_superuser"],
        "pk",
    )
    User = get_user_model()
    for user in users:
        user["groups"] = list(
            User.objects.only("pk")
            .get(pk=user["id"])
            .groups.order_by("pk")
            .values("id", "name")
        )
    data = {
        "users": users,
        "controls": rows(
            UserControl,
            [
                "id",
                "user_id",
                "version",
                "api_version",
                "auth_epoch",
                "service_preferences",
                "creation_receipt",
            ],
        ),
        "identities": rows(
            ServiceIdentity,
            [
                "id",
                "user_id",
                "service_id",
                "external_id",
                "external_username",
                "minio_policy",
                "jenkins_admin",
            ],
        ),
        "targets": rows(
            Target,
            [
                "id",
                "user_id",
                "service",
                "instance",
                "native_id",
                "ownership",
                "generation",
                "desired",
                "observed",
                "identity_id",
                "creation_operation_id",
                "authority_epoch",
                "block_authority_epoch",
                "block_receipt",
                "management_paused",
                "pause_actor_id",
            ],
        ),
        "operations": rows(
            Operation,
            [
                "id",
                "target_id",
                "generation",
                "action",
                "status",
                "error_code",
                "observed",
                "evidence",
                "actor_id",
                "authority_epoch",
            ],
            "target__user_id",
        ),
    }
    return json.loads(json.dumps(data, default=str, allow_nan=False))


def validate_queue_rows(rows, user_id: int) -> None:
    """All services, including unconfigured/imported rows, must be quiescent."""
    for row in rows:
        require(row.target.user_id == user_id)
        require(row.status == "pending" and row.target.management_paused is False)


def guard_queue(record) -> None:
    from user_admin.models import Operation, Target

    rows = Operation.objects.filter(
        status__in=["pending", "running", "outcome_unknown"]
    ).select_related("target")
    validate_queue_rows(rows, record["user_id"])
    require(
        not Target.objects.filter(
            user_id=record["user_id"], management_paused=True
        ).exists()
    )


def validate_subject(record):
    from django.contrib.auth import get_user_model
    from sso.access import identity_for
    from sso.models import Service, ServiceIdentity
    from user_admin.models import Operation, Target, UserChange, UserControl

    user = get_user_model().objects.defer("password").get(pk=record["user_id"])
    actor = (
        get_user_model()
        .objects.only("pk", "is_active", "is_superuser")
        .get(pk=record["actor_id"])
    )
    require(actor.is_active is True and actor.is_superuser is True)
    require(user.username == "fixture_worker_" + record["run"][:12])
    require(
        user.is_active is True and user.is_staff is False and user.is_superuser is False
    )
    service = Service.objects.get(slug="minio")
    require(list(user.groups.values_list("pk", flat=True)) == [service.group_id])
    require(
        identity_for(user, service) is None
        and not ServiceIdentity.objects.filter(user=user).exists()
    )
    require(
        UserControl.objects.get(user=user).creation_receipt
        == canonical_uuid(record["change_id"])
    )
    require(
        UserChange.objects.filter(
            pk=record["change_id"], user=user, actor_id=actor.pk, action="create"
        ).exists()
    )
    target = Target.objects.get(pk=record["target_id"])
    require(Target.objects.filter(user=user).count() == 1)
    require(
        target.user_id == user.pk
        and target.service == "minio"
        and target.instance == "primary"
    )
    require(
        target.generation == 1
        and target.desired == "enabled"
        and target.ownership == "unmanaged"
    )
    require(
        target.native_id == ""
        and target.identity_id is None
        and target.creation_operation_id is None
    )
    operation = Operation.objects.get(pk=record["operation_id"])
    require(Operation.objects.filter(target__user=user).count() == 1)
    require(target.observed == "unknown" and target.authority_epoch == 0)
    require(target.block_receipt == "" and target.block_authority_epoch == 0)
    require(
        operation.target_id == target.pk
        and operation.action == "create"
        and operation.generation == 1
    )
    require(
        operation.actor_id == actor.pk
        and operation.status == "pending"
        and operation.execution_token is None
    )
    require(
        operation.error_code == ""
        and operation.observed == ""
        and operation.evidence == {}
    )
    guard_queue(record)
    require(snapshot_state(exclude_user_id=user.pk) == record["before"])
    return user, service, target


def control_targets(record):
    from django.contrib.auth import get_user_model
    from user_admin.models import Operation, Target, UserChange, UserControl
    from .browser_control import binding_matches

    result = []
    for label, control in record["controls"].items():
        user = get_user_model().objects.defer("password").get(pk=control["user_id"])
        target = Target.objects.get(pk=control["target_id"])
        require(user.username == "fixture_" + label + "_" + record["run"][:12])
        require(
            user.is_active is True
            and user.is_staff is False
            and user.is_superuser is False
        )
        receipt = UserControl.objects.get(user=user).creation_receipt
        require(
            receipt is not None
            and UserChange.objects.filter(
                pk=receipt, user=user, action="create"
            ).exists()
        )
        require(
            target.user_id == user.pk
            and target.service == "minio"
            and target.instance == "primary"
        )
        require(
            target.native_id == control["native_id"] and target.ownership == "created"
        )
        require(
            target.management_paused is False
            and target.desired == target.observed == "enabled"
        )
        require(binding_matches(target, user))
        require(
            Operation.objects.filter(
                pk=target.creation_operation_id,
                target=target,
                action="create",
                status="succeeded",
                observed="unbound",
            ).exists()
        )
        binding = (
            Operation.objects.filter(target=target, action="bind")
            .order_by("-created_at", "-id")
            .first()
        )
        require(binding is not None and binding.generation == target.generation)
        require(
            binding.status in {"succeeded", "partial"} and binding.observed == "enabled"
        )
        require(binding.error_code in {"", "capability_unconfirmed"})
        result.append((control, user, target, binding))
    return result


def public_command_checks() -> None:
    from unittest.mock import Mock, patch
    from django.core.management import call_command
    from django.core.management.base import CommandError
    from django.db import connection
    from django.test.utils import CaptureQueriesContext
    from user_admin.worker_runtime import run_pass

    forbidden_factory = Mock(side_effect=RuntimeError("worker_fixture_rejected"))
    output = io.StringIO()
    prefix = "user_admin.management.commands.user_admin_worker."

    # Spy on the public command's real runtime, with a fail-fast factory sentinel
    # only for preview. Actual executable fixture passes use the default factory.
    def preview(*args, **kwargs):
        return run_pass(*args, **kwargs, factory=forbidden_factory)

    with (
        patch(prefix + "load_private_snapshot") as loader,
        patch(prefix + "run_pass", side_effect=preview),
    ):
        with CaptureQueriesContext(connection) as queries:
            call_command(
                "user_admin_worker",
                "--config",
                str(ROOT / "config/worker.json"),
                "--dry-run",
                "--once",
                stdout=output,
                stderr=output,
            )
        require(
            all(
                item["sql"].lstrip().upper().startswith("SELECT")
                for item in queries.captured_queries
            )
        )
        require(loader.call_count == 0 and forbidden_factory.call_count == 0)
    with patch(prefix + "load_private_snapshot") as loader:
        blocked = False
        try:
            call_command(
                "user_admin_worker",
                "--config",
                str(ROOT / "config/worker.json"),
                "--execute",
                "--once",
                stdout=output,
                stderr=output,
            )
        except CommandError as error:
            blocked = str(error) == "profile_activation_blocked"
        require(blocked and loader.call_count == 0)


def phase_outcome(operation, target):
    from .browser_control import phase_outcome as checked_outcome

    require(operation.action in {"create", "bind", "enable"})
    checked = checked_outcome(operation, target)
    return {key: checked[key] for key in ("action", "status", "reason", "observed")}


def check_native_controls(record, config, snapshot) -> None:
    import ssl
    from datetime import datetime, timezone
    from user_admin.adapters import Command
    from user_admin.native.http import NativeHTTP
    from user_admin.native.sigv4 import sign_s3
    from user_admin.worker_runtime import make_adapter

    instance = config.instances[0]
    secrets = snapshot[("minio", "primary")]
    context = ssl.create_default_context()
    context.load_verify_locations(cadata=secrets["ca_pem"])
    client = NativeHTTP(ORIGIN, context=context)
    for control, user, target, binding in control_targets(record):
        command = Command(
            target.pk,
            binding.pk,
            user.pk,
            "minio",
            "primary",
            target.generation,
            "bind",
            target.native_id,
            target.authority_epoch,
        )
        observed = make_adapter(instance, secrets, binding).inspect(command)
        require(observed.owner == target.pk and observed.subject == str(user.pk))
        require(
            observed.native_id == target.native_id
            and observed.instance == "primary"
            and observed.state == "enabled"
        )
        require(
            observed.binding is not None
            and observed.binding.external_id == str(user.pk)
        )
        require(
            observed.binding.external_username
            == observed.binding.minio_policy
            == target.native_id
        )
        path = "/" + target.native_id + "/probe.txt"
        headers = sign_s3(
            access_key=secrets["access_key_file"],
            secret_key=secrets["secret_key_file"],
            authority=client.authority,
            method="GET",
            target=path,
            now=datetime.now(timezone.utc),
        )
        reply = client.request("GET", path, headers=headers)
        require(
            reply.status == 200
            and hashlib.sha256(reply.body).hexdigest() == control["canary_sha256"]
        )


def probe(record):
    from sso.access import identity_for
    from user_admin.engine import provisioning_refusal
    from user_admin.models import Operation
    from user_admin.worker_config import load_private_snapshot
    from user_admin.worker_profiles import PROFILES
    from user_admin.worker_runtime import admission, candidates, run_pass
    from .browser_control import binding_matches

    config = load_fixture_config()
    validate_private_metadata(config)
    original_profiles = dict(PROFILES)
    local_profiles = fixture_profiles(PROFILES)
    user, service, target = validate_subject(record)
    control_targets(record)  # All controller and DB proofs before native IO.
    public_command_checks()
    admission(config, profiles=local_profiles)
    snapshot = load_private_snapshot(config)  # Exactly once, after public gates.
    require("ca_pem" in snapshot[("minio", "primary")])
    cursor = None
    phases = []
    for action in ("create", "bind", "enable"):
        guard_queue(record)
        target.refresh_from_db()
        eligible = candidates(config, limit=2, cursor=cursor)
        if action == "enable" and not eligible:
            break
        require(len(eligible) == 1)
        operation = eligible[0]
        require(
            operation.target_id == target.pk and operation.target.user_id == user.pk
        )
        require(
            operation.action == action
            and operation.generation == 1
            and operation.actor_id == record["actor_id"]
        )
        require(not provisioning_refusal(operation, target))
        require(operation.execution_token is None)
        if action == "create":
            require(str(operation.pk) == record["operation_id"])
        if action == "bind":
            require(
                operation.idempotency_key
                == uuid5(canonical_uuid(record["operation_id"]), "bind")
            )
        cursor, count, incomplete = run_pass(
            config,
            dry_run=False,
            limit=1,
            profiles=local_profiles,
            snapshot=snapshot,
            cursor=cursor,
        )
        require(
            count == 1 and cursor is not None and cursor.operation_id == operation.pk
        )
        operation.refresh_from_db()
        target.refresh_from_db()
        require(incomplete == (operation.status != "succeeded"))
        require(
            target.native_id == "ua-" + target.pk.hex and target.ownership == "created"
        )
        require(str(target.creation_operation_id) == record["operation_id"])
        phases.append(phase_outcome(operation, target))
        if action == "create":
            require(identity_for(user, service) is None)
        else:
            identity = identity_for(user, service)
            require(
                identity is not None
                and identity.pk == target.identity_id
                and binding_matches(target, user)
            )
        require(snapshot_state(exclude_user_id=user.pk) == record["before"])
    guard_queue(record)
    require(
        not Operation.objects.filter(
            target__user_id=user.pk,
            status__in=["pending", "running", "outcome_unknown"],
        ).exists()
    )
    require(
        [phase["action"] for phase in phases]
        in [["create", "bind"], ["create", "bind", "enable"]]
    )
    require(target.observed == "enabled" and binding_matches(target, user))
    check_native_controls(record, config, snapshot)
    require(snapshot_state(exclude_user_id=user.pk) == record["before"])
    require(dict(PROFILES) == original_profiles)
    require(
        all(
            profile.provisioning_blockers and profile.blockers
            for profile in PROFILES.values()
        )
    )
    return {
        "ok": True,
        "actual_dedicated_worker_settings": True,
        "fixture_profile_di": True,
        "production_profiles_unchanged": True,
        "public_cli_execute_blocked": True,
        "public_cli_preview_read_only": True,
        "snapshot_loaded_once": True,
        "automatic_provisioning": True,
        "identity_readiness_checked": True,
        "control_state_preserved": True,
        "control_native_data_policy_preserved": True,
        "phases": phases,
        "initial_enable": "tested" if len(phases) == 3 else "not_queued",
    }


def main() -> int:
    try:
        validate_environment(os.environ, os.getuid())
        require(len(sys.argv) == 1)
        reserve_started()
        record = read_record()
        import django

        django.setup()
        from django.conf import settings
        from auth.worker_urls import urlpatterns

        validate_settings(settings, urlpatterns)
        result = probe(record)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print('{"ok":false,"code":"worker_fixture_probe_failed"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
