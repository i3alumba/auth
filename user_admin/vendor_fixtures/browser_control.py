"""Explicit real-engine controller for a new, isolated browser/OIDC fixture.

Only the fixture's subjects are addressed. No automatic recovery, adoption,
production profile change, worker registration or credentials in stdout.
"""

import json
import os
from pathlib import Path
import sys
from uuid import UUID, uuid4

from .runner import write_proof

IDP = Path("/fixture-idp")
CONTROL = Path("/fixture-control")
NATIVE = Path("/fixture-native")


def require(condition, code):
    if condition is not True:
        raise RuntimeError(code)


def setup():
    require(
        os.environ.get("DJANGO_SETTINGS_MODULE")
        in {
            "user_admin.vendor_fixtures.browser_settings",
            "user_admin.vendor_fixtures.minio_browser_settings",
        },
        "browser_fixture_settings_required",
    )
    import django

    django.setup()
    from django.conf import settings

    database = settings.DATABASES["default"]
    require(
        database["NAME"] == "user_admin_browser_fixture"
        and database["HOST"] == "127.0.0.1"
        and str(database["PORT"]) == "15432",
        "browser_fixture_database_required",
    )
    require(
        (IDP / "marker").read_text() == "PUBLIC_PAGE_SYNTHETIC_FIXTURE_V1",
        "browser_fixture_marker_required",
    )
    UUID((IDP / "run-id").read_text())
    require(
        (fixture_service() == "minio")
        == (
            os.environ["DJANGO_SETTINGS_MODULE"]
            == "user_admin.vendor_fixtures.minio_browser_settings"
        ),
        "browser_fixture_service_settings_mismatch",
    )


def inputs():
    return json.loads((IDP / "bootstrap.json").read_text())


def fixture_service():
    service = inputs().get("service", "gitlab")
    require(
        type(service) is str and service in {"gitlab", "matrix", "minio"},
        "browser_fixture_service_invalid",
    )
    return service


def administrator_proof():
    from django.contrib.auth import authenticate
    from user_admin.authentication import issue_refresh

    credentials = inputs()["administrator"]
    user = authenticate(
        username=credentials["username"], password=credentials["password"]
    )
    require(
        user is not None and user.is_active and user.is_superuser,
        "browser_fixture_administrator_failed",
    )
    return issue_refresh(user).access_token


def bootstrap():
    from django.core.management import call_command
    from django.contrib.auth import get_user_model
    from django.contrib.auth.hashers import check_password
    from django.contrib.auth.models import Group
    from oauth2_provider.models import get_application_model
    from sso.models import Service, ServiceIdentity
    from user_admin.models import AdministrationLock

    call_command("migrate", verbosity=0, interactive=False)
    User = get_user_model()
    require(
        User.objects.count() == 0 and ServiceIdentity.objects.count() == 0,
        "browser_fixture_database_not_empty",
    )
    credentials = inputs()["administrator"]
    admin = User.objects.create_superuser(
        username=credentials["username"],
        password=credentials["password"],
        email="fixture-admin@example.invalid",
    )
    require(
        AdministrationLock.objects.filter(pk=1).exists(), "browser_fixture_lock_missing"
    )
    service = fixture_service()
    client_id = (IDP / (service + "-client-id")).read_text()
    secret = (IDP / (service + "-client-secret")).read_text()
    group = Group.objects.create(
        name="fixture_" + service + "_" + (IDP / "run-id").read_text().replace("-", "")
    )
    Service.objects.create(slug=service, group=group, oidc_client_id=client_id)
    application = get_application_model()(
        user=admin,
        client_id=client_id,
        client_secret=secret,
        client_type="confidential",
        authorization_grant_type="authorization-code",
        algorithm="RS256",
        skip_authorization=True,
        hash_client_secret=True,
        redirect_uris={
            "gitlab": "https://localhost:19443/users/auth/openid_connect/callback",
            "matrix": "https://localhost:19443/_synapse/client/oidc/callback",
            "minio": "https://minio.i3alumba.ru/oauth_callback",
        }[service],
        name="Isolated " + service + " browser fixture",
    )
    application.save()
    require(
        check_password(secret, application.client_secret),
        "browser_fixture_client_hash_failed",
    )
    return {"client_registered": True, "client_secret_hashed": True, "identities": 0}


def users():
    from django.contrib.auth import get_user_model

    return {
        label: get_user_model().objects.get(username=data["username"])
        for label, data in inputs()["subjects"].items()
    }


def phase_outcome(operation, target):
    """Only expected effects; PARTIAL alone never establishes fixture success."""
    from user_admin.models import Operation

    action, status, reason = operation.action, operation.status, operation.error_code
    expected = {
        Operation.Action.CREATE: "unbound",
        Operation.Action.BIND: "enabled",
        Operation.Action.BLOCK: "blocked",
        Operation.Action.ENABLE: "enabled",
    }
    require(action in expected, "browser_fixture_native_action_invalid")
    intermediate = (
        action == Operation.Action.BIND
        and status == Operation.Status.PARTIAL
        and reason == "native_enable_pending"
    )
    accepted = (
        (status == Operation.Status.SUCCEEDED and reason == "")
        or (
            action != Operation.Action.CREATE
            and status == Operation.Status.PARTIAL
            and reason == "capability_unconfirmed"
        )
        or intermediate
    )
    require(accepted, "browser_fixture_native_outcome_unaccepted")
    state = "blocked" if intermediate else expected[action]
    require(
        operation.observed == state and target.observed == state,
        "browser_fixture_native_state_mismatch",
    )
    require(
        (
            (target.identity_id is None)
            if action == Operation.Action.CREATE
            else (target.identity_id is not None)
        ),
        "browser_fixture_native_identity_state_mismatch",
    )
    evidence = operation.evidence
    require(
        type(evidence) is dict
        and set(evidence) == {"new_login", "existing_sessions", "api_credentials"}
        and all(
            value in {"unknown", "confirmed", "unsupported"}
            for value in evidence.values()
        ),
        "browser_fixture_evidence_invalid",
    )
    return {
        "action": action,
        "status": status,
        "reason": reason,
        "observed": state,
        "evidence": dict(evidence),
        "phase_complete": not intermediate,
        "ready_for_browser": state == "enabled" and target.identity_id is not None,
    }


def execute(user, action):
    from django.test import override_settings
    from user_admin.engine import execute as execute_operation
    from user_admin.models import Operation, Target
    from user_admin.worker_config import InstanceConfig
    from user_admin.worker_runtime import make_adapter

    service = fixture_service()
    target = Target.objects.get(user=user, service=service)
    require(
        not Operation.objects.filter(
            target=target,
            status__in=[Operation.Status.RUNNING, Operation.Status.UNKNOWN],
        ).exists(),
        "browser_fixture_target_reserved",
    )
    operation = Operation.objects.select_related("target").get(
        target=target,
        generation=target.generation,
        action=action,
        status=Operation.Status.PENDING,
    )
    config = InstanceConfig(
        "gitlab",
        "primary",
        "https://localhost:19443",
        "gitlab-18.1.0-ce-ban-v1",
        (("token_file", "admin-token"),),
    )
    credentials = {"ca_pem": (IDP / "ca.crt").read_text()}
    if service in {"gitlab", "matrix"}:
        credentials["token_file"] = (NATIVE / "admin-token").read_text()
    if service == "minio":
        config = InstanceConfig(
            "minio",
            "primary",
            "https://localhost:19000",
            "minio-2023-05-18-owned-s3-v1",
            (),
        )
        credentials.update(
            {
                "access_key_file": (NATIVE / "root-user")
                .read_text()
                .removesuffix("\n"),
                "secret_key_file": (NATIVE / "root-password")
                .read_text()
                .removesuffix("\n"),
            }
        )
    if service == "matrix":
        config = InstanceConfig(
            "matrix",
            "primary",
            "https://localhost:19443",
            "synapse-1.164.1-lock-v1",
            (),
            "matrixfixture.test",
        )
        credentials["registration_secret_file"] = (
            NATIVE / "registration-secret"
        ).read_text()
    adapter = make_adapter(config, credentials, operation)
    # Fixture controller only. The independent web process/CLI profiles stay off.
    with override_settings(USER_ADMIN_NATIVE_EXECUTION_ENABLED=True):
        result = execute_operation(
            operation.pk,
            adapter,
            execution_scope="lifecycle" if service == "gitlab" else "provision_only",
        )
    require(
        result in {Operation.Status.SUCCEEDED, Operation.Status.PARTIAL},
        "browser_fixture_native_step_failed",
    )
    operation.refresh_from_db()
    require(result == operation.status, "browser_fixture_native_status_mismatch")
    target.refresh_from_db()
    require(
        target.native_id != ""
        and target.ownership == Target.Ownership.CREATED
        and target.creation_operation_id is not None,
        "browser_fixture_creation_provenance_missing",
    )
    return target, phase_outcome(operation, target)


def create():
    from django.contrib.auth import get_user_model
    from sso.models import ServiceIdentity
    from user_admin.models import Operation, Target, UserControl
    from user_admin.service import apply_change

    require(
        get_user_model().objects.count() == 1, "browser_fixture_create_replay_forbidden"
    )
    proof = administrator_proof()
    accounts = {}
    outcomes = {}
    for label, account in inputs()["subjects"].items():
        key = uuid4()
        user, change, replayed = apply_change(
            proof=proof,
            key=key,
            action="create",
            data={**account, "is_admin": False, "services": {fixture_service(): True}},
        )
        require(
            replayed is False
            and UserControl.objects.get(user=user).creation_receipt == key,
            "browser_fixture_central_create_failed",
        )
        target, outcomes[label] = execute(user, Operation.Action.CREATE)
        require(
            target.instance == "primary"
            and target.observed == "unbound"
            and target.identity_id is None
            and not ServiceIdentity.objects.filter(user=user).exists(),
            "browser_fixture_unbound_invariant_failed",
        )
        require(
            Operation.objects.filter(
                target=target,
                generation=target.generation,
                action=Operation.Action.BIND,
                status=Operation.Status.PENDING,
            ).count()
            == 1,
            "browser_fixture_bind_not_queued",
        )
        from .browser_repository import owned_fixture_repository

        accounts[label] = {
            **(
                owned_fixture_repository(target)
                if fixture_service() == "gitlab"
                else {}
            ),
            "username": account["username"],
            "password": account["password"],
            "native_id": target.native_id,
            "auth_id": str(user.pk),
        }
    # Private login input, not evidence: only new fixture passwords, tmpfs/0600.
    with os.fdopen(
        os.open(
            CONTROL / "browser-accounts.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        ),
        "w",
    ) as stream:
        json.dump(accounts, stream)
    return {
        "central_create_and_native_create": True,
        "subjects_unbound": True,
        "native_outcomes": outcomes,
        "phase_complete": True,
        "identities": ServiceIdentity.objects.count(),
    }


def binding_matches(target, user):
    identity = target.identity
    if (
        identity is None
        or identity.user_id != user.pk
        or target.user_id != user.pk
        or identity.service.slug != target.service
    ):
        return False
    if target.service == "minio":
        from user_admin.native.minio_policy import resource_name

        return (
            target.native_id == resource_name(target.pk)
            and identity.external_id == str(user.pk)
            and identity.external_username == identity.minio_policy == target.native_id
        )
    return identity.external_id == target.native_id


def seed_minio_canaries():
    """Only fresh provenance-owned buckets, before binding; never fixture replay."""
    import hashlib
    import secrets
    import ssl
    from datetime import datetime, timezone
    from user_admin.models import Target
    from user_admin.native.http import NativeHTTP
    from user_admin.native.minio_policy import resource_name
    from user_admin.native.sigv4 import sign_s3

    require(fixture_service() == "minio", "browser_fixture_service_invalid")
    require(not (CONTROL / "minio-seeded").exists(), "browser_fixture_seed_replay")
    # Reserve before the first possible write. A lost reply never permits a
    # second seeding attempt, even if the later helper steps did not complete.
    with os.fdopen(
        os.open(CONTROL / "minio-seeded", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
        "w",
    ) as stream:
        stream.write("started")
    accounts = json.loads((CONTROL / "browser-accounts.json").read_text())
    access = (NATIVE / "root-user").read_text().removesuffix("\n")
    secret = (NATIVE / "root-password").read_text().removesuffix("\n")
    client = NativeHTTP(
        "https://localhost:19000",
        context=ssl.create_default_context(cafile=str(IDP / "ca.crt")),
    )
    for label, user in users().items():
        target = Target.objects.get(user=user, service="minio")
        require(
            target.ownership == Target.Ownership.CREATED
            and target.creation_operation_id is not None
            and target.identity_id is None
            and target.observed == "unbound"
            and target.native_id == resource_name(target.pk)
            and accounts[label]["native_id"] == target.native_id,
            "browser_fixture_seed_ownership_failed",
        )
        payload = secrets.token_bytes(48)
        path = "/" + target.native_id + "/probe.txt"
        headers = sign_s3(
            access_key=access,
            secret_key=secret,
            authority=client.authority,
            method="PUT",
            target=path,
            body=payload,
            now=datetime.now(timezone.utc),
        )
        reply = client.request("PUT", path, headers=headers, body=payload)
        require(reply.status == 200, "browser_fixture_seed_failed")
        accounts[label]["canary_sha256"] = hashlib.sha256(payload).hexdigest()
    with os.fdopen(
        os.open(
            CONTROL / "browser-accounts.seed.tmp",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        ),
        "w",
    ) as stream:
        json.dump(accounts, stream)
    os.replace(CONTROL / "browser-accounts.seed.tmp", CONTROL / "browser-accounts.json")
    return {"owned_canaries_seeded": True}


def create_worker_subject():
    """Queue fresh C only; the separate dedicated worker must do all native IO."""
    import secrets
    from django.contrib.auth import get_user_model
    from user_admin.models import Operation, Target
    from user_admin.service import apply_change
    from .worker_probe import snapshot_state

    require(fixture_service() == "minio", "browser_fixture_service_invalid")
    require(
        get_user_model().objects.count() == 3, "browser_fixture_worker_subject_replay"
    )
    with os.fdopen(
        os.open(
            CONTROL / "worker-subject-started",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        ),
        "w",
    ) as stream:
        stream.write("started")
    before = snapshot_state()
    run = (IDP / "run-id").read_text()
    actor = get_user_model().objects.get(username=inputs()["administrator"]["username"])
    key = uuid4()
    user, change, replayed = apply_change(
        proof=administrator_proof(),
        key=key,
        action="create",
        data={
            "username": "fixture_worker_" + run[:12],
            "password": secrets.token_urlsafe(40),
            "email": "fixture_worker_" + run[:12] + "@example.invalid",
            "is_admin": False,
            "services": {"minio": True},
        },
    )
    require(
        replayed is False and change.pk == key, "browser_fixture_worker_create_failed"
    )
    target = Target.objects.get(user=user, service="minio")
    operation = Operation.objects.get(target=target, action="create", status="pending")
    accounts = json.loads((CONTROL / "browser-accounts.json").read_text())
    controls = {}
    for label, control_user in users().items():
        control_target = Target.objects.get(user=control_user, service="minio")
        require(
            binding_matches(control_target, control_user),
            "browser_fixture_control_binding_changed",
        )
        controls[label] = {
            "user_id": control_user.pk,
            "target_id": str(control_target.pk),
            "native_id": control_target.native_id,
            "canary_sha256": accounts[label]["canary_sha256"],
        }
    record = {
        "run": run,
        "service": "minio",
        "user_id": user.pk,
        "actor_id": actor.pk,
        "change_id": str(key),
        "target_id": str(target.pk),
        "operation_id": str(operation.pk),
        "before": before,
        "controls": controls,
    }
    with os.fdopen(
        os.open(
            CONTROL / "worker-subject.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        ),
        "w",
    ) as stream:
        json.dump(record, stream, sort_keys=True)
    return {"worker_subject_created": True, "native_execution_delegated": True}


def central(action, grant=None):
    from user_admin.service import apply_change, etag
    from user_admin.authentication import current_epoch

    user = users()["a"]
    from oauth2_provider.models import (
        get_access_token_model,
        get_refresh_token_model,
        get_grant_model,
    )

    before = current_epoch(user.pk)
    prior_oauth_access = get_access_token_model().objects.filter(user=user).exists()
    apply_change(
        proof=administrator_proof(),
        key=uuid4(),
        action=action,
        data={"services": {fixture_service(): grant}} if grant is not None else {},
        user_id=user.pk,
        expected=etag(user),
    )
    result = {"central_change": True, "epoch_advanced": current_epoch(user.pk) > before}
    if action == "deactivate":
        removed = not any(
            model.objects.filter(user=user).exists()
            for model in [
                get_access_token_model(),
                get_refresh_token_model(),
                get_grant_model(),
            ]
        )
        require(
            prior_oauth_access and removed,
            "browser_fixture_deactivation_credential_removal_failed",
        )
        result.update(
            {"prior_oidc_access_existed": True, "oauth_credentials_removed": True}
        )
    return result


def phase(name):
    from sso.models import ServiceIdentity
    from user_admin.models import Operation

    if name == "bootstrap":
        return bootstrap()
    if name == "create":
        return create()
    if name == "seed-minio":
        return seed_minio_canaries()
    if name == "create-worker-subject":
        return create_worker_subject()
    if name == "bind":
        from oauth2_provider.models import get_access_token_model, get_grant_model

        subject = users()["a"]
        require(
            not get_access_token_model().objects.filter(user=subject).exists()
            and not get_grant_model().objects.filter(user=subject).exists(),
            "browser_fixture_unbound_credential_issued",
        )
        outcomes = {}
        for label, user in users().items():
            target, outcomes[label] = execute(user, Operation.Action.BIND)
            require(
                binding_matches(target, user)
                and ServiceIdentity.objects.filter(
                    user=user, service__slug=fixture_service()
                ).count()
                == 1,
                "browser_fixture_binding_not_published",
            )
        return {
            "engine_bind_published": True,
            "unbound_auth_credentials_absent": True,
            "native_outcomes": outcomes,
            "phase_complete": all(
                value["phase_complete"] for value in outcomes.values()
            ),
            "ready_for_browser": all(
                value["ready_for_browser"] for value in outcomes.values()
            ),
            "identities": ServiceIdentity.objects.count(),
        }
    if name in {"revoke", "grant"}:
        return central("update", name == "grant")
    if name in {"deactivate", "reactivate"}:
        return central(name)
    if name in {"block", "block-deactivated", "enable", "enable-reactivated"}:
        action = (
            Operation.Action.BLOCK
            if name.startswith("block")
            else Operation.Action.ENABLE
        )
        target, outcome = execute(users()["a"], action)
        require(
            target.identity_id is not None
            and target.identity.external_id == target.native_id,
            "browser_fixture_binding_changed",
        )
        return {
            "native_step": action,
            "observed": target.observed,
            "identity_preserved": True,
            "native_outcome": outcome,
            "phase_complete": outcome["phase_complete"],
            "ready_for_browser": outcome["ready_for_browser"],
        }
    raise RuntimeError("browser_fixture_unknown_phase")


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 2, "browser_fixture_phase_required")
        setup()
        result = phase(sys.argv[1])
        complete = result.get("phase_complete", True) is True
        print(
            json.dumps({"ok": complete, "phase": sys.argv[1], **result}, sort_keys=True)
        )
        if not complete:
            raise SystemExit(3)
    except Exception:
        print('{"ok":false,"code":"browser_fixture_control_failed"}')
        raise SystemExit(1) from None
