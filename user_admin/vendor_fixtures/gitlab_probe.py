"""Explicit local exact-GitLab cookie/PAT/Git and persisted-CI fixture.

Host phases supply own fixture-only password seed, SSH and async-worker checks.
No browser/OIDC or real CI script-execution acceptance is implied.
Tokens and native bodies remain in memory or protected fixture tmpfs only.
"""

import base64
from dataclasses import replace
import json
import os
from pathlib import Path
import time
import re
import ssl
import sys
from uuid import uuid4

import django

from .oidc import runtime_directory


class ProbeFailure(Exception):
    """Nonsecret stage code and selected HTTP status only."""


def advertised_refs(body):
    """Compare actual ref IDs, not variable Git transport capabilities/session IDs."""
    offset, values = 0, []
    while offset < len(body):
        if offset + 4 > len(body):
            raise ValueError("invalid_fixture_git_packet")
        size = int(body[offset : offset + 4], 16)
        offset += 4
        if size == 0:
            continue
        if size < 4 or offset + size - 4 > len(body):
            raise ValueError("invalid_fixture_git_packet")
        payload = body[offset : offset + size - 4].split(b"\x00", 1)[0].strip()
        offset += size - 4
        match = re.fullmatch(
            rb"([0-9a-f]{40,64}) (HEAD|refs/[A-Za-z0-9/_.-]+)", payload
        )
        if match:
            values.append((match[1].decode(), match[2].decode()))
    return tuple(sorted(values))


def probe(runtime):
    if os.environ.get("DJANGO_SETTINGS_MODULE") != "auth.test_settings":
        raise ProbeFailure("synthetic_settings_required")
    django.setup()
    from ..adapters import Command
    from ..engine import ControlError
    from ..native.gitlab import GitlabAdapter, Profile
    from ..native.http import NativeHTTP
    from .gitlab_cookie import LocalGitlabSession

    class FixtureHTTP(NativeHTTP):
        last = None

        def request(self, method, target, **kwargs):
            response = super().request(method, target, **kwargs)
            self.last = {
                "method": method,
                "path": target.split("?", 1)[0],
                "status": response.status,
                "content_type": response.content_type[:80],
            }
            return response

    client = FixtureHTTP(
        "https://localhost:19443",
        context=ssl.create_default_context(cafile=str(runtime / "tls/public.crt")),
        timeout=10,
    )
    admin = (runtime / "out/admin-token").read_text().strip()
    baseline = json.loads((runtime / "out/build.json").read_text())
    if baseline != {"version": "18.1.0", "enterprise": False, "gitlab_com": False}:
        raise ProbeFailure("fixture_exact_ce_selfmanaged_required")
    receipts, profiles = {}, {}
    adapter = GitlabAdapter(
        client=client,
        token=admin,
        instance="local-fixture",
        profiles=lambda cmd: profiles[cmd.target_id],
        receipts=lambda cmd: receipts.get(cmd.target_id, ""),
    )

    admission_summary = {}

    def require(condition, code):
        if not condition:
            raise ProbeFailure(
                code, {"last_http": client.last, "admission": admission_summary}
            )

    def api(method, path, payload=None, *, token=admin, expected=(200,)):
        headers = {"PRIVATE-TOKEN": token}
        body = b""
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode()
        response = client.request(method, "/api/v4" + path, headers=headers, body=body)
        if expected is not None:
            require(response.status in expected, "api_status_unexpected")
        return response

    def native(cmd):
        try:
            result = adapter.apply(cmd)
        except Exception as error:
            code = (
                error.code if isinstance(error, ControlError) else type(error).__name__
            )
            raise ProbeFailure(
                "native_" + cmd.action + "_" + code, client.last
            ) from None
        if cmd.action == "block":
            receipts[cmd.target_id] = result.block_receipt
        return result

    def provision(subject, email):
        command = Command(
            uuid4(), uuid4(), subject, "gitlab", "local-fixture", 1, "create", ""
        )
        profiles[command.target_id] = Profile(
            "ua_" + command.target_id.hex[:24], email, "Synthetic Fixture"
        )
        created = native(command)
        bound = replace(
            command, native_id=created.native_id, operation_id=uuid4(), action="bind"
        )
        require(native(bound).binding is not None, "native_binding_missing")
        return bound

    def pat(command):
        # Admin endpoint, scoped only to NEW synthetic subject; never production.
        result = api(
            "POST",
            "/users/" + command.native_id + "/personal_access_tokens",
            {"name": "synthetic-fixture", "scopes": ["api"]},
            expected=(201,),
        ).json()
        require(
            type(result.get("token")) is str and bool(result["token"]), "pat_missing"
        )
        return result["token"]

    def repository(token):
        return api(
            "POST",
            "/projects",
            {
                "name": "synthetic-repository",
                "visibility": "private",
                "initialize_with_readme": True,
            },
            token=token,
            expected=(201,),
        ).json()

    def refs(command, project, token):
        authorization = base64.b64encode(
            (profiles[command.target_id].username + ":" + token).encode()
        ).decode()
        return client.request(
            "GET",
            "/"
            + project["path_with_namespace"]
            + ".git/info/refs?service=git-upload-pack",
            headers={"Authorization": "Basic " + authorization},
        )

    def stable(command):
        user = api("GET", "/users/" + command.native_id).json()
        return {
            key: user.get(key)
            for key in [
                "id",
                "username",
                "email",
                "is_admin",
                "identities",
                "note",
                "confirmed_at",
                "created_at",
            ]
        }

    setting = api("GET", "/application/settings").json()
    require(
        setting.get("enforce_email_subaddress_restrictions") is False,
        "email_subaddress_setting_not_explicit_false",
    )

    def host_phase(phase, payload):
        directory = Path("/fixture-out")
        requested = directory / "phase-request.json"
        temporary = directory / "phase-request.part"
        temporary.write_text(json.dumps({"phase": phase, **payload}))
        temporary.chmod(0o600)
        temporary.replace(requested)
        deadline = time.monotonic() + 130
        while time.monotonic() < deadline:
            try:
                answer = json.loads(
                    (directory / ("phase-" + phase + ".json")).read_text()
                )
                require(
                    answer.get("phase") == phase and answer.get("ok") is True,
                    "host_phase_" + phase + "_failed",
                )
                return answer
            except (FileNotFoundError, PermissionError):
                time.sleep(0.1)
        raise ProbeFailure("host_phase_" + phase + "_timeout")

    def setup_ci(command, project, token):
        project_path = "/projects/" + str(project["id"])
        api(
            "POST",
            project_path + "/repository/files/.gitlab-ci.yml",
            {
                "branch": project["default_branch"],
                "commit_message": "synthetic CI fixture",
                "content": "\n".join(
                    [
                        "stages: [test]",
                        "pending_job:",
                        "  stage: test",
                        "  script: ['true']",
                        "running_job:",
                        "  stage: test",
                        "  script: ['true']",
                        "",
                    ]
                ),
            },
            token=token,
            expected=(201,),
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            rows = api("GET", project_path + "/jobs").json()
            if sum(row["status"] == "pending" for row in rows) >= 2:
                break
            time.sleep(0.3)
        else:
            raise ProbeFailure("ci_pending_jobs_missing")
        runner = api(
            "POST",
            "/user/runners",
            {
                "runner_type": "project_type",
                "project_id": project["id"],
                "description": "synthetic-fixture",
                "run_untagged": True,
            },
            expected=(201,),
        ).json()
        body = json.dumps(
            {
                "token": runner["token"],
                "system_id": "s_" + command.target_id.hex,
                "info": {
                    "name": "synthetic-runner",
                    "version": "18.1.0",
                    "revision": "fixture",
                    "platform": "linux",
                    "architecture": "amd64",
                    "executor": "shell",
                    "features": {},
                },
            }
        ).encode()
        claimed = client.request(
            "POST",
            "/api/v4/jobs/request",
            headers={"Content-Type": "application/json"},
            body=body,
        )
        require(claimed.status == 201, "ci_runner_job_not_claimed")
        rows = api("GET", project_path + "/jobs").json()
        require(
            any(row["status"] == "running" for row in rows)
            and any(row["status"] == "pending" for row in rows),
            "ci_running_pending_baseline_missing",
        )
        schedule = api(
            "POST",
            project_path + "/pipeline_schedules",
            {
                "description": "synthetic-future-schedule",
                "ref": project["default_branch"],
                "cron": "0 0 1 1 *",
                "cron_timezone": "UTC",
                "active": True,
            },
            token=token,
            expected=(201,),
        ).json()
        return schedule["id"]

    def ci_snapshot(project, schedule_id):
        path = "/projects/" + str(project["id"])
        jobs = api("GET", path + "/jobs").json()
        pipelines = api("GET", path + "/pipelines").json()
        schedule = api("GET", path + "/pipeline_schedules/" + str(schedule_id)).json()
        return {
            "jobs": sorted(
                (
                    row["id"],
                    row["status"],
                    row.get("failure_reason"),
                    row["pipeline"]["id"],
                    row["user"]["id"],
                )
                for row in jobs
            ),
            "pipelines": sorted(
                (row["id"], row["status"], row["sha"], row["ref"]) for row in pipelines
            ),
            "schedule": {
                **{
                    key: schedule.get(key)
                    for key in [
                        "id",
                        "active",
                        "ref",
                        "cron",
                        "cron_timezone",
                        "next_run_at",
                    ]
                },
                "owner_id": schedule["owner"]["id"],
            },
        }

    first = provision(1003, "synthetic@example.test")
    control = provision(1004, "synthetic+control@example.test")
    key_a, key_b = pat(first), pat(control)
    require(
        str(api("GET", "/user", token=key_a).json()["id"]) == first.native_id,
        "baseline_pat_user_mismatch",
    )
    project_a, project_b = repository(key_a), repository(key_b)
    baseline_refs_a, baseline_refs_b = refs(first, project_a, key_a), refs(
        control, project_b, key_b
    )
    require(
        baseline_refs_a.status == baseline_refs_b.status == 200
        and b"git-upload-pack" in baseline_refs_a.body
        and b"git-upload-pack" in baseline_refs_b.body,
        "baseline_git_https_refs_failed",
    )
    refs_a, refs_b = advertised_refs(baseline_refs_a.body), advertised_refs(
        baseline_refs_b.body
    )
    require(bool(refs_a) and bool(refs_b), "baseline_repository_ref_ids_missing")
    for label, cmd in [("a", first), ("b", control)]:
        key = (runtime / "keys" / (label + ".pub")).read_text()
        api(
            "POST",
            "/users/" + cmd.native_id + "/keys",
            {"title": "synthetic-fixture", "key": key},
            expected=(201,),
        )
    host_payload = {
        "a": {
            "id": first.native_id,
            "marker": adapter.marker(first),
            "repository": project_a["path_with_namespace"],
        },
        "b": {
            "id": control.native_id,
            "marker": adapter.marker(control),
            "repository": project_b["path_with_namespace"],
        },
    }
    host_phase("seed", host_payload)
    # Fixture-only password seeding precedes the preserved-credential baseline.
    key_a, key_b = pat(first), pat(control)
    password_a = Path("/fixture-out/password-a").read_text()
    password_b = Path("/fixture-out/password-b").read_text()
    session_a, session_b = LocalGitlabSession(client.context), LocalGitlabSession(
        client.context
    )
    session_a.login(profiles[first.target_id].username, password_a)
    session_b.login(profiles[control.target_id].username, password_b)
    require(
        str(session_a.request("/api/v4/user").json()["id"]) == first.native_id,
        "baseline_cookie_a_failed",
    )
    require(
        str(session_b.request("/api/v4/user").json()["id"]) == control.native_id,
        "baseline_cookie_b_failed",
    )
    cookie_data_a = (
        "/api/v4/projects/"
        + str(project_a["id"])
        + "/repository/files/README.md/raw?ref="
        + project_a["default_branch"]
    )
    cookie_data_b = (
        "/api/v4/projects/"
        + str(project_b["id"])
        + "/repository/files/README.md/raw?ref="
        + project_b["default_branch"]
    )
    baseline_cookie_a, baseline_cookie_b = session_a.request(
        cookie_data_a
    ), session_b.request(cookie_data_b)
    require(
        baseline_cookie_a.status == baseline_cookie_b.status == 200
        and bool(baseline_cookie_a.body)
        and bool(baseline_cookie_b.body),
        "baseline_cookie_private_data_failed",
    )
    schedule_a, schedule_b = setup_ci(first, project_a, key_a), setup_ci(
        control, project_b, key_b
    )
    ci_a, ci_b = ci_snapshot(project_a, schedule_a), ci_snapshot(project_b, schedule_b)
    group_a = api(
        "POST",
        "/groups",
        {"name": "Synthetic A", "path": "group_" + first.target_id.hex},
        token=key_a,
        expected=(201,),
    ).json()["id"]
    group_b = api(
        "POST",
        "/groups",
        {"name": "Synthetic B", "path": "group_" + control.target_id.hex},
        token=key_b,
        expected=(201,),
    ).json()["id"]
    api(
        "POST",
        f"/groups/{group_a}/members",
        {"user_id": int(control.native_id), "access_level": 40},
        token=key_a,
        expected=(201,),
    )
    api(
        "POST",
        f"/groups/{group_b}/members",
        {"user_id": int(first.native_id), "access_level": 30},
        token=key_b,
        expected=(201,),
    )

    def memberships():
        result = []
        for group in [group_a, group_b]:
            for command in [first, control]:
                member = api(
                    "GET", f"/groups/{group}/members/{command.native_id}"
                ).json()
                result.append(
                    (
                        group,
                        member["id"],
                        member["access_level"],
                        member.get("expires_at"),
                    )
                )
        return sorted(result)

    original_memberships = memberships()
    # CI setup intentionally commits .gitlab-ci.yml. Preserve the completed
    # baseline, not the earlier initial README-only repository state.
    refs_a, refs_b = advertised_refs(
        refs(first, project_a, key_a).body
    ), advertised_refs(refs(control, project_b, key_b).body)
    host_phase("baseline", host_payload)
    stable_a, stable_b = stable(first), stable(control)
    original_cookie_a = session_a.frozen_copy()
    blocked = replace(first, action="block", generation=2, operation_id=uuid4())
    native(blocked)
    host_phase("ban", host_payload)
    admission_findings = []
    cookie_self_while_banned = (
        original_cookie_a.frozen_copy().request("/api/v4/user").status
    )
    cookie_data_while_banned = original_cookie_a.frozen_copy().request(cookie_data_a)
    if (
        cookie_data_while_banned.status not in {401, 403, 404}
        or cookie_data_while_banned.body == baseline_cookie_a.body
    ):
        admission_findings.append("old_cookie_protected_data_not_denied")
    fresh_banned = LocalGitlabSession(client.context)
    fresh_banned.login(profiles[first.target_id].username, password_a)
    fresh_login_self = fresh_banned.request("/api/v4/user").status
    if fresh_login_self not in {401, 403}:
        admission_findings.append("fresh_password_login_not_denied")
    admission_summary.update(
        {
            "findings": admission_findings,
            "cookie_data_status": cookie_data_while_banned.status,
            "cookie_data_equal": cookie_data_while_banned.body
            == baseline_cookie_a.body,
            "fresh_password_login_self_status": fresh_login_self,
        }
    )
    require(
        str(session_b.request("/api/v4/user").json()["id"]) == control.native_id,
        "control_cookie_affected",
    )
    require(
        session_b.request(cookie_data_b).body == baseline_cookie_b.body,
        "control_cookie_private_data_affected",
    )
    require(
        ci_snapshot(project_a, schedule_a) == ci_a
        and ci_snapshot(project_b, schedule_b) == ci_b,
        "ci_state_changed_while_banned",
    )
    denied_pat = api("GET", "/user", token=key_a, expected=None)
    require(denied_pat.status in {401, 403}, "old_pat_not_denied")
    require(
        str(api("GET", "/user", token=key_b).json()["id"]) == control.native_id,
        "control_pat_affected",
    )
    require(
        refs(first, project_a, key_a).status in {401, 403}, "git_https_refs_not_denied"
    )
    require(refs(control, project_b, key_b).status == 200, "control_git_https_affected")
    require(
        stable(first) == stable_a and stable(control) == stable_b,
        "stable_native_user_changed",
    )
    require(
        api("GET", "/users/" + control.native_id).json()["state"] == "active",
        "control_user_banned",
    )
    enabled = replace(first, action="enable", generation=3, operation_id=uuid4())
    native(enabled)
    host_phase("enable", host_payload)
    old_cookie_after = original_cookie_a.frozen_copy().request("/api/v4/user").status
    fresh_enabled = LocalGitlabSession(client.context)
    fresh_enabled.login(profiles[first.target_id].username, password_a)
    require(
        str(fresh_enabled.request("/api/v4/user").json()["id"]) == first.native_id,
        "original_password_not_preserved",
    )
    require(
        ci_snapshot(project_a, schedule_a) == ci_a
        and ci_snapshot(project_b, schedule_b) == ci_b,
        "ci_state_changed_after_unban",
    )
    require(
        memberships() == original_memberships,
        "original_group_memberships_or_roles_changed",
    )
    require(
        str(api("GET", "/user", token=key_a).json()["id"]) == first.native_id,
        "original_pat_not_restored",
    )
    require(
        advertised_refs(refs(first, project_a, key_a).body) == refs_a,
        "original_git_refs_not_preserved",
    )
    require(
        advertised_refs(refs(control, project_b, key_b).body) == refs_b,
        "control_git_refs_not_preserved",
    )
    require(
        stable(first) == stable_a and stable(control) == stable_b,
        "original_native_user_not_preserved",
    )
    return {
        "ok": not admission_findings,
        "admission_findings": admission_findings,
        "cookie_private_repository_status_while_banned": cookie_data_while_banned.status,
        "cookie_private_repository_bytes_equal_while_banned": cookie_data_while_banned.body
        == baseline_cookie_a.body,
        "fresh_login_self_status_while_banned": fresh_login_self,
        "scope": "isolated exact-image GitLab HTTP-cookie/PAT/Git/CI-state fixture",
        "api_version": "18.1.0",
        "enterprise": False,
        "gitlab_com": False,
        "email_subaddress_restrictions_explicit_false": True,
        "candidate_create_bind_ban_unban": True,
        "old_pat_and_git_https_refs_denied_while_banned": True,
        "same_pat_and_repository_refs_restore_after_unban": True,
        "control_user_and_ids_roles_bindings_preserved": True,
        "original_group_memberships_and_access_levels_preserved": True,
        "password_login_and_original_cookie_private_data_denied_while_banned": not admission_findings,
        "original_password_and_keys_preserved": True,
        "old_cookie_status_after_unban": old_cookie_after,
        "cookie_self_endpoint_status_while_banned": cookie_self_while_banned,
        "ssh_baseline_ban_enable_same_keys": True,
        "ci_pending_running_claimed_jobs_and_active_schedules_preserved": True,
        "real_ci_script_execution": "not_claimed",
        "duplicate_worker_completion_observed": True,
        "actual_browser_oidc": "not_tested",
        "permanent_credential_revocation": "not_claimed",
    }


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ProbeFailure("synthetic_runtime_required")
        result = probe(runtime_directory(sys.argv[1]))
    except Exception as error:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error_type": type(error).__name__,
                    "code": (
                        error.args[0]
                        if type(error) is ProbeFailure
                        else "native_probe_failed"
                    ),
                    "diagnostic": (
                        error.args[1]
                        if type(error) is ProbeFailure and len(error.args) > 1
                        else None
                    ),
                }
            )
        )
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))
    if result.get("ok") is not True:
        raise SystemExit(1)
