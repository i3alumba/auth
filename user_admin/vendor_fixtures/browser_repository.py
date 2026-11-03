"""Private README canary only for provenance-confirmed NEW GitLab fixture users."""

import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import time
from urllib.parse import quote

from ..native.http import NativeHTTP


def require(condition, code):
    if condition is not True:
        raise RuntimeError(code)


def create_private_repository(client, target, admin_token):
    require(
        target.ownership == "created"
        and target.creation_operation_id is not None
        and target.creation_operation.target_id == target.pk
        and re.fullmatch(r"[1-9][0-9]*", target.native_id) is not None,
        "browser_fixture_repository_owner_required",
    )

    def request(method, path, *, token=admin_token, data=None, expected=200):
        reply = client.request(
            method,
            "/api/v4" + path,
            headers={
                "PRIVATE-TOKEN": token,
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
            body=(
                json.dumps(data, separators=(",", ":")).encode()
                if data is not None
                else b""
            ),
        )
        require(reply.status == expected, "browser_fixture_repository_request_failed")
        return reply

    user = request("GET", "/users/" + target.native_id).json()
    marker = "user-admin-v1:" + json.dumps(
        {
            "owner": str(target.pk),
            "subject": str(target.user_id),
            "instance": target.instance,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    require(
        type(user) is dict
        and str(user.get("id")) == target.native_id
        and user.get("is_admin") is False
        and user.get("note") == marker,
        "browser_fixture_repository_owner_mismatch",
    )
    token = (
        request(
            "POST",
            "/users/" + target.native_id + "/personal_access_tokens",
            data={"name": "isolated-browser-fixture", "scopes": ["api"]},
            expected=201,
        )
        .json()
        .get("token")
    )
    require(
        type(token) is str and bool(token), "browser_fixture_repository_token_missing"
    )
    project = request(
        "POST",
        "/projects",
        token=token,
        data={
            "name": "fixture-browser-data",
            "visibility": "private",
            "initialize_with_readme": True,
        },
        expected=201,
    ).json()
    require(
        type(project) is dict
        and type(project.get("id")) is int
        and project["id"] > 0
        and project.get("visibility") == "private"
        and str(project.get("owner", {}).get("id")) == target.native_id,
        "browser_fixture_project_owner_mismatch",
    )
    branch = project.get("default_branch")
    require(
        type(branch) is str
        and re.fullmatch(r"[a-zA-Z0-9_/-]{1,100}", branch) is not None,
        "browser_fixture_branch_invalid",
    )
    path = (
        "/api/v4/projects/"
        + str(project["id"])
        + "/repository/files/README.md/raw?ref="
        + quote(branch, safe="")
    )
    body = b""
    for attempt in range(50):
        reply = client.request("GET", path, headers={"PRIVATE-TOKEN": token})
        if reply.status == 200:
            body = reply.body
            break
        require(reply.status == 404, "browser_fixture_readme_failed")
        time.sleep(0.1)
    require(bool(body), "browser_fixture_readme_missing")
    return {
        "private_url": "https://localhost:19443" + path,
        "private_data_sha256": hashlib.sha256(body).hexdigest(),
    }


def owned_fixture_repository(target):
    require(
        os.environ.get("DJANGO_SETTINGS_MODULE")
        == "user_admin.vendor_fixtures.browser_settings",
        "browser_fixture_settings_required",
    )
    client = NativeHTTP(
        "https://localhost:19443",
        context=ssl.create_default_context(cafile="/fixture-idp/ca.crt"),
    )
    return create_private_repository(
        client, target, Path("/fixture-native/admin-token").read_text()
    )
