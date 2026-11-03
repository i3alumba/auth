import hashlib
import json
from types import SimpleNamespace
from uuid import uuid4

from django.test import SimpleTestCase

from .vendor_fixtures.browser_repository import create_private_repository


class BrowserRepositoryFixtureTests(SimpleTestCase):
    def fixture(self, *, foreign_marker=False, admin=False, project_owner=9001):
        key = uuid4()
        target = SimpleNamespace(
            pk=key,
            user_id=42,
            instance="primary",
            native_id="9001",
            ownership="created",
            creation_operation_id=uuid4(),
            creation_operation=SimpleNamespace(target_id=key),
        )
        marker = "user-admin-v1:" + json.dumps(
            {"owner": str(key), "subject": "42", "instance": "primary"},
            sort_keys=True,
            separators=(",", ":"),
        )
        data = [
            {
                "id": 9001,
                "is_admin": admin,
                "note": "foreign" if foreign_marker else marker,
            },
            {"token": "PUBLIC_FIXTURE_USER_TOKEN"},
            {
                "id": 8001,
                "visibility": "private",
                "owner": {"id": project_owner},
                "default_branch": "main",
            },
            None,
        ]
        calls = []

        def request(method, path, **kwargs):
            calls.append((method, path, kwargs))
            value = data[len(calls) - 1]
            return SimpleNamespace(
                status=201 if method == "POST" else 200,
                json=lambda: value,
                body=b"PUBLIC_FIXTURE_README",
            )

        return target, SimpleNamespace(request=request), calls

    def test_only_data_hash_and_private_resource_url_returned(self):
        target, client, calls = self.fixture()
        result = create_private_repository(client, target, "PUBLIC_FIXTURE_ADMIN")
        self.assertEqual(
            result["private_data_sha256"],
            hashlib.sha256(b"PUBLIC_FIXTURE_README").hexdigest(),
        )
        self.assertEqual(
            result["private_url"],
            "https://localhost:19443/api/v4/projects/8001/repository/files/README.md/raw?ref=main",
        )
        self.assertNotIn("TOKEN", json.dumps(result))
        self.assertEqual(len(calls), 4)
        self.assertEqual(json.loads(calls[2][2]["body"])["visibility"], "private")

    def test_unmanaged_or_wrong_creation_provenance_never_mints_token(self):
        for change in ["unmanaged", "wrong_provenance"]:
            target, client, calls = self.fixture()
            if change == "unmanaged":
                target.ownership = "unmanaged"
            else:
                target.creation_operation.target_id = uuid4()
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                create_private_repository(client, target, "PUBLIC_FIXTURE_ADMIN")
            self.assertEqual(calls, [])

    def test_native_marker_or_admin_mismatch_stops_before_token(self):
        for options in [{"foreign_marker": True}, {"admin": True}]:
            target, client, calls = self.fixture(**options)
            with self.subTest(options=options), self.assertRaises(RuntimeError):
                create_private_repository(client, target, "PUBLIC_FIXTURE_ADMIN")
            self.assertEqual(len(calls), 1)

    def test_project_in_other_namespace_never_becomes_readiness(self):
        target, client, calls = self.fixture(project_owner=7)
        with self.assertRaisesMessage(
            RuntimeError, "browser_fixture_project_owner_mismatch"
        ):
            create_private_repository(client, target, "PUBLIC_FIXTURE_ADMIN")
        self.assertEqual(len(calls), 3)
