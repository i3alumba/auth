import copy
import json
import os
from pathlib import Path
import tempfile

from django.test import SimpleTestCase

from .worker_config import WorkerError, load_config, load_private_snapshot


class WorkerConfigTests(SimpleTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/dev/shm")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.path = self.root / "worker.json"
        self.data = {
            "schema_version": 1,
            "private_root": str(self.private),
            "instances": [
                {
                    "service": "gitlab",
                    "instance": "primary",
                    "origin": "https://gitlab.example.invalid",
                    "acceptance_profile": "gitlab-18.1.0-ce-ban-v1",
                    "credentials": {"token_file": "gitlab-token"},
                }
            ],
        }

    def config(self, data=None):
        self.path.write_text(json.dumps(self.data if data is None else data))
        return load_config(str(self.path))

    def secret(self, value=b"SYNTHETIC_TOKEN_NOT_A_SECRET\n", name="gitlab-token"):
        path = self.private / name
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    def test_preview_does_not_require_or_read_credentials(self):
        config = self.config()
        self.assertEqual(config.instances[0].service, "gitlab")
        self.assertFalse(list(self.private.iterdir()))

    def test_scope_defaults_narrow_and_requires_known_explicit_values(self):
        self.assertEqual(self.config().execution_scope, "provision_only")
        for scope in ("provision_only", "lifecycle"):
            self.assertEqual(
                self.config({**self.data, "execution_scope": scope}).execution_scope,
                scope,
            )
        for scope in (None, True, [], "", "all"):
            with self.subTest(scope=scope), self.assertRaises(WorkerError):
                self.config({**self.data, "execution_scope": scope})

    def test_bounded_private_snapshot_with_single_trailing_newline(self):
        self.secret()
        snapshot = load_private_snapshot(self.config())
        self.assertEqual(
            snapshot[("gitlab", "primary")]["token_file"],
            "SYNTHETIC_TOKEN_NOT_A_SECRET",
        )

    def test_unknown_keys_duplicate_pairs_and_profile_mismatch(self):
        for change in [
            lambda d: d.update(execute=True),
            lambda d: d["instances"].append(copy.deepcopy(d["instances"][0])),
            lambda d: d["instances"][0].update(
                acceptance_profile="minio-2023-05-18-owned-s3-v1"
            ),
            lambda d: d["instances"][0].update(service="jenkins"),
            lambda d: d["instances"][0]["credentials"].update(
                token="SYNTHETIC_LITERAL"
            ),
        ]:
            data = copy.deepcopy(self.data)
            change(data)
            with self.subTest(data=list(data)), self.assertRaises(WorkerError):
                self.config(data)

    def test_json_duplicate_nonfinite_and_boolean_version_rejected(self):
        for raw in [
            '{"schema_version":1,"schema_version":1}',
            '{"schema_version":NaN}',
            json.dumps({**self.data, "schema_version": True}),
        ]:
            self.path.write_text(raw)
            with self.subTest(raw=raw[:25]), self.assertRaises(WorkerError):
                load_config(str(self.path))

    def test_fixed_verified_origin_shape(self):
        for origin in [
            "http://localhost",
            "https://user:pass@localhost",
            "https://localhost/prefix",
            "https://localhost/?q=1",
            "https://localhost/#fragment",
            "https://localhost:0",
            "https://localhost:65536",
            "https://local\\host",
            "https://local\nhost",
        ]:
            data = copy.deepcopy(self.data)
            data["instances"][0]["origin"] = origin
            with self.subTest(origin=origin), self.assertRaises(WorkerError):
                self.config(data)

    def test_secret_names_cannot_escape_private_root(self):
        for filename in ["../token", "/tmp/token", "sub/token", ".", "..", True]:
            data = copy.deepcopy(self.data)
            data["instances"][0]["credentials"]["token_file"] = filename
            with self.subTest(filename=filename), self.assertRaises(WorkerError):
                self.config(data)

    def test_symlink_secret_and_hardlink_are_rejected(self):
        outside = self.secret(name="outside")
        path = self.private / "gitlab-token"
        path.symlink_to(outside)
        with self.assertRaises(WorkerError):
            load_private_snapshot(self.config())
        path.unlink()
        os.link(outside, path)
        with self.assertRaises(WorkerError):
            load_private_snapshot(self.config())

    def test_permissions_regular_files_and_limits(self):
        path = self.secret()
        for mode, raw in [
            (0o644, b"PUBLIC_SYNTHETIC"),
            (0o600, b"x" * 16385),
            (0o600, b""),
            (0o600, b"embedded\nnewline"),
            (0o600, b"double\n\n"),
        ]:
            path.write_bytes(raw)
            path.chmod(mode)
            with self.subTest(mode=mode, size=len(raw)), self.assertRaises(WorkerError):
                load_private_snapshot(self.config())
        path.unlink()
        os.mkfifo(path, mode=0o600)
        with self.assertRaises(WorkerError):
            load_private_snapshot(self.config())

    def test_private_root_symlink_or_writable_parent_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.private)
        for root in [str(alias), str(self.private) + "/../private"]:
            with self.subTest(root=root), self.assertRaises(WorkerError):
                self.config({**self.data, "private_root": root})
        self.private.chmod(0o755)
        with self.assertRaises(WorkerError):
            self.config()

    def test_config_symlink_and_overlong_config_rejected(self):
        self.config()
        alias = self.root / "linked.json"
        alias.symlink_to(self.path)
        with self.assertRaises(WorkerError):
            load_config(str(alias))
        self.path.write_bytes(b" " * 65537)
        with self.assertRaises(WorkerError):
            load_config(str(self.path))

    def test_matrix_server_and_credential_schema(self):
        data = copy.deepcopy(self.data)
        data["instances"][0] = {
            "service": "matrix",
            "instance": "primary",
            "origin": "https://matrix.example.invalid",
            "acceptance_profile": "synapse-1.164.1-lock-v1",
            "server_name": "matrix.example.invalid",
            "credentials": {
                "token_file": "matrix-token",
                "registration_secret_file": "matrix-registration",
            },
        }
        self.assertEqual(
            self.config(data).instances[0].server_name, "matrix.example.invalid"
        )
        del data["instances"][0]["server_name"]
        with self.assertRaises(WorkerError):
            self.config(data)
