"""Offline boundary tests; no native IO or dedicated-settings override."""

from copy import deepcopy
from dataclasses import replace
import importlib
import io
import os
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID

from django.test import SimpleTestCase

from .vendor_fixtures import worker_probe as probe
from .worker_config import InstanceConfig, WorkerConfig
from .worker_profiles import PROFILES


class WorkerProbeFixtureTests(SimpleTestCase):
    fixture_run = "0123456789abcdef0123456789abcdef"

    def environment(self):
        return {
            "DJANGO_SETTINGS_MODULE": "auth.worker_settings",
            "DJANGO_DEBUG": "false",
            "SSO_ENABLED": "false",
            "USER_ADMIN_WORKER_ENABLED": "1",
        }

    def settings(self):
        return SimpleNamespace(
            SETTINGS_MODULE="auth.worker_settings",
            DEBUG=False,
            SSO_ENABLED=False,
            USER_ADMIN_API_ENABLED=False,
            USER_ADMIN_WORKER_ENABLED=True,
            USER_ADMIN_NATIVE_EXECUTION_ENABLED=True,
            ROOT_URLCONF="auth.worker_urls",
            OAUTH2_PROVIDER={"OIDC_RSA_PRIVATE_KEY": "", "OIDC_ENABLED": False},
            DATABASES={
                "default": {
                    "ENGINE": "django.db.backends.postgresql_psycopg2",
                    "NAME": "user_admin_browser_fixture",
                    "USER": "user_admin_browser_fixture",
                    "HOST": "127.0.0.1",
                    "PORT": "15432",
                }
            },
        )

    def record(self):
        return {
            "run": self.fixture_run,
            "service": "minio",
            "user_id": 4,
            "actor_id": 1,
            "change_id": str(UUID(int=11)),
            "target_id": str(UUID(int=12)),
            "operation_id": str(UUID(int=13)),
            "before": {},
            "controls": {
                label: {
                    "user_id": user_id,
                    "target_id": str(UUID(int=user_id)),
                    "native_id": "ua-" + UUID(int=user_id).hex,
                    "canary_sha256": "a" * 64,
                }
                for label, user_id in [("a", 2), ("b", 3)]
            },
        }

    def config(self):
        return WorkerConfig(
            "/fixture-worker/private",
            (
                InstanceConfig(
                    "minio",
                    "primary",
                    probe.ORIGIN,
                    probe.PROFILE,
                    (
                        ("access_key_file", "root-user"),
                        ("secret_key_file", "root-password"),
                    ),
                    ca_file="ca.crt",
                ),
            ),
            "provision_only",
        )

    def test_import_is_inert(self):
        before = dict(os.environ)
        with patch("os.open") as opened, patch("django.setup") as setup:
            importlib.reload(probe)
        opened.assert_not_called()
        setup.assert_not_called()
        self.assertEqual(dict(os.environ), before)

    def test_exact_environment_and_no_issuer_key_even_empty(self):
        probe.validate_environment(self.environment(), 1000)
        for key in self.environment():
            for value in [None, "", "true", "auth.settings"]:
                environ = self.environment()
                environ[key] = value
                with (
                    self.subTest(key=key, value=value),
                    self.assertRaises(RuntimeError),
                ):
                    probe.validate_environment(environ, 1000)
        for key in ["SSO_RSA_PRIVATE_KEY", "SSO_RSA_PRIVATE_KEY_FILE"]:
            for value in ["", "synthetic-unused"]:
                with (
                    self.subTest(key=key, value=value),
                    self.assertRaises(RuntimeError),
                ):
                    probe.validate_environment({**self.environment(), key: value}, 1000)
        with self.assertRaises(RuntimeError):
            probe.validate_environment(self.environment(), 0)

    def test_bad_environment_stops_before_marker_django_and_database(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(probe, "reserve_started") as started,
            patch("django.setup") as setup,
            patch("sys.stdout", new_callable=io.StringIO) as output,
        ):
            self.assertEqual(probe.main(), 1)
        started.assert_not_called()
        setup.assert_not_called()
        self.assertEqual(
            output.getvalue(), '{"ok":false,"code":"worker_fixture_probe_failed"}\n'
        )

    def test_actual_settings_database_routes_and_issuer_are_exact(self):
        probe.validate_settings(self.settings(), [])
        for key in ["ENGINE", "NAME", "USER", "HOST", "PORT"]:
            settings = self.settings()
            settings.DATABASES["default"][key] = "wrong"
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                probe.validate_settings(settings, [])
        for key, value in [
            ("SETTINGS_MODULE", "auth.settings"),
            ("DEBUG", True),
            ("SSO_ENABLED", True),
            ("USER_ADMIN_API_ENABLED", True),
            ("USER_ADMIN_WORKER_ENABLED", False),
            ("USER_ADMIN_NATIVE_EXECUTION_ENABLED", False),
            ("ROOT_URLCONF", "auth.urls"),
            (
                "OAUTH2_PROVIDER",
                {"OIDC_RSA_PRIVATE_KEY": "not-empty", "OIDC_ENABLED": False},
            ),
        ]:
            settings = self.settings()
            setattr(settings, key, value)
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                probe.validate_settings(settings, [])
        with self.assertRaises(RuntimeError):
            probe.validate_settings(self.settings(), [object()])

    def test_record_is_strict_run_scoped_and_has_no_password_slot(self):
        probe.validate_record(self.record(), self.fixture_run)
        for key, value in [
            ("run", str(UUID(hex=self.fixture_run))),
            ("service", "matrix"),
            ("user_id", True),
            ("actor_id", 0),
            ("target_id", UUID(int=12).hex),
            ("operation_id", UUID(int=13)),
            ("change_id", "not-a-uuid"),
            ("before", []),
        ]:
            record = self.record()
            record[key] = value
            with self.subTest(key=key), self.assertRaises((RuntimeError, ValueError)):
                probe.validate_record(record, self.fixture_run)
        record = self.record()
        record["password"] = "not-accepted"
        with self.assertRaises(RuntimeError):
            probe.validate_record(record, self.fixture_run)
        for run in [
            self.fixture_run.upper(),
            str(UUID(hex=self.fixture_run)),
            self.fixture_run + "\n",
        ]:
            with self.subTest(run=run), self.assertRaises(RuntimeError):
                probe.validate_record(self.record(), run)

    def test_controls_require_distinct_subjects_owned_native_ids_and_hash_only(self):
        for changes in [
            {"user_id": True},
            {"user_id": 4},
            {"user_id": 1},
            {"target_id": str(UUID(int=12))},
            {"native_id": "foreign"},
            {"canary_sha256": "x" * 64},
            {"password": "not-accepted"},
        ]:
            record = self.record()
            record["controls"]["a"].update(changes)
            with self.subTest(changes=list(changes)), self.assertRaises(RuntimeError):
                probe.validate_record(record, self.fixture_run)
        record = self.record()
        record["controls"]["b"] = deepcopy(record["controls"]["a"])
        with self.assertRaises(RuntimeError):
            probe.validate_record(record, self.fixture_run)

    def test_fixed_origin_profile_scope_and_private_root(self):
        config = self.config()
        probe.validate_config(config)
        for config in [
            replace(config, execution_scope="lifecycle"),
            replace(config, private_root="/other/private"),
            replace(config, instances=config.instances * 2),
            replace(
                config,
                instances=(
                    replace(config.instances[0], origin="https://127.0.0.1:19000"),
                ),
            ),
            replace(
                config, instances=(replace(config.instances[0], instance="secondary"),)
            ),
            replace(config, instances=(replace(config.instances[0], ca_file=""),)),
            replace(
                config,
                instances=(replace(config.instances[0], acceptance_profile="other"),),
            ),
        ]:
            with self.subTest(config=config), self.assertRaises(RuntimeError):
                probe.validate_config(config)

    def test_scope_must_be_explicit_before_real_config_loader(self):
        for document in [b"{}", b'{"execution_scope":"lifecycle"}']:
            with (
                patch("user_admin.worker_config._directory", return_value=71),
                patch("user_admin.worker_config._read_at", return_value=document),
                patch("os.close"),
                patch("user_admin.worker_config.load_config") as loader,
                self.assertRaises(RuntimeError),
            ):
                probe.load_fixture_config()
            loader.assert_not_called()
        with (
            patch("user_admin.worker_config._directory", return_value=71),
            patch(
                "user_admin.worker_config._read_at",
                return_value=b'{"execution_scope":"provision_only"}',
            ),
            patch("os.close"),
            patch(
                "user_admin.worker_config.load_config", return_value=self.config()
            ) as loader,
        ):
            self.assertEqual(probe.load_fixture_config(), self.config())
        loader.assert_called_once_with("/fixture-worker/config/worker.json")

    def test_profile_di_copies_only_chosen_provisioning_gate(self):
        original = dict(PROFILES)
        local = probe.fixture_profiles(PROFILES)
        self.assertEqual(set(local), {probe.PROFILE})
        self.assertIsNot(local[probe.PROFILE], PROFILES[probe.PROFILE])
        self.assertEqual(local[probe.PROFILE].provisioning_blockers, ())
        self.assertEqual(
            local[probe.PROFILE].blockers, PROFILES[probe.PROFILE].blockers
        )
        self.assertEqual(PROFILES, original)
        for name in PROFILES:
            self.assertTrue(PROFILES[name].provisioning_blockers)
        with self.assertRaises(RuntimeError):
            probe.fixture_profiles(local)

    def test_foreign_pending_including_unconfigured_service_is_rejected(self):
        for status in ["pending", "running", "outcome_unknown"]:
            row = SimpleNamespace(
                status=status,
                target=SimpleNamespace(
                    user_id=99, management_paused=False, service="jenkins"
                ),
            )
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                probe.validate_queue_rows([row], 4)
        own = SimpleNamespace(
            status="pending", target=SimpleNamespace(user_id=4, management_paused=False)
        )
        probe.validate_queue_rows([own], 4)
        for status in ["running", "outcome_unknown"]:
            own.status = status
            with self.assertRaises(RuntimeError):
                probe.validate_queue_rows([own], 4)
        own.status = "pending"
        own.target.management_paused = True
        with self.assertRaises(RuntimeError):
            probe.validate_queue_rows([own], 4)

    def test_exclusive_marker_uses_no_retry_and_precedes_django(self):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        with (
            patch("user_admin.worker_config._directory", return_value=71),
            patch(
                "os.fstat", return_value=SimpleNamespace(st_uid=1000, st_mode=0o40700)
            ),
            patch("os.getuid", return_value=1000),
            patch("os.open", side_effect=FileExistsError) as opened,
            patch("os.close") as closed,
        ):
            with self.assertRaises(FileExistsError):
                probe.reserve_started()
        opened.assert_called_once_with("started", flags, 0o600, dir_fd=71)
        closed.assert_called_once_with(71)
        with (
            patch.dict(os.environ, self.environment(), clear=True),
            patch("os.getuid", return_value=1000),
            patch("sys.argv", ["worker_probe"]),
            patch.object(
                probe, "reserve_started", side_effect=FileExistsError("never print")
            ) as started,
            patch("django.setup") as setup,
            patch("sys.stdout", new_callable=io.StringIO) as output,
        ):
            self.assertEqual(probe.main(), 1)
        started.assert_called_once_with()
        setup.assert_not_called()
        self.assertNotIn("never print", output.getvalue())

    def test_expected_partials_require_exact_effect_and_binding(self):
        operation = SimpleNamespace(
            action="bind",
            status="partial",
            error_code="capability_unconfirmed",
            observed="enabled",
            evidence={
                "new_login": "unknown",
                "existing_sessions": "unknown",
                "api_credentials": "unknown",
            },
        )
        target = SimpleNamespace(observed="enabled", identity_id=2)
        result = probe.phase_outcome(operation, target)
        self.assertEqual(
            result,
            {
                "action": "bind",
                "status": "partial",
                "reason": "capability_unconfirmed",
                "observed": "enabled",
            },
        )
        self.assertEqual(set(result), {"action", "status", "reason", "observed"})
        for changes in [
            {"status": "outcome_unknown"},
            {"error_code": "authority_changed"},
            {"observed": "blocked"},
            {"action": "block"},
        ]:
            bad = SimpleNamespace(**{**vars(operation), **changes})
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                probe.phase_outcome(bad, target)
        target.identity_id = None
        with self.assertRaises(RuntimeError):
            probe.phase_outcome(operation, target)

    def test_genuinely_queued_enable_intermediate_and_create_are_distinct(self):
        evidence = dict.fromkeys(
            ["new_login", "existing_sessions", "api_credentials"], "unknown"
        )
        operation = SimpleNamespace(
            action="bind",
            status="partial",
            error_code="native_enable_pending",
            observed="blocked",
            evidence=evidence,
        )
        target = SimpleNamespace(observed="blocked", identity_id=2)
        self.assertEqual(probe.phase_outcome(operation, target)["observed"], "blocked")
        operation.action = "create"
        operation.status = "succeeded"
        operation.error_code = ""
        operation.observed = target.observed = "unbound"
        target.identity_id = None
        self.assertEqual(probe.phase_outcome(operation, target)["action"], "create")
        operation.status = "partial"
        operation.error_code = "capability_unconfirmed"
        with self.assertRaises(RuntimeError):
            probe.phase_outcome(operation, target)
