import importlib
import io
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings


class WorkerCommandTests(TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/dev/shm")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        private = self.root / "private"
        private.mkdir(mode=0o700)
        self.path = self.root / "worker.json"
        self.path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "private_root": str(private),
                    "instances": [
                        {
                            "service": "gitlab",
                            "instance": "primary",
                            "origin": "https://gitlab.example.invalid",
                            "acceptance_profile": "gitlab-18.1.0-ce-ban-v1",
                            "credentials": {"token_file": "absent-token"},
                        }
                    ],
                }
            )
        )

    def command(self, *args):
        output = io.StringIO()
        call_command(
            "user_admin_worker",
            "--config",
            str(self.path),
            *args,
            stdout=output,
            stderr=output,
        )
        return output.getvalue()

    def test_default_is_once_preview_with_no_credentials_or_transport(self):
        with (
            patch(
                "user_admin.management.commands.user_admin_worker.load_private_snapshot"
            ) as loader,
            patch("user_admin.worker_runtime.NativeHTTP") as transport,
        ):
            output = self.command()
        loader.assert_not_called()
        transport.assert_not_called()
        summary = json.loads(output.splitlines()[0])
        self.assertEqual(summary["mode"], "dry_run")
        self.assertEqual(summary["credentials"], "unchecked")
        self.assertNotIn("origin", output)

    def test_web_settings_reject_execution_before_credential_loading(self):
        with (
            patch(
                "user_admin.management.commands.user_admin_worker.load_private_snapshot"
            ) as loader,
            self.assertRaisesMessage(CommandError, "worker_execution_disabled"),
        ):
            self.command("--execute")
        loader.assert_not_called()

    @override_settings(
        SETTINGS_MODULE="auth.worker_settings",
        USER_ADMIN_WORKER_ENABLED=True,
        USER_ADMIN_NATIVE_EXECUTION_ENABLED=True,
    )
    def test_dedicated_settings_opt_in_cannot_clear_profile_gate(self):
        with (
            patch(
                "user_admin.management.commands.user_admin_worker.load_private_snapshot"
            ) as loader,
            self.assertRaisesMessage(CommandError, "profile_activation_blocked"),
        ):
            self.command("--execute")
        loader.assert_not_called()

    def test_operational_failure_has_no_exception_or_secret_output(self):
        secret = "SYNTHETIC_NATIVE_TOKEN_NEVER_PRINT"
        output = io.StringIO()
        with patch(
            "user_admin.management.commands.user_admin_worker.run_pass",
            side_effect=RuntimeError(secret),
        ):
            with self.assertRaises(CommandError) as result:
                call_command(
                    "user_admin_worker",
                    "--config",
                    str(self.path),
                    stdout=output,
                    stderr=output,
                )
        self.assertEqual(str(result.exception), "worker_runtime_failed")
        self.assertNotIn(secret, output.getvalue())
        self.assertEqual(result.exception.returncode, 2)

    def test_invalid_lifecycle_and_limits_fail_before_config_loading(self):
        for args in [
            ("--watch", "--operation", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            ("--batch-size", "0"),
            ("--batch-size", "101"),
            ("--interval", "nan"),
            ("--interval", "0.01"),
        ]:
            with (
                self.subTest(args=args),
                patch(
                    "user_admin.management.commands.user_admin_worker.load_config"
                ) as loader,
                self.assertRaisesMessage(CommandError, "invalid_worker_options"),
            ):
                self.command(*args)
            loader.assert_not_called()

    def test_worker_settings_do_not_mutate_web_and_have_no_http_routes(self):
        from auth import settings as web
        from auth import worker_settings, worker_urls

        with patch.dict(
            os.environ,
            {"USER_ADMIN_WORKER_ENABLED": "1", "USER_ADMIN_API_ENABLED": "true"},
        ):
            module = importlib.reload(worker_settings)
            self.assertIs(module.USER_ADMIN_NATIVE_EXECUTION_ENABLED, True)
            self.assertIs(module.USER_ADMIN_API_ENABLED, False)
            self.assertEqual(module.ROOT_URLCONF, "auth.worker_urls")
        self.assertIs(web.USER_ADMIN_NATIVE_EXECUTION_ENABLED, False)
        self.assertEqual(worker_urls.urlpatterns, [])
        with patch.dict(os.environ, {"USER_ADMIN_WORKER_ENABLED": "true"}):
            self.assertIs(
                importlib.reload(worker_settings).USER_ADMIN_WORKER_ENABLED, False
            )
