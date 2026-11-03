"""Release switches never enable a native executor in the web process."""

import json
from pathlib import Path
import subprocess
import sys

from django.test import SimpleTestCase


class ReleaseSwitchTests(SimpleTestCase):
    def test_release_switches_are_opt_in_and_web_native_execution_stays_disabled(self):
        for flag in ["USER_ADMIN_API_ENABLED", "USER_ADMIN_HOSTING_GRANTS_READY"]:
            for value, expected in [
                (None, False),
                ("false", False),
                ("invalid", False),
                ("TRUE", True),
                ("yes", True),
                ("1", True),
            ]:
                with self.subTest(flag=flag, value=value):
                    # No inherited credentials, keys or production environment.
                    env = {
                        "DJANGO_DEBUG": "true",
                        "SSO_ENABLED": "false",
                        "USER_ADMIN_NATIVE_EXECUTION_ENABLED": "true",
                    }
                    if value is not None:
                        env[flag] = value
                    result = subprocess.run(
                        [
                            sys.executable,
                            "-B",
                            "-c",
                            "import json; from auth import settings; print(json.dumps("
                            "[settings.USER_ADMIN_API_ENABLED, "
                            "settings.USER_ADMIN_NATIVE_EXECUTION_ENABLED, "
                            "settings.USER_ADMIN_HOSTING_GRANTS_READY]))",
                        ],
                        cwd=Path(__file__).resolve().parents[1],
                        env=env,
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(
                        json.loads(result.stdout),
                        [
                            expected if flag == "USER_ADMIN_API_ENABLED" else False,
                            False,
                            (
                                expected
                                if flag == "USER_ADMIN_HOSTING_GRANTS_READY"
                                else False
                            ),
                        ],
                    )
