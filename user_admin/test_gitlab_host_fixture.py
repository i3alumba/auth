"""No-Docker checks for the exact-owned GitLab host-phase helper boundaries."""

from contextlib import ExitStack
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

from django.test import SimpleTestCase

from .vendor_fixtures.gitlab_host import GitlabHostPhases, read_immutable_source
from .vendor_fixtures.runner import FixtureContainers


class GitlabHostFixtureTests(SimpleTestCase):
    def helper(self, stderr="", returncode=0):
        containers = SimpleNamespace(
            service="gitlab",
            launch=Mock(
                return_value=subprocess.CompletedProcess(
                    [], returncode, stdout="", stderr=stderr
                )
            ),
        )
        return (
            GitlabHostPhases(
                Path("/synthetic-only"),
                "a" * 64,
                "b" * 64,
                containers,
                "synthetic-image",
            ),
            containers,
        )

    def test_both_source_helpers_are_cleaned_on_timeout_and_interruption(self):
        for path in ["/opt/gitlab/embedded/bin/runsvdir-start", "/assets/sshd_config"]:
            for failure in [
                subprocess.TimeoutExpired("docker", 1),
                KeyboardInterrupt(),
            ]:
                owned = ["c" * 64]
                calls = []

                def invoke(args, **kwargs):
                    calls.append(args)
                    if args[:2] == ["docker", "run"]:
                        raise failure
                    if args[:2] == ["docker", "rm"]:
                        owned.clear()
                        return subprocess.CompletedProcess([], 0, stdout="", stderr="")
                    return subprocess.CompletedProcess(
                        [], 0, stdout="\\n".join(owned), stderr=""
                    )

                fixtures = FixtureContainers("a" * 32, invoke=invoke, service="gitlab")
                with (
                    self.subTest(path=path, failure=type(failure).__name__),
                    self.assertRaises(type(failure)),
                    ExitStack() as guard,
                ):
                    guard.callback(fixtures.cleanup)
                    read_immutable_source(fixtures, "synthetic-image", path)
                self.assertEqual(len(fixtures.names), 1)
                self.assertIn(["docker", "rm", "-f", "c" * 64], calls)
                self.assertFalse(owned)

    def test_invalid_container_ids_or_service_do_not_reach_execution(self):
        with self.assertRaisesRegex(ValueError, "fixture_container_id_required"):
            GitlabHostPhases(
                Path("/synthetic-only"),
                "bad",
                "b" * 64,
                SimpleNamespace(service="gitlab"),
                "synthetic-image",
            )
        with self.assertRaisesRegex(ValueError, "fixture_service_required"):
            GitlabHostPhases(
                Path("/synthetic-only"),
                "a" * 64,
                "b" * 64,
                SimpleNamespace(service="unrelated"),
                "synthetic-image",
            )

    def test_repository_cannot_inject_command_or_arbitrary_remote(self):
        helper, containers = self.helper()
        for repository in [
            "../../etc/passwd",
            "ua_" + "a" * 24 + "/x;anything",
            "https://other.invalid/repository",
        ]:
            with self.subTest(repository=repository), self.assertRaises(ValueError):
                helper.ssh_refs("ban", "a", repository)
        containers.launch.assert_not_called()

    def test_network_failure_is_not_authentication_denial(self):
        repository = "ua_" + "a" * 24 + "/synthetic-repository"
        helper, containers = self.helper("Connection refused", 128)
        self.assertFalse(helper.ssh_refs("ban", "a", repository)[2])
        helper, containers = self.helper("Permission denied (publickey).", 128)
        self.assertTrue(helper.ssh_refs("ban", "a", repository)[2])

    def test_phase_reordering_is_not_replayed(self):
        helper, containers = self.helper()
        with self.assertRaisesRegex(ValueError, "fixture_phase_order_invalid"):
            helper.handle({"phase": "enable"})
        containers.launch.assert_not_called()
