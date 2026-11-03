"""Mocked host-Docker failure paths; no process/container/native API is run."""

from pathlib import Path
import json
import subprocess
from tempfile import TemporaryDirectory
from unittest.mock import Mock

from django.test import SimpleTestCase

from .vendor_fixtures.runner import (
    FixtureContainers,
    checked_probe,
    initialize_proof,
    write_proof,
)

RUN = "a" * 32
CID_A, CID_B = "b" * 64, "c" * 64


def result(stdout="", code=0):
    return subprocess.CompletedProcess([], code, stdout=stdout, stderr="")


class FixtureRunnerTests(SimpleTestCase):
    def test_probe_requires_dictionary_exact_true_and_zero_exit(self):
        self.assertIs(checked_probe('{"ok": true}', 0)["ok"], True)
        for output, code in [
            ('{"ok": true}', 1),
            ('{"ok": 1}', 0),
            ('{"ok": "true"}', 0),
            ("[]", 0),
            ("null", 0),
            ("not-json", 0),
        ]:
            with self.subTest(output=output, code=code):
                self.assertIs(checked_probe(output, code)["ok"], False)

    def test_bootstrap_failure_cannot_leave_previous_green_evidence(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "proof.json"
            write_proof(path, {"ok": True, "run": "previous"})
            initialize_proof(path, RUN)
            try:
                raise RuntimeError("synthetic_bootstrap_failure")
            except RuntimeError:
                pass
            self.assertEqual(
                json.loads(path.read_text()),
                {"ok": False, "run": RUN, "stage": "initializing"},
            )
            self.assertEqual(list(path.parent.glob("*.tmp")), [])

    def test_detached_and_helper_timeouts_are_registered_before_invoke_and_cleaned(
        self,
    ):
        for detached in [True, False]:
            plans = []
            invoke = Mock(side_effect=subprocess.TimeoutExpired("docker", 1))
            fixtures = FixtureContainers(RUN, invoke=invoke, on_plan=plans.append)
            with (
                self.subTest(detached=detached),
                self.assertRaises(subprocess.TimeoutExpired),
            ):
                fixtures.launch(
                    "helper",
                    ["--network", "none", "synthetic-image"],
                    detached=detached,
                    timeout=1,
                )
            self.assertEqual(plans, [tuple(fixtures.names)])
            self.assertEqual(len(fixtures.names), 1)
            invoke.reset_mock()
            invoke.side_effect = [result(CID_A + "\n"), result(), result()]
            self.assertTrue(fixtures.cleanup()["checked_absent"])
            self.assertEqual(
                invoke.call_args_list[1].args[0], ["docker", "rm", "-f", CID_A]
            )
            lookup = invoke.call_args_list[0].args[0]
            self.assertIn("name=^/" + fixtures.names[0] + "$", lookup)
            self.assertIn("label=public-page.fixture.run=" + RUN, lookup)

    def test_cleanup_continues_after_one_owned_removal_fails(self):
        invoke = Mock(return_value=result())
        fixtures = FixtureContainers(RUN, invoke=invoke)
        fixtures.launch("first", [], detached=True, timeout=1)
        fixtures.launch("second", [], detached=False, timeout=1)
        remaining = {fixtures.names[0]: CID_A, fixtures.names[1]: CID_B}
        removals = []

        def fake(args, **kwargs):
            if args[:2] == ["docker", "rm"]:
                removals.append(args[-1])
                if args[-1] == CID_B:
                    return result(code=1)
                remaining.pop(fixtures.names[0])
                return result()
            name = next(
                (name for name in fixtures.names if "name=^/" + name + "$" in args),
                None,
            )
            return result(remaining.get(name, ""))

        invoke.side_effect = fake
        cleanup = fixtures.cleanup()
        self.assertFalse(cleanup["checked_absent"])
        self.assertEqual(cleanup["failures"], [fixtures.names[1]])
        self.assertEqual(removals, [CID_B, CID_A])

    def test_unproven_ids_never_reach_removal(self):
        invoke = Mock(return_value=result("invalid-id"))
        fixtures = FixtureContainers(RUN, invoke=invoke)
        fixtures.launch("server", [], detached=True, timeout=1)
        invoke.reset_mock()
        self.assertFalse(fixtures.cleanup()["checked_absent"])
        self.assertFalse(
            any(call.args[0][:2] == ["docker", "rm"] for call in invoke.call_args_list)
        )

    def test_name_collision_without_run_label_does_not_remove_foreign_container(self):
        invoke = Mock(return_value=result())
        fixtures = FixtureContainers(RUN, invoke=invoke)
        fixtures.launch("server", [], detached=True, timeout=1)
        invoke.reset_mock()
        self.assertTrue(fixtures.cleanup()["checked_absent"])
        self.assertEqual(invoke.call_count, 2)
        self.assertTrue(
            all(
                "label=public-page.fixture.run=" + RUN in call.args[0]
                for call in invoke.call_args_list
            )
        )

    def test_service_namespace_is_explicit_and_cannot_inject_metadata(self):
        for service in ["synapse", "gitlab", "minio"]:
            invoke = Mock(return_value=result())
            fixtures = FixtureContainers(RUN, invoke=invoke, service=service)
            fixtures.launch("server", [], detached=True, timeout=1)
            self.assertEqual(
                fixtures.names, ["users-" + service + "-" + RUN + "-server"]
            )
            self.assertIn(
                "public-page.fixture=" + service + "-exact", invoke.call_args.args[0]
            )
        with self.assertRaisesRegex(ValueError, "invalid_fixture_service"):
            FixtureContainers(RUN, service="unrelated.*")

    def test_run_and_role_cannot_inject_filters_or_reuse_names(self):
        with self.assertRaises(ValueError):
            FixtureContainers("not-a-uuid")
        fixtures = FixtureContainers(RUN, invoke=Mock(return_value=result()))
        with self.assertRaises(ValueError):
            fixtures.launch("server.*", [], detached=True, timeout=1)
        fixtures.launch("server", [], detached=True, timeout=1)
        with self.assertRaises(ValueError):
            fixtures.launch("server", [], detached=True, timeout=1)
