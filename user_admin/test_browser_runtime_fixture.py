from pathlib import Path
import subprocess
from unittest.mock import patch

from django.test import SimpleTestCase

from .vendor_fixtures.browser_runtime import (
    MemoryBudget,
    bounded_args,
    local_image_id,
    public_libraries,
)


class BrowserRuntimeFixtureTests(SimpleTestCase):
    def test_budget_cannot_exceed_six_decimal_gigabytes(self):
        budget = MemoryBudget()
        for role, memory in [
            ("gitlab", 4_300_000_000),
            ("browser", 768_000_000),
            ("auth", 320_000_000),
            ("postgres", 256_000_000),
            ("namespace", 32_000_000),
            ("controller", 128_000_000),
            ("helper", 96_000_000),
        ]:
            budget.reserve(role, memory)
        self.assertEqual(sum(budget.reservations.values()), 5_900_000_000)
        with self.assertRaisesMessage(ValueError, "fixture_aggregate_memory_exceeded"):
            budget.reserve("extra", 100_000_001)
        self.assertNotIn("extra", budget.reservations)

    def test_budget_stays_charged_until_confirmed_absence(self):
        budget = MemoryBudget(limit=100)
        budget.reserve("helper", 100)
        for observed in [False, None, "true", 1]:
            with self.subTest(observed=observed), self.assertRaises(ValueError):
                budget.release("helper", checked_absent=observed)
        self.assertEqual(budget.reservations, {"helper": 100})
        budget.release("helper", checked_absent=True)
        budget.reserve("next", 100)

    def test_bad_or_duplicate_reservations_and_boolean_sizes_fail(self):
        for limit in [True, 0, 6_000_000_001]:
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                MemoryBudget(limit=limit)
        budget = MemoryBudget()
        budget.reserve("helper", 1)
        for role, size in [
            ("helper", 1),
            ("../../escape", 1),
            ("next", True),
            ("next", 0),
        ]:
            with self.subTest(role=role, size=size), self.assertRaises(ValueError):
                budget.reserve(role, size)

    def test_nonroot_readonly_caps_and_no_swap_are_not_optional(self):
        args = bounded_args(memory=768_000_000, uid=1000, gid=1000, pids=256)
        self.assertEqual(args[args.index("--memory") + 1], "768000000")
        self.assertEqual(args[args.index("--memory-swap") + 1], "768000000")
        self.assertEqual(args[args.index("--pull") + 1], "never")
        self.assertIn("--read-only", args)
        self.assertIn("ALL", args)
        self.assertIn("no-new-privileges", args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--no-sandbox", args)
        for change in [
            {"uid": 0},
            {"memory": True},
            {"cpus": float("nan")},
            {"pids": 769},
        ]:
            options = {"memory": 768_000_000, "uid": 1000, "gid": 1000, **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                bounded_args(**options)

    def test_cached_image_resolution_returns_only_immutable_identity(self):
        calls = []
        identity = "sha256:" + "a" * 64

        def invoke(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(
                args, 0, stdout=identity + "\n", stderr=""
            )

        self.assertEqual(local_image_id("postgres:17.9-alpine", invoke), identity)
        self.assertEqual(
            calls,
            [
                [
                    "docker",
                    "image",
                    "inspect",
                    "postgres:17.9-alpine",
                    "--format",
                    "{{.Id}}",
                ]
            ],
        )

    def test_missing_local_image_fails_without_run_or_pull(self):
        calls = []

        def invoke(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

        with self.assertRaisesMessage(RuntimeError, "fixture_local_image_required"):
            local_image_id("postgres:17.9-alpine", invoke)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:3], ["docker", "image", "inspect"])
        with self.assertRaises(ValueError):
            local_image_id("--injected-option", invoke)
        self.assertEqual(len(calls), 1)

    def libraries(self, stdout, code=0):
        def invoke(args, **kwargs):
            self.assertEqual(args, ["ldd", "/usr/bin/node"])
            return subprocess.CompletedProcess(args, code, stdout=stdout, stderr="")

        with (
            patch(
                "user_admin.vendor_fixtures.browser_runtime.PUBLIC_BINARIES",
                (Path("/usr/bin/node"),),
            ),
            patch(
                "user_admin.vendor_fixtures.browser_runtime.PUBLIC_LIBRARY_DIRECTORIES",
                (),
            ),
        ):
            return public_libraries(invoke=invoke)

    def test_only_explicit_public_dependencies_are_selected(self):
        result = self.libraries("libm.so.6 => /usr/lib/libm.so.6 (0x1)\n")
        self.assertEqual(result["libm.so.6"], Path("/usr/lib/libm.so.6").resolve())
        self.assertIn("ld-linux-x86-64.so.2", result)

    def test_missing_foreign_and_colliding_dependencies_fail_closed(self):
        for text in [
            "libgone.so => not found",
            "private.so => /home/not-a-real-user/private.so (0x1)",
            "libsame.so => /usr/lib/a/libsame.so (0x1)\nlibsame.so => /usr/lib/b/libsame.so (0x2)",
        ]:
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                self.libraries(text)
        with self.assertRaises(RuntimeError):
            self.libraries("", code=1)
