from dataclasses import replace
from unittest.mock import Mock, patch
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.db import connection

from .models import Operation, Target
from .native.receipts import (
    confirmed_block_receipt,
    confirmed_ownership,
    confirmed_policy,
    policy_history,
)
from .worker_config import InstanceConfig, WorkerConfig, WorkerError
from .worker_profiles import PROFILES
from .worker_runtime import (
    admission,
    candidates,
    gitlab_profile,
    make_adapter,
    run_pass,
)


class WorkerRuntimeTests(TestCase):
    def setUp(self):
        self.instance = InstanceConfig(
            "gitlab",
            "primary",
            "https://gitlab.example.invalid",
            "gitlab-18.1.0-ce-ban-v1",
            (("token_file", "gitlab-token"),),
        )
        self.config = WorkerConfig("/not-read-in-preview", (self.instance,))
        self.count = 0

    def operation(
        self,
        *,
        email=None,
        service="gitlab",
        instance="primary",
        paused=False,
        status=Operation.Status.PENDING,
    ):
        self.count += 1
        user = get_user_model().objects.create(
            username=f"synthetic{self.count}",
            email=f"synthetic{self.count}@example.invalid" if email is None else email,
        )
        target = Target.objects.create(
            user=user,
            service=service,
            instance=instance,
            desired=Target.Desired.ENABLED,
            generation=1,
            management_paused=paused,
        )
        return Operation.objects.create(
            target=target,
            actor_id=user.pk,
            base_version=1,
            generation=1,
            action=Operation.Action.CREATE,
            idempotency_key=uuid4(),
            status=status,
        )

    def test_dry_run_has_no_dml_factory_or_native_calls(self):
        operation = self.operation()
        events = []
        factory = Mock(side_effect=AssertionError("must not construct adapters"))
        with CaptureQueriesContext(connection) as captured:
            cursor, count, incomplete = run_pass(
                self.config, report=events.append, factory=factory
            )
        self.assertEqual(count, 1)
        self.assertFalse(incomplete)
        self.assertEqual(cursor.operation_id, operation.pk)
        self.assertEqual(events[0]["status"], "preview_pending")
        self.assertFalse(
            any(
                query["sql"].lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
                for query in captured
            )
        )
        factory.assert_not_called()
        operation.refresh_from_db()
        self.assertEqual(operation.status, Operation.Status.PENDING)

    def test_exclusions_before_limit_include_reserved_targets(self):
        self.operation(instance="unconfigured")
        self.operation(service="jenkins")
        self.operation(paused=True)
        reserved = self.operation(status=Operation.Status.UNKNOWN)
        Operation.objects.create(
            target=reserved.target,
            actor_id=reserved.actor_id,
            base_version=1,
            generation=2,
            action=Operation.Action.BLOCK,
            idempotency_key=uuid4(),
        )
        good = self.operation()
        self.assertEqual(
            [row.pk for row in candidates(self.config, limit=1)], [good.pk]
        )
        self.assertEqual(candidates(self.config, limit=1, operation_id=reserved.pk), [])

    def test_invalid_email_advances_keyset_without_claim(self):
        bad = self.operation(email="")
        good = self.operation()
        events = []
        cursor, count, partial = run_pass(self.config, limit=1, report=events.append)
        self.assertEqual(cursor.operation_id, bad.pk)
        self.assertTrue(partial)
        self.assertEqual(events[0]["status"], "gitlab_email_required")
        cursor, count, partial = run_pass(self.config, limit=1, cursor=cursor)
        self.assertEqual(cursor.operation_id, good.pk)
        self.assertFalse(partial)
        cursor, count, partial = run_pass(self.config, limit=1, cursor=cursor)
        self.assertIsNone(cursor)
        bad.refresh_from_db()
        self.assertEqual(bad.status, Operation.Status.PENDING)

    def test_profile_reloads_user_changed_after_batch_selection(self):
        operation = self.operation()
        selected = candidates(self.config, limit=1)[0]
        get_user_model().objects.filter(pk=operation.target.user_id).update(email="")
        with self.assertRaisesMessage(WorkerError, "gitlab_email_required"):
            gitlab_profile(selected)
        other = self.operation(email="taken@example.invalid")
        get_user_model().objects.filter(pk=operation.target.user_id).update(
            email=other.target.user.email.upper()
        )
        with self.assertRaisesMessage(WorkerError, "gitlab_email_conflict"):
            gitlab_profile(selected)

    def test_adapter_callback_does_not_freeze_factory_profile(self):
        from types import SimpleNamespace

        operation = self.operation()
        adapter = make_adapter(
            self.instance, {"token_file": "PUBLIC_SYNTHETIC_TOKEN"}, operation
        )
        get_user_model().objects.filter(pk=operation.target.user_id).update(
            email="fresh@example.invalid"
        )
        profile = adapter.profiles(
            SimpleNamespace(
                target_id=operation.target_id, user_id=operation.target.user_id
            )
        )
        self.assertEqual(profile.email, "fresh@example.invalid")

    def test_known_local_email_collision_stays_pending(self):
        first = self.operation(email="same@example.invalid")
        self.operation(email="SAME@example.invalid")
        events = []
        run_pass(self.config, limit=1, report=events.append)
        self.assertEqual(events[0]["status"], "gitlab_email_conflict")
        first.refresh_from_db()
        self.assertEqual(first.status, Operation.Status.PENDING)

    def test_uuid_usernames_are_stable_injective_and_within_vendor_limit(self):
        first, second = self.operation(), self.operation()
        a, b = gitlab_profile(first), gitlab_profile(second)
        self.assertRegex(a.username, r"^ua_[a-z2-7]{26}$")
        self.assertNotEqual(a.username, b.username)
        self.assertEqual(a.username, gitlab_profile(first).username)
        self.assertEqual(a.email, first.target.user.email)
        self.assertNotEqual(a.username, first.target.user.username)

    def test_web_cannot_execute_even_with_native_flag_injected(self):
        self.operation()
        factory = Mock()
        with (
            override_settings(
                SETTINGS_MODULE="auth.settings",
                USER_ADMIN_NATIVE_EXECUTION_ENABLED=True,
                USER_ADMIN_WORKER_ENABLED=True,
            ),
            self.assertRaisesMessage(WorkerError, "worker_execution_disabled"),
        ):
            run_pass(self.config, dry_run=False, factory=factory)
        factory.assert_not_called()

    @override_settings(
        SETTINGS_MODULE="auth.worker_settings",
        USER_ADMIN_NATIVE_EXECUTION_ENABLED=True,
        USER_ADMIN_WORKER_ENABLED=True,
    )
    def test_actual_profiles_remain_blocked_before_selection_or_factory(self):
        with (
            patch("user_admin.worker_runtime.candidates") as select,
            self.assertRaisesMessage(WorkerError, "profile_activation_blocked"),
        ):
            run_pass(self.config, dry_run=False)
        select.assert_not_called()
        self.assertTrue(PROFILES[self.instance.acceptance_profile].blockers)

    @override_settings(
        SETTINGS_MODULE="auth.worker_settings",
        USER_ADMIN_NATIVE_EXECUTION_ENABLED=True,
        USER_ADMIN_WORKER_ENABLED=True,
    )
    def test_engine_is_only_executor_and_partial_remains_partial(self):
        operation = self.operation()
        profiles = {
            code: replace(profile, blockers=(), provisioning_blockers=())
            for code, profile in PROFILES.items()
        }
        adapter = object()
        factory = Mock(return_value=adapter)
        events = []
        with patch(
            "user_admin.worker_runtime.execute", return_value=Operation.Status.PARTIAL
        ) as execute:
            cursor, count, incomplete = run_pass(
                self.config,
                dry_run=False,
                profiles=profiles,
                snapshot={("gitlab", "primary"): {}},
                factory=factory,
                report=events.append,
            )
        execute.assert_called_once_with(
            operation.pk, adapter, execution_scope="provision_only"
        )
        self.assertTrue(incomplete)
        self.assertEqual(events[0]["status"], "partial")
        self.assertNotIn("evidence", events[0])

    @override_settings(
        SETTINGS_MODULE="auth.worker_settings",
        USER_ADMIN_NATIVE_EXECUTION_ENABLED=True,
        USER_ADMIN_WORKER_ENABLED=True,
    )
    def test_shutdown_between_factory_and_claim_stops_without_replay(self):
        self.operation()
        profiles = {
            code: replace(profile, blockers=(), provisioning_blockers=())
            for code, profile in PROFILES.items()
        }
        with patch("user_admin.worker_runtime.execute") as execute:
            run_pass(
                self.config,
                dry_run=False,
                profiles=profiles,
                snapshot={("gitlab", "primary"): {}},
                factory=Mock(),
                stopping=Mock(side_effect=[False, True]),
            )
        execute.assert_not_called()

    @override_settings(
        SETTINGS_MODULE="auth.worker_settings",
        USER_ADMIN_NATIVE_EXECUTION_ENABLED=True,
        USER_ADMIN_WORKER_ENABLED=True,
    )
    def test_lifecycle_clearance_does_not_clear_provisioning_gates(self):
        profiles = {
            code: replace(profile, blockers=()) for code, profile in PROFILES.items()
        }
        with self.assertRaisesMessage(WorkerError, "profile_activation_blocked"):
            admission(self.config, profiles)
        admission(replace(self.config, execution_scope="lifecycle"), profiles)

    @override_settings(
        SETTINGS_MODULE="auth.worker_settings",
        USER_ADMIN_NATIVE_EXECUTION_ENABLED=True,
        USER_ADMIN_WORKER_ENABLED=True,
    )
    def test_deferred_block_does_not_construct_adapter_or_starve_create(self):
        block = self.operation()
        Operation.objects.filter(pk=block.pk).update(action="block")
        good = self.operation()
        profiles = {
            code: replace(profile, provisioning_blockers=())
            for code, profile in PROFILES.items()
        }
        factory = Mock(return_value=object())
        with patch(
            "user_admin.worker_runtime.execute",
            side_effect=["unsupported", "succeeded"],
        ) as execute:
            cursor, count, incomplete = run_pass(
                self.config,
                profiles=profiles,
                dry_run=False,
                snapshot={("gitlab", "primary"): {}},
                factory=factory,
            )
        self.assertEqual(count, 2)
        self.assertTrue(incomplete)
        self.assertEqual(cursor.operation_id, good.pk)
        self.assertEqual(factory.call_count, 1)
        self.assertEqual(execute.call_args_list[0].args, (block.pk, None))

    def test_invalid_scope_never_selects_or_constructs_adapter(self):
        with (
            patch("user_admin.worker_runtime.candidates") as select,
            self.assertRaisesMessage(WorkerError, "invalid_worker_scope"),
        ):
            run_pass(replace(self.config, execution_scope="all"))
        select.assert_not_called()

    def test_factory_receipt_wiring_and_unconfigured_service_rejection(self):
        operation = self.operation()
        with patch("user_admin.worker_runtime.GitlabAdapter") as adapter:
            make_adapter(
                self.instance, {"token_file": "PUBLIC_SYNTHETIC_TOKEN"}, operation
            )
        self.assertIs(adapter.call_args.kwargs["receipts"], confirmed_block_receipt)
        matrix = InstanceConfig(
            "matrix",
            "primary",
            "https://matrix.example.invalid",
            "synapse-1.164.1-lock-v1",
            (),
            "matrix.example.invalid",
        )
        with patch("user_admin.worker_runtime.SynapseAdapter") as adapter:
            make_adapter(
                matrix,
                {
                    "token_file": "PUBLIC_SYNTHETIC_TOKEN",
                    "registration_secret_file": "PUBLIC_SYNTHETIC_REGISTRATION",
                },
                operation,
            )
        self.assertIs(adapter.call_args.kwargs["ownership"], confirmed_ownership)
        minio = InstanceConfig(
            "minio",
            "primary",
            "https://minio.example.invalid",
            "minio-2023-05-18-owned-s3-v1",
            (),
        )
        with patch("user_admin.worker_runtime.MinioAdapter") as adapter:
            make_adapter(
                minio,
                {
                    "access_key_file": "PUBLIC_ACCESS",
                    "secret_key_file": "PUBLIC_SYNTHETIC_SECRET",
                },
                operation,
            )
        self.assertIs(adapter.call_args.kwargs["policy_receipts"], confirmed_policy)
        self.assertIs(adapter.call_args.kwargs["policy_history"], policy_history)
        with self.assertRaisesMessage(WorkerError, "service_excluded"):
            make_adapter(replace(self.instance, service="jenkins"), {}, operation)
