"""Real multi-connection locking tests, ONLY the isolated PostgreSQL fixture."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from unittest import skipUnless
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import close_old_connections, connection
from django.test import TransactionTestCase, override_settings

from sso.models import Service

from .engine import ControlError, execute, schedule
from .models import AdministrationLock, Operation, Target, UserControl
from .tests import FakeNative


@skipUnless(connection.vendor == "postgresql", "isolated PostgreSQL fixture required")
@override_settings(USER_ADMIN_NATIVE_EXECUTION_ENABLED=True)
class PostgreSQLConcurrencyTests(TransactionTestCase):
    def setUp(self):
        AdministrationLock.objects.get_or_create(pk=1)
        User = get_user_model()
        self.actor = User.objects.create_user(
            username="pg-admin", is_superuser=True, is_staff=True
        )
        self.user = User.objects.create_user(username="pg-user")
        group = Group.objects.create(name="pg-gitlab")
        Service.objects.create(slug="gitlab", group=group)
        self.user.groups.add(group)
        UserControl.objects.create(user=self.user, creation_receipt=uuid4())

    def request(self, action="create", version=0):
        return schedule(
            actor_id=self.actor.pk,
            user_id=self.user.pk,
            service="gitlab",
            instance="fixture",
            action=action,
            idempotency_key=uuid4(),
            expected_version=version,
        )

    @staticmethod
    def worker(function, *args):
        close_old_connections()
        try:
            return function(*args)
        finally:
            close_old_connections()

    def test_two_workers_do_not_duplicate_create_or_hold_db_lock_during_io(self):
        adapter = FakeNative()
        entered, release = Event(), Event()

        def pause(_):
            entered.set()
            if not release.wait(10):
                raise RuntimeError("synthetic native fixture timed out")

        adapter.after_apply = pause
        operation = self.request()
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.worker, execute, operation.pk, adapter)
            try:
                self.assertTrue(entered.wait(5))
                second = pool.submit(self.worker, execute, operation.pk, adapter)
                self.assertEqual(second.result(timeout=5), "running")
                # This would block if remote IO still held the singleton row lock.
                block = self.request(action="block", version=1)
                reserved = pool.submit(self.worker, execute, block.pk, adapter)
                self.assertEqual(reserved.result(timeout=5), "target_reserved")
            finally:
                release.set()
            self.assertEqual(first.result(timeout=5), "superseded")
        adapter.after_apply = None
        self.assertEqual(execute(block.pk, adapter), "succeeded")
        self.assertEqual(adapter.calls, ["create", "block"])
        target = Target.objects.get(pk=operation.target_id)
        self.assertEqual(target.observed, "blocked")
        self.assertEqual(target.native_id, "native-42")

    def test_concurrent_same_version_commits_only_one_goal(self):
        barrier = Barrier(2)

        def submit():
            barrier.wait(timeout=5)
            try:
                return self.request().status
            except ControlError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.worker, submit)
            second = pool.submit(self.worker, submit)
            results = [first.result(timeout=10), second.result(timeout=10)]
        self.assertCountEqual(results, ["pending", "stale_version"])
        self.assertEqual(Operation.objects.count(), 1)
        self.assertEqual(Target.objects.count(), 1)
        self.assertEqual(UserControl.objects.get(user=self.user).version, 1)
