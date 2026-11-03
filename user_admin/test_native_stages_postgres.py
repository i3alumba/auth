"""Staged publication races on isolated real PostgreSQL, never production."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest import skipUnless
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import close_old_connections, connection
from django.test import TransactionTestCase, override_settings
from rest_framework_simplejwt.tokens import AccessToken

from sso.models import Service, ServiceIdentity
from .engine import execute, schedule
from .models import AdministrationLock, Operation, Target, UserControl
from .management import management_state, set_management
from .service import ChangeError
from .test_native_stages import StagedNative


@skipUnless(connection.vendor == "postgresql", "isolated PostgreSQL fixture required")
@override_settings(USER_ADMIN_NATIVE_EXECUTION_ENABLED=True)
class PostgreSQLStagingTests(TransactionTestCase):
    def setUp(self):
        AdministrationLock.objects.get_or_create(pk=1)
        User = get_user_model()
        self.actor = User.objects.create_user(
            username="pg-stages-admin", is_superuser=True, is_staff=True
        )
        self.user = User.objects.create_user(username="pg-stages-user")
        self.service = Service.objects.create(
            slug="gitlab", group=Group.objects.create(name="pg-stages-gitlab")
        )
        self.user.groups.add(self.service.group)
        UserControl.objects.create(user=self.user, creation_receipt=uuid4())
        self.adapter = StagedNative()

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

    def held_binding(self):
        create = self.request()
        self.assertEqual(execute(create.pk, self.adapter), "succeeded")
        bind = Operation.objects.get(target=create.target, action="bind")
        entered, release = Event(), Event()

        def pause(command):
            entered.set()
            if not release.wait(10):
                raise RuntimeError("synthetic native fixture deadline")

        self.adapter.after_apply = pause
        return create, bind, entered, release

    def test_real_pause_during_native_io_stays_unsafe_and_prevents_publication(self):
        create, bind, entered, release = self.held_binding()
        proof = AccessToken.for_user(self.actor)
        with ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(self.worker, execute, bind.pk, self.adapter)
            try:
                self.assertTrue(entered.wait(5))
                state, _ = set_management(
                    proof=proof,
                    key=uuid4(),
                    target_id=create.target_id,
                    expected_epoch=0,
                    paused=True,
                )
                self.assertTrue(state["paused"])
                self.assertFalse(state["safe_for_manual_changes"])
                with self.assertRaisesMessage(ChangeError, "native_target_reserved"):
                    set_management(
                        proof=proof,
                        key=uuid4(),
                        target_id=create.target_id,
                        expected_epoch=1,
                        paused=False,
                    )
            finally:
                release.set()
            self.assertEqual(first.result(timeout=5), "partial")
        target = Target.objects.get(pk=create.target_id)
        self.assertTrue(management_state(target)["safe_for_manual_changes"])
        self.assertFalse(ServiceIdentity.objects.filter(user=self.user).exists())
        bind.refresh_from_db()
        self.assertEqual(bind.observed, "enabled")
        self.assertEqual(bind.error_code, "authority_changed")

    def test_real_pause_during_inspection_defers_without_dispatch(self):
        create = self.request()
        self.assertEqual(execute(create.pk, self.adapter), "succeeded")
        bind = Operation.objects.get(target=create.target, action="bind")
        entered, release = Event(), Event()

        def hold_inspection(command):
            entered.set()
            if not release.wait(10):
                raise RuntimeError("synthetic inspection fixture deadline")

        self.adapter.after_inspect = hold_inspection
        with ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(self.worker, execute, bind.pk, self.adapter)
            try:
                self.assertTrue(entered.wait(5))
                state, _ = set_management(
                    proof=AccessToken.for_user(self.actor),
                    key=uuid4(),
                    target_id=create.target_id,
                    expected_epoch=0,
                    paused=True,
                )
                self.assertFalse(state["safe_for_manual_changes"])
            finally:
                release.set()
            self.assertEqual(first.result(timeout=5), "pending")
        self.assertEqual(self.adapter.calls, ["create"])
        bind.refresh_from_db()
        self.assertIsNone(bind.execution_token)
        self.assertTrue(
            management_state(Target.objects.get(pk=create.target_id))[
                "safe_for_manual_changes"
            ]
        )

    def test_two_workers_bind_once_and_revocation_during_io_prevents_publication(self):
        create, bind, entered, release = self.held_binding()
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.worker, execute, bind.pk, self.adapter)
            try:
                self.assertTrue(entered.wait(5))
                second = pool.submit(self.worker, execute, bind.pk, self.adapter)
                self.assertEqual(second.result(timeout=5), "running")
                block = self.request("block", version=1)
                self.assertFalse(
                    ServiceIdentity.objects.filter(user=self.user).exists()
                )
            finally:
                release.set()
            self.assertEqual(first.result(timeout=5), "superseded")
        self.assertFalse(ServiceIdentity.objects.filter(user=self.user).exists())
        self.assertEqual(self.adapter.calls, ["create", "bind"])
        self.assertEqual(Target.objects.get(pk=create.target_id).native_id, "42")
        self.adapter.after_apply = None
        self.assertEqual(execute(block.pk, self.adapter), "succeeded")

    def test_racing_foreign_external_id_survives_without_rolling_back_native_receipt(
        self,
    ):
        create, bind, entered, release = self.held_binding()
        with ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(self.worker, execute, bind.pk, self.adapter)
            try:
                self.assertTrue(entered.wait(5))
                other = get_user_model().objects.create_user(
                    username="pg-foreign-owner"
                )
                identity = ServiceIdentity.objects.create(
                    user=other,
                    service=self.service,
                    external_id="42",
                    external_username="foreign",
                )
            finally:
                release.set()
            self.assertEqual(first.result(timeout=5), "failed")
        identity.refresh_from_db()
        self.assertEqual(identity.user_id, other.pk)
        self.assertFalse(ServiceIdentity.objects.filter(user=self.user).exists())
        target = Target.objects.get(pk=create.target_id)
        self.assertEqual(target.creation_operation_id, create.pk)
        self.assertEqual(target.native_id, "42")
        self.assertIsNone(target.identity_id)
