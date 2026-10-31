"""PostgreSQL-only concurrency coverage for the MinIO single-use guard."""

import json
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from unittest import skipUnless
from unittest.mock import patch

from django.db import connection, connections
from django.test import Client, TransactionTestCase, override_settings
from django.utils import timezone

from .minio_guard import CALLBACK, COOKIE, digest
from .models import MinioLoginChallenge


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL concurrency")
@override_settings(
    SSO_MINIO_GUARD_ENABLED=True,
    SSO_MINIO_PUBLIC_URL="https://minio.i3alumba.ru",
    ALLOWED_HOSTS=["minio.i3alumba.ru"],
)
class MinioGuardPostgresTests(TransactionTestCase):
    def test_concurrent_callbacks_consume_challenge_exactly_once(self):
        state = secrets.token_urlsafe(32)
        browser = secrets.token_urlsafe(32)
        challenge = MinioLoginChallenge.objects.create(
            state_hash=digest(state),
            browser_hash=digest(browser),
            original_state="synthetic-console-state",
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        barrier = Barrier(4, timeout=20)

        def callback(client: Client) -> int:
            return client.post(
                CALLBACK,
                json.dumps({"code": "synthetic-code", "state": state}),
                content_type="application/json",
                secure=True,
                HTTP_HOST="minio.i3alumba.ru",
                HTTP_ORIGIN="https://minio.i3alumba.ru",
            ).status_code

        def concurrent_callback() -> tuple[int, int]:
            # Django connections are thread-local; retain each until all are ready.
            connections.close_all()
            try:
                client = Client(enforce_csrf_checks=True)
                client.cookies[COOKIE] = browser
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    backend_pid = cursor.fetchone()[0]
                barrier.wait()
                return backend_pid, callback(client)
            finally:
                connections.close_all()

        with patch("sso.minio_guard.backend", return_value=(204, b"", [])) as backend:
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(concurrent_callback) for _ in range(4)]
                results = [future.result(timeout=40) for future in futures]

            self.assertEqual(len({pid for pid, _ in results}), 4)
            self.assertCountEqual(
                [status for _, status in results], [204, 403, 403, 403]
            )
            backend.assert_called_once()
            self.assertEqual(backend.call_args.args[:2], (CALLBACK, "POST"))
            self.assertEqual(
                json.loads(backend.call_args.args[2]),
                {"code": "synthetic-code", "state": "synthetic-console-state"},
            )
            challenge.refresh_from_db()
            self.assertIsNotNone(challenge.consumed_at)

            replay_client = Client(enforce_csrf_checks=True)
            replay_client.cookies[COOKIE] = browser
            self.assertEqual(callback(replay_client), 403)
            backend.assert_called_once()
