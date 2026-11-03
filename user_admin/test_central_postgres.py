"""Deterministic, separate-connection central races in the isolated PG fixture."""

import base64
import hashlib
from urllib.parse import urlencode, parse_qs, urlsplit

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import close_old_connections, connection, transaction
from django.test import Client, TransactionTestCase, override_settings
from oauth2_provider.models import Application, get_access_token_model
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken

from sso import tests as fixtures
from sso.models import Service, ServiceIdentity
from sso.validator import SSOValidator

from .authentication import EpochModelBackend, credential_lock
from .models import AdministrationLock, UserChange, UserControl
from .service import ChangeError, _revoke, apply_change, etag

PASSWORD = "Synthetic-Concurrent-Password-86!"


@skipUnless(connection.vendor == "postgresql", "isolated PostgreSQL fixture required")
@override_settings(USER_ADMIN_API_ENABLED=True)
class CentralPostgreSQLTests(TransactionTestCase):
    authorization = fixtures.OIDCTests.authorization
    code = fixtures.OIDCTests.code
    verifier = fixtures.OIDCTests.verifier

    def setUp(self):
        AdministrationLock.objects.get_or_create(pk=1)
        User = get_user_model()
        self.admin = User.objects.create_user(
            username="race-admin", password=PASSWORD, is_staff=True, is_superuser=True
        )
        self.other = User.objects.create_user(
            username="other-admin", password=PASSWORD, is_staff=True, is_superuser=True
        )
        self.user = User.objects.create_user(username="race-member", password=PASSWORD)
        self.proof = AccessToken.for_user(self.admin)
        self.other_proof = AccessToken.for_user(self.other)
        self.client = Client()
        group = Group.objects.create(name="pg-central-matrix")
        self.service = Service.objects.create(
            slug="matrix", group=group, oidc_client_id="matrix"
        )
        self.user.groups.add(group)
        ServiceIdentity.objects.create(
            user=self.user,
            service=self.service,
            external_id="@race:example",
            external_username="race",
        )
        self.app = Application.objects.create(
            client_id="matrix",
            client_secret="x" * 40,
            client_type="confidential",
            authorization_grant_type="authorization-code",
            algorithm="RS256",
            redirect_uris="https://matrix.example/callback",
            skip_authorization=True,
        )

    @staticmethod
    def worker(function, *args):
        close_old_connections()
        try:
            return function(*args)
        finally:
            close_old_connections()

    def revoke_round_trip(self, user):
        with transaction.atomic():
            credential_lock()
            control, _ = UserControl.objects.get_or_create(user=user)
            get_user_model().objects.filter(pk=user.pk).update(is_active=False)
            _revoke(user, control)
            get_user_model().objects.filter(pk=user.pk).update(is_active=True)

    def test_two_administrators_cannot_concurrently_remove_each_other(self):
        barrier = Barrier(2)
        a_etag, b_etag = etag(self.admin), etag(self.other)

        def demote(proof, target_id, expected):
            barrier.wait(timeout=10)
            try:
                apply_change(
                    proof=proof,
                    key=uuid4(),
                    action="update",
                    data={"is_admin": False},
                    user_id=target_id,
                    expected=expected,
                )
                return "ok"
            except ChangeError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(self.worker, demote, self.proof, self.other.pk, b_etag)
            b = pool.submit(
                self.worker, demote, self.other_proof, self.admin.pk, a_etag
            )
            self.assertCountEqual(
                [a.result(timeout=15), b.result(timeout=15)],
                ["ok", "administrator_required"],
            )
        self.assertEqual(
            get_user_model().objects.filter(is_active=True, is_superuser=True).count(),
            1,
        )

    def test_concurrent_same_etag_profile_updates_have_one_winner(self):
        barrier = Barrier(2)
        expected = etag(self.user)

        def save(email):
            barrier.wait(timeout=10)
            try:
                apply_change(
                    proof=self.proof,
                    key=uuid4(),
                    action="update",
                    data={"email": email},
                    user_id=self.user.pk,
                    expected=expected,
                )
                return "ok"
            except ChangeError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(self.worker, save, "one@example.test")
            b = pool.submit(self.worker, save, "two@example.test")
            self.assertCountEqual(
                [a.result(timeout=15), b.result(timeout=15)], ["ok", "stale_version"]
            )
        self.assertEqual(UserChange.objects.count(), 1)
        self.assertEqual(UserControl.objects.get(user=self.user).api_version, 1)

    def test_bearer_waiting_for_mutation_lock_cannot_cross_revocation(self):
        waiting = Event()
        original = credential_lock

        def blocked_lock():
            waiting.set()
            original()

        expected = etag(self.user)

        def request():
            client = APIClient()
            client.credentials(HTTP_AUTHORIZATION="Bearer " + str(self.proof))
            return client.patch(
                f"/api/user-admin/users/{self.user.pk}/",
                {"email": "stale@example.test"},
                format="json",
                HTTP_IDEMPOTENCY_KEY=str(uuid4()),
                HTTP_IF_MATCH=expected,
            ).status_code

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                credential_lock()
                with patch("user_admin.service.credential_lock", blocked_lock):
                    result = pool.submit(self.worker, request)
                    self.assertTrue(waiting.wait(10))
                    self.revoke_round_trip(self.admin)
            self.assertEqual(result.result(timeout=15), 401)
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "")
        self.assertFalse(UserChange.objects.exists())

    def test_password_verification_paused_before_issuance_cannot_cross_epoch(self):
        original = EpochModelBackend.authenticate
        for route in [
            "/api/token/",
            "/api/session/login/",
            "/sso/login/",
            "/admin/login/",
        ]:
            with self.subTest(route=route):
                entered, release = Event(), Event()

                def authenticate_then_wait(backend, *args, **kwargs):
                    user = original(backend, *args, **kwargs)
                    if user:
                        entered.set()
                        if not release.wait(10):
                            raise RuntimeError("synthetic barrier timed out")
                    return user

                def request():
                    client = Client()
                    if route == "/api/session/login/":
                        return client.post(
                            route,
                            {"username": self.admin.username, "password": PASSWORD},
                            content_type="application/json",
                        ).status_code
                    return client.post(
                        route, {"username": self.admin.username, "password": PASSWORD}
                    ).status_code

                with (
                    patch.object(
                        EpochModelBackend, "authenticate", authenticate_then_wait
                    ),
                    ThreadPoolExecutor(max_workers=1) as pool,
                ):
                    result = pool.submit(self.worker, request)
                    try:
                        self.assertTrue(entered.wait(10))
                        self.revoke_round_trip(self.admin)
                    finally:
                        release.set()
                    self.assertIn(result.result(timeout=15), [401, 403])

    def test_both_password_routes_reject_actor_revoked_while_waiting(self):
        for own in [False, True]:
            with self.subTest(own=own):
                client = Client()
                self.assertTrue(
                    client.login(username=self.admin.username, password=PASSWORD)
                )
                waiting = Event()

                def blocked_lock():
                    waiting.set()
                    credential_lock()

                def request():
                    url = (
                        "/admin/password_change/"
                        if own
                        else f"/admin/auth/user/{self.user.pk}/password/"
                    )
                    data = (
                        {
                            "old_password": PASSWORD,
                            "new_password1": "Unwanted-Synthetic-Password-92!",
                            "new_password2": "Unwanted-Synthetic-Password-92!",
                        }
                        if own
                        else {
                            "password1": "Unwanted-Synthetic-Password-92!",
                            "password2": "Unwanted-Synthetic-Password-92!",
                        }
                    )
                    return client.post(url, data).status_code

                seam = (
                    "user_admin.passwords.credential_lock"
                    if own
                    else "user_admin.admin.credential_lock"
                )
                with ThreadPoolExecutor(max_workers=1) as pool:
                    with transaction.atomic():
                        credential_lock()
                        with patch(seam, blocked_lock):
                            result = pool.submit(self.worker, request)
                            self.assertTrue(waiting.wait(10))
                            self.revoke_round_trip(self.admin)
                    self.assertEqual(result.result(timeout=15), 403)
                self.admin.refresh_from_db()
                self.user.refresh_from_db()
                self.assertTrue(self.admin.check_password(PASSWORD))
                self.assertTrue(self.user.check_password(PASSWORD))

    def test_oidc_code_and_refresh_validation_cannot_outlive_revocation(self):
        for refresh in [False, True]:
            with self.subTest(refresh=refresh):
                # A genuine new login after each revocation, not a refreshed stamp.
                self.assertTrue(
                    self.client.login(username=self.user.username, password=PASSWORD)
                )
                params = {
                    "client_id": "matrix",
                    "response_type": "code",
                    "redirect_uri": self.app.redirect_uris,
                    "scope": "openid profile groups",
                    "state": "state",
                    "nonce": "nonce",
                    "code_challenge": base64.urlsafe_b64encode(
                        hashlib.sha256(self.verifier.encode()).digest()
                    )
                    .rstrip(b"=")
                    .decode(),
                    "code_challenge_method": "S256",
                }
                auth = self.client.get("/o/authorize/?" + urlencode(params))
                code = parse_qs(urlsplit(auth["Location"]).query)["code"][0]
                token_data = {
                    "grant_type": "authorization_code",
                    "code": code,
                    "code_verifier": self.verifier,
                    "redirect_uri": self.app.redirect_uris,
                    "client_id": "matrix",
                    "client_secret": "x" * 40,
                }
                if refresh:
                    initial = self.client.post("/o/token/", token_data)
                    self.assertEqual(initial.status_code, 200, initial.content)
                    token_data = {
                        "grant_type": "refresh_token",
                        "refresh_token": initial.json()["refresh_token"],
                        "client_id": "matrix",
                        "client_secret": "x" * 40,
                    }
                entered, release = Event(), Event()
                original = SSOValidator.save_bearer_token

                def save_after_wait(validator, token, request, *args, **kwargs):
                    entered.set()
                    if not release.wait(10):
                        raise RuntimeError("synthetic barrier timed out")
                    return original(validator, token, request, *args, **kwargs)

                def exchange():
                    return Client().post("/o/token/", token_data)

                with (
                    patch.object(SSOValidator, "save_bearer_token", save_after_wait),
                    ThreadPoolExecutor(max_workers=1) as pool,
                ):
                    result = pool.submit(self.worker, exchange)
                    try:
                        self.assertTrue(entered.wait(10))
                        self.revoke_round_trip(self.user)
                    finally:
                        release.set()
                    response = result.result(timeout=15)
                self.assertEqual(response.status_code, 400, response.content)
                for field in ["access_token", "refresh_token", "id_token"]:
                    self.assertNotIn(field, response.json())
                self.assertFalse(
                    get_access_token_model().objects.filter(user=self.user).exists()
                )
