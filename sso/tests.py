import base64
import hashlib
import io
import json
from types import SimpleNamespace
from urllib.parse import urlencode, parse_qs, urlsplit

import bcrypt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.management.base import CommandError
from django.core.management.color import no_style
from django.db import connection
from django.test import TestCase, Client, override_settings
from oauth2_provider.models import Application
from rest_framework_simplejwt.tokens import RefreshToken

from .access import services_for
from .models import Service, ServiceIdentity, ProvisionRun
from .validator import SSOValidator

User = get_user_model()


class SSOFixture(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            pk=1, username="i3alumba", password="test-password"
        )
        self.group = Group.objects.create(pk=5, name="Matrix")
        self.user.groups.add(self.group)
        self.app = Application.objects.create(
            client_id="matrix",
            client_secret="x" * 40,
            client_type="confidential",
            authorization_grant_type="authorization-code",
            algorithm="RS256",
            redirect_uris="https://matrix.example/callback",
            skip_authorization=True,
        )
        self.service = Service.objects.create(
            slug="matrix", group=self.group, oidc_client_id="matrix"
        )
        self.identity = ServiceIdentity.objects.create(
            user=self.user,
            service=self.service,
            external_id="@existing:example",
            external_username="existing",
        )


class AccessTests(SSOFixture):
    def test_default_deny_no_superuser_bypass(self):
        self.assertTrue(services_for(self.user)["matrix"]["enabled"])
        self.user.groups.clear()
        self.user.is_superuser = True
        self.assertFalse(services_for(self.user)["matrix"]["enabled"])
        self.user.groups.add(self.group)
        self.identity.delete()
        self.assertFalse(services_for(self.user)["matrix"]["enabled"])

    def test_jwt_legacy_fields_and_access(self):
        self.assertEqual(self.client.get("/api/access/").status_code, 401)
        jwt = str(RefreshToken.for_user(self.user).access_token)
        headers = {"HTTP_AUTHORIZATION": f"Bearer {jwt}"}
        self.assertTrue(
            self.client.get("/api/access/", **headers).json()["services"]["matrix"][
                "enabled"
            ]
        )
        data = self.client.get("/api/user/1/", **headers).json()
        self.assertEqual(data["id"], 1)
        self.assertEqual(data["groups"], [{"id": 5, "name": "Matrix"}])
        self.assertEqual(
            data["services"],
            {
                "drive": False,
                "matrix": True,
                "gitlab": False,
                "minio": False,
                "jenkins": False,
            },
        )
        self.assertTrue(all(type(value) is bool for value in data["services"].values()))
        services = self.client.get("/api/access/", **headers).json()["services"]
        self.assertEqual(
            services["matrix"], {"enabled": True, "url": "https://matrix.i3alumba.ru"}
        )
        self.assertTrue(
            all(
                type(value["enabled"]) is bool and isinstance(value["url"], str)
                for value in services.values()
            )
        )


class SessionTests(SSOFixture):
    def setUp(self):
        super().setUp()
        self.client = Client(enforce_csrf_checks=True)

    def csrf(self):
        return self.client.get("/api/session/").json()["csrfToken"]

    def login(self):
        return self.client.post(
            "/api/session/login/",
            json.dumps({"username": "i3alumba", "password": "test-password"}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=self.csrf(),
        )

    def test_csrf_and_no_tokens_on_get(self):
        response = self.client.get("/api/session/")
        self.assertFalse(response.json()["authenticated"])
        self.assertNotIn("access", response.json())
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(self.client.post("/api/session/login/", {}).status_code, 403)
        self.assertEqual(self.client.post("/api/session/token/").status_code, 403)
        self.assertEqual(self.client.post("/api/session/logout/").status_code, 403)

    def test_session_rotation_reissue_logout(self):
        self.client.force_login(self.user)
        previous = self.client.session.session_key
        response = self.login()
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(previous, self.client.session.session_key)
        self.assertIn("access", response.json())
        csrf = response.json()["csrfToken"]
        self.assertEqual(
            self.client.post("/api/session/token/", HTTP_X_CSRFTOKEN=csrf).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                "/api/session/logout/",
                json.dumps({"refresh": response.json()["refresh"]}),
                content_type="application/json",
                HTTP_X_CSRFTOKEN=csrf,
            ).status_code,
            200,
        )
        self.assertFalse(self.client.get("/api/session/").json()["authenticated"])
        self.assertEqual(
            self.client.post(
                "/api/token/refresh/", {"refresh": response.json()["refresh"]}
            ).status_code,
            401,
        )

    def test_anonymous_session_rotated(self):
        session = self.client.session
        session["before"] = True
        session.save()
        previous = session.session_key
        self.assertEqual(self.login().status_code, 200)
        self.assertNotEqual(previous, self.client.session.session_key)

    def test_no_bearer_session_bridge(self):
        token = str(RefreshToken.for_user(self.user).access_token)
        self.assertEqual(
            self.client.post(
                "/api/session/token/",
                HTTP_X_CSRFTOKEN=self.csrf(),
                HTTP_AUTHORIZATION=f"Bearer {token}",
            ).status_code,
            401,
        )

    def test_rate_limit_shared_and_next_safe(self):
        for _ in range(5):
            self.client.post(
                "/sso/login/",
                {"username": "i3alumba", "password": "bad"},
                HTTP_X_CSRFTOKEN=self.csrf(),
            )
        self.assertEqual(self.login().status_code, 401)
        self.assertEqual(
            self.client.post(
                "/sso/login/",
                {
                    "username": "unknown",
                    "password": "bad",
                    "next": "https://evil.example",
                },
                HTTP_X_CSRFTOKEN=self.csrf(),
            ).status_code,
            200,
        )

    def test_native_login_no_open_redirect(self):
        response = self.client.post(
            "/sso/login/",
            {
                "username": "i3alumba",
                "password": "test-password",
                "next": "https://evil.example",
            },
            HTTP_X_CSRFTOKEN=self.csrf(),
        )
        self.assertEqual(response["Location"], "/")
        self.assertNotIn("access", response["Location"])

    def test_foreign_refresh_cannot_blacklist(self):
        other = User.objects.create_user(username="other")
        refresh = str(RefreshToken.for_user(other))
        self.login()
        response = self.client.post(
            "/api/session/logout/",
            json.dumps({"refresh": refresh}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=self.csrf(),
        )
        self.assertEqual(response.status_code, 403)
        RefreshToken(refresh)

    def test_csrf_exact_origin_and_cookie_flags(self):
        response = self.client.get(
            "/api/session/", HTTP_ORIGIN="https://main.i3alumba.ru"
        )
        self.assertEqual(
            response["Access-Control-Allow-Origin"], "https://main.i3alumba.ru"
        )
        self.assertEqual(response["Access-Control-Allow-Credentials"], "true")
        self.assertTrue(response.cookies[settings.CSRF_COOKIE_NAME]["httponly"])
        self.assertFalse(response.cookies[settings.CSRF_COOKIE_NAME]["domain"])
        self.assertNotIn(
            "Access-Control-Allow-Origin",
            self.client.get("/api/session/", HTTP_ORIGIN="https://evil.example"),
        )
        self.assertEqual(
            self.client.post(
                "/api/session/login/",
                json.dumps({"username": "i3alumba", "password": "test-password"}),
                content_type="application/json",
                HTTP_X_CSRFTOKEN=self.csrf(),
                HTTP_ORIGIN="https://evil.example",
            ).status_code,
            403,
        )

    def test_inactive_cannot_login(self):
        self.user.is_active = False
        self.user.save()
        self.assertEqual(self.login().status_code, 401)

    def test_rate_limit_expires(self):
        from django.utils import timezone
        from datetime import timedelta
        from .models import LoginAttempt

        for _ in range(5):
            self.client.post(
                "/sso/login/",
                {"username": "i3alumba", "password": "bad"},
                HTTP_X_CSRFTOKEN=self.csrf(),
            )
        LoginAttempt.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.login().status_code, 200)

    def test_legacy_jwt_contract_and_shared_login_limit(self):
        response = self.client.post(
            "/api/token/", {"username": "i3alumba", "password": "test-password"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"access", "refresh"})
        self.assertFalse(self.client.get("/api/session/").json()["authenticated"])
        for _ in range(4):
            self.client.post("/api/token/", {"username": "i3alumba", "password": "bad"})
        self.assertEqual(self.login().status_code, 401)
        response = self.client.post(
            "/sso/login/",
            {"username": "i3alumba", "password": "test-password"},
            HTTP_X_CSRFTOKEN=self.csrf(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid credentials or rate limit")

    def test_browser_attempts_limit_legacy_jwt_login(self):
        for _ in range(5):
            self.client.post(
                "/api/session/login/",
                json.dumps({"username": "i3alumba", "password": "bad"}),
                content_type="application/json",
                HTTP_X_CSRFTOKEN=self.csrf(),
            )
        response = self.client.post(
            "/api/token/", {"username": "i3alumba", "password": "test-password"}
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {"detail": "No active account found with the given credentials"},
        )


class OIDCTests(SSOFixture):
    verifier = "a" * 64

    def authorization(self, **changes):
        self.client.force_login(self.user)
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
        params.update(changes)
        params = {key: value for key, value in params.items() if value is not None}
        return self.client.get("/o/authorize/?" + urlencode(params))

    def code(self):
        response = self.authorization()
        self.assertEqual(response.status_code, 302, response.content)
        query = parse_qs(urlsplit(response["Location"]).query)
        self.assertIn("code", query, query)
        self.assertEqual(query["state"], ["state"])
        return query["code"][0]

    def exchange(self, code, **changes):
        params = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.app.redirect_uris,
            "client_id": "matrix",
            "client_secret": "x" * 40,
            "code_verifier": self.verifier,
        }
        params.update(changes)
        params = {key: value for key, value in params.items() if value is not None}
        return self.client.post("/o/token/", params)

    def test_discovery_and_no_registration(self):
        discovery = self.client.get("/o/.well-known/openid-configuration")
        self.assertEqual(discovery.status_code, 200)
        self.assertEqual(discovery.json()["issuer"], "https://auth.i3alumba.ru/o")
        self.assertEqual(self.client.get("/o/.well-known/jwks.json").status_code, 200)
        for path in ["register/", "applications/register/", "introspect/", "device/"]:
            self.assertEqual(self.client.get("/o/" + path).status_code, 404)

    def test_code_pkce_replay_userinfo_and_claims(self):
        code = self.code()
        response = self.exchange(code)
        self.assertEqual(response.status_code, 200, response.content)
        data = response.json()
        import jwt
        from django.conf import settings
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        public = load_pem_private_key(
            settings.OAUTH2_PROVIDER["OIDC_RSA_PRIVATE_KEY"].encode(), None
        ).public_key()
        claims = jwt.decode(
            data["id_token"],
            public,
            algorithms=["RS256"],
            audience="matrix",
            issuer="https://auth.i3alumba.ru/o",
        )
        self.assertEqual(claims["sub"], "1")
        self.assertEqual(claims["nonce"], "nonce")
        self.assertEqual(claims["groups"], ["service_matrix"])
        self.assertEqual(claims["matrix_localpart"], "existing")
        self.assertFalse(claims["email_verified"])
        self.assertNotIn("policy", claims)
        self.assertNotIn("jenkins_eligible", claims)
        self.assertEqual(self.exchange(code).status_code, 400)
        header = {"HTTP_AUTHORIZATION": "Bearer " + data["access_token"]}
        self.assertEqual(self.client.get("/o/userinfo/", **header).status_code, 200)
        self.user.groups.clear()
        self.assertEqual(self.client.get("/o/userinfo/", **header).status_code, 401)
        self.assertEqual(
            self.client.post(
                "/o/token/",
                {
                    "grant_type": "refresh_token",
                    "refresh_token": data["refresh_token"],
                    "client_id": "matrix",
                    "client_secret": "x" * 40,
                },
            ).status_code,
            400,
        )

    def test_exchange_live_group_and_inactive(self):
        code = self.code()
        self.user.groups.clear()
        self.assertEqual(self.exchange(code).status_code, 400)
        self.user.groups.add(self.group)
        self.user.is_active = False
        self.user.save()
        self.assertEqual(self.exchange(code).status_code, 400)

    def test_bad_pkce_redirect_and_crossclient(self):
        code = self.code()
        self.assertEqual(self.exchange(code, code_verifier="b" * 64).status_code, 400)
        self.assertEqual(
            self.exchange(code, redirect_uri="https://evil.example").status_code, 400
        )
        other = Application.objects.create(
            client_id="other",
            client_secret="z" * 40,
            client_type="confidential",
            authorization_grant_type="authorization-code",
            algorithm="RS256",
            redirect_uris="https://other.example/cb",
        )
        Service.objects.create(slug="gitlab", group=self.group, oidc_client_id="other")
        self.assertEqual(
            self.exchange(code, client_id="other", client_secret="z" * 40).status_code,
            400,
        )

    def test_authorize_denials(self):
        for params in [
            {"code_challenge": "", "code_challenge_method": ""},
            {"code_challenge_method": "plain"},
            {"nonce": ""},
            {"state": ""},
            {"scope": "profile"},
            {"response_type": "token"},
            {"redirect_uri": "https://matrix.example/callback/evil"},
            {"redirect_uri": ""},
        ]:
            response = self.authorization(**params)
            self.assertNotIn("code=", response.get("Location", ""), params)
        self.user.groups.clear()
        self.assertNotIn("code=", self.authorization().get("Location", ""))

    def test_only_code_grants(self):
        for grant in ["password", "client_credentials", "implicit"]:
            response = self.client.post(
                "/o/token/",
                {
                    "grant_type": grant,
                    "client_id": "matrix",
                    "client_secret": "x" * 40,
                    "username": "i3alumba",
                    "password": "test-password",
                },
            )
            self.assertNotEqual(response.status_code, 200)

    def test_client_specific_claims(self):
        validator = SSOValidator()
        self.service.slug = "jenkins"
        self.service.save()
        self.identity.external_username = "i3alumba"
        self.identity.jenkins_admin = True
        self.identity.save()
        claims = validator.get_additional_claims(
            SimpleNamespace(user=self.user, client=self.app)
        )
        self.assertEqual(claims["jenkins_uid"], "i3alumba")
        self.assertEqual(claims["jenkins_eligible"], "true")
        self.assertNotIn("matrix_localpart", claims)
        self.service.slug = "minio"
        self.service.save()
        self.identity.minio_policy = "explicit-policy"
        self.identity.save()
        claims = validator.get_additional_claims(
            SimpleNamespace(user=self.user, client=self.app)
        )
        self.assertEqual(claims["policy"], "explicit-policy")
        self.assertNotIn("jenkins_eligible", claims)

    def test_refresh_rotation_replay_and_explicit_revoke(self):
        data = self.exchange(self.code()).json()

        def refresh(value):
            return self.client.post(
                "/o/token/",
                {
                    "grant_type": "refresh_token",
                    "refresh_token": value,
                    "client_id": "matrix",
                    "client_secret": "x" * 40,
                },
            )

        rotated = refresh(data["refresh_token"])
        self.assertEqual(rotated.status_code, 200, rotated.content)
        self.assertNotEqual(rotated.json()["refresh_token"], data["refresh_token"])
        self.assertEqual(refresh(data["refresh_token"]).status_code, 400)
        # Use a fresh family because replay intentionally revokes the first family.
        data = self.exchange(self.code()).json()
        self.assertEqual(
            self.client.post(
                "/o/revoke_token/",
                {
                    "token": data["refresh_token"],
                    "client_id": "matrix",
                    "client_secret": "x" * 40,
                },
            ).status_code,
            200,
        )
        self.assertEqual(refresh(data["refresh_token"]).status_code, 400)

    def test_identity_removal_blocks_exchange(self):
        code = self.code()
        self.identity.delete()
        self.assertEqual(self.exchange(code).status_code, 400)

    def test_inactive_userinfo_and_refresh(self):
        data = self.exchange(self.code()).json()
        self.user.is_active = False
        self.user.save()
        self.assertEqual(
            self.client.get(
                "/o/userinfo/", HTTP_AUTHORIZATION="Bearer " + data["access_token"]
            ).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                "/o/token/",
                {
                    "grant_type": "refresh_token",
                    "refresh_token": data["refresh_token"],
                    "client_id": "matrix",
                    "client_secret": "x" * 40,
                },
            ).status_code,
            400,
        )

    def test_pkce_exception_only_named_confidential_minio(self):
        validator = SSOValidator()
        request = SimpleNamespace(client=self.app)
        with override_settings(SSO_MINIO_PKCE_EXCEPTION_CLIENT_ID="matrix"):
            self.assertTrue(validator.is_pkce_required("matrix", request))
            self.service.slug = "minio"
            self.service.save()
            self.assertFalse(validator.is_pkce_required("matrix", request))
            self.app.client_type = "public"
            self.assertTrue(validator.is_pkce_required("matrix", request))

    def test_jenkins_eligibility_is_explicit(self):
        self.service.slug = "jenkins"
        self.service.save()
        self.user.is_superuser = True
        claims = SSOValidator().get_additional_claims(
            SimpleNamespace(user=self.user, client=self.app)
        )
        self.assertNotIn("jenkins_eligible", claims)

    def test_unauthenticated_redirect_to_native_login(self):
        self.client.logout()
        response = self.client.get("/o/authorize/?client_id=matrix")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith("/sso/login/?next="))

    @override_settings(SSO_MINIO_PKCE_EXCEPTION_CLIENT_ID="matrix")
    def test_minio_exception_without_nonce_or_pkce_and_exact_nonce_echo(self):
        self.service.slug = "minio"
        self.service.save()
        for nonce in [None, "exact-rp-requested-nonce"]:
            response = self.authorization(
                nonce=nonce, code_challenge=None, code_challenge_method=None
            )
            self.assertEqual(response.status_code, 302)
            query = parse_qs(urlsplit(response["Location"]).query)
            self.assertIn("code", query, query)
            token = self.exchange(query["code"][0], code_verifier=None)
            self.assertEqual(token.status_code, 200, token.content)
            import jwt
            from django.conf import settings
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )

            public = load_pem_private_key(
                settings.OAUTH2_PROVIDER["OIDC_RSA_PRIVATE_KEY"].encode(), None
            ).public_key()
            claims = jwt.decode(
                token.json()["id_token"],
                public,
                algorithms=["RS256"],
                audience="matrix",
                issuer="https://auth.i3alumba.ru/o",
            )
            if nonce is None:
                self.assertNotIn("nonce", claims)
            else:
                self.assertEqual(claims["nonce"], nonce)
                self.assertNotEqual(claims["nonce"], "wrong-rp-session-nonce")
        response = self.authorization(
            nonce=None, state=None, code_challenge=None, code_challenge_method=None
        )
        self.assertNotIn("code=", response.get("Location", ""))

    def test_nonce_exception_not_available_to_other_service_or_unnamed_minio(self):
        with override_settings(SSO_MINIO_PKCE_EXCEPTION_CLIENT_ID="matrix"):
            response = self.authorization(nonce=None)
            self.assertNotIn("code=", response.get("Location", ""))
        self.service.slug = "minio"
        self.service.save()
        with override_settings(SSO_MINIO_PKCE_EXCEPTION_CLIENT_ID="different-client"):
            response = self.authorization(nonce=None)
            self.assertNotIn("code=", response.get("Location", ""))


class ProvisionTests(TestCase):
    def setUp(self):
        User.objects.create_user(pk=1, username="i3alumba")
        User.objects.create_user(pk=2, username="gore")
        Group.objects.create(pk=4, name="Gitlab")
        with connection.cursor() as cursor:
            for sql in connection.ops.sequence_reset_sql(no_style(), [User, Group]):
                cursor.execute(sql)
        self.config = {
            "users": [{"id": 1, "username": "i3alumba"}],
            "services": [
                {
                    "slug": "gitlab",
                    "group": {"id": 4, "name": "Gitlab"},
                    "client": {
                        "id": "gitlab",
                        "secret": "a" * 40,
                        "redirect_uris": ["https://gitlab.example/callback"],
                    },
                }
            ],
            "identities": [
                {
                    "username": "i3alumba",
                    "service": "gitlab",
                    "external_id": "4",
                    "external_username": "i3alumba",
                }
            ],
        }

    def run_config(self, apply=False):
        from unittest.mock import patch

        output = io.StringIO()
        with patch("sys.stdin", io.StringIO(json.dumps(self.config))):
            call_command("provision_sso", config="-", apply=apply, stdout=output)
        self.assertNotIn("a" * 40, output.getvalue())

    def test_dryrun_apply_idempotency(self):
        self.run_config()
        self.assertFalse(Service.objects.exists())
        self.assertFalse(Application.objects.exists())
        self.assertFalse(ProvisionRun.objects.exists())
        self.run_config(True)
        self.run_config(True)
        self.assertEqual(ServiceIdentity.objects.count(), 1)
        self.assertEqual(ProvisionRun.objects.count(), 1)
        self.assertEqual(
            ProvisionRun.objects.get().created_ids["identities"],
            [ServiceIdentity.objects.get().pk],
        )

    def test_conflicts_rollback(self):
        self.run_config(True)
        self.config["identities"][0]["external_id"] = "wrong"
        with self.assertRaises(CommandError):
            self.run_config(True)
        self.assertEqual(ServiceIdentity.objects.get().external_id, "4")
        self.config["users"][0]["username"] = "renamed"
        with self.assertRaises(CommandError):
            self.run_config(True)

    def test_secret_and_redirect_collisions(self):
        self.run_config(True)
        self.config["services"][0]["client"]["secret"] = "b" * 40
        with self.assertRaises(CommandError):
            self.run_config(True)
        self.config["services"][0]["client"]["id"] = "other"
        with self.assertRaises(CommandError):
            self.run_config(True)

    def test_import_and_rehash(self):
        raw = bcrypt.hashpw(
            "пароль".encode(), bcrypt.gensalt(rounds=13, prefix=b"2a")
        ).decode()
        self.config["users"].append({"username": "procsima", "import_bcrypt": raw})
        self.run_config(True)
        self.run_config(True)
        user = User.objects.get(username="procsima")
        self.assertNotEqual(user.pk, 1)
        self.assertTrue(user.check_password("пароль"))
        user.refresh_from_db()
        self.assertTrue(user.password.startswith("pbkdf2_sha256$"))
        self.run_config(True)
        self.assertEqual(User.objects.get(username="procsima").password, user.password)

    def test_bcrypt_unicode_and_72byte_compatibility(self):
        # Synthetic vectors generated by independent libxcrypt crypt(3), $2a$04$.
        vectors = [
            ("unicode-пароль", "Y2s5C9KVZGN9gfjTztIlanDv5.JrZkO"),
            ("a" * 72, "BzzIgyKkz7xMWYSzkIjUSnxEQFQ0WNe"),
            ("a" * 73, "BzzIgyKkz7xMWYSzkIjUSnxEQFQ0WNe"),
            ("界" * 25, "InMCZhXHkAk1hbNTj/UBA1cCqWyZVwa"),
        ]
        for password, checksum in vectors:
            encoded = "bcrypt$$2a$04$abcdefghijklmnopqrstuu" + checksum
            self.assertTrue(check_password(password, encoded))
            self.assertFalse(check_password("wrong", encoded))

    def test_bad_import_fails_closed(self):
        self.config["users"].append(
            {"username": "procsima", "import_bcrypt": "$2a$bad"}
        )
        with self.assertRaises(CommandError):
            self.run_config(True)
        self.assertFalse(User.objects.filter(username="procsima").exists())

    def test_import_conflict_does_not_replace_password(self):
        self.config["users"].append({"username": "procsima", "unusable_password": True})
        self.run_config(True)
        self.config["users"][-1] = {
            "username": "procsima",
            "import_bcrypt": bcrypt.hashpw(
                b"synthetic", bcrypt.gensalt(rounds=13, prefix=b"2a")
            ).decode(),
        }
        with self.assertRaises(CommandError):
            self.run_config(True)
        self.assertFalse(User.objects.get(username="procsima").has_usable_password())

    def test_external_identity_collision_rolls_back(self):
        self.config["identities"].append(
            {
                "username": "gore",
                "service": "gitlab",
                "external_id": "4",
                "external_username": "gore",
            }
        )
        self.config["users"].append({"id": 2, "username": "gore"})
        with self.assertRaises(CommandError):
            self.run_config(True)
        self.assertFalse(Service.objects.exists())
        self.assertFalse(Application.objects.exists())

    def test_unknown_reserved_claims_rejected(self):
        self.config["identities"][0]["claims"] = {"policy": "consoleAdmin"}
        with self.assertRaises(CommandError):
            self.run_config(True)
        self.assertFalse(Service.objects.exists())

    def test_protected_identity_foreign_keys(self):
        from django.db.models.deletion import ProtectedError

        self.run_config(True)
        with self.assertRaises(ProtectedError):
            User.objects.get(pk=1).delete()
        with self.assertRaises(ProtectedError):
            Group.objects.get(pk=4).delete()

    def test_null_import_rejected(self):
        self.config["users"].append({"username": "procsima", "import_bcrypt": None})
        with self.assertRaises(CommandError):
            self.run_config(True)
        self.assertFalse(User.objects.filter(username="procsima").exists())

    def test_rerun_never_regrants_revoked_membership(self):
        self.run_config(True)
        before = ProvisionRun.objects.get().created_ids
        user = User.objects.get(pk=1)
        user.groups.clear()
        self.run_config(True)
        self.assertFalse(user.groups.exists())
        self.assertEqual(ProvisionRun.objects.get().created_ids, before)

    def test_rerun_preserves_admin_changed_roles_and_ignores_initial_role_changes(self):
        self.config["services"] = [
            {"slug": "jenkins", "group": {"name": "Jenkins", "create": True}}
        ]
        self.config["identities"] = [
            {
                "username": "i3alumba",
                "service": "jenkins",
                "external_id": "i3alumba",
                "external_username": "i3alumba",
                "jenkins_admin": True,
            }
        ]
        self.run_config(True)
        identity = ServiceIdentity.objects.get()
        identity.jenkins_admin = False
        identity.save()
        fingerprint = ProvisionRun.objects.get().fingerprint
        self.run_config(True)
        identity.refresh_from_db()
        self.assertFalse(identity.jenkins_admin)
        self.config["identities"][0].pop("jenkins_admin")
        self.run_config(True)
        self.assertEqual(ProvisionRun.objects.get().fingerprint, fingerprint)
        self.assertFalse(ServiceIdentity.objects.get().jenkins_admin)

    def test_rerun_preserves_minio_policy(self):
        Group.objects.create(pk=3, name="Minio")
        self.config["services"] = [
            {"slug": "minio", "group": {"id": 3, "name": "Minio"}}
        ]
        self.config["identities"] = [
            {
                "username": "i3alumba",
                "service": "minio",
                "external_id": "existing",
                "external_username": "existing",
                "minio_policy": "initial-policy",
            }
        ]
        self.run_config(True)
        ServiceIdentity.objects.update(minio_policy="admin-changed-policy")
        self.run_config(True)
        self.assertEqual(
            ServiceIdentity.objects.get().minio_policy, "admin-changed-policy"
        )

    def test_cleaned_password_config_preserves_rehashed_password_and_ledger(self):
        raw = bcrypt.hashpw(
            b"synthetic", bcrypt.gensalt(rounds=13, prefix=b"2a")
        ).decode()
        self.config["users"].append({"username": "procsima", "import_bcrypt": raw})
        self.run_config(True)
        user = User.objects.get(username="procsima")
        self.assertTrue(user.check_password("synthetic"))
        user.refresh_from_db()
        preferred = user.password
        self.assertTrue(preferred.startswith("pbkdf2_sha256$"))
        ledger = ProvisionRun.objects.get()
        before = ledger.created_ids
        self.assertNotIn(raw, json.dumps(before))
        self.config["users"][-1] = {"username": "procsima"}
        self.run_config(True)
        self.assertEqual(User.objects.get(username="procsima").password, preferred)
        self.assertEqual(ProvisionRun.objects.get().created_ids, before)
        self.assertEqual(ProvisionRun.objects.get().fingerprint, ledger.fingerprint)

    def test_unowned_or_missing_cleaned_procsima_fails_closed(self):
        self.config["users"].append({"username": "procsima"})
        with self.assertRaises(CommandError):
            self.run_config(True)
        self.assertFalse(User.objects.filter(username="procsima").exists())
        User.objects.create_user(username="procsima")
        self.config["users"][-1]["unusable_password"] = True
        with self.assertRaises(CommandError):
            self.run_config(True)
        self.assertFalse(ProvisionRun.objects.exists())

    def test_deleted_bootstrap_objects_are_never_recreated(self):
        self.config["users"].append({"username": "procsima", "unusable_password": True})
        self.run_config(True)
        user = User.objects.get(username="procsima")
        user.delete()
        with self.assertRaises(CommandError):
            self.run_config(True)
        self.assertFalse(User.objects.filter(username="procsima").exists())

    def test_deleted_identity_client_service_or_group_is_not_recreated(self):
        from django.db import transaction

        self.run_config(True)
        for kind in ["identity", "client", "service", "group"]:
            with transaction.atomic():
                if kind == "identity":
                    ServiceIdentity.objects.all().delete()
                elif kind == "client":
                    Application.objects.all().delete()
                else:
                    ServiceIdentity.objects.all().delete()
                    Service.objects.all().delete()
                    if kind == "group":
                        Group.objects.all().delete()
                with self.assertRaises(CommandError):
                    self.run_config(True)
                (
                    self.assertFalse(ServiceIdentity.objects.exists())
                    if kind != "client"
                    else self.assertFalse(Application.objects.exists())
                )
                transaction.set_rollback(True)

    def test_bootstrap_manifest_order_does_not_change_provenance(self):
        self.config["users"].append({"id": 2, "username": "gore"})
        self.run_config(True)
        before = ProvisionRun.objects.get().fingerprint
        self.config["users"].reverse()
        self.run_config(True)
        self.assertEqual(ProvisionRun.objects.get().fingerprint, before)
