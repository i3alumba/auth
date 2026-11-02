"""The real self-profile HTTP contract consumed by administrator services."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken

from api.serializers import UserSerializer


class CurrentUserAdministratorContractTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="profile-admin", password=None, is_staff=True
        )
        self.other = get_user_model().objects.create_user(
            username="other-admin", password=None, is_staff=True
        )
        self.token = str(AccessToken.for_user(self.user))
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + self.token)

    def test_actual_list_route_returns_only_self_with_exact_boolean_flags(self):
        response = self.client.get("/api/user/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["id"], self.user.pk)
        self.assertIs(data[0]["is_active"], True)
        self.assertIs(data[0]["is_staff"], True)
        self.assertIn("groups", data[0])
        self.assertIn("services", data[0])
        self.assertNotIn("password", data[0])
        self.assertNotIn("is_superuser", data[0])

    def test_same_bearer_immediately_observes_staff_revocation(self):
        self.assertIs(self.client.get("/api/user/").json()[0]["is_staff"], True)
        get_user_model().objects.filter(pk=self.user.pk).update(is_staff=False)
        self.assertIs(self.client.get("/api/user/").json()[0]["is_staff"], False)

    def test_inactive_bearer_and_anonymous_requests_are_denied(self):
        get_user_model().objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertEqual(self.client.get("/api/user/").status_code, 401)
        self.client.credentials()
        self.assertEqual(self.client.get("/api/user/").status_code, 401)

    def test_flags_are_read_only_and_do_not_grant_or_change_account_roles(self):
        serializer = UserSerializer(
            self.user,
            data={"is_staff": False, "is_active": False},
            partial=True,
        )
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data, {})
        self.assertTrue(serializer.fields["is_staff"].read_only)
        self.assertTrue(serializer.fields["is_active"].read_only)
        self.assertEqual(
            self.client.patch("/api/user/", {}, format="json").status_code, 405
        )
