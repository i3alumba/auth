from django.test import TestCase


class ReverseProxyTests(TestCase):
    def test_discovery_never_downgrades_public_endpoints_behind_traefik(self):
        response = self.client.get(
            "/o/.well-known/openid-configuration",
            HTTP_HOST="auth.i3alumba.ru",
            HTTP_X_FORWARDED_PROTO="https",
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["issuer"], "https://auth.i3alumba.ru/o")
        for name in [
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
        ]:
            self.assertTrue(data[name].startswith("https://auth.i3alumba.ru/"), name)
