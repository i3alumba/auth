import json

from django.http import HttpResponseForbidden
from oauth2_provider.models import get_application_model
from oauth2_provider.views import (
    AuthorizationView,
    ConnectDiscoveryInfoView,
    JwksInfoView,
    TokenView,
)

from .validator import allowed


class ServiceAuthorizationView(AuthorizationView):
    def dispatch(self, request, *args, **kwargs):
        # DOT's first validation pass has no oauthlib user. Gate its Django view,
        # then check again in the validator during actual grant issuance.
        if request.user.is_authenticated:
            data = request.POST if request.method == "POST" else request.GET
            client = (
                get_application_model()
                .objects.filter(client_id=data.get("client_id"))
                .first()
            )
            if not allowed(request.user, client):
                return HttpResponseForbidden("Service access denied")
        return super().dispatch(request, *args, **kwargs)


class ServiceTokenView(TokenView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        # OAuthLibCore directly converts a save-hook OAuth2Error into JSON bytes,
        # but its exception headers omit the MIME type. Never return token errors
        # as text/html (or a successful token response after failed persistence).
        response["Content-Type"] = "application/json"
        response["Cache-Control"] = "no-store"
        return response


class ServiceDiscoveryView(ConnectDiscoveryInfoView):
    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        data = json.loads(response.content)
        data["id_token_signing_alg_values_supported"] = ["RS256"]
        data["code_challenge_methods_supported"] = ["S256"]
        data["grant_types_supported"] = ["authorization_code", "refresh_token"]
        response.content = json.dumps(data)
        del response["Access-Control-Allow-Origin"]
        return response


class ServiceJwksView(JwksInfoView):
    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        del response["Access-Control-Allow-Origin"]
        return response
