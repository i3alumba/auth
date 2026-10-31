from urllib.parse import urlsplit

from django.conf import settings
from oauth2_provider.oauth2_validators import OAuth2Validator

from .access import identity_for
from .models import Service


def service_for(client):
    if (
        not client
        or client.client_type != "confidential"
        or client.authorization_grant_type != "authorization-code"
        or client.algorithm != "RS256"
    ):
        return None
    return Service.objects.filter(oidc_client_id=client.client_id).first()


def allowed(user, client):
    return bool(identity_for(user, service_for(client)))


class SSOValidator(OAuth2Validator):
    oidc_claim_scope = None

    def validate_client_id(self, client_id, request, *args, **kwargs):
        return super().validate_client_id(client_id, request, *args, **kwargs) and bool(
            service_for(request.client)
        )

    def validate_response_type(
        self, client_id, response_type, client, request, *args, **kwargs
    ):
        return (
            response_type == "code"
            and bool(request.state)
            and (bool(request.nonce) or not self.is_pkce_required(client_id, request))
            and (request.user is None or allowed(request.user, client))
            and (
                not self.is_pkce_required(client_id, request)
                or (
                    bool(request.code_challenge)
                    and request.code_challenge_method == "S256"
                )
            )
            and super().validate_response_type(
                client_id, response_type, client, request, *args, **kwargs
            )
        )

    def validate_grant_type(
        self, client_id, grant_type, client, request, *args, **kwargs
    ):
        return (
            bool(service_for(client))
            and grant_type in {"authorization_code", "refresh_token"}
            and super().validate_grant_type(
                client_id, grant_type, client, request, *args, **kwargs
            )
        )

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        return "openid" in scopes and super().validate_scopes(
            client_id, scopes, client, request, *args, **kwargs
        )

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        # Require an explicit redirect_uri even for single-callback clients.
        return None

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        parts = urlsplit(redirect_uri)
        return (
            parts.scheme == "https"
            and bool(parts.netloc)
            and not parts.fragment
            and not parts.username
            and redirect_uri in request.client.redirect_uris.split()
        )

    def confirm_redirect_uri(
        self, client_id, code, redirect_uri, client, *args, **kwargs
    ):
        return (
            redirect_uri in client.redirect_uris.split()
            and super().confirm_redirect_uri(
                client_id, code, redirect_uri, client, *args, **kwargs
            )
        )

    def is_pkce_required(self, client_id, request):
        service = service_for(request.client)
        return not (
            service
            and service.slug == "minio"
            and client_id == settings.SSO_MINIO_PKCE_EXCEPTION_CLIENT_ID
        )

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        return super().validate_code(
            client_id, code, client, request, *args, **kwargs
        ) and allowed(request.user, client)

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        return super().validate_refresh_token(
            refresh_token, client, request, *args, **kwargs
        ) and allowed(request.user, client)

    def validate_bearer_token(self, token, scopes, request):
        return super().validate_bearer_token(token, scopes, request) and allowed(
            request.user, request.client
        )

    def get_additional_claims(self, request):
        service = service_for(request.client)
        identity = identity_for(request.user, service)
        if not identity:
            return {}
        claims = {
            "preferred_username": identity.external_username,
            "groups": [f"service_{service.slug}"],
            "email_verified": False,
        }
        if service.slug == "matrix":
            claims["matrix_localpart"] = identity.external_username
        if service.slug == "minio" and identity.minio_policy:
            claims["policy"] = identity.minio_policy
        if service.slug == "jenkins":
            claims["jenkins_uid"] = identity.external_username
            if identity.jenkins_admin:
                claims["jenkins_eligible"] = "true"
        return claims
