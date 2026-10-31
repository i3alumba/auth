from django.urls import path
from oauth2_provider import views

from .oidc_views import ServiceAuthorizationView, ServiceDiscoveryView, ServiceJwksView

app_name = "oauth2_provider"
urlpatterns = [
    path("authorize/", ServiceAuthorizationView.as_view(), name="authorize"),
    path("token/", views.TokenView.as_view(), name="token"),
    path("revoke_token/", views.RevokeTokenView.as_view(), name="revoke-token"),
    path("userinfo/", views.UserInfoView.as_view(), name="user-info"),
    path(
        ".well-known/openid-configuration",
        ServiceDiscoveryView.as_view(),
        name="oidc-connect-discovery-info",
    ),
    path(".well-known/jwks.json", ServiceJwksView.as_view(), name="jwks-info"),
]
