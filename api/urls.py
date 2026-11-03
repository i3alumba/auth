from rest_framework.routers import DefaultRouter
from django.urls import include, path
from rest_framework_simplejwt.views import (
    TokenVerifyView,
    TokenRefreshView,
)

from api.views import GroupViewSet, UserViewSet
from sso.tokens import LimitedTokenObtainPairView
from user_admin.authentication import (
    EpochTokenRefreshSerializer,
    EpochTokenVerifySerializer,
)

router = DefaultRouter()
router.register("user", UserViewSet, basename="user")
router.register("group", GroupViewSet, basename="group")

urlpatterns = [
    path("", include(router.urls)),
    path("user-admin/", include("user_admin.urls")),
    path("token/", LimitedTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path(
        "token/refresh/",
        TokenRefreshView.as_view(serializer_class=EpochTokenRefreshSerializer),
        name="token_refresh",
    ),
    path(
        "token/verify/",
        TokenVerifyView.as_view(serializer_class=EpochTokenVerifySerializer),
        name="token_verify",
    ),
]
