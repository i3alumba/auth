from rest_framework.routers import DefaultRouter
from django.urls import include, path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenVerifyView,
    TokenRefreshView,
)

from api.views import GroupViewSet, UserViewSet

router = DefaultRouter()
router.register("user", UserViewSet, basename="user")
router.register("group", GroupViewSet, basename="group")

urlpatterns = [
    path("", include(router.urls)),
    path("token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("token/verify/", TokenVerifyView.as_view(), name="token_verify"),
]
