from django.urls import path

from .views import (
    ActivationView,
    CapabilitiesView,
    ChangeView,
    NativeManagementView,
    ReactivationView,
    UserView,
    UsersView,
)

urlpatterns = [
    path("capabilities/", CapabilitiesView.as_view()),
    path("users/", UsersView.as_view()),
    path("users/<int:user_id>/", UserView.as_view()),
    path("users/<int:user_id>/deactivate/", ActivationView.as_view()),
    path("users/<int:user_id>/reactivate/", ReactivationView.as_view()),
    path(
        "users/<int:user_id>/native/<str:service>/<str:action>/",
        NativeManagementView.as_view(),
    ),
    path("changes/<uuid:change_id>/", ChangeView.as_view()),
]
