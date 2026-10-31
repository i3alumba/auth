from django.urls import path
from . import sessions, views

urlpatterns = [
    path("access/", views.access),
    path("session/", sessions.session),
    path("session/login/", sessions.session_login),
    path("session/token/", sessions.session_token),
    path("session/logout/", sessions.session_logout),
]
