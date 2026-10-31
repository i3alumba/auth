"""
URL configuration for auth project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.conf import settings
from sso.sessions import native_login
from django.contrib import admin
from django.urls import include, path, re_path
from sso.minio_guard import console_login

from api.urls import urlpatterns as api_urlpatterns

urlpatterns = [
    re_path(r"^api/v1/login(?P<suffix>.*)$", console_login),
    path("api/", include("sso.urls")),
    path("api/", include(api_urlpatterns)),
    path("sso/login/", native_login),
    path("admin/", admin.site.urls),
]

if settings.SSO_ENABLED:
    urlpatterns += [path("o/", include("sso.oidc_urls"))]
