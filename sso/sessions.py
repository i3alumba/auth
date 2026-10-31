import json
from datetime import timedelta

from django.contrib.auth import authenticate, login, logout
from django.db import transaction
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import render, redirect
from django.utils import timezone
from django.utils.crypto import salted_hmac
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_GET, require_POST, require_http_methods
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from api.serializers import UserSerializer
from .models import LoginAttempt


def pair(user):
    refresh = RefreshToken.for_user(user)
    return {"access": str(refresh.access_token), "refresh": str(refresh)}


def consume_login_attempt(request, username):
    key = salted_hmac(
        "sso.login", username.casefold() + "\0" + request.META.get("REMOTE_ADDR", "")
    ).hexdigest()
    now = timezone.now()
    with transaction.atomic():
        LoginAttempt.objects.filter(expires_at__lte=now).delete()
        attempt, _ = LoginAttempt.objects.select_for_update().get_or_create(
            key=key, defaults={"expires_at": now + timedelta(minutes=15)}
        )
        if attempt.failures >= 5:
            return False
        # Count all attempts, including successful ones, to bound password work.
        attempt.failures += 1
        attempt.save(update_fields=["failures"])
        return True


def credentials(request, username, password):
    if not consume_login_attempt(request, username):
        return None
    return authenticate(request, username=username, password=password)


def payload(request):
    try:
        data = json.loads(request.body)
        return data if isinstance(data, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}


@never_cache
@require_GET
def session(request):
    data = {
        "authenticated": request.user.is_authenticated,
        "csrfToken": get_token(request),
    }
    if request.user.is_authenticated:
        data["user"] = UserSerializer(request.user).data
    return JsonResponse(data)


@never_cache
@csrf_protect
@require_POST
def session_login(request):
    data = payload(request)
    username, password = data.get("username"), data.get("password")
    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or len(username) > 150
        or len(password) > 4096
    ):
        return JsonResponse({"detail": "Invalid credentials"}, status=400)
    user = credentials(request, username, password)
    if not user:
        return JsonResponse({"detail": "Invalid credentials or rate limit"}, status=401)
    login(request, user)
    request.session.cycle_key()
    return JsonResponse({**pair(user), "csrfToken": get_token(request)})


@never_cache
@csrf_protect
@require_POST
def session_token(request):
    if not request.user.is_authenticated or not request.user.is_active:
        return JsonResponse({"detail": "Session required"}, status=401)
    return JsonResponse(pair(request.user))


@never_cache
@csrf_protect
@require_POST
def session_logout(request):
    refresh = payload(request).get("refresh")
    if refresh:
        try:
            token = RefreshToken(refresh)
            if not request.user.is_authenticated or str(token["user_id"]) != str(
                request.user.pk
            ):
                return JsonResponse({"detail": "Not your refresh token"}, status=403)
            token.blacklist()
        except (TokenError, KeyError, TypeError):
            return JsonResponse({"detail": "Invalid refresh token"}, status=400)
    logout(request)
    return JsonResponse({"authenticated": False})


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def native_login(request):
    target = request.POST.get("next", request.GET.get("next", "/"))
    if not url_has_allowed_host_and_scheme(
        target, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        target = "/"
    error = None
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        user = (
            credentials(request, username, password)
            if len(username) <= 150 and len(password) <= 4096
            else None
        )
        if user:
            login(request, user)
            request.session.cycle_key()
            return redirect(target)
        error = "Invalid credentials or rate limit"
    return render(request, "sso/login.html", {"next": target, "error": error})
