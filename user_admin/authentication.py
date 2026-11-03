"""Central credential epochs: reactivation must not resurrect old credentials."""

from dataclasses import dataclass, field

from django.contrib.auth import BACKEND_SESSION_KEY, get_user_model, logout
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.core.exceptions import PermissionDenied
from django.db import transaction
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.serializers import (
    TokenRefreshSerializer,
    TokenVerifySerializer,
)
from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken

from .models import AdministrationLock, UserControl

EPOCH = "ua_epoch"
BACKEND = "user_admin.authentication.EpochModelBackend"


@dataclass(frozen=True)
class LoginProof:
    user_id: int
    epoch: int
    password_state: str = field(repr=False)


class EpochModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # Password verification and the captured epoch describe ONE auth event.
        # Never upgrade that event to a later epoch at session/token issuance.
        with transaction.atomic():
            credential_lock()
            user = super().authenticate(request, username, password, **kwargs)
            if user is not None:
                user._ua_login_proof = LoginProof(
                    user.pk, current_epoch(user.pk), user.password
                )
            return user


class CompatibleAuthenticationMiddleware(AuthenticationMiddleware):
    def process_request(self, request):
        # Preserve existing epoch-zero sessions after the backend class changes.
        # This translates a known backend path, never the epoch/user/hash proof.
        if (
            request.session.get(BACKEND_SESSION_KEY)
            == "django.contrib.auth.backends.ModelBackend"
        ):
            request.session[BACKEND_SESSION_KEY] = BACKEND
        super().process_request(request)


def check_login_proof(user, proof):
    if (
        type(proof) is not LoginProof
        or proof.user_id != user.pk
        or proof.epoch != current_epoch(user.pk)
        or proof.password_state != user.password
    ):
        raise AuthenticationFailed(
            "Authentication event revoked", code="credentials_revoked"
        )


def credential_lock():
    AdministrationLock.objects.select_for_update().get(pk=1)


def current_epoch(user_id):
    value = (
        UserControl.objects.filter(user_id=user_id)
        .values_list("auth_epoch", flat=True)
        .first()
    )
    return value if value is not None else 0


def fresh_active_user(user_id):
    user = get_user_model().objects.filter(pk=user_id, is_active=True).first()
    if user is None:
        raise AuthenticationFailed("Active credentials required", code="user_inactive")
    return user


def check_epoch(token):
    user_id = token.get("user_id")
    if type(user_id) not in {int, str}:
        raise AuthenticationFailed("Invalid credentials", code="token_revoked")
    try:
        parsed_id = int(user_id)
        if not 0 < parsed_id < 2**63:
            raise ValueError
    except (ValueError, TypeError, OverflowError):
        raise AuthenticationFailed(
            "Invalid credentials", code="token_revoked"
        ) from None
    user = fresh_active_user(parsed_id)
    epoch = token.get(EPOCH, 0)
    if type(epoch) is not int or epoch != current_epoch(user.pk):
        raise AuthenticationFailed("Credentials revoked", code="token_revoked")
    return user


def issue_refresh(user, session_epoch=None):
    # Same singleton as deactivation. A request authenticated before a revoke
    # cannot acquire the new epoch while using an old browser session.
    proof = getattr(user, "_ua_login_proof", None)
    with transaction.atomic():
        credential_lock()
        user = fresh_active_user(user.pk)
        epoch = current_epoch(user.pk)
        if session_epoch is None:
            check_login_proof(user, proof)
        if session_epoch is not None and (
            type(session_epoch) is not int or session_epoch != epoch
        ):
            raise AuthenticationFailed("Session revoked", code="session_revoked")
        token = RefreshToken.for_user(user)
        token[EPOCH] = epoch
        return token


class EpochJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        user = super().get_user(validated_token)
        check_epoch(validated_token)
        return user


class EpochTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        with transaction.atomic():
            credential_lock()
            check_epoch(self.token_class(attrs["refresh"]))
            return super().validate(attrs)


class EpochTokenVerifySerializer(TokenVerifySerializer):
    def validate(self, attrs):
        result = super().validate(attrs)
        check_epoch(UntypedToken(attrs["token"]))
        return result


def stamp_session_epoch(sender, request, user, **kwargs):
    if request is None:
        return
    with transaction.atomic():
        credential_lock()
        try:
            fresh = fresh_active_user(user.pk)
            proof = getattr(user, "_ua_login_proof", None)
            if proof is not None:
                check_login_proof(fresh, proof)
            elif current_epoch(fresh.pk) != 0:
                # Legacy trusted programmatic login is compatible only at zero.
                raise AuthenticationFailed("Authentication proof required")
        except AuthenticationFailed as error:
            raise PermissionDenied("Active session required") from error
        request.session[EPOCH] = current_epoch(fresh.pk)


class SessionEpochMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            epoch = request.session.get(EPOCH, 0)
            if type(epoch) is not int or epoch != current_epoch(request.user.pk):
                logout(request)
            else:
                # Carry the session's original proof into OAuth validation; do
                # not substitute a freshly read epoch on a stale request later.
                request.user._ua_session_epoch = epoch
        return self.get_response(request)
