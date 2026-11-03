"""Serialize both legacy password routes and save no stale user flags."""

from django.contrib import admin
from django.contrib.admin.forms import AdminPasswordChangeForm as OwnPasswordForm
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AdminPasswordChangeForm as OtherPasswordForm
from django.contrib.auth.views import PasswordChangeView
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.urls import reverse
from django.utils.crypto import constant_time_compare
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables

from .authentication import EPOCH, credential_lock, current_epoch


def fresh_session_actor(request):
    actor = (
        get_user_model()
        .objects.filter(pk=request.user.pk, is_active=True, is_staff=True)
        .first()
    )
    epoch = request.session.get(EPOCH, 0)
    if actor is None or type(epoch) is not int or epoch != current_epoch(actor.pk):
        raise PermissionDenied("Session revoked")
    session_hash = request.session.get("_auth_user_hash", "")
    if not any(
        constant_time_compare(session_hash, candidate)
        for candidate in (
            actor.get_session_auth_hash(),
            *actor.get_session_auth_fallback_hash(),
        )
    ):
        raise PermissionDenied("Session revoked")
    actor._ua_session_epoch = epoch
    return actor


class PasswordOnlySaveMixin:
    @sensitive_variables("self", "user")
    def set_password_and_save(self, user, password_field_name="password1", commit=True):
        # Keep Django's validation/unusable-password branch and commit=False
        # semantics. Only narrow the eventual save, never reimplement the choice.
        user = super().set_password_and_save(
            user, password_field_name=password_field_name, commit=False
        )
        if commit:
            user.save(update_fields=["password"])
        return user


class SafeOwnPasswordForm(PasswordOnlySaveMixin, OwnPasswordForm):
    pass


class SafeOtherPasswordForm(PasswordOnlySaveMixin, OtherPasswordForm):
    pass


@sensitive_post_parameters()
def own_password_change(request):
    def response():
        request.current_app = admin.site.name
        options = {
            "form_class": SafeOwnPasswordForm,
            "success_url": reverse(
                "admin:password_change_done", current_app=admin.site.name
            ),
            "extra_context": admin.site.each_context(request),
        }
        if admin.site.password_change_template is not None:
            options["template_name"] = admin.site.password_change_template
        return PasswordChangeView.as_view(**options)(request)

    if request.method != "POST":
        return response()
    with transaction.atomic():
        credential_lock()
        request.user = fresh_session_actor(request)
        return response()
