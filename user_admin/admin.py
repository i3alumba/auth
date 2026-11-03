"""Legacy admin transition: preserve its path while the new API is disabled."""

from django.conf import settings
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin
from django.core.exceptions import PermissionDenied
from django.db import transaction

from django.views.decorators.debug import sensitive_post_parameters
from django.utils.decorators import method_decorator

from .authentication import credential_lock
from .models import UserControl
from .passwords import SafeOtherPasswordForm, fresh_session_actor

User = get_user_model()


class GuardedUserAdmin(UserAdmin):
    change_password_form = SafeOtherPasswordForm

    @method_decorator(sensitive_post_parameters())
    def user_change_password(self, request, id, form_url=""):
        if request.method != "POST":
            return super().user_change_password(request, id, form_url)
        with transaction.atomic():
            credential_lock()
            request.user = fresh_session_actor(request)
            if (
                getattr(settings, "USER_ADMIN_API_ENABLED", False)
                and not request.user.is_superuser
            ):
                raise PermissionDenied("Administrator required")
            return super().user_change_password(request, id, form_url)

    def get_readonly_fields(self, request, obj=None):
        fields = list(super().get_readonly_fields(request, obj))
        if getattr(settings, "USER_ADMIN_API_ENABLED", False):
            fields += [
                "username",
                "is_active",
                "is_staff",
                "is_superuser",
                "groups",
                "user_permissions",
            ]
        return fields

    def has_add_permission(self, request):
        return not getattr(
            settings, "USER_ADMIN_API_ENABLED", False
        ) and super().has_add_permission(request)

    def has_delete_permission(self, request, obj=None):
        return False  # User lifecycle uses reversible deactivation, never deletion.

    def changeform_view(self, request, object_id=None, form_url="", extra_context=None):
        if request.method != "POST":
            return super().changeform_view(request, object_id, form_url, extra_context)
        with transaction.atomic():
            credential_lock()
            actor = fresh_session_actor(request)
            request.user = actor
            if (
                getattr(settings, "USER_ADMIN_API_ENABLED", False)
                and not actor.is_superuser
            ):
                raise PermissionDenied("Administrator required")
            return super().changeform_view(request, object_id, form_url, extra_context)

    def save_model(self, request, obj, form, change):
        if not change:
            return super().save_model(request, obj, form, change)
        with transaction.atomic():
            credential_lock()
            old = User.objects.select_for_update().get(pk=obj.pk)
            fields = set(form.changed_data) & {
                "username",
                "email",
                "first_name",
                "last_name",
                "is_active",
                "is_staff",
                "is_superuser",
            }
            if getattr(settings, "USER_ADMIN_API_ENABLED", False):
                fields &= {"email", "first_name", "last_name"}
            losing_admin = ("is_active" in fields and not obj.is_active) or (
                "is_superuser" in fields and not obj.is_superuser
            )
            if losing_admin and old.is_superuser:
                if old.pk == request.user.pk or (
                    old.is_active
                    and User.objects.filter(is_active=True, is_superuser=True).count()
                    <= 1
                ):
                    raise PermissionDenied("Administrator lockout prevented")
            if "is_active" in fields and old.is_active and not obj.is_active:
                from .service import _revoke

                control, _ = UserControl.objects.get_or_create(user=old)
                _revoke(old, control)
            if fields:
                # A stale profile form cannot restore flags/password from its old
                # model instance. Native identities and group writes are excluded.
                obj.save(update_fields=sorted(fields))


admin.site.unregister(User)
admin.site.register(User, GuardedUserAdmin)
