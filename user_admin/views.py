"""Bearer-only, live-superuser HTTP boundary. Disabled until explicit rollout."""

from uuid import UUID

from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.exceptions import APIException, PermissionDenied
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .authentication import EpochJWTAuthentication
from .grants import MANAGED
from .models import Operation, Target, UserChange
from .service import ChangeError, apply_change, editable_services, row


class AdministrationError(APIException):
    def __init__(self, code, status):
        self.status_code = status
        super().__init__({"code": code})


class AdministratorView(APIView):
    authentication_classes = [EpochJWTAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]
    require_enabled = True

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if (
            not get_user_model()
            .objects.filter(pk=request.user.pk, is_active=True, is_superuser=True)
            .exists()
        ):
            raise PermissionDenied("Administrator required")
        if self.require_enabled and not getattr(
            settings, "USER_ADMIN_API_ENABLED", False
        ):
            raise AdministrationError("administration_disabled", 503)

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        response["Cache-Control"] = "no-store"
        return response

    def change(self, request, action, user_id=None):
        try:
            try:
                key = UUID(request.headers.get("Idempotency-Key", ""))
            except (ValueError, AttributeError):
                raise ChangeError("idempotency_key_required") from None
            user, change, replayed = apply_change(
                proof=request.auth,
                key=key,
                action=action,
                data=request.data,
                user_id=user_id,
                expected=request.headers.get("If-Match"),
            )
        except ChangeError as error:
            raise AdministrationError(error.code, error.status) from None
        return Response(
            {
                "user": row(user),
                "change_id": str(change.pk),
                "replayed": replayed,
                "detail": (
                    "Existing result returned; no changes or password updates."
                    if replayed
                    else "Central changes saved; native status must be checked separately."
                ),
            },
            status=202,
        )


class CapabilitiesView(AdministratorView):
    require_enabled = False

    def get(self, request):
        return Response(
            {
                "administrator": True,
                "actor_id": request.user.pk,
                "enabled": bool(getattr(settings, "USER_ADMIN_API_ENABLED", False)),
                "native_execution_enabled": bool(
                    getattr(settings, "USER_ADMIN_NATIVE_EXECUTION_ENABLED", False)
                ),
                "editable_services": editable_services(),
                "readonly_services": [
                    slug
                    for slug in (*MANAGED, "jenkins")
                    if slug not in editable_services()
                ],
                "native_targets": Target.Service.values,
                "native_adapters_accepted": False,
            }
        )


class UsersView(AdministratorView):
    def get(self, request):
        raw_page = request.query_params.get("page", "1")
        try:
            if len(raw_page) > 8:
                raise ValueError
            page = int(raw_page)
            if page < 1:
                raise ValueError
        except (ValueError, TypeError):
            raise AdministrationError("invalid_page", 400) from None
        users = get_user_model().objects.order_by("pk")
        count = users.count()
        return Response(
            {
                "count": count,
                "page": page,
                "page_size": 50,
                "next_page": page + 1 if page * 50 < count else None,
                "results": [row(user) for user in users[(page - 1) * 50 : page * 50]],
            }
        )

    def post(self, request):
        return self.change(request, "create")


class UserView(AdministratorView):
    def patch(self, request, user_id):
        return self.change(request, "update", user_id)


class ActivationView(AdministratorView):
    action = "deactivate"

    def post(self, request, user_id):
        return self.change(request, self.action, user_id)


class ReactivationView(ActivationView):
    action = "reactivate"


class NativeManagementView(AdministratorView):
    def post(self, request, user_id, service, action):
        from .management import set_management

        if service not in Target.Service.values or action not in {"pause", "resume"}:
            raise AdministrationError("invalid_native_control", 400)
        if type(request.data) is not dict or set(request.data) != {"expected_epoch"}:
            raise AdministrationError("invalid_native_control", 400)
        target = Target.objects.filter(user_id=user_id, service=service).first()
        if target is None:
            raise AdministrationError("native_target_not_found", 404)
        try:
            try:
                key = UUID(request.headers.get("Idempotency-Key", ""))
            except (ValueError, AttributeError):
                raise ChangeError("idempotency_key_required") from None
            state, replayed = set_management(
                proof=request.auth,
                key=key,
                target_id=target.pk,
                expected_epoch=request.data["expected_epoch"],
                paused=action == "pause",
            )
        except ChangeError as error:
            raise AdministrationError(error.code, error.status) from None
        return Response({"management": state, "replayed": replayed}, status=202)


class ChangeView(AdministratorView):
    def get(self, request, change_id):
        change = UserChange.objects.filter(pk=change_id).first()
        if not change:
            raise AdministrationError("change_not_found", 404)
        # Native keys are uuid5(change, service), not the user-supplied key itself.
        from uuid import uuid5

        from .phases import latest_phase

        keys = [uuid5(change.pk, slug) for slug in Target.Service.values]
        native = []
        for initial in Operation.objects.filter(
            idempotency_key__in=keys
        ).select_related("target"):
            operation = latest_phase(initial.target, initial.generation) or initial
            native.append(
                {
                    "service": operation.target.service,
                    "phase": operation.action,
                    "status": operation.status,
                    "reason": operation.error_code,
                    "evidence": operation.evidence,
                }
            )
        return Response(
            {
                "id": str(change.pk),
                "user_id": change.user_id,
                "action": change.action,
                "changed_fields": change.changed_fields,
                "native": native,
            }
        )
