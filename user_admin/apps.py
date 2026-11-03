from django.apps import AppConfig


class UserAdminConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "user_admin"

    def ready(self):
        from django.contrib.auth.signals import user_logged_in
        from .authentication import stamp_session_epoch

        # Credential proof hook only; no queries/jobs/native work during startup.
        user_logged_in.connect(
            stamp_session_epoch, dispatch_uid="user_admin.session_epoch"
        )
