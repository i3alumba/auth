from django.contrib import admin
from .models import Service, ServiceIdentity, ProvisionRun


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ["slug", "group", "oidc_client_id"]


@admin.register(ServiceIdentity)
class ServiceIdentityAdmin(admin.ModelAdmin):
    list_display = ["user", "service", "external_id", "external_username"]
    list_filter = ["service"]


@admin.register(ProvisionRun)
class ProvisionRunAdmin(admin.ModelAdmin):
    list_display = ["id", "created_at"]
    readonly_fields = ["fingerprint", "created_at", "created_ids"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
