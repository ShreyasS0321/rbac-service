from django.contrib import admin

from rbac.models import (
    AuditEvent,
    Permission,
    Principal,
    Role,
    RoleAssignment,
    RoleEdge,
    RolePermission,
)


@admin.register(Principal)
class PrincipalAdmin(admin.ModelAdmin):
    list_display = ("username", "email", "is_active", "is_staff", "is_superuser", "date_joined")
    list_filter = ("is_active", "is_staff", "is_superuser")
    search_fields = ("username", "email")


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ("resource_type", "action")
    list_filter = ("resource_type",)
    search_fields = ("resource_type", "action")


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("key", "name", "is_system")
    list_filter = ("is_system",)
    search_fields = ("key", "name")


@admin.register(RoleEdge)
class RoleEdgeAdmin(admin.ModelAdmin):
    list_display = ("child", "parent")
    search_fields = ("child__key", "parent__key")


@admin.register(RolePermission)
class RolePermissionAdmin(admin.ModelAdmin):
    list_display = ("role", "permission", "effect")
    list_filter = ("effect",)
    search_fields = ("role__key",)


@admin.register(RoleAssignment)
class RoleAssignmentAdmin(admin.ModelAdmin):
    list_display = ("principal", "role", "scope_type", "scope_id", "expires_at", "granted_by")
    list_filter = ("scope_type",)
    search_fields = ("principal__username", "role__key")


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("created_at", "actor", "action", "target_type", "target_id")
    list_filter = ("action", "target_type")
    search_fields = ("target_id", "request_id")
    readonly_fields = (
        "actor",
        "action",
        "target_type",
        "target_id",
        "before",
        "after",
        "request_id",
        "created_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
