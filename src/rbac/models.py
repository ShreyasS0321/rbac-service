from typing import Any

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import timezone


class Effect(models.TextChoices):
    ALLOW = "allow", "Allow"
    DENY = "deny", "Deny"


class PrincipalManager(BaseUserManager):
    def create_user(self, username: str, password: str | None = None, **extra: Any) -> "Principal":
        if not username:
            raise ValueError("username is required")
        user: Principal = self.model(username=username, **extra)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(
        self, username: str, password: str | None = None, **extra: Any
    ) -> "Principal":
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        return self.create_user(username, password, **extra)


class Principal(AbstractBaseUser):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = PrincipalManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS: list[str] = []

    def __str__(self) -> str:
        return self.username

    def has_perm(self, perm: str, obj: object | None = None) -> bool:
        return self.is_superuser

    def has_module_perms(self, app_label: str) -> bool:
        return self.is_superuser


class Permission(models.Model):
    resource_type = models.CharField(max_length=64)
    action = models.CharField(max_length=64)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["resource_type", "action"],
                name="rbac_permission_unique_type_action",
            )
        ]

    def __str__(self) -> str:
        return f"{self.resource_type}:{self.action}"


class Role(models.Model):
    key = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(blank=True)
    is_system = models.BooleanField(default=False)

    def __str__(self) -> str:
        return self.key


class RolePermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="grants")
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE, related_name="grants")
    effect = models.CharField(max_length=5, choices=Effect.choices, default=Effect.ALLOW)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["role", "permission"],
                name="rbac_rolepermission_unique_role_perm",
            )
        ]

    def __str__(self) -> str:
        return f"{self.role.key} {self.effect} {self.permission}"


class RoleEdge(models.Model):
    parent = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="parent_edges")
    child = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="child_edges")

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["parent", "child"],
                name="rbac_roleedge_unique_child_parent",
            ),
            models.CheckConstraint(
                condition=~models.Q(child=models.F("parent")),
                name="rbac_roleedge_no_self_loop",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.child.key} -> {self.parent.key}"
