from typing import Any

from django.db import IntegrityError, transaction
from rest_framework import generics, status
from rest_framework.decorators import api_view
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import BaseSerializer
from rest_framework.views import APIView

from rbac import audit, resolver
from rbac.models import Principal, Role
from rbac.resolver import CycleError
from rbac.serializers import CheckSerializer, EdgeSerializer, RoleSerializer


def _actor(request: Request) -> Principal | None:
    user = getattr(request, "user", None)
    return user if isinstance(user, Principal) else None


@api_view(["POST"])
def check_view(request: Request) -> Response:
    serializer = CheckSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data
    allowed = resolver.check(
        data["principal_id"],
        data["permission_id"],
        data["scope_type"],
        data["scope_id"],
    )
    return Response({"allowed": allowed})


class RoleListCreate(generics.ListCreateAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

    def perform_create(self, serializer: BaseSerializer[Any]) -> None:
        with transaction.atomic():
            role = serializer.save()
            audit.record(
                "role.create", role, actor=_actor(self.request), after=audit.snapshot(role)
            )


class RoleDetail(generics.RetrieveDestroyAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

    def perform_destroy(self, instance: Role) -> None:
        if instance.is_system:
            raise PermissionDenied("system roles cannot be deleted")
        with transaction.atomic():
            audit.record(
                "role.delete", instance, actor=_actor(self.request), before=audit.snapshot(instance)
            )
            instance.delete()


class EdgeCreate(APIView):
    def post(self, request: Request) -> Response:
        serializer = EdgeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        child = serializer.validated_data["child"]
        parent = serializer.validated_data["parent"]
        try:
            with transaction.atomic():
                edge = resolver.add_edge(child.id, parent.id)
                audit.record("edge.create", edge, actor=_actor(request), after=audit.snapshot(edge))
        except CycleError as exc:
            raise ValidationError(str(exc)) from exc
        except IntegrityError as exc:
            raise ValidationError("edge already exists") from exc
        return Response(
            {"child": edge.child_id, "parent": edge.parent_id}, status=status.HTTP_201_CREATED
        )
