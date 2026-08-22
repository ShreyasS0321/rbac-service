from django.contrib import admin
from django.http import HttpRequest, JsonResponse
from django.urls import path

from rbac.api import EdgeCreate, RoleDetail, RoleListCreate, check_view


def healthz(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"status": "ok"})


urlpatterns = [
    path("admin/", admin.site.urls),
    path("healthz", healthz),
    path("api/v1/check", check_view),
    path("api/v1/roles", RoleListCreate.as_view()),
    path("api/v1/roles/<int:pk>", RoleDetail.as_view()),
    path("api/v1/edges", EdgeCreate.as_view()),
]
