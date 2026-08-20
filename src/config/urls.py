from django.contrib import admin
from django.http import HttpRequest, JsonResponse
from django.urls import path

from rbac.api import check_view


def healthz(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"status": "ok"})


urlpatterns = [
    path("admin/", admin.site.urls),
    path("healthz", healthz),
    path("api/v1/check", check_view),
]
