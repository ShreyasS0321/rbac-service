from django.contrib import admin
from django.http import HttpRequest, JsonResponse
from django.urls import path


def healthz(request: HttpRequest) -> JsonResponse:

    return JsonResponse({"status": "ok"})


urlpatterns = [path("admin/", admin.site.urls), path("healthz", healthz)]
