import json
from typing import Any

from django.core.serializers.json import DjangoJSONEncoder
from django.db import models

from rbac.models import AuditEvent, Principal


def snapshot(instance: models.Model) -> dict[str, Any]:
    data = {f.attname: getattr(instance, f.attname) for f in instance._meta.concrete_fields}
    result: dict[str, Any] = json.loads(json.dumps(data, cls=DjangoJSONEncoder))
    return result


def record(
    action: str,
    target: models.Model,
    *,
    actor: Principal | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    request_id: str = "",
) -> AuditEvent:
    return AuditEvent.objects.create(
        actor=actor,
        action=action,
        target_type=target._meta.model_name or "",
        target_id=str(target.pk),
        before=before,
        after=after,
        request_id=request_id,
    )
