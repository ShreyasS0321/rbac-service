import pytest
from rest_framework.test import APIClient

from rbac.models import AuditEvent, Role

pytestmark = pytest.mark.django_db


@pytest.fixture
def api():
    return APIClient()


def test_create_role_writes_audit(api):
    resp = api.post("/api/v1/roles", {"key": "editor", "name": "Editor"})
    assert resp.status_code == 201
    assert resp.data["key"] == "editor"
    role = Role.objects.get(key="editor")
    event = AuditEvent.objects.get(action="role.create")
    assert event.target_id == str(role.id)
    assert event.after["key"] == "editor"


def test_is_system_ignored_on_create(api):
    resp = api.post("/api/v1/roles", {"key": "admin", "name": "Admin", "is_system": True})
    assert resp.status_code == 201
    assert Role.objects.get(key="admin").is_system is False


def test_list_roles(api):
    Role.objects.create(key="viewer", name="Viewer")
    resp = api.get("/api/v1/roles")
    assert resp.status_code == 200
    assert any(r["key"] == "viewer" for r in resp.data)


def test_delete_role_writes_audit(api):
    role = Role.objects.create(key="editor", name="Editor")
    resp = api.delete(f"/api/v1/roles/{role.id}")
    assert resp.status_code == 204
    assert not Role.objects.filter(id=role.id).exists()
    event = AuditEvent.objects.get(action="role.delete")
    assert event.before["key"] == "editor"


def test_cannot_delete_system_role(api):
    role = Role.objects.create(key="admin", name="Admin", is_system=True)
    resp = api.delete(f"/api/v1/roles/{role.id}")
    assert resp.status_code == 403
    assert Role.objects.filter(id=role.id).exists()


def test_duplicate_key_is_400(api):
    Role.objects.create(key="editor", name="Editor")
    resp = api.post("/api/v1/roles", {"key": "editor", "name": "Dup"})
    assert resp.status_code == 400
