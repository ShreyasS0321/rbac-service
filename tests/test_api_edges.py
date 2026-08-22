import pytest
from rest_framework.test import APIClient

from rbac.models import AuditEvent, Role, RoleEdge

pytestmark = pytest.mark.django_db


@pytest.fixture
def api():
    return APIClient()


def test_create_edge(api):
    child = Role.objects.create(key="editor", name="Editor")
    parent = Role.objects.create(key="viewer", name="Viewer")
    resp = api.post("/api/v1/edges", {"child": child.id, "parent": parent.id})
    assert resp.status_code == 201
    assert RoleEdge.objects.filter(child=child, parent=parent).exists()
    assert AuditEvent.objects.filter(action="edge.create").exists()


def test_edge_cycle_rejected(api):
    a = Role.objects.create(key="a", name="A")
    b = Role.objects.create(key="b", name="B")
    api.post("/api/v1/edges", {"child": a.id, "parent": b.id})
    resp = api.post("/api/v1/edges", {"child": b.id, "parent": a.id})
    assert resp.status_code == 400
    assert RoleEdge.objects.count() == 1


def test_edge_self_loop_rejected(api):
    a = Role.objects.create(key="a", name="A")
    resp = api.post("/api/v1/edges", {"child": a.id, "parent": a.id})
    assert resp.status_code == 400


def test_edge_duplicate_rejected(api):
    child = Role.objects.create(key="editor", name="Editor")
    parent = Role.objects.create(key="viewer", name="Viewer")
    api.post("/api/v1/edges", {"child": child.id, "parent": parent.id})
    resp = api.post("/api/v1/edges", {"child": child.id, "parent": parent.id})
    assert resp.status_code == 400
    assert RoleEdge.objects.count() == 1


def test_edge_unknown_role_is_400(api):
    child = Role.objects.create(key="editor", name="Editor")
    resp = api.post("/api/v1/edges", {"child": child.id, "parent": 999999})
    assert resp.status_code == 400


def test_edge_cycle_writes_no_audit(api):
    a = Role.objects.create(key="a", name="A")
    b = Role.objects.create(key="b", name="B")
    api.post("/api/v1/edges", {"child": a.id, "parent": b.id})
    api.post("/api/v1/edges", {"child": b.id, "parent": a.id})
    assert AuditEvent.objects.filter(action="edge.create").count() == 1
