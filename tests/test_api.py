import pytest
from rest_framework.test import APIClient

from rbac.models import Effect, Permission, Principal, Role, RoleAssignment, RolePermission

pytestmark = pytest.mark.django_db


@pytest.fixture
def api():
    return APIClient()


def test_check_allowed(api):
    alice = Principal.objects.create_user("alice", "pw")
    editor = Role.objects.create(key="editor", name="Editor")
    write = Permission.objects.create(resource_type="document", action="write")
    RolePermission.objects.create(role=editor, permission=write, effect=Effect.ALLOW)
    RoleAssignment.objects.create(principal=alice, role=editor)

    resp = api.post("/api/v1/check", {"principal_id": alice.id, "permission_id": write.id})
    assert resp.status_code == 200
    assert resp.data == {"allowed": True}


def test_check_denied_when_no_grant(api):
    alice = Principal.objects.create_user("alice", "pw")
    perm = Permission.objects.create(resource_type="document", action="write")
    resp = api.post("/api/v1/check", {"principal_id": alice.id, "permission_id": perm.id})
    assert resp.status_code == 200
    assert resp.data == {"allowed": False}


def test_check_missing_field_is_400(api):
    resp = api.post("/api/v1/check", {"principal_id": 1})
    assert resp.status_code == 400
