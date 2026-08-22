import pytest
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from rbac.models import AuditEvent, Principal

pytestmark = pytest.mark.django_db


def test_token_identifies_actor_in_audit():
    alice = Principal.objects.create_user("alice", "pw")
    token = Token.objects.create(user=alice)
    api = APIClient()
    api.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

    resp = api.post("/api/v1/roles", {"key": "editor", "name": "Editor"})
    assert resp.status_code == 201
    event = AuditEvent.objects.get(action="role.create")
    assert event.actor == alice


def test_no_token_leaves_actor_null():
    api = APIClient()
    resp = api.post("/api/v1/roles", {"key": "editor", "name": "Editor"})
    assert resp.status_code == 201
    event = AuditEvent.objects.get(action="role.create")
    assert event.actor is None


def test_bad_token_rejected():
    api = APIClient()
    api.credentials(HTTP_AUTHORIZATION="Token deadbeef")
    resp = api.post("/api/v1/roles", {"key": "editor", "name": "Editor"})
    assert resp.status_code == 401
