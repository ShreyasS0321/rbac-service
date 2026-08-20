import pytest

from rbac.audit import record, snapshot
from rbac.models import AuditEvent

pytestmark = pytest.mark.django_db


def test_snapshot_is_json_safe(make_role):
    role = make_role("editor")
    snap = snapshot(role)
    assert snap["key"] == "editor"
    assert snap["is_system"] is False
    assert snap["id"] == role.id


def test_snapshot_serializes_datetime(make_principal):
    alice = make_principal("alice")
    snap = snapshot(alice)
    assert isinstance(snap["date_joined"], str)


def test_snapshot_foreign_key_as_id(make_role):
    from rbac.resolver import add_edge

    child, parent = make_role("editor"), make_role("viewer")
    edge = add_edge(child.id, parent.id)
    snap = snapshot(edge)
    assert snap["child_id"] == child.id
    assert snap["parent_id"] == parent.id


def test_record_creates_event(make_principal, make_role):
    actor = make_principal("root")
    role = make_role("editor")
    event = record("role.create", role, actor=actor, after=snapshot(role))
    assert AuditEvent.objects.count() == 1
    event.refresh_from_db()
    assert event.action == "role.create"
    assert event.target_type == "role"
    assert event.target_id == str(role.id)
    assert event.actor == actor
    assert event.after["key"] == "editor"
    assert event.before is None


def test_record_update_before_and_after(make_role):
    role = make_role("editor")
    before = snapshot(role)
    role.name = "Content Editor"
    role.save()
    event = record("role.update", role, before=before, after=snapshot(role))
    assert event.before["name"] == "Editor"
    assert event.after["name"] == "Content Editor"
