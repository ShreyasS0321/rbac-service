import pytest
from django.db import IntegrityError

from rbac.models import AuditEvent, Effect, Principal, RoleAssignment, RoleEdge, RolePermission

pytestmark = pytest.mark.django_db


def test_permission_str(make_permission):
    perm = make_permission("document", "read")
    assert str(perm) == "document:read"


def test_permission_duplicate_pair_rejected(make_permission):
    make_permission("document", "read")
    with pytest.raises(IntegrityError):
        make_permission("document", "read")


def test_permission_same_type_different_action_allowed(make_permission):
    make_permission("document", "read")
    make_permission("document", "write")


def test_role_str(make_role):
    assert str(make_role("editor")) == "editor"


def test_role_duplicate_key_rejected(make_role):
    make_role("editor")
    with pytest.raises(IntegrityError):
        make_role("editor")


def test_create_user_hashes_password():
    user = Principal.objects.create_user("alice", "secret")
    assert user.password != "secret"
    assert user.check_password("secret")


def test_create_user_requires_username():
    with pytest.raises(ValueError):
        Principal.objects.create_user("", "secret")


def test_create_superuser_sets_flags():
    root = Principal.objects.create_superuser("root", "secret")
    assert root.is_staff
    assert root.is_superuser


def test_has_perm_tracks_superuser(make_principal):
    root = Principal.objects.create_superuser("root", "pw")
    regular = make_principal("regular")
    assert root.has_perm("anything") is True
    assert regular.has_perm("anything") is False


def test_roleedge_str(make_role):
    edge = RoleEdge.objects.create(child=make_role("editor"), parent=make_role("viewer"))
    assert str(edge) == "editor -> viewer"


def test_roleedge_self_loop_rejected(make_role):
    viewer = make_role("viewer")
    with pytest.raises(IntegrityError):
        RoleEdge.objects.create(child=viewer, parent=viewer)


def test_roleedge_duplicate_rejected(make_role):
    child, parent = make_role("editor"), make_role("viewer")
    RoleEdge.objects.create(child=child, parent=parent)
    with pytest.raises(IntegrityError):
        RoleEdge.objects.create(child=child, parent=parent)


def test_rolepermission_unique_role_perm_rejected(make_role, make_permission):
    role, perm = make_role("editor"), make_permission("document", "read")
    RolePermission.objects.create(role=role, permission=perm, effect=Effect.ALLOW)
    with pytest.raises(IntegrityError):
        RolePermission.objects.create(role=role, permission=perm, effect=Effect.DENY)


def test_assignment_duplicate_global_rejected(make_principal, make_role):
    alice, admin = make_principal("alice"), make_role("admin")
    RoleAssignment.objects.create(principal=alice, role=admin)
    with pytest.raises(IntegrityError):
        RoleAssignment.objects.create(principal=alice, role=admin)


def test_assignment_duplicate_scoped_rejected(make_principal, make_role):
    alice, admin = make_principal("alice"), make_role("admin")
    RoleAssignment.objects.create(principal=alice, role=admin, scope_type="org", scope_id="42")
    with pytest.raises(IntegrityError):
        RoleAssignment.objects.create(principal=alice, role=admin, scope_type="org", scope_id="42")


def test_assignment_different_scope_allowed(make_principal, make_role):
    alice, admin = make_principal("alice"), make_role("admin")
    RoleAssignment.objects.create(principal=alice, role=admin, scope_type="org", scope_id="42")
    RoleAssignment.objects.create(principal=alice, role=admin, scope_type="org", scope_id="99")
    assert RoleAssignment.objects.filter(principal=alice, role=admin).count() == 2


def test_assignment_global_and_scoped_coexist(make_principal, make_role):
    alice, admin = make_principal("alice"), make_role("admin")
    RoleAssignment.objects.create(principal=alice, role=admin)
    RoleAssignment.objects.create(principal=alice, role=admin, scope_type="org", scope_id="42")
    assert RoleAssignment.objects.filter(principal=alice, role=admin).count() == 2


def test_assignment_half_scope_rejected(make_principal, make_role):
    alice, admin = make_principal("alice"), make_role("admin")
    with pytest.raises(IntegrityError):
        RoleAssignment.objects.create(principal=alice, role=admin, scope_type="org")


def test_auditevent_json_roundtrip(make_principal):
    event = AuditEvent.objects.create(
        actor=make_principal("root"),
        action="role.update",
        target_type="role",
        target_id="5",
        before={"key": "editor", "name": "Editor"},
        after={"key": "editor", "name": "Content Editor"},
    )
    event.refresh_from_db()
    assert event.before == {"key": "editor", "name": "Editor"}
    assert event.after["name"] == "Content Editor"
    assert event.created_at is not None


def test_auditevent_survives_actor_deletion(make_principal):
    actor = make_principal("root")
    event = AuditEvent.objects.create(
        actor=actor, action="role.delete", target_type="role", target_id="5"
    )
    actor.delete()
    event.refresh_from_db()
    assert event.actor is None
