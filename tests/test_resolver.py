from datetime import timedelta

import pytest
from django.utils import timezone

from rbac.models import Effect, RoleAssignment, RoleEdge, RolePermission
from rbac.resolver import check, effective_permissions, resolved_role_ids

pytestmark = pytest.mark.django_db


@pytest.fixture
def chain(make_role):
    viewer = make_role("viewer")
    editor = make_role("editor")
    admin = make_role("admin")
    RoleEdge.objects.create(child=editor, parent=viewer)
    RoleEdge.objects.create(child=admin, parent=editor)
    return viewer, editor, admin


def test_direct_role_only(make_principal, make_role):
    alice = make_principal("alice")
    viewer = make_role("viewer")
    RoleAssignment.objects.create(principal=alice, role=viewer)
    assert resolved_role_ids(alice.id) == {viewer.id}


def test_walks_full_chain(make_principal, chain):
    viewer, editor, admin = chain
    alice = make_principal("alice")
    RoleAssignment.objects.create(principal=alice, role=admin)
    assert resolved_role_ids(alice.id) == {admin.id, editor.id, viewer.id}


def test_diamond_reached_once(make_principal, make_role):
    lead = make_role("lead")
    eng = make_role("engineer")
    mgr = make_role("manager")
    emp = make_role("employee")
    RoleEdge.objects.create(child=lead, parent=eng)
    RoleEdge.objects.create(child=lead, parent=mgr)
    RoleEdge.objects.create(child=eng, parent=emp)
    RoleEdge.objects.create(child=mgr, parent=emp)
    alice = make_principal("alice")
    RoleAssignment.objects.create(principal=alice, role=lead)
    assert resolved_role_ids(alice.id) == {lead.id, eng.id, mgr.id, emp.id}


def test_no_assignment_is_empty(make_principal):
    alice = make_principal("alice")
    assert resolved_role_ids(alice.id) == set()


def test_scoped_assignment_matches_only_its_scope(make_principal, make_role):
    bob = make_principal("bob")
    admin = make_role("admin")
    RoleAssignment.objects.create(principal=bob, role=admin, scope_type="org", scope_id="42")
    assert resolved_role_ids(bob.id, "org", "42") == {admin.id}
    assert resolved_role_ids(bob.id, "org", "99") == set()
    assert resolved_role_ids(bob.id) == set()


def test_global_assignment_matches_every_scope(make_principal, make_role):
    root = make_principal("root")
    admin = make_role("admin")
    RoleAssignment.objects.create(principal=root, role=admin)
    assert resolved_role_ids(root.id) == {admin.id}
    assert resolved_role_ids(root.id, "org", "42") == {admin.id}


def test_expired_assignment_ignored(make_principal, make_role):
    alice = make_principal("alice")
    admin = make_role("admin")
    RoleAssignment.objects.create(
        principal=alice, role=admin, expires_at=timezone.now() - timedelta(hours=1)
    )
    assert resolved_role_ids(alice.id) == set()


def test_future_expiry_still_active(make_principal, make_role):
    alice = make_principal("alice")
    admin = make_role("admin")
    RoleAssignment.objects.create(
        principal=alice, role=admin, expires_at=timezone.now() + timedelta(hours=1)
    )
    assert resolved_role_ids(alice.id) == {admin.id}


def test_effective_permissions_direct_allow(make_principal, make_role, make_permission):
    alice = make_principal("alice")
    editor = make_role("editor")
    write = make_permission("document", "write")
    RoleAssignment.objects.create(principal=alice, role=editor)
    RolePermission.objects.create(role=editor, permission=write, effect=Effect.ALLOW)
    assert effective_permissions(alice.id) == {write.id}


def test_permission_inherited_from_parent(make_principal, chain, make_permission):
    viewer, editor, admin = chain
    read = make_permission("document", "read")
    RolePermission.objects.create(role=viewer, permission=read, effect=Effect.ALLOW)
    alice = make_principal("alice")
    RoleAssignment.objects.create(principal=alice, role=admin)
    assert read.id in effective_permissions(alice.id)


def test_deny_beats_allow_same_role(make_principal, make_role, make_permission):
    alice = make_principal("alice")
    editor = make_role("editor")
    delete = make_permission("document", "delete")
    RolePermission.objects.create(role=editor, permission=delete, effect=Effect.DENY)
    RoleAssignment.objects.create(principal=alice, role=editor)
    assert delete.id not in effective_permissions(alice.id)


def test_inherited_deny_overrides_child_allow(make_principal, chain, make_permission):
    viewer, editor, admin = chain
    export = make_permission("document", "export")
    RolePermission.objects.create(role=viewer, permission=export, effect=Effect.DENY)
    RolePermission.objects.create(role=admin, permission=export, effect=Effect.ALLOW)
    alice = make_principal("alice")
    RoleAssignment.objects.create(principal=alice, role=admin)
    assert export.id not in effective_permissions(alice.id)


def test_check_true_and_false(make_principal, make_role, make_permission):
    alice = make_principal("alice")
    editor = make_role("editor")
    write = make_permission("document", "write")
    other = make_permission("document", "read")
    RolePermission.objects.create(role=editor, permission=write, effect=Effect.ALLOW)
    RoleAssignment.objects.create(principal=alice, role=editor)
    assert check(alice.id, write.id) is True
    assert check(alice.id, other.id) is False


def test_scoped_permission_isolated(make_principal, make_role, make_permission):
    bob = make_principal("bob")
    admin = make_role("admin")
    manage = make_permission("org", "manage")
    RolePermission.objects.create(role=admin, permission=manage, effect=Effect.ALLOW)
    RoleAssignment.objects.create(principal=bob, role=admin, scope_type="org", scope_id="42")
    assert check(bob.id, manage.id, "org", "42") is True
    assert check(bob.id, manage.id, "org", "99") is False
