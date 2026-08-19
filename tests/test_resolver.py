from datetime import timedelta

import pytest
from django.utils import timezone

from rbac.models import RoleAssignment, RoleEdge
from rbac.resolver import resolved_role_ids

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
