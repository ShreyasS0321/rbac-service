import pytest

pytestmark = pytest.mark.django_db

MODELS = [
    "principal",
    "permission",
    "role",
    "roleedge",
    "rolepermission",
    "roleassignment",
    "auditevent",
]


@pytest.mark.parametrize("model", MODELS)
def test_admin_changelist_renders(admin_client, model):
    response = admin_client.get(f"/admin/rbac/{model}/")
    assert response.status_code == 200


def test_audit_admin_is_read_only(admin_client):
    response = admin_client.get("/admin/rbac/auditevent/add/")
    assert response.status_code == 403
