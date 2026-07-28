import pytest

from rbac.models import Permission, Principal, Role


@pytest.fixture
def make_principal():
    def _make(username: str = "user", **extra) -> Principal:
        return Principal.objects.create_user(username=username, password="pw", **extra)

    return _make


@pytest.fixture
def make_role():
    def _make(key: str, **extra) -> Role:
        return Role.objects.create(key=key, name=extra.pop("name", key.title()), **extra)

    return _make


@pytest.fixture
def make_permission():
    def _make(resource_type: str, action: str) -> Permission:
        return Permission.objects.create(resource_type=resource_type, action=action)

    return _make
