from django.db import connection

_ROLE_CLOSURE_CTE = """
WITH RECURSIVE role_closure AS (
    SELECT role_id, 0 AS depth
    FROM   rbac_roleassignment
    WHERE  principal_id = %(principal)s
      AND  (scope_id IS NULL OR (scope_type = %(stype)s AND scope_id = %(sid)s))
      AND  (expires_at IS NULL OR expires_at > now())

    UNION

    SELECT e.parent_id, rc.depth + 1
    FROM   rbac_roleedge e
    JOIN   role_closure rc ON e.child_id = rc.role_id
    WHERE  rc.depth < 32
)
"""

_ROLE_CLOSURE_SQL = _ROLE_CLOSURE_CTE + "SELECT DISTINCT role_id FROM role_closure;"

_EFFECTIVE_PERMISSIONS_SQL = (
    _ROLE_CLOSURE_CTE
    + """
SELECT rp.permission_id
FROM   rbac_rolepermission rp
JOIN   role_closure rc ON rc.role_id = rp.role_id
GROUP BY rp.permission_id
HAVING bool_or(rp.effect = 'deny') = false;
"""
)


def resolved_role_ids(
    principal_id: int, scope_type: str | None = None, scope_id: str | None = None
) -> set[int]:
    with connection.cursor() as cur:
        cur.execute(
            _ROLE_CLOSURE_SQL,
            {"principal": principal_id, "stype": scope_type, "sid": scope_id},
        )
        rows = cur.fetchall()
    return {row[0] for row in rows}


def effective_permissions(
    principal_id: int, scope_type: str | None = None, scope_id: str | None = None
) -> set[int]:
    with connection.cursor() as cur:
        cur.execute(
            _EFFECTIVE_PERMISSIONS_SQL,
            {"principal": principal_id, "stype": scope_type, "sid": scope_id},
        )
        rows = cur.fetchall()
    return {row[0] for row in rows}


def check(
    principal_id: int,
    permission_id: int,
    scope_type: str | None = None,
    scope_id: str | None = None,
) -> bool:
    return permission_id in effective_permissions(principal_id, scope_type, scope_id)
