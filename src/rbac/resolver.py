from django.db import connection

_ROLE_CLOSURE_SQL = """
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
SELECT DISTINCT role_id FROM role_closure;
"""


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
