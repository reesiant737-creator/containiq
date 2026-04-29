from flask import request as flask_request
from ..app import db
from ..models.audit import AuditLog


def audit(
    action: str,
    *,
    user_id: int = None,
    org_id: int = None,
    resource_type: str = None,
    resource_id: str = None,
    case_id: int = None,
    payload: dict = None,
    outcome: str = "success",
):
    """Append an immutable audit record. Never raises — failures are logged to stderr."""
    try:
        ip = None
        try:
            ip = flask_request.remote_addr
        except RuntimeError:
            pass

        entry = AuditLog(
            org_id=org_id or 0,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            case_id=case_id,
            ip_address=ip,
            outcome=outcome,
        )
        if payload:
            entry.payload = payload
        db.session.add(entry)
        db.session.commit()
    except Exception as exc:
        import sys
        print(f"[AUDIT ERROR] {action}: {exc}", file=sys.stderr)
