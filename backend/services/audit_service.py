"""Audit service – thin helper to insert audit log entries."""

from datetime import datetime
from sqlalchemy.orm import Session
from backend.models.audit_log import AuditLog


def log_action(
    db: Session,
    *,
    actor: str,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict | None = None,
    ip: str | None = None,
):
    """Create an audit log entry.  Caller is responsible for committing."""
    entry = AuditLog(
        actor_email=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details or {},
        ip_address=ip,
        timestamp=datetime.utcnow(),
    )
    db.add(entry)
