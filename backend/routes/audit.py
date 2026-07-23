"""Admin audit-log routes – paginated list and CSV export (admin-only)."""

import csv
import io
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.audit_log import AuditLog
from backend.models.user import User
from backend.routes.auth import verify_token


router = APIRouter()


def _require_admin(email: str, db: Session) -> User:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def _log_to_dict(log: AuditLog) -> dict:
    return {
        "id": log.id,
        "actor_email": log.actor_email,
        "action": log.action,
        "target_type": log.target_type,
        "target_id": log.target_id,
        "details": log.details,
        "ip_address": log.ip_address,
        "timestamp": log.timestamp.isoformat() if log.timestamp else None,
    }


@router.get("/audit-logs")
async def get_audit_logs(
    page: int = 1,
    per_page: int = 25,
    action: Optional[str] = None,
    actor_email: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    _require_admin(email, db)

    query = db.query(AuditLog)

    if action:
        query = query.filter(AuditLog.action == action)
    if actor_email:
        query = query.filter(AuditLog.actor_email.ilike(f"%{actor_email}%"))
    if start_date:
        try:
            sd = datetime.fromisoformat(start_date)
            query = query.filter(AuditLog.timestamp >= sd)
        except ValueError:
            pass
    if end_date:
        try:
            ed = datetime.fromisoformat(end_date)
            query = query.filter(AuditLog.timestamp <= ed)
        except ValueError:
            pass

    total = query.count()
    logs = (
        query.order_by(AuditLog.timestamp.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
        "logs": [_log_to_dict(l) for l in logs],
    }


@router.get("/audit-logs/export")
async def export_audit_logs(
    action: Optional[str] = None,
    actor_email: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    _require_admin(email, db)

    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    if actor_email:
        query = query.filter(AuditLog.actor_email.ilike(f"%{actor_email}%"))
    if start_date:
        try:
            query = query.filter(AuditLog.timestamp >= datetime.fromisoformat(start_date))
        except ValueError:
            pass
    if end_date:
        try:
            query = query.filter(AuditLog.timestamp <= datetime.fromisoformat(end_date))
        except ValueError:
            pass

    logs = query.order_by(AuditLog.timestamp.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Actor", "Action", "Target Type", "Target ID", "Details", "IP"])
    for log in logs:
        writer.writerow([
            log.timestamp.isoformat() if log.timestamp else "",
            log.actor_email,
            log.action,
            log.target_type or "",
            log.target_id or "",
            str(log.details or {}),
            log.ip_address or "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_logs.csv"},
    )
