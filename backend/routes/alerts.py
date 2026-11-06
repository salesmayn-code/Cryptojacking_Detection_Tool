"""Alerts routes with persistent storage and user-scoped access control."""

from typing import Optional
from datetime import datetime
import json
import os
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.alert import Alert
from backend.models.system import MonitoredSystem
from backend.models.user import User
from backend.routes.auth import verify_token


router = APIRouter()


class AlertUpdate(BaseModel):
    status: str


class AlertWhitelistRequest(BaseModel):
    process_name: str
    scope: Optional[str] = "path_signature"
    notes: Optional[str] = None


def _get_current_user(email: str, db: Session) -> User:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def _get_allowed_system_ids(user: User, db: Session) -> list[str]:
    if user.role == "admin":
        return [s.system_id for s in db.query(MonitoredSystem.system_id).all()]
    return [
        s.system_id
        for s in db.query(MonitoredSystem.system_id).filter(MonitoredSystem.owner_email == user.email).all()
    ]


def _alert_to_dict(alert: Alert) -> dict:
    return {
        "alert_id": alert.id,
        "system_id": alert.system_id,
        "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
        "alert_type": alert.alert_type,
        "confidence": alert.confidence,
        "detection_method": alert.detection_method,
        "metrics": alert.metrics,
        "suspicious_processes": alert.suspicious_processes,
        "virustotal_results": alert.virustotal_results,
        "feature_importance": alert.feature_importance or {},
        "status": alert.status,
    }


@router.get("/")
async def get_all_alerts(
    status: Optional[str] = None,
    system_id: Optional[str] = None,
    limit: int = 100,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    user = _get_current_user(email, db)
    allowed_system_ids = _get_allowed_system_ids(user, db)

    if system_id and system_id not in allowed_system_ids:
        raise HTTPException(status_code=403, detail="Not authorized")

    query = db.query(Alert).filter(Alert.system_id.in_(allowed_system_ids))
    if status:
        query = query.filter(Alert.status == status)
    if system_id:
        query = query.filter(Alert.system_id == system_id)

    alerts = query.order_by(Alert.timestamp.desc()).limit(limit).all()

    return {
        "total": len(alerts),
        "alerts": [_alert_to_dict(a) for a in alerts],
    }


@router.get("/stats/summary")
async def get_alert_stats(
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    user = _get_current_user(email, db)
    allowed_system_ids = _get_allowed_system_ids(user, db)

    query = db.query(Alert).filter(Alert.system_id.in_(allowed_system_ids))
    total = query.count()
    unread = query.filter(Alert.status == "unread").count()
    acknowledged = query.filter(Alert.status == "acknowledged").count()

    latest = query.order_by(Alert.timestamp.desc()).first()

    return {
        "total_alerts": total,
        "unread_alerts": unread,
        "acknowledged_alerts": acknowledged,
        "latest_alert": {
            "alert_id": latest.id,
            "system_id": latest.system_id,
            "confidence": latest.confidence,
            "timestamp": latest.timestamp.isoformat() if latest.timestamp else None,
        }
        if latest
        else None,
    }


@router.get("/system/{system_id}")
async def get_system_alerts(
    system_id: str,
    limit: int = 50,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    user = _get_current_user(email, db)
    allowed_system_ids = _get_allowed_system_ids(user, db)
    if system_id not in allowed_system_ids:
        raise HTTPException(status_code=403, detail="Not authorized")

    alerts = (
        db.query(Alert)
        .filter(Alert.system_id == system_id)
        .order_by(Alert.timestamp.desc())
        .limit(limit)
        .all()
    )

    return {
        "system_id": system_id,
        "total_alerts": len(alerts),
        "alerts": [_alert_to_dict(a) for a in alerts],
    }


@router.get("/{alert_id}")
async def get_alert(
    alert_id: int,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    user = _get_current_user(email, db)
    allowed_system_ids = set(_get_allowed_system_ids(user, db))

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.system_id not in allowed_system_ids:
        raise HTTPException(status_code=403, detail="Not authorized")

    return _alert_to_dict(alert)


@router.put("/{alert_id}")
async def update_alert(
    alert_id: int,
    update: AlertUpdate,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    user = _get_current_user(email, db)
    allowed_system_ids = set(_get_allowed_system_ids(user, db))

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.system_id not in allowed_system_ids:
        raise HTTPException(status_code=403, detail="Not authorized")

    alert.status = update.status
    from backend.services.audit_service import log_action
    log_action(db, actor=email, action="alert.status_change", target_type="alert",
               target_id=str(alert.id), details={"new_status": update.status})
    db.commit()
    return {"status": "success", "alert": {"alert_id": alert.id, "status": alert.status}}


@router.delete("/{alert_id}")
async def delete_alert(
    alert_id: int,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    user = _get_current_user(email, db)
    allowed_system_ids = set(_get_allowed_system_ids(user, db))

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.system_id not in allowed_system_ids:
        raise HTTPException(status_code=403, detail="Not authorized")

    from backend.services.audit_service import log_action
    log_action(
        db,
        actor=email,
        action="alert.delete",
        target_type="alert",
        target_id=str(alert.id),
        details={"system_id": alert.system_id},
    )

    db.delete(alert)
    db.commit()
    return {"status": "success", "deleted": alert_id}


def _policy_path() -> Path:
    return Path(os.getenv("PROCESS_POLICY_PATH", str(Path(__file__).resolve().parents[2] / "backend" / "process_policy.json")))


def _load_policy() -> dict:
    path = _policy_path()
    if not path.exists():
        return {"version": 1, "allow_rules": [], "deny_rules": [], "svchost_policy": {}, "thresholds": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {"version": 1, "allow_rules": [], "deny_rules": [], "svchost_policy": {}, "thresholds": {}}


def _write_policy(policy: dict) -> None:
    path = _policy_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)
    os.replace(tmp_path, path)


def _resolve_process_context(alert: Alert) -> list[dict]:
    metrics = alert.metrics or {}
    context = metrics.get("process_context")
    if isinstance(context, list) and context:
        return context
    return []


@router.post("/{alert_id}/whitelist")
async def whitelist_alert_process(
    alert_id: int,
    request: AlertWhitelistRequest,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    user = _get_current_user(email, db)
    allowed_system_ids = set(_get_allowed_system_ids(user, db))

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.system_id not in allowed_system_ids:
        raise HTTPException(status_code=403, detail="Not authorized")

    process_name = (request.process_name or "").strip()
    if not process_name:
        raise HTTPException(status_code=400, detail="process_name is required")

    context = _resolve_process_context(alert)
    target = next((p for p in context if str(p.get("name") or "").lower() == process_name.lower()), None)
    if target is None:
        raise HTTPException(status_code=404, detail="Process details not found in alert context")

    scope = (request.scope or "path_signature").strip().lower()
    rule_id = f"user-whitelist-{alert.id}-{int(time.time())}"

    rule = {
        "id": rule_id,
        "name_exact": [process_name.lower()],
        "min_match_count": 1,
        "added_by": email,
        "added_at": datetime.utcnow().isoformat(),
    }

    exe_path = str(target.get("exe_path") or "").lower()
    exe_hash = str(target.get("exe_hash") or "").lower()
    publisher = str(target.get("publisher") or "").lower()
    signature_status = str(target.get("signature_status") or "").lower()

    if scope == "hash" and exe_hash:
        rule["hash_exact"] = [exe_hash]
        rule["min_match_count"] = 1
    elif scope in {"path_signature", "path+signature"}:
        if exe_path:
            rule["path_contains"] = [str(Path(exe_path).parent).lower()]
        if publisher:
            rule["publisher_contains"] = [publisher]
        if signature_status:
            rule["signature_status_exact"] = [signature_status]
        rule["min_match_count"] = 2

    if request.notes:
        rule["notes"] = request.notes.strip()

    policy = _load_policy()
    allow_rules = policy.get("allow_rules")
    if not isinstance(allow_rules, list):
        policy["allow_rules"] = allow_rules = []
    allow_rules.append(rule)
    _write_policy(policy)

    alert.status = "acknowledged"
    from backend.services.audit_service import log_action
    log_action(db, actor=email, action="alert.whitelist", target_type="alert",
               target_id=str(alert.id), details={"rule_id": rule_id, "process_name": process_name})
    db.commit()

    return {"status": "success", "rule_id": rule_id, "alert_id": alert.id}
