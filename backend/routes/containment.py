"""Containment & persistence-audit command queue routes for CryptoDetect."""

from __future__ import annotations

from datetime import datetime
import ipaddress
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.agent_command import AgentCommand, VALID_CONTAINMENT_ACTIONS
from backend.models.alert import Alert
from backend.models.system import MonitoredSystem
from backend.models.user import User
from backend.routes.auth import verify_api_key, verify_token


router = APIRouter()


PROTECTED_PATH_PREFIXES = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "/usr/bin/",
    "/bin/",
    "/sbin/",
)

PROTECTED_PROCESS_NAMES = {
    "system",
    "system idle process",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "dwm.exe",
    "explorer.exe",
    "cryptodetect-agent-v1.exe",
    "cryptodetect-agent-v9.exe",
}


class AlertActionRequest(BaseModel):
    action: str
    pid: Optional[int] = None
    create_time: Optional[float] = None
    process_name: Optional[str] = None
    exe_path: Optional[str] = None
    exe_hash: Optional[str] = None
    remote_ip: Optional[str] = None


class CommandResultRequest(BaseModel):
    status: str  # "completed" | "failed"
    result_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


def _get_current_user(email: str, db: Session) -> User:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def _assert_system_access(user: User, system_id: str, db: Session) -> MonitoredSystem:
    system = db.query(MonitoredSystem).filter(MonitoredSystem.system_id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")
    if user.role != "admin" and system.owner_email != user.email:
        raise HTTPException(status_code=403, detail="Not authorized")
    return system


def _is_protected_binary(process_name: Optional[str], exe_path: Optional[str]) -> bool:
    name_norm = str(process_name or "").strip().lower()
    path_norm = str(exe_path or "").strip().lower().replace("/", "\\")
    if name_norm in PROTECTED_PROCESS_NAMES and (not path_norm or any(p.replace("/", "\\") in path_norm for p in PROTECTED_PATH_PREFIXES)):
        return True
    if path_norm and any(p.replace("/", "\\") in path_norm for p in PROTECTED_PATH_PREFIXES):
        return True
    if "cryptodetect" in name_norm:
        return True
    return False


def _validate_public_remote_ip(ip_text: Optional[str]) -> str:
    raw = str(ip_text or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="remote_ip is required for block_ip action")
    try:
        ip_obj = ipaddress.ip_address(raw)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid remote_ip format")
    if (
        ip_obj.is_loopback
        or ip_obj.is_private
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        raise HTTPException(status_code=400, detail="Refusing to firewall-block local, private, or reserved IP")
    return str(ip_obj)


def _resolve_target_from_alert(alert: Alert, request: AlertActionRequest) -> Dict[str, Any]:
    action = str(request.action or "").strip().lower()
    if action not in VALID_CONTAINMENT_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported containment action: {action}")

    metrics = alert.metrics or {}
    context = metrics.get("process_context") or []

    matched = None
    if request.pid is not None:
        matched = next((p for p in context if isinstance(p, dict) and p.get("pid") == request.pid), None)
    if matched is None and request.process_name:
        pname = request.process_name.strip().lower()
        matched = next(
            (p for p in context if isinstance(p, dict) and str(p.get("name") or "").lower() == pname),
            None,
        )
    if matched is None and context and isinstance(context[0], dict):
        matched = context[0]

    pid = request.pid if request.pid is not None else (matched.get("pid") if matched else None)
    create_time = request.create_time if request.create_time is not None else (matched.get("create_time") if matched else None)
    process_name = request.process_name or (matched.get("name") if matched else None)
    exe_path = request.exe_path or (matched.get("exe_path") if matched else None)
    exe_hash = request.exe_hash or (matched.get("exe_hash") if matched else None)

    remote_ip = request.remote_ip
    if not remote_ip and matched:
        ips = matched.get("remote_ips_sample") or []
        if ips:
            remote_ip = ips[0]

    if action in {"suspend_process", "resume_process", "kill_process_tree"}:
        if pid is None and not process_name:
            raise HTTPException(status_code=400, detail="Target pid or process_name is required")
        if action == "kill_process_tree" and _is_protected_binary(process_name, exe_path):
            raise HTTPException(status_code=400, detail="Refusing to terminate protected Windows OS process")

    if action == "quarantine_binary":
        if not exe_path:
            raise HTTPException(status_code=400, detail="Target exe_path is required to quarantine binary")
        if _is_protected_binary(process_name, exe_path):
            raise HTTPException(status_code=400, detail="Refusing to quarantine protected Windows system file")

    if action == "block_ip":
        remote_ip = _validate_public_remote_ip(remote_ip)

    return {
        "pid": int(pid) if pid is not None else None,
        "create_time": float(create_time) if create_time is not None else None,
        "process_name": str(process_name) if process_name else None,
        "exe_path": str(exe_path) if exe_path else None,
        "exe_hash": str(exe_hash) if exe_hash else None,
        "remote_ip": remote_ip,
    }


@router.post("/alerts/{alert_id}/actions")
async def enqueue_alert_containment_action(
    alert_id: int,
    payload: AlertActionRequest,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Queue an authenticated operator containment or persistence-audit command for an endpoint alert."""
    user = _get_current_user(email, db)
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    _assert_system_access(user, alert.system_id, db)

    action = str(payload.action or "").strip().lower()
    target_payload = _resolve_target_from_alert(alert, payload)

    cmd = AgentCommand(
        system_id=alert.system_id,
        alert_id=alert.id,
        action=action,
        target_payload=target_payload,
        status="pending",
        requested_by=email,
    )
    db.add(cmd)
    db.flush()

    from backend.services.audit_service import log_action

    log_action(
        db,
        actor=email,
        action=f"containment.{action}",
        target_type="alert",
        target_id=str(alert.id),
        details={"system_id": alert.system_id, "command_id": cmd.id, "target": target_payload},
    )
    db.commit()
    db.refresh(cmd)
    return {"status": "queued", "command": cmd.to_dict()}


@router.get("/alerts/{alert_id}/actions")
async def list_alert_containment_actions(
    alert_id: int,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """List containment commands and latest persistence audit status linked to an alert."""
    user = _get_current_user(email, db)
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    _assert_system_access(user, alert.system_id, db)

    commands = (
        db.query(AgentCommand)
        .filter(AgentCommand.alert_id == alert.id)
        .order_by(AgentCommand.created_at.desc(), AgentCommand.id.desc())
        .limit(30)
        .all()
    )
    latest_persistence = (
        db.query(AgentCommand)
        .filter(
            AgentCommand.system_id == alert.system_id,
            AgentCommand.action == "audit_persistence",
            AgentCommand.status == "completed",
        )
        .order_by(AgentCommand.completed_at.desc(), AgentCommand.id.desc())
        .first()
    )
    return {
        "alert_id": alert.id,
        "system_id": alert.system_id,
        "commands": [c.to_dict() for c in commands],
        "latest_persistence_audit": latest_persistence.to_dict() if latest_persistence else None,
    }


@router.post("/systems/{system_id}/persistence-audit")
async def enqueue_system_persistence_audit(
    system_id: str,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Queue a host persistence mechanism scan (Scheduled Tasks, Registry Run, Services, WSL2)."""
    user = _get_current_user(email, db)
    _assert_system_access(user, system_id, db)

    cmd = AgentCommand(
        system_id=system_id,
        alert_id=None,
        action="audit_persistence",
        target_payload={},
        status="pending",
        requested_by=email,
    )
    db.add(cmd)
    db.flush()

    from backend.services.audit_service import log_action

    log_action(
        db,
        actor=email,
        action="containment.audit_persistence",
        target_type="system",
        target_id=system_id,
        details={"command_id": cmd.id},
    )
    db.commit()
    db.refresh(cmd)
    return {"status": "queued", "command": cmd.to_dict()}


@router.get("/systems/{system_id}/commands")
async def list_system_commands(
    system_id: str,
    limit: int = 30,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    """Fetch recent containment/audit command executions for a monitored system."""
    user = _get_current_user(email, db)
    _assert_system_access(user, system_id, db)

    commands = (
        db.query(AgentCommand)
        .filter(AgentCommand.system_id == system_id)
        .order_by(AgentCommand.created_at.desc(), AgentCommand.id.desc())
        .limit(max(1, min(limit, 100)))
        .all()
    )
    return {"system_id": system_id, "commands": [c.to_dict() for c in commands]}


@router.get("/agent/commands/{system_id}")
async def agent_poll_pending_commands(
    system_id: str,
    user: dict = Depends(verify_api_key),
    db: Session = Depends(get_db),
):
    """Endpoint polling route for monitoring agents to claim pending operator commands."""
    if user.get("system_id") != system_id:
        raise HTTPException(status_code=403, detail="Not authorized for this system")

    pending = (
        db.query(AgentCommand)
        .filter(AgentCommand.system_id == system_id, AgentCommand.status == "pending")
        .order_by(AgentCommand.created_at.asc(), AgentCommand.id.asc())
        .limit(10)
        .all()
    )
    now = datetime.utcnow()
    for cmd in pending:
        cmd.status = "dispatched"
        cmd.updated_at = now
    if pending:
        db.commit()

    return {"system_id": system_id, "commands": [c.to_dict() for c in pending]}


@router.post("/agent/commands/{command_id}/result")
async def agent_report_command_result(
    command_id: int,
    payload: CommandResultRequest,
    user: dict = Depends(verify_api_key),
    db: Session = Depends(get_db),
):
    """Receive command execution outcome and forensic output from the endpoint agent."""
    cmd = db.query(AgentCommand).filter(AgentCommand.id == command_id).first()
    if not cmd:
        raise HTTPException(status_code=404, detail="Command not found")
    if cmd.system_id != user.get("system_id"):
        raise HTTPException(status_code=403, detail="Not authorized for this command")

    if cmd.status != "dispatched":
        raise HTTPException(status_code=409, detail="Command is not awaiting a result")

    norm_status = str(payload.status or "").strip().lower()
    if norm_status not in {"completed", "failed"}:
        raise HTTPException(status_code=400, detail="Command outcome status must be completed or failed")

    now = datetime.utcnow()
    cmd.status = norm_status
    cmd.result_data = payload.result_data or {}
    cmd.error_message = payload.error_message
    cmd.updated_at = now
    cmd.completed_at = now
    db.commit()
    db.refresh(cmd)
    return {"status": "recorded", "command": cmd.to_dict()}

