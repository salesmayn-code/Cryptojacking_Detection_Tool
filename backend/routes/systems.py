"""Systems Routes - Persistent database storage."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from datetime import datetime
import os

router = APIRouter()

from backend.database import get_db
from backend.models.system import MonitoredSystem
from backend.models.user import User
from backend.routes.auth import verify_token

HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("SYSTEM_HEARTBEAT_INTERVAL_SECONDS", "10"))
MISSED_HEARTBEAT_THRESHOLD = int(os.getenv("SYSTEM_MISSED_HEARTBEAT_THRESHOLD", "3"))
OFFLINE_THRESHOLD_SECONDS = int(
    os.getenv(
        "SYSTEM_OFFLINE_THRESHOLD_SECONDS",
        str(HEARTBEAT_INTERVAL_SECONDS * MISSED_HEARTBEAT_THRESHOLD),
    )
)


class SystemUpdate(BaseModel):
    system_name: Optional[str] = None
    system_description: Optional[str] = None
    status: Optional[str] = None


class SystemCreate(BaseModel):
    system_name: str
    system_description: Optional[str] = None
    owner_email: str


def _get_current_user(email: str, db: Session) -> User:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def _has_system_access(user: User, system: MonitoredSystem) -> bool:
    return user.role == "admin" or system.owner_email == user.email


def _resolved_status(system: MonitoredSystem) -> str:
    if not system.last_seen:
        return "offline"
    age_seconds = (datetime.utcnow() - system.last_seen).total_seconds()
    return "online" if age_seconds <= OFFLINE_THRESHOLD_SECONDS else "offline"


def _refresh_system_status(system: MonitoredSystem) -> bool:
    target = _resolved_status(system)
    if system.status != target:
        system.status = target
        return True
    return False


def refresh_all_system_statuses(db: Session) -> int:
    """Refresh all systems and persist any online/offline transitions."""
    systems = db.query(MonitoredSystem).all()
    changed_count = 0
    for system in systems:
        if _refresh_system_status(system):
            changed_count += 1
    if changed_count:
        db.commit()
    return changed_count


def _system_response(system: MonitoredSystem) -> dict:
    return {
        "system_id": system.system_id,
        "system_name": system.system_name,
        "system_description": system.system_description,
        "owner_email": system.owner_email,
        "status": system.status,
        "created_at": system.created_at.isoformat() if system.created_at else None,
        "last_seen": system.last_seen.isoformat() if system.last_seen else None,
        "device_info": system.device_info,
    }


@router.post("/")
async def create_system(
    payload: SystemCreate,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    current_user = _get_current_user(email, db)
    if current_user.role != "admin" and payload.owner_email != current_user.email:
        raise HTTPException(status_code=403, detail="Not authorized to create systems for other users")

    owner = db.query(User).filter(User.email == payload.owner_email).first()
    if not owner:
        raise HTTPException(status_code=404, detail="Owner not found")

    system_id = User.generate_system_id()
    while db.query(MonitoredSystem).filter(MonitoredSystem.system_id == system_id).first():
        system_id = User.generate_system_id()

    system = MonitoredSystem(
        system_id=system_id,
        system_name=payload.system_name.strip(),
        system_description=payload.system_description,
        owner_email=payload.owner_email,
        status="offline",
        device_info={}
    )

    db.add(system)
    db.commit()
    db.refresh(system)

    from services.audit_service import log_action
    log_action(db, actor=email, action="system.create", target_type="system",
               target_id=system_id, details={"system_name": payload.system_name})
    db.commit()

    return {"status": "success", "system": _system_response(system)}


@router.get("/")
async def get_all_systems(
    owner_email: Optional[str] = None,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Get systems visible to current user and resolve online/offline state."""
    current_user = _get_current_user(email, db)

    query = db.query(MonitoredSystem)
    if current_user.role != "admin":
        if owner_email and owner_email != current_user.email:
            raise HTTPException(status_code=403, detail="Not authorized")
        query = query.filter(MonitoredSystem.owner_email == current_user.email)
    elif owner_email:
        query = query.filter(MonitoredSystem.owner_email == owner_email)

    systems = query.order_by(MonitoredSystem.created_at.desc()).all()
    changed = False
    for system in systems:
        changed = _refresh_system_status(system) or changed
    if changed:
        db.commit()

    return {
        "total": len(systems),
        "systems": [_system_response(s) for s in systems]
    }


@router.get("/{system_id}")
async def get_system(
    system_id: str,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    current_user = _get_current_user(email, db)
    system = db.query(MonitoredSystem).filter(MonitoredSystem.system_id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")
    if not _has_system_access(current_user, system):
        raise HTTPException(status_code=403, detail="Not authorized")

    if _refresh_system_status(system):
        db.commit()
        db.refresh(system)

    return _system_response(system)


@router.put("/{system_id}")
async def update_system(
    system_id: str,
    update: SystemUpdate,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    current_user = _get_current_user(email, db)
    system = db.query(MonitoredSystem).filter(MonitoredSystem.system_id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")
    if not _has_system_access(current_user, system):
        raise HTTPException(status_code=403, detail="Not authorized")

    if update.system_name is not None:
        system.system_name = update.system_name
    if update.system_description is not None:
        system.system_description = update.system_description
    if update.status is not None:
        system.status = update.status

    from services.audit_service import log_action
    log_action(db, actor=email, action="system.update", target_type="system",
               target_id=system_id, details={"fields": update.dict(exclude_unset=True)})
    db.commit()
    db.refresh(system)

    return {"status": "success", "system": {
        "system_id": system.system_id,
        "system_name": system.system_name,
        "status": system.status
    }}


@router.delete("/{system_id}")
async def delete_system(
    system_id: str,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    current_user = _get_current_user(email, db)
    system = db.query(MonitoredSystem).filter(MonitoredSystem.system_id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")
    if not _has_system_access(current_user, system):
        raise HTTPException(status_code=403, detail="Not authorized")

    from services.audit_service import log_action
    log_action(db, actor=email, action="system.delete", target_type="system",
               target_id=system_id, details={"system_name": system.system_name})
    db.delete(system)
    db.commit()
    return {"status": "success", "message": f"System {system_id} deleted"}
