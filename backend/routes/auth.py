"""Authentication Routes - Persistent database storage."""
from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import os
import platform
from pathlib import Path

router = APIRouter()
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# Import DB dependencies
from backend.database import get_db
from backend.models.user import User
from backend.models.system import MonitoredSystem

PROFILE_PICTURES_DIR = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / "uploads" / "profile_pictures"
PROFILE_PICTURES_DIR.mkdir(parents=True, exist_ok=True)
MAX_PROFILE_PICTURE_SIZE_BYTES = 2 * 1024 * 1024


class UserRegister(BaseModel):
    email: str
    password: str
    full_name: str

class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict


class ProfileUpdate(BaseModel):
    full_name: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class AgentValidateRequest(BaseModel):
    system_id: str
    api_key: str
    device_name: str | None = None


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")


def verify_api_key(x_api_key: str = Header(None, alias="X-API-Key"), db: Session = Depends(get_db)):
    """Verify API key for monitoring agent using the database."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    user = db.query(User).filter(User.api_key == x_api_key).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return {
        "email": user.email,
        "full_name": user.full_name,
        "system_id": user.system_id,
        "api_key": user.api_key,
        "role": user.role
    }


@router.post("/register", response_model=Token)
async def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """Register user, create system, return credentials"""
    # Check if email already exists
    existing = db.query(User).filter(User.email == user_data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create user
    system_id = User.generate_system_id()
    api_key = User.generate_api_key()

    new_user = User(
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=pwd_context.hash(user_data.password),
        system_id=system_id,
        api_key=api_key
    )
    db.add(new_user)

    # Auto-create monitored system
    device_info = {
        "system": platform.system(),
        "node": platform.node(),
        "processor": platform.processor() or "Unknown"
    }

    new_system = MonitoredSystem(
        system_id=system_id,
        system_name=f"{user_data.full_name}'s {device_info['system']} Device",
        system_description=f"Auto-registered from {device_info['node']}",
        owner_email=user_data.email,
        status="offline",
        device_info=device_info
    )
    db.add(new_system)
    db.commit()

    from services.audit_service import log_action
    log_action(db, actor=user_data.email, action="user.register", target_type="user",
               target_id=user_data.email, details={"system_id": system_id})
    db.commit()

    access_token = create_access_token(data={"sub": user_data.email})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "email": user_data.email,
            "full_name": user_data.full_name,
            "system_id": system_id,
            "api_key": api_key,
            "role": new_user.role,
            "profile_picture_url": new_user.profile_picture_url
        }
    }


@router.post("/login", response_model=Token)
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """Login - query persistent database."""
    user = db.query(User).filter(User.email == user_data.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not pwd_context.verify(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": user.email})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "email": user.email,
            "full_name": user.full_name,
            "system_id": user.system_id,
            "api_key": user.api_key,
            "role": user.role,
            "profile_picture_url": user.profile_picture_url
        }
    }


@router.get("/profile")
async def get_profile(email: str = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    system = db.query(MonitoredSystem).filter(MonitoredSystem.system_id == user.system_id).first()

    return {
        "email": user.email,
        "full_name": user.full_name,
        "system_id": user.system_id,
        "api_key": user.api_key,
        "role": user.role,
        "profile_picture_url": user.profile_picture_url,
        "password_updated_at": user.password_updated_at.isoformat() if user.password_updated_at else None,
        "system_name": system.system_name if system else None,
        "last_seen": system.last_seen.isoformat() if system and system.last_seen else None,
        "created_at": user.created_at.isoformat() if user.created_at else None
    }


@router.put("/profile")
async def update_profile(update: ProfileUpdate, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.full_name = update.full_name.strip()
    db.commit()
    db.refresh(user)

    system = db.query(MonitoredSystem).filter(MonitoredSystem.system_id == user.system_id).first()
    if system and system.owner_email == user.email and "'s" in (system.system_name or ""):
        system.system_name = f"{user.full_name}'s {platform.system()} Device"
        db.commit()

    return {
        "status": "success",
        "user": {
            "email": user.email,
            "full_name": user.full_name,
            "system_id": user.system_id,
            "api_key": user.api_key,
            "role": user.role,
            "profile_picture_url": user.profile_picture_url
        }
    }


@router.put("/profile/password")
async def update_password(payload: PasswordChange, email: str = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not pwd_context.verify(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")

    if pwd_context.verify(payload.new_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="New password must be different from current password")

    user.hashed_password = pwd_context.hash(payload.new_password)
    user.password_updated_at = datetime.utcnow()
    from services.audit_service import log_action
    log_action(db, actor=email, action="user.password_change", target_type="user",
               target_id=email)
    db.commit()

    return {"status": "success", "message": "Password updated successfully"}


@router.post("/profile/picture")
async def upload_profile_picture(
    picture: UploadFile = File(...),
    email: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not picture.content_type or not picture.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image uploads are allowed")

    content = await picture.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(content) > MAX_PROFILE_PICTURE_SIZE_BYTES:
        raise HTTPException(status_code=400, detail="Image must be 2MB or smaller")

    suffix = Path(picture.filename or "").suffix.lower()
    if suffix not in {".png", ".jpg", ".jpeg", ".webp"}:
        suffix = ".png"

    filename = f"user_{user.id}_{int(datetime.utcnow().timestamp())}{suffix}"
    file_path = PROFILE_PICTURES_DIR / filename

    with open(file_path, "wb") as f:
        f.write(content)

    user.profile_picture_url = f"/api/auth/profile/picture/{filename}"
    db.commit()

    return {
        "status": "success",
        "profile_picture_url": user.profile_picture_url
    }


@router.get("/profile/picture/{filename}")
async def get_profile_picture(filename: str):
    requested = (PROFILE_PICTURES_DIR / filename).resolve()
    root = PROFILE_PICTURES_DIR.resolve()
    if root not in requested.parents and requested != root:
        raise HTTPException(status_code=404, detail="File not found")
    if not requested.exists() or not requested.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    suffix = requested.suffix.lower()
    media_type = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp",
    }.get(suffix, "application/octet-stream")

    return FileResponse(path=str(requested), media_type=media_type)


@router.get("/agent/bootstrap")
async def agent_bootstrap(user: dict = Depends(verify_api_key), db: Session = Depends(get_db)):
    """Resolve agent configuration from API key only."""
    system = db.query(MonitoredSystem).filter(MonitoredSystem.system_id == user["system_id"]).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found for API key")

    return {
        "system_id": system.system_id,
        "system_name": system.system_name,
        "owner_email": user["email"]
    }


@router.post("/agent/validate")
async def agent_validate(payload: AgentValidateRequest, db: Session = Depends(get_db)):
    """Validate explicit System ID + API key combination for GUI setup mode."""
    user = db.query(User).filter(User.api_key == payload.api_key, User.system_id == payload.system_id).first()
    if not user:
        return {
            "valid": False,
            "system_name": None,
            "polling_interval": None
        }

    system = db.query(MonitoredSystem).filter(MonitoredSystem.system_id == payload.system_id).first()
    if not system:
        return {
            "valid": False,
            "system_name": None,
            "polling_interval": None
        }

    return {
        "valid": True,
        "system_name": system.system_name,
        "polling_interval": 5
    }
