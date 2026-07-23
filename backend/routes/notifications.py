"""Notification channel routes – CRUD + verification for email/WhatsApp."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.notification_channel import NotificationChannel
from backend.models.user import User
from backend.routes.auth import verify_token


router = APIRouter()


class ChannelCreate(BaseModel):
    channel_type: str          # "email" | "whatsapp"
    target: str                # email address or phone number


class ChannelVerify(BaseModel):
    code: str


class ChannelToggle(BaseModel):
    enabled: bool


def _get_current_user(email: str, db: Session) -> User:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def _channel_to_dict(ch: NotificationChannel) -> dict:
    return {
        "id": ch.id,
        "channel_type": ch.channel_type,
        "target": ch.target,
        "verified": ch.verified,
        "enabled": ch.enabled,
        "created_at": ch.created_at.isoformat() if ch.created_at else None,
    }


@router.get("/channels")
async def list_channels(
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    _get_current_user(email, db)
    channels = (
        db.query(NotificationChannel)
        .filter(NotificationChannel.user_email == email)
        .order_by(NotificationChannel.created_at.desc())
        .all()
    )
    return {"channels": [_channel_to_dict(c) for c in channels]}


@router.post("/channels")
async def add_channel(
    payload: ChannelCreate,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    _get_current_user(email, db)

    if payload.channel_type not in ("email", "whatsapp"):
        raise HTTPException(status_code=400, detail="channel_type must be 'email' or 'whatsapp'")

    raw_target = payload.target.strip()
    if not raw_target:
        raise HTTPException(status_code=400, detail="target is required")

    from backend.services.verification_service import normalize_channel_target
    try:
        normalized_target = normalize_channel_target(payload.channel_type, raw_target)
    except RuntimeError as err:
        raise HTTPException(status_code=400, detail=str(err))

    # Prevent duplicates
    existing = (
        db.query(NotificationChannel)
        .filter(
            NotificationChannel.user_email == email,
            NotificationChannel.channel_type == payload.channel_type,
            NotificationChannel.target == normalized_target,
        )
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail="This channel is already registered")

    channel = NotificationChannel(
        user_email=email,
        channel_type=payload.channel_type,
        target=normalized_target,
        verified=False,
        enabled=True,
    )
    db.add(channel)
    db.commit()
    db.refresh(channel)

    # Send verification OTP
    try:
        from backend.services.verification_service import send_verification
        delivery_info = await send_verification(channel, db)
    except RuntimeError as e:
        # Channel was created but OTP delivery failed – tell the user why
        return {
            "status": "success",
            "channel": _channel_to_dict(channel),
            "message": f"Channel added but verification code could not be sent: {e}",
            "send_error": str(e),
        }
    except Exception as e:
        print(f"[NOTIFY] Verification send failed: {e}")
        return {
            "status": "success",
            "channel": _channel_to_dict(channel),
            "message": "Channel added but verification code could not be sent. Try resending.",
            "send_error": "Unexpected error while sending verification code.",
        }

    if delivery_info.get("delivery") == "dev-preview":
        return {
            "status": "success",
            "channel": _channel_to_dict(channel),
            "message": f"Channel added in dev mode. Use preview OTP to verify {channel.target}.",
            "verification_preview_code": delivery_info.get("preview_code"),
        }

    return {
        "status": "success",
        "channel": _channel_to_dict(channel),
        "message": f"Verification code sent to {channel.target}!",
    }

@router.post("/channels/{channel_id}/verify")
async def verify_channel(
    channel_id: int,
    payload: ChannelVerify,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    channel = db.query(NotificationChannel).filter(
        NotificationChannel.id == channel_id,
        NotificationChannel.user_email == email,
    ).first()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")

    from backend.services.verification_service import verify_otp
    ok, reason = verify_otp(channel, payload.code)
    if not ok:
        raise HTTPException(status_code=400, detail=reason)

    channel.verified = True
    channel.verify_code = None
    channel.code_expires = None
    db.commit()

    return {"status": "success", "message": "Channel verified", "channel": _channel_to_dict(channel)}


@router.post("/channels/{channel_id}/resend")
async def resend_verification(
    channel_id: int,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    channel = db.query(NotificationChannel).filter(
        NotificationChannel.id == channel_id,
        NotificationChannel.user_email == email,
    ).first()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    if channel.verified:
        raise HTTPException(status_code=400, detail="Channel is already verified")

    from backend.services.verification_service import send_verification
    try:
        delivery_info = await send_verification(channel, db)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        print(f"[NOTIFY] Resend failed: {e}")
        raise HTTPException(status_code=502, detail="Failed to send verification code. Please try again.")

    if delivery_info.get("delivery") == "dev-preview":
        return {
            "status": "success",
            "message": f"Dev preview OTP generated for {channel.target}",
            "verification_preview_code": delivery_info.get("preview_code"),
        }

    return {"status": "success", "message": f"Verification code resent to {channel.target}!"}


@router.put("/channels/{channel_id}")
async def toggle_channel(
    channel_id: int,
    payload: ChannelToggle,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    channel = db.query(NotificationChannel).filter(
        NotificationChannel.id == channel_id,
        NotificationChannel.user_email == email,
    ).first()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")

    channel.enabled = payload.enabled
    db.commit()

    return {"status": "success", "channel": _channel_to_dict(channel)}


@router.delete("/channels/{channel_id}")
async def delete_channel(
    channel_id: int,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    channel = db.query(NotificationChannel).filter(
        NotificationChannel.id == channel_id,
        NotificationChannel.user_email == email,
    ).first()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")

    db.delete(channel)
    db.commit()

    return {"status": "success", "message": "Channel deleted"}
