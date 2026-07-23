"""Verification service – OTP generation, sending, and validation."""

import os
import random
import string
from datetime import datetime, timedelta
from email_validator import EmailNotValidError, validate_email
from sqlalchemy.orm import Session
from backend.models.notification_channel import NotificationChannel


OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 10
VERIFICATION_DEV_MODE = os.getenv("VERIFICATION_DEV_MODE", os.getenv("DEBUG", "False")).lower() in {
    "1",
    "true",
    "yes",
    "on",
}


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _normalize_whatsapp_target(raw_target: str) -> str:
    target = (raw_target or "").strip()
    if target.lower().startswith("whatsapp:"):
        target = target.split(":", 1)[1].strip()

    for token in (" ", "-", "(", ")"):
        target = target.replace(token, "")

    if target.startswith("00"):
        target = f"+{target[2:]}"
    elif not target.startswith("+"):
        target = f"+{target}"

    digits = target[1:]
    if not digits.isdigit() or not (8 <= len(digits) <= 15):
        raise RuntimeError("Phone must be in international format, e.g. +923001234567")

    return target


def normalize_channel_target(channel_type: str, target: str) -> str:
    normalized = (target or "").strip()
    if not normalized:
        raise RuntimeError("Target is required")

    if channel_type == "email":
        try:
            return validate_email(normalized, check_deliverability=False).email
        except EmailNotValidError as err:
            raise RuntimeError(str(err))

    if channel_type == "whatsapp":
        return _normalize_whatsapp_target(normalized)

    raise RuntimeError(f"Unsupported channel type: {channel_type}")


def generate_otp() -> str:
    """Generate a random 6-digit OTP."""
    return ''.join(random.choices(string.digits, k=OTP_LENGTH))


async def send_verification(channel: NotificationChannel, db: Session) -> dict:
    """Generate OTP, store it on the channel, and send via the appropriate medium.

    Raises RuntimeError if the code could not be delivered so the caller can
    report the problem to the user without leaking the code.
    """
    channel.target = normalize_channel_target(channel.channel_type, channel.target)

    code = generate_otp()
    channel.verify_code = code
    channel.code_expires = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    db.commit()

    if channel.channel_type == "email":
        delivery = await _send_email_otp(channel.target, code)
    elif channel.channel_type == "whatsapp":
        delivery = await _send_whatsapp_otp(channel.target, code)
    else:
        raise RuntimeError(f"Unsupported channel type: {channel.channel_type}")

    return {
        "channel_type": channel.channel_type,
        "target": channel.target,
        **delivery,
    }


def verify_otp(channel: NotificationChannel, code: str) -> tuple[bool, str]:
    """Validate the supplied OTP against the channel's stored code."""
    if not channel.verify_code:
        return False, "No verification code was sent"

    if channel.code_expires and datetime.utcnow() > channel.code_expires:
        return False, "Verification code has expired. Please request a new one."

    if channel.verify_code != code.strip():
        return False, "Incorrect verification code"

    return True, "Verified"


async def _send_email_otp(to: str, code: str) -> dict:
    """Send OTP email via SMTP (aiosmtplib). Raises on failure."""
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USERNAME")
    smtp_pass = os.getenv("SMTP_PASSWORD")
    email_from = os.getenv("EMAIL_FROM", smtp_user)
    smtp_use_ssl = _env_flag("SMTP_USE_SSL", False)
    smtp_starttls = _env_flag("SMTP_STARTTLS", not smtp_use_ssl)

    if not smtp_server or not smtp_user:
        if VERIFICATION_DEV_MODE:
            print(f"[VERIFY] DEV fallback email OTP for {to}: {code}")
            return {
                "delivery": "dev-preview",
                "preview_code": code,
                "message": "SMTP not configured. Dev preview code returned.",
            }
        raise RuntimeError("Email is not configured. Please set SMTP_SERVER and SMTP_USERNAME.")

    if smtp_use_ssl and smtp_starttls:
        smtp_starttls = False

    print(f"[VERIFY] Attempting to send email to {to} via {smtp_server}:{smtp_port}...")

    try:
        import aiosmtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"CryptoDetect Verification Code: {code}"
        msg["From"] = email_from
        msg["To"] = to

        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;background:#f8fafc;border-radius:12px">
            <h2 style="color:#1e293b;margin:0 0 8px">CryptoDetect</h2>
            <p style="color:#475569">Your verification code is:</p>
            <div style="font-size:32px;font-weight:700;letter-spacing:8px;color:#6366f1;text-align:center;padding:16px;background:#fff;border-radius:8px;border:1px solid #e2e8f0">{code}</div>
            <p style="color:#94a3b8;font-size:13px;margin-top:12px">This code expires in {OTP_EXPIRY_MINUTES} minutes.</p>
        </div>
        """
        msg.attach(MIMEText(html, "html"))

        await aiosmtplib.send(
            msg,
            hostname=smtp_server,
            port=smtp_port,
            username=smtp_user,
            password=smtp_pass,
            use_tls=smtp_use_ssl,
            start_tls=smtp_starttls,
        )
        print(f"[VERIFY] Email OTP sent to {to}")
        return {"delivery": "email"}
    except ImportError:
        raise RuntimeError(
            "Email library (aiosmtplib) is not installed. "
            "Run: pip install aiosmtplib"
        )
    except Exception as e:
        print(f"[VERIFY] Email send failed: {e}")
        raise RuntimeError(f"Failed to send email to {to}: {e}")


async def _send_whatsapp_otp(to: str, code: str) -> dict:
    """Send OTP via Twilio WhatsApp API. Raises on failure."""
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    from_number = os.getenv("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")

    normalized_to = _normalize_whatsapp_target(to)

    if not account_sid or not auth_token:
        if VERIFICATION_DEV_MODE:
            print(f"[VERIFY] DEV fallback WhatsApp OTP for {normalized_to}: {code}")
            return {
                "delivery": "dev-preview",
                "preview_code": code,
                "message": "Twilio not configured. Dev preview code returned.",
            }
        raise RuntimeError("Twilio is not configured. Set TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN.")

    print(f"[VERIFY] Attempting to send WhatsApp message to {normalized_to} using Twilio SID {account_sid[:8]}...")

    try:
        from twilio.rest import Client
    except ImportError:
        raise RuntimeError(
            "Twilio library is not installed. "
            "Run: pip install twilio"
        )

    try:
        client = Client(account_sid, auth_token)
        to_number = f"whatsapp:{normalized_to}"
        message = client.messages.create(
            body=f"Your CryptoDetect verification code is: {code}\nExpires in {OTP_EXPIRY_MINUTES} minutes.",
            from_=from_number,
            to=to_number,
        )
        print(f"[VERIFY] WhatsApp OTP sent to {normalized_to} (SID: {message.sid})")
        return {"delivery": "whatsapp"}
    except Exception as e:
        error_msg = str(e)
        print(f"[VERIFY] WhatsApp send failed: {error_msg}")
        # Give user-friendly messages for common Twilio errors
        if "not a valid phone number" in error_msg.lower():
            raise RuntimeError(
                f"'{to}' is not a valid phone number. Please use international format like +923001234567"
            )
        if "not currently available" in error_msg.lower() or "sandbox" in error_msg.lower():
            raise RuntimeError(
                "This number hasn't joined the Twilio sandbox yet. "
                "Please send 'join <your-keyword>' to the Twilio WhatsApp number first."
            )
        if "authenticate" in error_msg.lower() or "credentials" in error_msg.lower():
            raise RuntimeError(
                "Twilio authentication failed. Please check TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN in .env"
            )
        raise RuntimeError(f"Failed to send WhatsApp message: {error_msg}")
