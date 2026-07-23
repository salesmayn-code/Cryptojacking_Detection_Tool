"""Notification service – dispatches alerts to verified channels."""

import os
from sqlalchemy.orm import Session

from backend.models.alert import Alert
from backend.models.notification_channel import NotificationChannel
from backend.models.system import MonitoredSystem


class NotificationService:
    """Send email / WhatsApp messages for high-confidence alerts."""

    CONFIDENCE_THRESHOLD = 0.70

    @staticmethod
    async def dispatch_alert(alert: Alert, db: Session):
        """Look up verified+enabled channels for the system owner, send via each."""
        system = db.query(MonitoredSystem).filter(
            MonitoredSystem.system_id == alert.system_id
        ).first()
        if not system:
            return

        channels = (
            db.query(NotificationChannel)
            .filter(
                NotificationChannel.user_email == system.owner_email,
                NotificationChannel.verified == True,
                NotificationChannel.enabled == True,
            )
            .all()
        )

        for channel in channels:
            try:
                if channel.channel_type == "email":
                    await NotificationService._send_email_alert(channel.target, alert)
                elif channel.channel_type == "whatsapp":
                    await NotificationService._send_whatsapp_alert(channel.target, alert)
            except Exception as e:
                print(f"[NOTIFY] Failed to send to {channel.channel_type}:{channel.target}: {e}")

    @staticmethod
    def _env_flag(name: str, default: bool = False) -> bool:
        value = os.getenv(name)
        if value is None:
            return default
        return value.strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _reason_summary(alert: Alert) -> str:
        metrics = alert.metrics or {}
        reasons = metrics.get("reason_summary")
        if isinstance(reasons, list) and reasons:
            return ", ".join([str(r) for r in reasons[:4] if r])

        fallback = []
        policy_hits = metrics.get("policy_hits") or []
        if any(h.get("decision") == "deny" for h in policy_hits if isinstance(h, dict)):
            fallback.append("Blacklisted process")
        if (metrics.get("miner_network_hits") or []):
            fallback.append("Mining pool traffic")
        if (metrics.get("threat_intel_hits") or []):
            fallback.append("Threat intel match")
        if (metrics.get("static_evidence_hits") or []):
            fallback.append("Static indicators")
        if (metrics.get("dynamic_evidence") or {}).get("dynamic_score"):
            fallback.append("Behavioral anomaly")
        if (alert.suspicious_processes or []):
            fallback.append("Suspicious processes")

        return ", ".join(fallback[:4]) if fallback else "Multiple risk signals"

    @staticmethod
    async def _send_email_alert(to: str, alert: Alert):
        """Send alert notification email."""
        smtp_server = os.getenv("SMTP_SERVER")
        smtp_user = os.getenv("SMTP_USERNAME")
        smtp_pass = os.getenv("SMTP_PASSWORD")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        email_from = os.getenv("EMAIL_FROM", smtp_user)
        smtp_use_ssl = NotificationService._env_flag("SMTP_USE_SSL", False)
        smtp_starttls = NotificationService._env_flag("SMTP_STARTTLS", not smtp_use_ssl)

        # SSL and STARTTLS are mutually exclusive
        if smtp_use_ssl and smtp_starttls:
            smtp_starttls = False

        if not smtp_server or not smtp_user:
            print(f"[NOTIFY] SMTP not configured – alert {alert.id} for {to}")
            return

        try:
            import aiosmtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            confidence_pct = f"{alert.confidence * 100:.1f}%"
            procs = ', '.join(alert.suspicious_processes or []) or 'None detected'
            reasons = NotificationService._reason_summary(alert)

            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"🚨 CryptoDetect Alert – {alert.system_id} ({confidence_pct})"
            msg["From"] = email_from
            msg["To"] = to

            html = f"""
            <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:24px;background:#fef2f2;border-radius:12px;border:1px solid #fecaca">
                <h2 style="color:#dc2626;margin:0 0 8px">⚠️ Cryptojacking Alert</h2>
                <table style="width:100%;font-size:14px;color:#1e293b;border-collapse:collapse">
                    <tr><td style="padding:6px 0;font-weight:600;width:120px">System ID</td><td>{alert.system_id}</td></tr>
                    <tr><td style="padding:6px 0;font-weight:600">Confidence</td><td style="color:#dc2626;font-weight:700">{confidence_pct}</td></tr>
                    <tr><td style="padding:6px 0;font-weight:600">Detection</td><td>{alert.detection_method}</td></tr>
                    <tr><td style="padding:6px 0;font-weight:600">Reasons</td><td>{reasons}</td></tr>
                    <tr><td style="padding:6px 0;font-weight:600">Processes</td><td><code>{procs}</code></td></tr>
                    <tr><td style="padding:6px 0;font-weight:600">Time</td><td>{alert.timestamp.isoformat() if alert.timestamp else 'N/A'}</td></tr>
                </table>
                <p style="color:#94a3b8;font-size:12px;margin-top:16px">Log in to your CryptoDetect dashboard to review this alert.</p>
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
            print(f"[NOTIFY] Email alert sent to {to}")
        except Exception as e:
            print(f"[NOTIFY] Email alert failed for {to}: {e}")

    @staticmethod
    async def _send_whatsapp_alert(to: str, alert: Alert):
        """Send alert notification via Twilio WhatsApp."""
        account_sid = os.getenv("TWILIO_ACCOUNT_SID")
        auth_token = os.getenv("TWILIO_AUTH_TOKEN")
        from_number = os.getenv("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")

        if not account_sid or not auth_token:
            print(f"[NOTIFY] Twilio not configured – alert {alert.id} for {to}")
            return

        try:
            from twilio.rest import Client
            client = Client(account_sid, auth_token)
            confidence_pct = f"{alert.confidence * 100:.1f}%"
            procs = ', '.join(alert.suspicious_processes or []) or 'None'
            reasons = NotificationService._reason_summary(alert)

            body = (
                f"🚨 *CryptoDetect Alert*\n"
                f"System: {alert.system_id}\n"
                f"Confidence: {confidence_pct}\n"
                f"Method: {alert.detection_method}\n"
                f"Reasons: {reasons}\n"
                f"Processes: {procs}\n"
                f"Time: {alert.timestamp.isoformat() if alert.timestamp else 'N/A'}"
            )

            message = client.messages.create(
                body=body,
                from_=from_number,
                to=f"whatsapp:{to}" if not to.startswith("whatsapp:") else to,
            )
            print(f"[NOTIFY] WhatsApp alert sent to {to} (SID: {message.sid})")
        except Exception as e:
            print(f"[NOTIFY] WhatsApp alert failed for {to}: {e}")
