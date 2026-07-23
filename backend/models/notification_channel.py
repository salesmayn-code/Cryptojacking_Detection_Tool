"""Notification channel model – stores verified email/WhatsApp targets."""

from sqlalchemy import Column, String, DateTime, Integer, Boolean, ForeignKey, Index
from sqlalchemy.orm import relationship
from backend.database import Base
from datetime import datetime


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String, ForeignKey("users.email"), nullable=False, index=True)
    channel_type = Column(String, nullable=False)          # "email" | "whatsapp"
    target = Column(String, nullable=False)                 # email address or +phone
    verified = Column(Boolean, default=False)
    verify_code = Column(String, nullable=True)             # 6-digit OTP
    code_expires = Column(DateTime, nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="notification_channels")

    __table_args__ = (
        Index('idx_notif_user_type', 'user_email', 'channel_type'),
    )
