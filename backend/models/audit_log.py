"""Audit Log model – tracks sensitive admin and system actions."""

from sqlalchemy import Column, String, DateTime, Integer, JSON, Index
from backend.database import Base
from datetime import datetime


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    actor_email = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False)            # e.g. "system.delete", "user.role_change"
    target_type = Column(String, nullable=True)         # "system" | "user" | "alert" | "settings"
    target_id = Column(String, nullable=True)           # e.g. system_id or user email
    details = Column(JSON, default=dict)                # freeform context
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index('idx_audit_actor_action', 'actor_email', 'action'),
        Index('idx_audit_timestamp', 'timestamp'),
    )
