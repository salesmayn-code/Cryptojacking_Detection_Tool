"""ORM model for signed human-in-the-loop agent containment & audit commands."""

from datetime import datetime
from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, JSON, String, Text

from backend.database import Base


VALID_CONTAINMENT_ACTIONS = {
    "suspend_process",
    "resume_process",
    "kill_process_tree",
    "quarantine_binary",
    "block_ip",
    "audit_persistence",
}


class AgentCommand(Base):
    __tablename__ = "agent_commands"

    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(String, ForeignKey("monitored_systems.system_id"), nullable=False, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String, nullable=False)
    target_payload = Column(JSON, default=dict)
    status = Column(String, default="pending", nullable=False, index=True)
    requested_by = Column(String, nullable=False)
    result_data = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("idx_agent_cmd_sys_status", "system_id", "status"),
        Index("idx_agent_cmd_alert", "alert_id"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "command_id": self.id,
            "system_id": self.system_id,
            "alert_id": self.alert_id,
            "action": self.action,
            "target_payload": self.target_payload or {},
            "status": self.status,
            "requested_by": self.requested_by,
            "result_data": self.result_data or {},
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
