from sqlalchemy import Column, String, DateTime, Integer, Float, ForeignKey, JSON, Index
from sqlalchemy.orm import relationship
from backend.database import Base
from datetime import datetime


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(String, ForeignKey("monitored_systems.system_id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    alert_type = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    detection_method = Column(String, default="heuristic")
    metrics = Column(JSON, default=dict)
    suspicious_processes = Column(JSON, default=list)
    virustotal_results = Column(JSON, default=list)
    feature_importance = Column(JSON, default=dict)
    status = Column(String, default="unread", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    system = relationship("MonitoredSystem", back_populates="alerts")

    __table_args__ = (
        Index('idx_alert_system_status', 'system_id', 'status'),
        Index('idx_alert_timestamp', 'timestamp'),
    )
