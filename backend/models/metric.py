from sqlalchemy import Column, String, DateTime, Integer, Float, ForeignKey, JSON, Index
from sqlalchemy.orm import relationship
from backend.database import Base
from datetime import datetime


class SystemMetric(Base):
    __tablename__ = "system_metrics"

    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(String, ForeignKey("monitored_systems.system_id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    cpu_percent = Column(Float)
    memory_percent = Column(Float)
    network_bytes_sent = Column(Integer)
    network_bytes_recv = Column(Integer)
    processes_data = Column(JSON, default=list)
    raw_metrics = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    system = relationship("MonitoredSystem", back_populates="metrics")

    __table_args__ = (
        Index('idx_metric_system_time', 'system_id', 'timestamp'),
    )
