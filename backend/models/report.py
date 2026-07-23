from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, JSON, String
from sqlalchemy.orm import relationship
from datetime import datetime

from backend.database import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(String, ForeignKey("monitored_systems.system_id"), nullable=False)
    owner_email = Column(String, nullable=False, index=True)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    metrics = Column(JSON, default=list, nullable=False)
    format = Column(String, nullable=False)
    status = Column(String, default="completed", nullable=False)
    file_path = Column(String, nullable=False)
    file_type = Column(String, nullable=False)
    size_bytes = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    system = relationship("MonitoredSystem", back_populates="reports")

    __table_args__ = (
        Index("idx_report_system_created", "system_id", "created_at"),
    )
