from sqlalchemy import Column, String, DateTime, Integer, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.database import Base
from datetime import datetime


class MonitoredSystem(Base):
    __tablename__ = "monitored_systems"

    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(String, unique=True, index=True, nullable=False)
    system_name = Column(String, nullable=False)
    system_description = Column(Text)
    owner_email = Column(String, ForeignKey("users.email"), nullable=False)
    status = Column(String, default="offline", nullable=False)
    last_seen = Column(DateTime, nullable=True)
    device_info = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    owner = relationship("User", back_populates="monitored_systems")
    metrics = relationship("SystemMetric", back_populates="system", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="system", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="system", cascade="all, delete-orphan")
