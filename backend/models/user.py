from sqlalchemy import Column, String, DateTime, Integer
from sqlalchemy.orm import relationship
from backend.database import Base
from datetime import datetime
import hashlib
import secrets
import random
import string


class User(Base):
    __tablename__ = "users"
    API_KEY_HASH_PREFIX = "sha256$"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    system_id = Column(String, unique=True, index=True, nullable=False)
    api_key = Column(String, unique=True, index=True, nullable=False)
    role = Column(String, default="user", nullable=False)
    profile_picture_url = Column(String, nullable=True)
    password_updated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    monitored_systems = relationship("MonitoredSystem", back_populates="owner", cascade="all, delete-orphan")
    notification_channels = relationship("NotificationChannel", back_populates="user", cascade="all, delete-orphan")

    @staticmethod
    def generate_system_id():
        chars = string.ascii_uppercase + string.digits
        return f"SYS-{''.join(random.choices(chars, k=8))}"

    @staticmethod
    def generate_api_key():
        return secrets.token_urlsafe(32)

    @classmethod
    def hash_api_key(cls, api_key: str) -> str:
        if api_key.startswith(cls.API_KEY_HASH_PREFIX):
            return api_key
        digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        return f"{cls.API_KEY_HASH_PREFIX}{digest}"

    @staticmethod
    def mask_api_key(api_key: str | None) -> str:
        if not api_key:
            return "••••••••••••"
        tail = api_key[-4:] if len(api_key) >= 4 else ""
        return f"••••••••••••{tail}"
