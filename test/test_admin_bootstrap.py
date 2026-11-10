"""Tests for consumer admin bootstrap, initial admin claim, and UAC privilege helpers."""

from pathlib import Path
import sys
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.database import Base, get_db
from backend.main import app
from backend.models.system import MonitoredSystem
from backend.models.user import User
from backend.routes.auth import create_access_token, pwd_context


@pytest.fixture
def auth_client():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    db = TestingSessionLocal()

    yield client, db

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def test_first_user_can_claim_initial_admin(auth_client):
    client, db = auth_client

    # Register first normal user
    reg_resp = client.post(
        "/api/auth/register",
        json={"email": "first_user@corp.com", "password": "SecurePassword123!", "full_name": "First User"},
    )
    assert reg_resp.status_code == 200
    token = reg_resp.json()["access_token"]
    assert reg_resp.json()["user"]["role"] == "user"

    headers = {"Authorization": f"Bearer {token}"}

    # Claim initial admin
    claim_resp = client.post("/api/auth/claim-initial-admin", headers=headers)
    assert claim_resp.status_code == 200
    data = claim_resp.json()
    assert data["status"] == "success"
    assert data["user"]["role"] == "admin"

    # Idempotent re-claim by same admin
    reclaim_resp = client.post("/api/auth/claim-initial-admin", headers=headers)
    assert reclaim_resp.status_code == 200
    assert reclaim_resp.json()["user"]["role"] == "admin"

    # Register a second user
    reg2_resp = client.post(
        "/api/auth/register",
        json={"email": "second_user@corp.com", "password": "SecurePassword123!", "full_name": "Second User"},
    )
    assert reg2_resp.status_code == 200
    token2 = reg2_resp.json()["access_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    # Second user attempting to claim admin is rejected (403)
    reject_resp = client.post("/api/auth/claim-initial-admin", headers=headers2)
    assert reject_resp.status_code == 403
    assert "already exists" in reject_resp.json()["detail"]


def test_admin_email_env_auto_promotes(auth_client, monkeypatch):
    client, db = auth_client
    monkeypatch.setenv("ADMIN_EMAIL", "designated_ciso@corp.com")

    reg_resp = client.post(
        "/api/auth/register",
        json={"email": "designated_ciso@corp.com", "password": "SecurePassword123!", "full_name": "Chief InfoSec"},
    )
    assert reg_resp.status_code == 200
    assert reg_resp.json()["user"]["role"] == "admin"
