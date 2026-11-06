"""
CryptoDetect – Integration Tests: REST API Endpoints
=====================================================
Tests data flow between the Monitoring Agent, FastAPI backend,
and database layer. Uses FastAPI TestClient (no live server needed).
"""
import pytest
import json
import time
import numpy as np
from unittest.mock import patch, MagicMock
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.testclient import TestClient
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
#  Minimal stub of the CryptoDetect FastAPI app
#  (mirrors the production API endpoints)
# ─────────────────────────────────────────────────────────────────────────────

app   = FastAPI(title="CryptoDetect API – Test Stub")

# In-memory stores (replace the real DB for testing)
_users:   dict = {}
_systems: dict = {}
_metrics: list = []
_alerts:  list = []

VALID_API_KEY   = "test_api_key_64chars_" + "a" * 43      # 64 chars
VALID_SYSTEM_ID = "SYS-TEST001"

# Seed a test system
_systems[VALID_SYSTEM_ID] = {
    "system_id": VALID_SYSTEM_ID,
    "owner": "operator@test.com",
    "status": "offline",
    "last_seen": None,
    "api_key": VALID_API_KEY,
}


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: str

class LoginRequest(BaseModel):
    email: str
    password: str

class MetricEntry(BaseModel):
    timestamp: str
    cpu_total: float
    mem_percent: float
    network_lo_rx: int
    network_lo_tx: int
    processes: Optional[List[dict]] = []

class MetricsBatchRequest(BaseModel):
    system_id: str
    metrics: List[MetricEntry]


# ── Auth Endpoints ────────────────────────────────────────────────────────────

@app.post("/api/auth/register", status_code=201)
def register(body: RegisterRequest):
    if body.email in _users:
        raise HTTPException(status_code=400, detail="Email already registered")
    import secrets
    system_id = "SYS-" + secrets.token_hex(4).upper()
    api_key   = secrets.token_hex(32)
    _users[body.email] = {"email": body.email, "password_hash": "hashed", "full_name": body.full_name}
    _systems[system_id] = {"system_id": system_id, "owner": body.email, "api_key": api_key, "status": "offline"}
    return {"message": "Account created", "system_id": system_id, "api_key": api_key}

@app.post("/api/auth/login")
def login(body: LoginRequest):
    if body.email not in _users:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": "mock.jwt.token", "token_type": "bearer"}


# ── Metrics Ingestion Endpoint ────────────────────────────────────────────────

@app.post("/api/metrics/batch")
def ingest_batch(body: MetricsBatchRequest, x_api_key: str = Header(...)):
    # Validate API key
    system = _systems.get(body.system_id)
    if not system or system["api_key"] != x_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key or System ID")

    # Update heartbeat
    system["status"]    = "online"
    system["last_seen"] = datetime.utcnow().isoformat()

    # Persist metrics
    for m in body.metrics:
        _metrics.append({**m.dict(), "system_id": body.system_id})

    # Mock ML inference: flag if cpu_total >= 90
    alerts_generated = []
    for m in body.metrics:
        if m.cpu_total >= 90.0:
            alert = {
                "id": len(_alerts) + 1,
                "system_id": body.system_id,
                "alert_type": "cryptojacking_detected",
                "confidence": 0.97,
                "detection_method": "ml_xgboost",
                "timestamp": m.timestamp,
                "status": "unread",
            }
            _alerts.append(alert)
            alerts_generated.append(alert)

    return {
        "status": "ok",
        "metrics_stored": len(body.metrics),
        "alerts": alerts_generated,
        "inference_ms": 42,
    }


# ── System Status Endpoint ────────────────────────────────────────────────────

@app.get("/api/systems/{system_id}/status")
def system_status(system_id: str, authorization: str = Header(...)):
    system = _systems.get(system_id)
    if not system:
        raise HTTPException(status_code=404, detail="System not found")
    return system


# ── Alerts Endpoints ──────────────────────────────────────────────────────────

@app.get("/api/alerts")
def list_alerts(system_id: str, authorization: str = Header(...)):
    return [a for a in _alerts if a["system_id"] == system_id]

@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: int, status: str, authorization: str = Header(...)):
    for alert in _alerts:
        if alert["id"] == alert_id:
            alert["status"] = status
            return alert
    raise HTTPException(status_code=404, detail="Alert not found")


# ── Agent Validation Endpoint ─────────────────────────────────────────────────

@app.post("/api/auth/agent/validate")
def validate_agent(x_api_key: str = Header(...), x_system_id: str = Header(...)):
    system = _systems.get(x_system_id)
    if not system or system["api_key"] != x_api_key:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"valid": True, "system_id": x_system_id}


# ─────────────────────────────────────────────────────────────────────────────
#  Test Client
# ─────────────────────────────────────────────────────────────────────────────

client = TestClient(app, raise_server_exceptions=False)

AUTH_HEADER  = {"Authorization": "Bearer mock.jwt.token"}
AGENT_HEADERS = {"x-api-key": VALID_API_KEY}


def make_batch(cpu: float = 20.0, n: int = 1):
    metrics = [
        MetricEntry(
            timestamp=datetime.utcnow().isoformat(),
            cpu_total=cpu, mem_percent=52.0,
            network_lo_rx=1024, network_lo_tx=512,
        ).dict()
        for _ in range(n)
    ]
    return {"system_id": VALID_SYSTEM_ID, "metrics": metrics}


# ─────────────────────────────────────────────────────────────────────────────
#  Test Class: User Registration
# ─────────────────────────────────────────────────────────────────────────────

class TestUserRegistration:

    def test_register_new_user_returns_201(self):
        resp = client.post("/api/auth/register", json={
            "email": "newuser@test.com", "password": "Pass123!", "full_name": "New User"
        })
        assert resp.status_code == 201

    def test_register_returns_system_id_and_api_key(self):
        resp = client.post("/api/auth/register", json={
            "email": "another@test.com", "password": "Pass123!", "full_name": "Another"
        })
        body = resp.json()
        assert "system_id" in body
        assert "api_key" in body

    def test_register_duplicate_email_returns_400(self):
        payload = {"email": "dup@test.com", "password": "Pass!", "full_name": "Dup"}
        client.post("/api/auth/register", json=payload)            # first registration
        resp = client.post("/api/auth/register", json=payload)     # duplicate
        assert resp.status_code == 400

    def test_register_missing_field_returns_422(self):
        resp = client.post("/api/auth/register", json={"email": "x@test.com"})
        assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
#  Test Class: Login
# ─────────────────────────────────────────────────────────────────────────────

class TestLogin:

    def test_login_registered_user_returns_token(self):
        client.post("/api/auth/register", json={
            "email": "login_user@test.com", "password": "P@ss!", "full_name": "L User"
        })
        resp = client.post("/api/auth/login", json={
            "email": "login_user@test.com", "password": "P@ss!"
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_login_unknown_user_returns_401(self):
        resp = client.post("/api/auth/login", json={
            "email": "ghost@test.com", "password": "whatever"
        })
        assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
#  Test Class: Agent Validation
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentValidation:

    def test_valid_credentials_return_200(self):
        resp = client.post("/api/auth/agent/validate", headers={
            "x-api-key": VALID_API_KEY, "x-system-id": VALID_SYSTEM_ID
        })
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_invalid_api_key_returns_401(self):
        resp = client.post("/api/auth/agent/validate", headers={
            "x-api-key": "wrong_key_" + "z" * 54,
            "x-system-id": VALID_SYSTEM_ID,
        })
        assert resp.status_code == 401

    def test_wrong_system_id_returns_401(self):
        resp = client.post("/api/auth/agent/validate", headers={
            "x-api-key": VALID_API_KEY, "x-system-id": "SYS-WRONG"
        })
        assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
#  Test Class: Metrics Batch Ingestion
# ─────────────────────────────────────────────────────────────────────────────

class TestMetricsBatchIngestion:

    def test_valid_batch_returns_200(self):
        resp = client.post("/api/metrics/batch",
                           json=make_batch(), headers=AGENT_HEADERS)
        assert resp.status_code == 200

    def test_response_contains_metrics_stored_count(self):
        resp = client.post("/api/metrics/batch",
                           json=make_batch(n=3), headers=AGENT_HEADERS)
        assert resp.json()["metrics_stored"] == 3

    def test_invalid_api_key_rejected_with_401(self):
        resp = client.post("/api/metrics/batch",
                           json=make_batch(),
                           headers={"x-api-key": "bad_key"})
        assert resp.status_code == 401

    def test_normal_cpu_produces_no_alert(self):
        resp = client.post("/api/metrics/batch",
                           json=make_batch(cpu=20.0), headers=AGENT_HEADERS)
        assert resp.json()["alerts"] == []

    def test_high_cpu_produces_alert(self):
        resp = client.post("/api/metrics/batch",
                           json=make_batch(cpu=96.5), headers=AGENT_HEADERS)
        alerts = resp.json()["alerts"]
        assert len(alerts) >= 1
        assert alerts[0]["alert_type"] == "cryptojacking_detected"

    def test_alert_contains_confidence_score(self):
        resp = client.post("/api/metrics/batch",
                           json=make_batch(cpu=97.0), headers=AGENT_HEADERS)
        alert = resp.json()["alerts"][0]
        assert "confidence" in alert
        assert 0.0 <= alert["confidence"] <= 1.0

    def test_system_heartbeat_updated_after_batch(self):
        client.post("/api/metrics/batch", json=make_batch(), headers=AGENT_HEADERS)
        system = _systems[VALID_SYSTEM_ID]
        assert system["status"] == "online"
        assert system["last_seen"] is not None

    def test_inference_time_reported(self):
        resp = client.post("/api/metrics/batch",
                           json=make_batch(), headers=AGENT_HEADERS)
        assert "inference_ms" in resp.json()


# ─────────────────────────────────────────────────────────────────────────────
#  Test Class: Alert Management
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertManagement:

    def _seed_alert(self):
        """Push a high-CPU batch to seed an alert."""
        client.post("/api/metrics/batch",
                    json=make_batch(cpu=99.0), headers=AGENT_HEADERS)

    def test_get_alerts_returns_list(self):
        self._seed_alert()
        resp = client.get(f"/api/alerts?system_id={VALID_SYSTEM_ID}",
                          headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_alert_has_required_fields(self):
        self._seed_alert()
        resp  = client.get(f"/api/alerts?system_id={VALID_SYSTEM_ID}",
                           headers=AUTH_HEADER)
        alert = resp.json()[-1]
        for field in ["id", "system_id", "alert_type", "confidence", "status"]:
            assert field in alert, f"Missing field: {field}"

    def test_acknowledge_alert_updates_status(self):
        self._seed_alert()
        alerts   = client.get(f"/api/alerts?system_id={VALID_SYSTEM_ID}",
                              headers=AUTH_HEADER).json()
        alert_id = alerts[-1]["id"]
        resp     = client.patch(f"/api/alerts/{alert_id}?status=acknowledged",
                                headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert resp.json()["status"] == "acknowledged"

    def test_unknown_alert_id_returns_404(self):
        resp = client.patch("/api/alerts/999999?status=acknowledged",
                            headers=AUTH_HEADER)
        assert resp.status_code == 404
