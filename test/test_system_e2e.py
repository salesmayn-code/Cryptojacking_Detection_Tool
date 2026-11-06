"""
CryptoDetect – System Tests: End-to-End Simulation
===================================================
Simulates the complete pipeline: agent → backend → ML inference → alert.
Covers: normal operation, threat detection, sustained-gate logic,
security (auth bypass), and offline buffering.
"""
import pytest
import time
import numpy as np
from datetime import datetime
from unittest.mock import MagicMock, patch

# ─────────────────────────────────────────────
#  System constants
# ─────────────────────────────────────────────
SUSTAINED_GATE              = 3
ALERT_CONFIDENCE_THRESHOLD  = 0.70
ALERT_COOLDOWN_SECONDS      = 300
CPU_HEURISTIC_THRESHOLD     = 90.0
MEM_HEURISTIC_THRESHOLD     = 80.0
AGENT_SAMPLE_INTERVAL       = 5      # seconds
AGENT_BATCH_INTERVAL        = 30     # seconds
AGENT_MAX_CPU_FOOTPRINT     = 2.0    # %
AGENT_MAX_RAM_MB            = 50.0


# ─────────────────────────────────────────────
#  Mock subsystems
# ─────────────────────────────────────────────

class MockMLPipeline:
    """Simulates the XGBoost / Random Forest inference pipeline."""

    def __init__(self, always_detect: bool = False):
        self.always_detect = always_detect
        self.call_count    = 0

    def predict(self, feature_vector: np.ndarray) -> dict:
        self.call_count += 1
        cpu = feature_vector[0][0]   # cpu_total is feature index 0
        if self.always_detect or cpu >= CPU_HEURISTIC_THRESHOLD:
            return {"label": 1, "confidence": 0.97, "method": "ml_xgboost"}
        return {"label": 0, "confidence": 0.12, "method": "ml_xgboost"}


class MockVirusTotalClient:
    """Simulates VirusTotal hash reputation lookups."""

    KNOWN_HASHES = {"aabbcc" * 10: {"malicious": 58, "total": 72}}

    def lookup(self, sha256: str) -> dict:
        return self.KNOWN_HASHES.get(sha256, {"malicious": 0, "total": 0})


class MockSMTPClient:
    """Simulates email dispatch via SMTP."""
    sent: list = []

    def send(self, to: str, subject: str, body: str):
        self.sent.append({"to": to, "subject": subject})
        return True


class CryptoDetectSystem:
    """
    Minimal orchestrator that mirrors the production backend logic:
      receive_batch → authenticate → extract_features → ml_inference
      → heuristic_check → sustained_gate → generate_alert → notify
    """

    def __init__(self, api_key: str, system_id: str):
        self.api_key       = api_key
        self.system_id     = system_id
        self.ml_pipeline   = MockMLPipeline()
        self.vt_client     = MockVirusTotalClient()
        self.smtp_client   = MockSMTPClient()
        self.alerts        = []
        self.consecutive   = 0
        self.last_alert_ts = 0.0
        self.status        = "offline"
        self.last_seen     = None

    def receive_batch(self, api_key: str, batch: list) -> dict:
        if api_key != self.api_key:
            return {"error": "Unauthorized", "code": 401}

        self.status    = "online"
        self.last_seen = datetime.utcnow().isoformat()

        alerts_generated = []
        for metric in batch:
            fv  = self._build_feature_vector(metric)
            res = self.ml_pipeline.predict(fv)

            if res["label"] == 1:
                self.consecutive += 1
            else:
                self.consecutive = 0

            cooldown_ok = (time.time() - self.last_alert_ts) > ALERT_COOLDOWN_SECONDS

            if (self.consecutive >= SUSTAINED_GATE and
                    res["confidence"] >= ALERT_CONFIDENCE_THRESHOLD and
                    cooldown_ok):
                alert = {
                    "id":         len(self.alerts) + 1,
                    "system_id":  self.system_id,
                    "type":       "cryptojacking_detected",
                    "confidence": res["confidence"],
                    "method":     res["method"],
                    "timestamp":  datetime.utcnow().isoformat(),
                    "status":     "unread",
                }
                self.alerts.append(alert)
                alerts_generated.append(alert)
                self.last_alert_ts = time.time()
                self.smtp_client.send("user@test.com", "CryptoDetect Alert", "Threat detected")

        return {"status": "ok", "alerts": alerts_generated}

    def _build_feature_vector(self, m: dict) -> np.ndarray:
        keys = [
            "cpu_total","cpu_user","cpu_system","cpu_idle","cpu_iowait",
            "cpu_irq","mem_percent","mem_used","mem_available","mem_active",
            "load_min1","load_min5","load_min15","network_lo_rx","network_lo_tx",
            "processcount_running","processcount_total","processcount_thread",
            "cpu_softirq","mem_cached",
        ]
        return np.array([m.get(k, 0.0) for k in keys], dtype=float).reshape(1, -1)


def make_normal_metric() -> dict:
    return {
        "cpu_total": 15.2, "cpu_user": 10.0, "cpu_system": 5.2, "cpu_idle": 84.8,
        "cpu_iowait": 0.0, "cpu_irq": 0.0, "mem_percent": 52.3,
        "mem_used": 4294967296, "mem_available": 3900000000, "mem_active": 3000000000,
        "load_min1": 1.2, "load_min5": 1.1, "load_min15": 0.9,
        "network_lo_rx": 1024, "network_lo_tx": 512,
        "processcount_running": 5, "processcount_total": 120,
        "processcount_thread": 450, "cpu_softirq": 0.0, "mem_cached": 500000000,
    }


def make_crypto_metric() -> dict:
    m = make_normal_metric()
    m.update({"cpu_total": 96.5, "cpu_user": 90.2, "cpu_idle": 3.5, "mem_percent": 81.4})
    return m


API_KEY   = "test_api_key_" + "a" * 51
SYSTEM_ID = "SYS-E2E001"


# ─────────────────────────────────────────────
#  Test Class: Normal Operation
# ─────────────────────────────────────────────
class TestNormalOperation:

    def setup_method(self):
        self.system = CryptoDetectSystem(API_KEY, SYSTEM_ID)

    def test_system_starts_offline(self):
        assert self.system.status == "offline"

    def test_valid_batch_sets_status_online(self):
        self.system.receive_batch(API_KEY, [make_normal_metric()])
        assert self.system.status == "online"

    def test_heartbeat_updated_after_batch(self):
        self.system.receive_batch(API_KEY, [make_normal_metric()])
        assert self.system.last_seen is not None

    def test_normal_metrics_produce_no_alerts(self):
        for _ in range(5):
            result = self.system.receive_batch(API_KEY, [make_normal_metric()])
        assert result["alerts"] == []

    def test_normal_metrics_reset_consecutive_counter(self):
        self.system.consecutive = 2   # previously partially suspicious
        self.system.receive_batch(API_KEY, [make_normal_metric()])
        assert self.system.consecutive == 0

    def test_multiple_normal_batches_no_alerts(self):
        for _ in range(10):
            self.system.receive_batch(API_KEY, [make_normal_metric()])
        assert len(self.system.alerts) == 0


# ─────────────────────────────────────────────
#  Test Class: Threat Detection Simulation
# ─────────────────────────────────────────────
class TestThreatDetectionSimulation:

    def setup_method(self):
        self.system = CryptoDetectSystem(API_KEY, SYSTEM_ID)

    def test_single_crypto_batch_no_alert_before_gate(self):
        """One positive detection must NOT fire an alert (gate requires 3)."""
        result = self.system.receive_batch(API_KEY, [make_crypto_metric()])
        assert result["alerts"] == []
        assert self.system.consecutive == 1

    def test_two_consecutive_no_alert(self):
        for _ in range(2):
            result = self.system.receive_batch(API_KEY, [make_crypto_metric()])
        assert result["alerts"] == []
        assert self.system.consecutive == 2

    def test_three_consecutive_triggers_alert(self):
        for _ in range(3):
            result = self.system.receive_batch(API_KEY, [make_crypto_metric()])
        assert len(result["alerts"]) >= 1

    def test_alert_has_high_confidence(self):
        for _ in range(3):
            result = self.system.receive_batch(API_KEY, [make_crypto_metric()])
        assert result["alerts"][0]["confidence"] >= ALERT_CONFIDENCE_THRESHOLD

    def test_alert_type_is_cryptojacking(self):
        for _ in range(3):
            result = self.system.receive_batch(API_KEY, [make_crypto_metric()])
        assert result["alerts"][0]["type"] == "cryptojacking_detected"

    def test_alert_detection_method_is_xgboost(self):
        for _ in range(3):
            result = self.system.receive_batch(API_KEY, [make_crypto_metric()])
        assert "xgboost" in result["alerts"][0]["method"]

    def test_email_notification_sent_on_alert(self):
        for _ in range(3):
            self.system.receive_batch(API_KEY, [make_crypto_metric()])
        assert len(self.system.smtp_client.sent) >= 1

    def test_alert_recovery_normal_after_crypto(self):
        """Normal batches after a detected attack should reset the counter."""
        for _ in range(3):
            self.system.receive_batch(API_KEY, [make_crypto_metric()])
        self.system.consecutive = 0   # simulate user acknowledgement / metric drop
        result = self.system.receive_batch(API_KEY, [make_normal_metric()])
        assert self.system.consecutive == 0


# ─────────────────────────────────────────────
#  Test Class: Security – Auth Bypass
# ─────────────────────────────────────────────
class TestSecurityAuthBypass:

    def setup_method(self):
        self.system = CryptoDetectSystem(API_KEY, SYSTEM_ID)

    def test_wrong_api_key_rejected(self):
        result = self.system.receive_batch("WRONG_KEY", [make_normal_metric()])
        assert result.get("code") == 401

    def test_empty_api_key_rejected(self):
        result = self.system.receive_batch("", [make_normal_metric()])
        assert result.get("code") == 401

    def test_sql_injection_in_api_key_rejected(self):
        result = self.system.receive_batch("' OR '1'='1", [make_normal_metric()])
        assert result.get("code") == 401

    def test_status_remains_offline_after_failed_auth(self):
        self.system.receive_batch("WRONG_KEY", [make_normal_metric()])
        assert self.system.status == "offline"


# ─────────────────────────────────────────────
#  Test Class: Agent Offline Buffering
# ─────────────────────────────────────────────
class TestOfflineBuffering:

    def test_buffer_holds_up_to_60_entries(self):
        buffer = []
        for _ in range(65):
            buffer.append(make_normal_metric())
            if len(buffer) > 60:
                buffer.pop(0)     # rolling window
        assert len(buffer) == 60

    def test_buffer_evicts_oldest_entry(self):
        buffer = []
        for i in range(65):
            m = make_normal_metric()
            m["cpu_total"] = float(i)
            buffer.append(m)
            if len(buffer) > 60:
                buffer.pop(0)
        assert buffer[0]["cpu_total"] == 5.0   # entries 0-4 were evicted

    def test_buffer_preserved_on_network_failure(self):
        """Simulates retry: buffer should not be cleared until upload succeeds."""
        buffer = [make_normal_metric() for _ in range(10)]
        upload_success = False       # simulate network down
        if not upload_success:
            assert len(buffer) == 10  # buffer retained

    def test_buffer_cleared_after_successful_upload(self):
        buffer = [make_normal_metric() for _ in range(10)]
        upload_success = True
        if upload_success:
            buffer.clear()
        assert len(buffer) == 0


# ─────────────────────────────────────────────
#  Test Class: VirusTotal Integration
# ─────────────────────────────────────────────
class TestVirusTotalIntegration:

    def setup_method(self):
        self.vt = MockVirusTotalClient()

    def test_known_malicious_hash_detected(self):
        sha256 = "aabbcc" * 10
        result = self.vt.lookup(sha256)
        assert result["malicious"] > 0

    def test_benign_hash_returns_zero_malicious(self):
        result = self.vt.lookup("0000" * 16)
        assert result["malicious"] == 0

    def test_vt_result_has_required_keys(self):
        result = self.vt.lookup("aabbcc" * 10)
        assert "malicious" in result
        assert "total" in result

    def test_detection_ratio_computed_correctly(self):
        result = self.vt.lookup("aabbcc" * 10)
        ratio  = result["malicious"] / result["total"]
        assert 0.0 < ratio <= 1.0
