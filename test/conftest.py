"""
CryptoDetect - Shared Test Fixtures
====================================
Shared fixtures and configuration for all test modules.
"""
import pytest
import numpy as np


# ─────────────────────────────────────────────
#  Sample data fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def normal_metrics():
    """Represents a healthy, benign system snapshot."""
    return {
        "cpu_total": 15.2, "cpu_user": 10.1, "cpu_system": 5.1,
        "cpu_idle": 84.8, "cpu_iowait": 0.0, "cpu_irq": 0.0,
        "mem_percent": 52.3, "mem_used": 4294967296, "mem_available": 3900000000,
        "mem_active": 3000000000, "load_min1": 1.2, "load_min5": 1.1,
        "load_min15": 0.9, "network_lo_rx": 1024, "network_lo_tx": 512,
        "processcount_running": 5, "processcount_total": 120,
        "processcount_thread": 450, "cpu_softirq": 0.0, "mem_cached": 500000000,
    }


@pytest.fixture
def cryptojacking_metrics():
    """Represents a system actively being cryptojacked (xmrig-like pattern)."""
    return {
        "cpu_total": 96.5, "cpu_user": 90.2, "cpu_system": 6.3,
        "cpu_idle": 3.5, "cpu_iowait": 0.0, "cpu_irq": 0.0,
        "mem_percent": 81.4, "mem_used": 13743895347, "mem_available": 1200000000,
        "mem_active": 12000000000, "load_min1": 7.8, "load_min5": 7.6,
        "load_min15": 7.4, "network_lo_rx": 1048576, "network_lo_tx": 524288,
        "processcount_running": 4, "processcount_total": 132,
        "processcount_thread": 512, "cpu_softirq": 0.0, "mem_cached": 800000000,
    }


@pytest.fixture
def sample_process_benign():
    return {
        "pid": 1234, "name": "chrome.exe", "cpu_percent": 3.2,
        "memory_percent": 1.8, "exe": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
        "sha256": "a" * 64, "signed": True, "parent_pid": 500,
    }


@pytest.fixture
def sample_process_suspicious():
    return {
        "pid": 9999, "name": "xmrig.exe", "cpu_percent": 94.1,
        "memory_percent": 78.5, "exe": "C:\\Users\\Public\\xmrig.exe",
        "sha256": "b" * 64, "signed": False, "parent_pid": 1,
    }


@pytest.fixture
def valid_user():
    return {"email": "operator@test.com", "password": "SecurePass123!", "full_name": "Security Operator"}


@pytest.fixture
def mock_alert():
    return {
        "id": 1, "system_id": "SYS-2XD43CWX", "alert_type": "cryptojacking_detected",
        "confidence": 0.97, "detection_method": "ml_xgboost",
        "target": "xmrig.exe", "status": "unread",
        "feature_importance": {"cpu_total": 0.42, "mem_percent": 0.28, "network_lo_rx": 0.18},
    }
