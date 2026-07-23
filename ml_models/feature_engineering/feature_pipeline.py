"""
feature_engineering/feature_pipeline.py
========================================
Canonical feature definitions and extraction functions for the
cryptojacking detection system.

Imported by:
  - backend/routes/metrics.py          (ML inference)
  - monitoring_agent/enhanced_agent.py (telemetry collection)

DO NOT modify SELECTED_FEATURES without retraining the models.
"""

from __future__ import annotations
import numpy as np
from typing import Dict, Any

# ─────────────────────────────────────────────────────────────────────────────
# Single source of truth — 20 features, exact order used during training
# ─────────────────────────────────────────────────────────────────────────────
SELECTED_FEATURES: list[str] = [
    # CPU features
    "cpu_total",            # psutil.cpu_percent()
    "cpu_user",             # psutil.cpu_times_percent().user
    "cpu_system",           # psutil.cpu_times_percent().system
    "cpu_idle",             # psutil.cpu_times_percent().idle
    "cpu_iowait",           # 0.0 on Windows
    "cpu_irq",              # psutil.cpu_times_percent().interrupt
    # Memory features
    "mem_percent",          # psutil.virtual_memory().percent
    "mem_used",             # psutil.virtual_memory().used
    "mem_available",        # psutil.virtual_memory().available
    "mem_active",           # psutil.virtual_memory().active (0 on Win)
    # Load average features
    "load_min1",            # psutil.getloadavg()[0]
    "load_min5",            # psutil.getloadavg()[1]
    "load_min15",           # psutil.getloadavg()[2]
    # Network features (bytes/sec delta)
    "network_lo_rx",        # bytes_recv delta
    "network_lo_tx",        # bytes_sent delta
    # Process count features
    "processcount_running", # running processes
    "processcount_total",   # total processes
    "processcount_thread",  # total threads
    # Additional CPU / memory
    "cpu_softirq",          # 0.0 on Windows
    "mem_cached",           # 0 on Windows
]

N_FEATURES: int = len(SELECTED_FEATURES)

# Per-feature valid bounds  (lo, hi) — None means unbounded
FEATURE_BOUNDS: Dict[str, tuple] = {
    "cpu_total":            (0,   100),
    "cpu_user":             (0,   100),
    "cpu_system":           (0,   100),
    "cpu_idle":             (0,   100),
    "cpu_iowait":           (0,   100),
    "cpu_irq":              (0,   100),
    "cpu_softirq":          (0,   100),
    "mem_percent":          (0,   100),
    "mem_used":             (0,   None),
    "mem_available":        (0,   None),
    "mem_active":           (0,   None),
    "mem_cached":           (0,   None),
    "load_min1":            (0,   None),
    "load_min5":            (0,   None),
    "load_min15":           (0,   None),
    "network_lo_rx":        (0,   None),
    "network_lo_tx":        (0,   None),
    "processcount_running": (0,   None),
    "processcount_total":   (1,   None),
    "processcount_thread":  (1,   None),
}


def extract_features_from_metrics(metrics: Dict[str, Any]) -> np.ndarray:
    """
    Convert an agent metrics payload into a numpy array of shape (20,)
    aligned to SELECTED_FEATURES.

    Expected metrics dict structure (from enhanced_agent.py)::

        {
            "cpu":           {"percent": 45.2},
            "cpu_times":     {"user": 30.1, "system": 5.0, "idle": 64.9,
                              "iowait": 0.0, "irq": 0.0, "softirq": 0.0},
            "memory":        {"percent": 62.3, "used": 8_500_000_000,
                              "available": 5_000_000_000,
                              "active": 4_200_000_000, "cached": 0},
            "load_avg":      {"min1": 1.5, "min5": 1.2, "min15": 0.9},
            "network":       {"bytes_recv_delta": 1024, "bytes_sent_delta": 512},
            "process_counts":{"running": 8, "total": 103, "thread": 520},
        }

    Returns
    -------
    np.ndarray
        Float64 array of length 20.
    """
    cpu_t = metrics.get("cpu_times", {})
    mem   = metrics.get("memory",    {})
    load  = metrics.get("load_avg",  {})
    net   = metrics.get("network",   {})
    proc  = metrics.get("process_counts", {})

    vector = [
        float(metrics.get("cpu", {}).get("percent",         0.0)),
        float(cpu_t.get("user",    0.0)),
        float(cpu_t.get("system",  0.0)),
        float(cpu_t.get("idle",    0.0)),
        float(cpu_t.get("iowait",  0.0)),
        float(cpu_t.get("irq",     0.0)),
        float(mem.get("percent",   0.0)),
        float(mem.get("used",      0.0)),
        float(mem.get("available", 0.0)),
        float(mem.get("active",    0.0)),
        float(load.get("min1",     0.0)),
        float(load.get("min5",     0.0)),
        float(load.get("min15",    0.0)),
        float(net.get("bytes_recv_delta", 0.0)),
        float(net.get("bytes_sent_delta", 0.0)),
        float(proc.get("running",  0)),
        float(proc.get("total",    0)),
        float(proc.get("thread",   0)),
        float(cpu_t.get("softirq", 0.0)),
        float(mem.get("cached",    0.0)),
    ]
    return np.array(vector, dtype=np.float64)


def validate_feature_vector(vector: np.ndarray) -> bool:
    """
    Sanity-check a feature vector against known valid bounds.

    Returns True if all values are finite and within expected ranges.
    """
    if len(vector) != N_FEATURES:
        return False

    for i, feat in enumerate(SELECTED_FEATURES):
        val = vector[i]
        if not np.isfinite(val):
            return False
        lo, hi = FEATURE_BOUNDS.get(feat, (None, None))
        if lo is not None and val < lo:
            return False
        if hi is not None and val > hi:
            return False

    return True


def get_feature_index(feature_name: str) -> int:
    """Return the index of a feature in SELECTED_FEATURES (for SHAP indexing)."""
    return SELECTED_FEATURES.index(feature_name)
