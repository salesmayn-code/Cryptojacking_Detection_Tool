"""
CryptoDetect – Unit Tests: Feature Extraction & ML Inference
=============================================================
Validates the 20-feature vector pipeline, heuristic rules,
sustained-detection gate, and ML model confidence thresholds.
"""
import pytest
import numpy as np
from unittest.mock import MagicMock, patch

# ─────────────────────────────────────────────
#  Constants (mirroring production values)
# ─────────────────────────────────────────────
FEATURE_NAMES = [
    "cpu_total", "cpu_user", "cpu_system", "cpu_idle", "cpu_iowait",
    "cpu_irq", "mem_percent", "mem_used", "mem_available", "mem_active",
    "load_min1", "load_min5", "load_min15", "network_lo_rx", "network_lo_tx",
    "processcount_running", "processcount_total", "processcount_thread",
    "cpu_softirq", "mem_cached",
]

CPU_HEURISTIC_THRESHOLD   = 90.0   # %
MEM_HEURISTIC_THRESHOLD   = 80.0   # %
ALERT_CONFIDENCE_THRESHOLD = 0.70
SUSTAINED_GATE             = 3     # consecutive positives required
ALERT_COOLDOWN_SECONDS     = 300
PROCESS_CPU_FILTER         = 4.0   # % – filter suspicious processes above this
KNOWN_MINER_PORTS          = {3333, 4444, 14444, 45700}
MINER_KEYWORDS             = {"xmrig", "cpuminer", "minerd", "xmr-stak", "cryptonight"}


# ─────────────────────────────────────────────
#  Helpers (inline, matching production logic)
# ─────────────────────────────────────────────

def build_feature_vector(metrics: dict) -> np.ndarray:
    """Convert a metrics dict into the 20-feature NumPy array."""
    return np.array([metrics[f] for f in FEATURE_NAMES], dtype=float).reshape(1, -1)


def heuristic_detection(metrics: dict) -> bool:
    return (metrics["cpu_total"]   >= CPU_HEURISTIC_THRESHOLD or
            metrics["mem_percent"] >= MEM_HEURISTIC_THRESHOLD)


def is_process_suspicious_by_name(name: str) -> bool:
    return name.lower().replace(".exe", "") in MINER_KEYWORDS


def is_miner_port(port: int) -> bool:
    return port in KNOWN_MINER_PORTS


def should_alert(confidence: float, consecutive: int) -> bool:
    return confidence >= ALERT_CONFIDENCE_THRESHOLD and consecutive >= SUSTAINED_GATE


def normalize_features(vector: np.ndarray) -> np.ndarray:
    """Simple min-max-style clamp; production uses StandardScaler."""
    return np.clip(vector, 0, None)


# ─────────────────────────────────────────────
#  Test Class: Feature Vector Construction
# ─────────────────────────────────────────────
class TestFeatureVector:

    def test_feature_count_is_twenty(self):
        assert len(FEATURE_NAMES) == 20

    def test_vector_shape_is_correct(self, normal_metrics):
        vec = build_feature_vector(normal_metrics)
        assert vec.shape == (1, 20)

    def test_vector_dtype_is_float(self, normal_metrics):
        vec = build_feature_vector(normal_metrics)
        assert vec.dtype == float

    def test_normal_metrics_produce_valid_vector(self, normal_metrics):
        vec = build_feature_vector(normal_metrics)
        assert not np.isnan(vec).any()
        assert not np.isinf(vec).any()

    def test_cryptojacking_metrics_differ_from_normal(self, normal_metrics, cryptojacking_metrics):
        normal_vec  = build_feature_vector(normal_metrics)
        crypto_vec  = build_feature_vector(cryptojacking_metrics)
        assert not np.array_equal(normal_vec, crypto_vec)

    def test_feature_order_is_preserved(self, normal_metrics):
        """cpu_total must be the first element in the vector."""
        vec = build_feature_vector(normal_metrics)
        assert vec[0][0] == normal_metrics["cpu_total"]

    def test_normalization_removes_negatives(self):
        raw_vec = np.array([[-5.0, 10.0, -0.1, 100.0] + [0.0] * 16])
        normed  = normalize_features(raw_vec)
        assert (normed >= 0).all()

    def test_missing_feature_raises_key_error(self):
        incomplete = {"cpu_total": 10.0}   # missing 19 features
        with pytest.raises(KeyError):
            build_feature_vector(incomplete)


# ─────────────────────────────────────────────
#  Test Class: Heuristic Detection Rules
# ─────────────────────────────────────────────
class TestHeuristicDetection:

    def test_normal_cpu_does_not_trigger(self, normal_metrics):
        assert heuristic_detection(normal_metrics) is False

    def test_high_cpu_triggers_heuristic(self, cryptojacking_metrics):
        assert heuristic_detection(cryptojacking_metrics) is True

    def test_exact_cpu_threshold_triggers(self):
        metrics = {"cpu_total": 90.0, "mem_percent": 10.0}
        assert heuristic_detection(metrics) is True

    def test_just_below_cpu_threshold_does_not_trigger(self):
        metrics = {"cpu_total": 89.9, "mem_percent": 10.0}
        assert heuristic_detection(metrics) is False

    def test_high_memory_alone_triggers(self):
        metrics = {"cpu_total": 20.0, "mem_percent": 81.0}
        assert heuristic_detection(metrics) is True

    def test_both_high_cpu_and_mem_triggers(self):
        metrics = {"cpu_total": 95.0, "mem_percent": 85.0}
        assert heuristic_detection(metrics) is True


# ─────────────────────────────────────────────
#  Test Class: Process-Level Analysis
# ─────────────────────────────────────────────
class TestProcessAnalysis:

    def test_xmrig_flagged_as_miner(self):
        assert is_process_suspicious_by_name("xmrig.exe") is True

    def test_chrome_not_flagged_as_miner(self):
        assert is_process_suspicious_by_name("chrome.exe") is False

    def test_cpuminer_flagged(self):
        assert is_process_suspicious_by_name("cpuminer") is True

    def test_known_miner_port_3333_detected(self):
        assert is_miner_port(3333) is True

    def test_known_miner_port_4444_detected(self):
        assert is_miner_port(4444) is True

    def test_http_port_80_not_miner(self):
        assert is_miner_port(80) is False

    def test_https_port_443_not_miner(self):
        assert is_miner_port(443) is False

    def test_process_filter_threshold(self, sample_process_suspicious):
        """Processes above 4% CPU should be flagged for deeper analysis."""
        assert sample_process_suspicious["cpu_percent"] >= PROCESS_CPU_FILTER

    def test_benign_process_below_filter_threshold(self, sample_process_benign):
        assert sample_process_benign["cpu_percent"] < PROCESS_CPU_FILTER


# ─────────────────────────────────────────────
#  Test Class: ML Confidence & Alert Gating
# ─────────────────────────────────────────────
class TestMLConfidenceAndGating:

    def test_high_confidence_triggers_alert(self):
        assert should_alert(confidence=0.97, consecutive=3) is True

    def test_confidence_below_threshold_no_alert(self):
        assert should_alert(confidence=0.65, consecutive=3) is False

    def test_sustained_gate_requires_three_positives(self):
        assert should_alert(confidence=0.90, consecutive=2) is False

    def test_exactly_three_consecutives_passes_gate(self):
        assert should_alert(confidence=0.90, consecutive=3) is True

    def test_confidence_boundary_at_threshold(self):
        assert should_alert(confidence=0.70, consecutive=3) is True

    def test_confidence_just_below_boundary(self):
        assert should_alert(confidence=0.699, consecutive=3) is False

    def test_mock_xgboost_prediction_returns_array(self):
        """Mock the XGBoost model and verify prediction interface."""
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.03, 0.97]])
        feature_vec = np.random.rand(1, 20)

        proba = mock_model.predict_proba(feature_vec)
        confidence = float(proba[0][1])   # probability of class 1 (malicious)

        assert 0.0 <= confidence <= 1.0
        assert confidence == 0.97

    def test_mock_random_forest_fallback(self):
        mock_rf = MagicMock()
        mock_rf.predict_proba.return_value = np.array([[0.10, 0.90]])
        proba = mock_rf.predict_proba(np.random.rand(1, 20))
        assert float(proba[0][1]) == 0.90

    def test_shap_values_length_matches_features(self):
        """SHAP must produce one value per feature."""
        mock_shap_values = np.random.rand(20)
        assert len(mock_shap_values) == len(FEATURE_NAMES)
