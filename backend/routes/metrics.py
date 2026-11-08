"""Metrics routes with persistent storage and ensemble ML inference."""

from datetime import datetime
import json
import os
import sys
from pathlib import Path
import re
import threading
import time
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.alert import Alert
from backend.models.metric import SystemMetric
from backend.models.system import MonitoredSystem
from backend.models.user import User
from backend.routes.auth import verify_api_key, verify_token


router = APIRouter()


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.append(str(_PROJECT_ROOT))


try:
    from feature_engineering import (
        FEATURE_BOUNDS,
        SELECTED_FEATURES,
        extract_features_from_metrics,
        validate_feature_vector,
    )
except Exception as feature_import_err:
    print(f"Feature pipeline import failed: {feature_import_err}")
    FEATURE_BOUNDS = {}
    SELECTED_FEATURES = []

    def extract_features_from_metrics(_: Dict[str, Any]) -> np.ndarray:
        return np.array([], dtype=np.float64)

    def validate_feature_vector(_: np.ndarray) -> bool:
        return False

try:
    from dynamic_analysis import DynamicBehaviorMonitor
    from dynamic_analysis.behavior_monitor import KNOWN_BROWSER_NAMES, TLS_TUNNEL_PORTS

    _behavior_monitor = DynamicBehaviorMonitor(max_samples=24)
except Exception:
    _behavior_monitor = None
    KNOWN_BROWSER_NAMES = {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
        "opera.exe", "vivaldi.exe", "iexplore.exe", "teams.exe",
    }
    TLS_TUNNEL_PORTS = {443, 8443}


# Threat-intel integrations are optional at runtime.
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".."))
try:
    from data_collection.api_clients.virustotal_client import VirusTotalClient

    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    vt_client = VirusTotalClient(api_key=vt_api_key) if vt_api_key else None
    VT_ENABLED = vt_client is not None
except Exception:
    vt_client = None
    VT_ENABLED = False

try:
    from data_collection.api_clients.malwarebazaar_client import MalwareBazaarClient

    mb_client = MalwareBazaarClient()
    MB_ENABLED = mb_client is not None
except Exception:
    mb_client = None
    MB_ENABLED = False

THREAT_INTEL_CACHE_TTL_SECONDS = int(os.getenv("THREAT_INTEL_CACHE_TTL_SECONDS", "21600"))
_threat_intel_cache: Dict[str, Dict[str, Any]] = {}
_threat_intel_lock = threading.Lock()

PROCESS_POLICY_PATH = os.getenv("PROCESS_POLICY_PATH", str(_PROJECT_ROOT / "backend" / "process_policy.json"))
LEGACY_ALLOWLIST_PATH = os.getenv("ALLOWLIST_PATH", str(_PROJECT_ROOT / "backend" / "allowlist.json"))
LEGACY_BLACKLIST_PATH = os.getenv("BLACKLIST_PATH", str(_PROJECT_ROOT / "backend" / "blacklist.json"))
_policy_cache: Dict[str, Any] = {}
_policy_mtime: Tuple[float, float, float] = (0.0, 0.0, 0.0)


MODEL_LOADED = False
MODEL_NAME = "heuristic"
ml_model = None
scaler = None
feature_names: List[str] = list(SELECTED_FEATURES)

_saved_models_dir = _PROJECT_ROOT / "ml_models" / "saved_models"
_metadata_path = _saved_models_dir / "model_metadata.json"


def _load_metadata_feature_names() -> List[str]:
    if not _metadata_path.exists():
        return []
    try:
        with open(_metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
        feats = metadata.get("features")
        if isinstance(feats, list) and feats:
            return [str(x) for x in feats]
    except Exception as err:
        print(f"Model metadata load warning: {err}")
    return []


def _resolve_model_path(path_like: str) -> Path:
    path = Path(path_like)
    if path.is_absolute():
        return path
    return (_PROJECT_ROOT / path).resolve()


def _normalize_loaded_object(obj: Any):
    if isinstance(obj, dict):
        model_candidate = obj.get("model") or obj.get("estimator")
        if model_candidate is not None and hasattr(model_candidate, "predict"):
            return model_candidate, obj.get("scaler"), obj.get("feature_names")
    if hasattr(obj, "predict"):
        return obj, None, None
    return None, None, None


def _init_model():
    global MODEL_LOADED, MODEL_NAME, ml_model, scaler, feature_names

    metadata_features = _load_metadata_feature_names()

    candidate_paths: List[Path] = []
    if os.getenv("XGBOOST_MODEL_PATH"):
        candidate_paths.append(_resolve_model_path(os.getenv("XGBOOST_MODEL_PATH")))
    if os.getenv("RANDOM_FOREST_MODEL_PATH"):
        candidate_paths.append(_resolve_model_path(os.getenv("RANDOM_FOREST_MODEL_PATH")))

    candidate_paths.extend(
        [
            _saved_models_dir / "xgboost.pkl",
            _saved_models_dir / "random_forest.pkl",
        ]
    )

    for model_path in candidate_paths:
        if not model_path.exists():
            continue
        try:
            loaded_obj = joblib.load(model_path)
            loaded_model, loaded_scaler, loaded_features = _normalize_loaded_object(loaded_obj)
            if loaded_model is None:
                print(f"Unsupported model artifact format: {model_path}")
                continue

            ml_model = loaded_model
            scaler = loaded_scaler
            feature_names = (
                list(loaded_features)
                if isinstance(loaded_features, list) and loaded_features
                else metadata_features or list(SELECTED_FEATURES)
            )

            if not feature_names and hasattr(ml_model, "n_features_in_"):
                feature_names = [f"feature_{idx}" for idx in range(int(ml_model.n_features_in_))]

            MODEL_NAME = model_path.stem
            MODEL_LOADED = True
            print(f"ML model loaded: {model_path}")
            print(f"Feature count: {len(feature_names)}")
            _init_shap_explainer()
            return
        except Exception as err:
            print(f"Model load error ({model_path}): {err}")

    MODEL_LOADED = False
    MODEL_NAME = "heuristic"
    print("ML model not found; using heuristic fallback")


# SHAP explainer for anomaly explanation panel
shap_explainer = None


def _init_shap_explainer():
    global shap_explainer
    if not MODEL_LOADED or ml_model is None:
        return
    try:
        import shap

        shap_explainer = shap.TreeExplainer(ml_model)
        print("SHAP TreeExplainer initialized")
    except Exception as shap_err:
        print(f"SHAP init skipped: {shap_err}")


_init_model()


class MetricsBatch(BaseModel):
    system_id: str
    metrics: List[dict]


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _extract_cpu_percent(metrics: dict) -> float:
    cpu_block = metrics.get("cpu", {})
    return _to_float(cpu_block.get("percent", cpu_block.get("cpu_percent", 0.0)))


def _extract_memory_percent(metrics: dict) -> float:
    mem_block = metrics.get("memory", {})
    return _to_float(mem_block.get("percent", mem_block.get("memory_percent", 0.0)))


def _sanitize_feature_vector(raw_vector: np.ndarray) -> np.ndarray:
    cleaned = np.array(raw_vector, dtype=np.float64)
    cleaned = np.nan_to_num(cleaned, nan=0.0, posinf=0.0, neginf=0.0)

    for idx, feat in enumerate(SELECTED_FEATURES):
        bounds = FEATURE_BOUNDS.get(feat)
        if not bounds:
            continue
        lo, hi = bounds
        if lo is not None and cleaned[idx] < lo:
            cleaned[idx] = float(lo)
        if hi is not None and cleaned[idx] > hi:
            cleaned[idx] = float(hi)

    return cleaned


def _build_model_row(metrics: dict) -> np.ndarray:
    extracted = extract_features_from_metrics(metrics)
    if extracted.size == 0:
        raise ValueError("Feature extraction returned an empty vector")
    if SELECTED_FEATURES and len(extracted) != len(SELECTED_FEATURES):
        raise ValueError("Feature vector length does not match selected feature set")

    cleaned = _sanitize_feature_vector(extracted)
    if not validate_feature_vector(cleaned):
        raise ValueError("Feature vector failed bounds validation")

    feature_map = {
        SELECTED_FEATURES[idx]: float(cleaned[idx])
        for idx in range(min(len(SELECTED_FEATURES), len(cleaned)))
    }

    ordered = np.array([feature_map.get(name, 0.0) for name in feature_names], dtype=np.float64)
    return ordered.reshape(1, -1)


def _prediction_is_attack(prediction: Any) -> bool:
    if isinstance(prediction, (np.ndarray, list, tuple)):
        prediction = prediction[0] if prediction else 0
    if isinstance(prediction, (int, float, np.integer, np.floating)):
        return int(prediction) == 1

    text = str(prediction).strip().lower()
    return text in {"1", "true", "attack", "anormal", "cryptojacking"}


def _positive_probability(probabilities: np.ndarray) -> float:
    if probabilities is None or len(probabilities) == 0:
        return 0.0

    if hasattr(ml_model, "classes_"):
        classes = list(getattr(ml_model, "classes_", []))
        if 1 in classes:
            idx = classes.index(1)
            return float(probabilities[idx])
        if "1" in classes:
            idx = classes.index("1")
            return float(probabilities[idx])

    idx = 1 if len(probabilities) > 1 else 0
    return float(probabilities[idx])


def _normalize_hash(value: Any) -> str:
    text = str(value or "").strip().lower()
    if len(text) == 64 and re.fullmatch(r"[a-f0-9]{64}", text):
        return text
    return ""


def _norm_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _safe_list(values: Any) -> List[str]:
    if not isinstance(values, list):
        return []
    return [str(x).strip().lower() for x in values if str(x).strip()]


def _legacy_allowlist_to_policy() -> Dict[str, Any]:
    if not os.path.exists(LEGACY_ALLOWLIST_PATH):
        return {}
    try:
        with open(LEGACY_ALLOWLIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return {
            "version": 1,
            "allow_rules": [
                {
                    "id": "legacy-allowlist",
                    "name_exact": _safe_list(data.get("name_exact")),
                    "name_contains": _safe_list(data.get("name_contains")),
                    "path_contains": _safe_list(data.get("path_contains")),
                    "hash_exact": _safe_list(data.get("hash_exact")),
                    "min_match_count": 1,
                }
            ],
            "deny_rules": [],
            "svchost_policy": {},
            "thresholds": {},
        }
    except Exception:
        return {}


def _legacy_blacklist_to_policy() -> Dict[str, Any]:
    if not os.path.exists(LEGACY_BLACKLIST_PATH):
        return {}
    try:
        with open(LEGACY_BLACKLIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return {
            "version": 1,
            "allow_rules": [],
            "deny_rules": [
                {
                    "id": "legacy-blacklist",
                    "name_exact": _safe_list(data.get("name_exact")),
                    "name_contains": _safe_list(data.get("name_contains")),
                    "path_contains": _safe_list(data.get("path_contains")),
                    "hash_exact": _safe_list(data.get("hash_exact")),
                    "publisher_contains": _safe_list(data.get("publisher_contains")),
                    "min_match_count": 1,
                }
            ],
            "svchost_policy": {},
            "thresholds": {},
        }
    except Exception:
        return {}


def _file_mtime(path: str) -> float:
    try:
        if os.path.exists(path):
            return float(os.path.getmtime(path))
    except Exception:
        pass
    return 0.0


def _merge_policy_layers(*layers: Dict[str, Any]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {
        "version": 1,
        "allow_rules": [],
        "deny_rules": [],
        "svchost_policy": {},
        "thresholds": {},
    }
    seen_ids = {"allow_rules": set(), "deny_rules": set()}

    for layer in layers:
        if not isinstance(layer, dict):
            continue

        for key in ("allow_rules", "deny_rules"):
            rules = layer.get(key) or []
            if not isinstance(rules, list):
                continue
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                rule_id = str(rule.get("id") or "").strip()
                if rule_id and rule_id in seen_ids[key]:
                    continue
                if rule_id:
                    seen_ids[key].add(rule_id)
                merged[key].append(dict(rule))

        svchost_policy = layer.get("svchost_policy")
        if isinstance(svchost_policy, dict):
            merged["svchost_policy"].update(svchost_policy)

        thresholds = layer.get("thresholds")
        if isinstance(thresholds, dict):
            merged["thresholds"].update(thresholds)

    return merged


def _load_process_policy() -> Dict[str, Any]:
    global _policy_cache, _policy_mtime
    try:
        mtimes = (
            _file_mtime(PROCESS_POLICY_PATH),
            _file_mtime(LEGACY_ALLOWLIST_PATH),
            _file_mtime(LEGACY_BLACKLIST_PATH),
        )
        if _policy_cache and mtimes == _policy_mtime:
            return _policy_cache

        base_policy: Dict[str, Any] = {}
        if os.path.exists(PROCESS_POLICY_PATH):
            with open(PROCESS_POLICY_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            base_policy = data if isinstance(data, dict) else {}

        legacy = _legacy_allowlist_to_policy()
        legacy_blacklist = _legacy_blacklist_to_policy()
        _policy_cache = _merge_policy_layers(base_policy, legacy, legacy_blacklist)
        _policy_mtime = mtimes
        return _policy_cache
    except Exception as err:
        print(f"Process policy load warning: {err}")
        return _policy_cache or {}


def _process_signals(proc: Dict[str, Any]) -> Dict[str, str]:
    static_data = proc.get("static_analysis") or {}
    return {
        "name": _norm_text(proc.get("name")),
        "path": _norm_text(proc.get("exe_path")),
        "hash": _normalize_hash(proc.get("exe_hash") or static_data.get("file_sha256")),
        "publisher": _norm_text(proc.get("publisher")),
        "parent_name": _norm_text(proc.get("parent_name")),
        "signature_status": _norm_text(proc.get("signature_status")),
    }


def _rule_match(rule: Dict[str, Any], signals: Dict[str, str]) -> Tuple[bool, List[str]]:
    checks = [
        ("name_exact", lambda vals: signals["name"] in vals),
        ("name_contains", lambda vals: any(v in signals["name"] for v in vals)),
        ("path_exact", lambda vals: signals["path"] in vals),
        ("path_contains", lambda vals: any(v in signals["path"] for v in vals)),
        ("hash_exact", lambda vals: signals["hash"] in vals),
        ("publisher_contains", lambda vals: any(v in signals["publisher"] for v in vals)),
        ("parent_name_exact", lambda vals: signals["parent_name"] in vals),
        ("parent_name_contains", lambda vals: any(v in signals["parent_name"] for v in vals)),
        ("signature_status_exact", lambda vals: signals["signature_status"] in vals),
    ]
    matched_signals: List[str] = []
    configured_categories = 0
    for key, matcher in checks:
        values = _safe_list(rule.get(key))
        if not values:
            continue
        configured_categories += 1
        if matcher(values):
            matched_signals.append(key)

    if configured_categories == 0:
        return False, []
    min_match_count = max(1, _int_from_any(rule.get("min_match_count"), configured_categories))
    return len(matched_signals) >= min_match_count, matched_signals


def _evaluate_policy(proc: Dict[str, Any]) -> Dict[str, Any]:
    policy = _load_process_policy()
    if not policy:
        return {"decision": "none", "rule_id": "", "matched_signals": []}

    signals = _process_signals(proc)

    for rule in policy.get("deny_rules", []) or []:
        if not isinstance(rule, dict):
            continue
        matched, matched_signals = _rule_match(rule, signals)
        if matched:
            return {
                "decision": "deny",
                "rule_id": str(rule.get("id") or "deny_rule"),
                "matched_signals": matched_signals,
            }

    for rule in policy.get("allow_rules", []) or []:
        if not isinstance(rule, dict):
            continue
        matched, matched_signals = _rule_match(rule, signals)
        if matched:
            return {
                "decision": "allow",
                "rule_id": str(rule.get("id") or "allow_rule"),
                "matched_signals": matched_signals,
            }

    return {"decision": "none", "rule_id": "", "matched_signals": []}


def _int_from_any(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_vt_detection_counts(vt_info: Dict[str, Any]) -> Tuple[int, int]:
    stats = vt_info.get("detection_ratio") or {}
    if not isinstance(stats, dict):
        return 0, 0
    malicious = _int_from_any(stats.get("malicious"), 0)
    total = sum(_int_from_any(v, 0) for v in stats.values())
    return malicious, total


def _lookup_threat_intel(file_hash: str) -> Dict[str, Any]:
    normalized_hash = _normalize_hash(file_hash)
    if not normalized_hash:
        return {"known_malicious": False, "score": 0, "sources": [], "details": {}}

    now = time.time()
    with _threat_intel_lock:
        cached = _threat_intel_cache.get(normalized_hash)
        if cached and (now - cached.get("cached_at", 0) < THREAT_INTEL_CACHE_TTL_SECONDS):
            return cached["result"]

    result: Dict[str, Any] = {
        "known_malicious": False,
        "score": 0,
        "sources": [],
        "details": {},
    }

    # VirusTotal hash reputation
    if VT_ENABLED and vt_client is not None:
        try:
            vt_info = vt_client.get_file_info(normalized_hash)
            if vt_info:
                malicious, total = _extract_vt_detection_counts(vt_info)
                vt_hit = malicious >= int(os.getenv("VT_MALICIOUS_THRESHOLD", "3"))
                if vt_hit:
                    result["known_malicious"] = True
                    result["score"] += 2
                    result["sources"].append("virustotal")
                result["details"]["virustotal"] = {
                    "malicious": malicious,
                    "total_engines": total,
                    "file_type": vt_info.get("file_type"),
                }
        except Exception as vt_err:
            result["details"]["virustotal_error"] = str(vt_err)

    # MalwareBazaar hash reputation
    if MB_ENABLED and mb_client is not None:
        try:
            mb_info = mb_client.get_sample_info(normalized_hash)
            if mb_info:
                signature = str(mb_info.get("signature") or "").lower()
                tags = [str(t).lower() for t in (mb_info.get("tags") or [])]
                miner_hit = (
                    _contains_miner_indicator(signature)
                    or any(_contains_miner_indicator(tag) for tag in tags)
                )
                if miner_hit:
                    result["known_malicious"] = True
                    result["score"] += 2
                    result["sources"].append("malwarebazaar")
                result["details"]["malwarebazaar"] = {
                    "signature": mb_info.get("signature"),
                    "tags": mb_info.get("tags", []),
                }
        except Exception as mb_err:
            result["details"]["malwarebazaar_error"] = str(mb_err)

    with _threat_intel_lock:
        _threat_intel_cache[normalized_hash] = {
            "cached_at": now,
            "result": result,
        }
    return result


BENIGN_SYSTEM_PROCESS_NAMES = {
    "system idle process",
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "dwm.exe",
    "winlogon.exe",
    "fontdrvhost.exe",
    "sihost.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "searchindexer.exe",
}

MINER_KEYWORDS = {
    "xmrig",
    "xmrig-notls",
    "xmr-stak",
    "cpuminer",
    "minerd",
    "ethminer",
    "phoenixminer",
    "nbminer",
    "lolminer",
    "gminer",
    "teamredminer",
    "nanominer",
    "trex",
    "t-rex",
    "cryptonight",
    "randomx",
    "stratum",
    "monero",
    "xmr",
}

MINER_POOL_PATTERNS = [
    r"stratum(?:2)?\+(?:tcp|ssl|udp)://",
    r"pool\.",
    r"minexmr",
    r"supportxmr",
    r"moneroocean",
    r"hashvault",
    r"herominers",
    r"c3pool",
    r"unmineable",
    r"nanopool",
    r"2miners",
    r"monero",
]

WSL_HOST_PROCESS_NAMES = {"vmmem", "vmmemwsl", "wsl.exe", "wslhost.exe"}

_CMDLINE_SIGMA_RULES: List[Tuple[str, re.Pattern]] = [
    ("stratum_uri", re.compile(r"stratum(?:2)?\+(?:tcp|ssl|udp)://", re.IGNORECASE)),
    (
        "miner_cli_flags",
        re.compile(
            r"(?:^|\s)(?:--donate-level(?:=|\s)|--cpu-max-threads-pct(?:=|\s)|--pause-on-active|"
            r"--randomx-[a-z-]+|--rig-id(?:=|\s)|-a\s+(?:rx/0|rx/wow|cn/\S+|randomx|cryptonight|kawpow|etchash|ghostrider))",
            re.IGNORECASE,
        ),
    ),
    ("monero_wallet_cli", re.compile(r"(?:^|[\s=:\"'])(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})(?:$|[\s\"'])")),
    (
        "pool_host_cli",
        re.compile(
            r"(?:supportxmr|minexmr|moneroocean|hashvault\.pro|herominers|nanopool\.org|2miners\.com|c3pool)",
            re.IGNORECASE,
        ),
    ),
    (
        "encoded_lolbin_miner",
        re.compile(
            r"(?:powershell|pwsh|cmd)(?:\.exe)?\b.*(?:-enc\b|-encodedcommand\b|frombase64string).*(?:xmrig|stratum|monero|randomx)",
            re.IGNORECASE,
        ),
    ),
]


def _analyze_cmdline(proc: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Run high-precision Sigma-style command-line inspection even on throttled processes."""
    cmdline = str(proc.get("cmdline") or "").strip()
    if not cmdline:
        return False, []
    matched = [rule_name for rule_name, pattern in _CMDLINE_SIGMA_RULES if pattern.search(cmdline)]
    return bool(matched), matched

MINER_NETWORK_PORTS = {3333, 3334, 4444, 5555, 6666, 7777, 9999, 14433, 14444}

ALERT_THRESHOLD_SCORE = int(os.getenv("ALERT_THRESHOLD_SCORE", "5"))
MIN_SIGNAL_COUNT = int(os.getenv("ALERT_MIN_SIGNAL_COUNT", "2"))
SUSTAINED_REQUIRED = int(os.getenv("ALERT_SUSTAINED_REQUIRED", "3"))
ALERT_COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", "300"))

_sustained_state: Dict[str, Dict[str, Any]] = {}
_sustained_lock = threading.Lock()

EXPECTED_PUBLISHERS = {
    "svchost.exe": "microsoft",
    "lsass.exe": "microsoft",
    "csrss.exe": "microsoft",
    "winlogon.exe": "microsoft",
    "services.exe": "microsoft",
    "explorer.exe": "microsoft",
    "dllhost.exe": "microsoft",
    "conhost.exe": "microsoft",
    "taskhostw.exe": "microsoft",
    "spoolsv.exe": "microsoft",
    "runtimebroker.exe": "microsoft",
    "searchindexer.exe": "microsoft",
    "sihost.exe": "microsoft",
    "dwm.exe": "microsoft",
    "chrome.exe": "google",
    "msedge.exe": "microsoft",
    "firefox.exe": "mozilla",
    "cs2.exe": "valve",
    "valorant.exe": "riot games",
    "gta5.exe": "rockstar",
}

EXPECTED_PATHS = {
    "svchost.exe": ["\\windows\\system32\\svchost.exe", "\\windows\\syswow64\\svchost.exe"],
    "lsass.exe": ["\\windows\\system32\\lsass.exe"],
    "csrss.exe": ["\\windows\\system32\\csrss.exe"],
    "winlogon.exe": ["\\windows\\system32\\winlogon.exe"],
    "services.exe": ["\\windows\\system32\\services.exe"],
    "explorer.exe": ["\\windows\\explorer.exe"],
    "dllhost.exe": ["\\windows\\system32\\dllhost.exe", "\\windows\\syswow64\\dllhost.exe"],
    "conhost.exe": ["\\windows\\system32\\conhost.exe"],
    "taskhostw.exe": ["\\windows\\system32\\taskhostw.exe"],
    "spoolsv.exe": ["\\windows\\system32\\spoolsv.exe"],
    "runtimebroker.exe": ["\\windows\\system32\\runtimebroker.exe"],
    "searchindexer.exe": ["\\windows\\system32\\searchindexer.exe"],
    "sihost.exe": ["\\windows\\system32\\sihost.exe"],
    "dwm.exe": ["\\windows\\system32\\dwm.exe"],
    "chrome.exe": ["\\google\\chrome\\"],
    "msedge.exe": ["\\microsoft\\edge\\"],
    "firefox.exe": ["\\mozilla firefox\\"],
    "cs2.exe": ["\\steam\\steamapps\\common\\counter-strike"],
    "valorant.exe": ["\\riot games\\valorant\\"],
    "gta5.exe": ["\\rockstar games\\", "\\steam\\steamapps\\"],
}

SUSPICIOUS_PATH_PATTERNS = [
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\windows\\temp\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\recycle",
    "\\$recycle",
]

TRUSTED_INSTALL_DIRS = [
    "\\program files\\",
    "\\program files (x86)\\",
    "\\windows\\",
    "\\users\\",
]


def _normalize_proc_name(raw_name: Any) -> str:
    return str(raw_name or "unknown").strip().lower()


def _contains_miner_indicator(text: str) -> bool:
    lowered = text.lower()
    if any(keyword in lowered for keyword in MINER_KEYWORDS):
        return True
    for pattern in MINER_POOL_PATTERNS:
        if re.search(pattern, lowered):
            return True
    return False


def _is_suspicious_path(path_text: str) -> bool:
    if not path_text:
        return False
    lowered = path_text.lower()
    return any(token in lowered for token in SUSPICIOUS_PATH_PATTERNS)


def _duplicate_name_paths(processes: List[dict]) -> Dict[str, List[str]]:
    name_to_dirs: Dict[str, set] = {}
    for proc in processes:
        name = _normalize_proc_name(proc.get("name"))
        path = _norm_text(proc.get("exe_path"))
        if not name or not path:
            continue
        directory = str(Path(path).parent).lower()
        name_to_dirs.setdefault(name, set()).add(directory)

    return {
        name: sorted(list(paths))
        for name, paths in name_to_dirs.items()
        if len(paths) > 1
    }


def _detect_spoof_attempt(proc: Dict[str, Any], duplicate_dirs: Dict[str, List[str]]) -> Dict[str, Any]:
    name = _normalize_proc_name(proc.get("name"))
    path = _norm_text(proc.get("exe_path"))
    publisher = _norm_text(proc.get("publisher"))
    evidence: List[str] = []

    if name in EXPECTED_PATHS and path:
        expected_paths = EXPECTED_PATHS.get(name, [])
        if expected_paths and not any(token in path for token in expected_paths):
            evidence.append("unexpected_path")

    if name in EXPECTED_PUBLISHERS and publisher:
        expected_pub = EXPECTED_PUBLISHERS.get(name, "")
        if expected_pub and expected_pub not in publisher:
            evidence.append("publisher_mismatch")

    if _is_suspicious_path(path):
        evidence.append("suspicious_path")

    if name in duplicate_dirs:
        evidence.append("duplicate_name_multiple_paths")

    return {
        "is_spoof": bool(evidence),
        "evidence": evidence,
        "duplicate_paths": duplicate_dirs.get(name, []),
    }


def _process_age_seconds(proc: Dict[str, Any]) -> float:
    try:
        create_time = float(proc.get("create_time") or 0.0)
    except (TypeError, ValueError):
        create_time = 0.0
    if create_time <= 0.0:
        return 0.0
    return max(0.0, time.time() - create_time)


def _is_registered_in_programs(exe_path: str) -> bool:
    if os.name != "nt" or not exe_path:
        return False
    try:
        import winreg
    except Exception:
        return False

    install_keys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    exe_dir = str(Path(exe_path).parent).lower()

    for reg_key in install_keys:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_key)
            count = winreg.QueryInfoKey(key)[0]
            for i in range(count):
                try:
                    sub_key_name = winreg.EnumKey(key, i)
                    sub_key = winreg.OpenKey(key, sub_key_name)
                    install_loc, _ = winreg.QueryValueEx(sub_key, "InstallLocation")
                    if install_loc and install_loc.lower() in exe_dir:
                        return True
                except (FileNotFoundError, OSError):
                    continue
        except Exception:
            continue

    return False


def _compute_trust_score(proc: Dict[str, Any]) -> Tuple[int, Dict[str, str]]:
    score = 0
    breakdown: Dict[str, str] = {}
    path = str(proc.get("exe_path") or "")
    publisher = _norm_text(proc.get("publisher"))
    signature_status = _norm_text(proc.get("signature_status"))

    if signature_status == "valid":
        score += 40
        breakdown["signed"] = f"valid:{publisher or 'unknown'}"
    else:
        breakdown["signed"] = "unsigned_or_invalid"

    if _is_registered_in_programs(path):
        score += 20
        breakdown["installed"] = "registered"
    else:
        breakdown["installed"] = "unregistered"

    path_lower = path.lower()
    if _is_suspicious_path(path_lower):
        score -= 20
        breakdown["path"] = "suspicious"
    elif any(token in path_lower for token in TRUSTED_INSTALL_DIRS):
        score += 20
        breakdown["path"] = "trusted"

    age_seconds = _process_age_seconds(proc)
    if age_seconds >= 300:
        score += 10
        breakdown["age"] = "established"
    elif age_seconds > 0:
        breakdown["age"] = "new"

    network_summary = proc.get("network_summary") or {}
    if bool(network_summary.get("has_miner_port")):
        score -= 30
        breakdown["network"] = "miner_port"
    else:
        score += 10
        breakdown["network"] = "clean"

    return max(0, min(100, score)), breakdown


def _check_whitelist(processes: List[dict]) -> Tuple[bool, str]:
    if not processes:
        return False, ""
    top = sorted(processes, key=lambda p: _to_float(p.get("cpu_percent", 0)), reverse=True)[:5]
    duplicate_dirs = _duplicate_name_paths(processes)

    for proc in top:
        proc_cpu = _to_float(proc.get("cpu_percent", 0))
        if proc_cpu < 20:
            continue

        spoof_eval = _detect_spoof_attempt(proc, duplicate_dirs)
        if spoof_eval.get("is_spoof"):
            continue

        if _analyze_cmdline(proc)[0]:
            continue
        if _extract_static_evidence(proc)[0]:
            continue
        if _extract_network_evidence(proc)[0]:
            continue

        policy_eval = _evaluate_policy(proc)
        if policy_eval["decision"] == "deny":
            continue

        if policy_eval["decision"] == "allow":
            return True, f"policy_allow:{policy_eval.get('rule_id')}"

        trust_score, breakdown = _compute_trust_score(proc)
        if trust_score >= 70:
            return True, f"trust_score:{trust_score}" if breakdown else "trust_score"

    return False, ""


def _update_sustained_state(system_id: str, is_attack: bool, force_alert: bool) -> bool:
    now = time.time()
    with _sustained_lock:
        state = _sustained_state.setdefault(
            system_id,
            {
                "consecutive": 0,
                "last_alert": 0.0,
            },
        )

        if force_alert:
            if now - state["last_alert"] < ALERT_COOLDOWN_SECONDS:
                return False
            state["last_alert"] = now
            state["consecutive"] = 0
            return True

        if not is_attack:
            state["consecutive"] = 0
            return False

        state["consecutive"] += 1
        if state["consecutive"] < SUSTAINED_REQUIRED:
            return False
        if now - state["last_alert"] < ALERT_COOLDOWN_SECONDS:
            return False

        state["last_alert"] = now
        state["consecutive"] = 0
        return True


def _build_process_context(processes: List[dict], suspicious_names: List[str]) -> List[Dict[str, Any]]:
    if not processes:
        return []
    names_lower = {str(name or "").lower() for name in suspicious_names}

    def _serialize_proc(proc: Dict[str, Any]) -> Dict[str, Any]:
        static_data = proc.get("static_analysis") if isinstance(proc.get("static_analysis"), dict) else {}
        net_summary = proc.get("network_summary") if isinstance(proc.get("network_summary"), dict) else {}
        return {
            "name": str(proc.get("name") or "unknown"),
            "pid": proc.get("pid"),
            "create_time": proc.get("create_time"),
            "exe_path": proc.get("exe_path"),
            "exe_hash": proc.get("exe_hash") or static_data.get("file_sha256"),
            "publisher": proc.get("publisher"),
            "signature_status": proc.get("signature_status"),
            "cmdline": proc.get("cmdline"),
            "cpu_percent": round(_to_float(proc.get("cpu_percent"), 0.0), 2),
            "gpu_compute_active": bool(proc.get("gpu_compute_active")),
            "gpu_memory_mb": round(_to_float(proc.get("gpu_memory_mb"), 0.0), 2),
            "yara_rules": list(static_data.get("yara_rules") or [])[:4],
            "resolved_domains": list(net_summary.get("resolved_domains") or [])[:4],
            "remote_ips_sample": list(net_summary.get("remote_ips_sample") or [])[:4],
            "remote_ports": list(net_summary.get("remote_ports") or [])[:6],
        }

    context = []
    for proc in processes:
        name = str(proc.get("name") or "")
        if names_lower and name.lower() not in names_lower:
            continue
        context.append(_serialize_proc(proc))
    if not context:
        context = [_serialize_proc(proc) for proc in processes[:5]]
    return context


def _compute_risk_score(
    is_cryptojacking: bool,
    confidence: float,
    processes: List[dict],
    miner_indicators: List[str],
    threat_intel_hits: List[Dict[str, Any]],
    miner_network_hits: List[Dict[str, Any]],
    policy_hits: List[Dict[str, Any]],
    dynamic_evidence: Dict[str, Any] = None,
) -> Tuple[int, List[str]]:
    score = 0
    signals: List[str] = []
    dyn = dynamic_evidence if isinstance(dynamic_evidence, dict) else {}

    if is_cryptojacking and confidence >= 0.75:
        score += 3
        signals.append("ml_attack")

    deny_hits = [h for h in policy_hits if h.get("decision") == "deny"]
    if deny_hits or miner_indicators:
        score += 5
        signals.append("blacklist_match")

    if miner_network_hits:
        score += 4
        signals.append("mining_pool_traffic")
        if any("tls_stratum_tunnel" in (h.get("indicators") or []) for h in miner_network_hits):
            signals.append("tls_stealth_tunnel")
        if any("dns_pool_domain_match" in (h.get("indicators") or []) for h in miner_network_hits):
            signals.append("dns_pool_domain")

    if threat_intel_hits:
        score += 3
        signals.append("threat_intel")

    unsigned_high_cpu = False
    hidden_high_cpu = False
    cmdline_hit_any = False
    yara_hit_any = False
    gpu_pid_active = False

    for proc in processes:
        cpu = _to_float(proc.get("cpu_percent", 0))
        static_data = proc.get("static_analysis") if isinstance(proc.get("static_analysis"), dict) else {}
        if _analyze_cmdline(proc)[0]:
            cmdline_hit_any = True
        if bool(static_data.get("yara_matched")):
            yara_hit_any = True
        if bool(proc.get("gpu_compute_active")):
            gpu_pid_active = True

        net_summary = proc.get("network_summary") if isinstance(proc.get("network_summary"), dict) else {}
        throttled_active = cpu >= 15 and (
            bool(miner_network_hits)
            or bool(net_summary.get("has_pool_domain"))
            or int(dyn.get("idle_surge_count", 0) or 0) > 0
            or int(dyn.get("throttled_count", 0) or 0) > 0
        )
        if cpu >= 50 or throttled_active:
            signature_status = _norm_text(proc.get("signature_status"))
            if signature_status not in {"valid"}:
                unsigned_high_cpu = True
            if _is_suspicious_path(_norm_text(proc.get("exe_path"))):
                hidden_high_cpu = True

    if cmdline_hit_any:
        score += 4
        signals.append("cmdline_sigma_match")
    if yara_hit_any:
        score += 4
        signals.append("yara_signature_match")
    if unsigned_high_cpu:
        score += 2
        signals.append("unsigned_high_cpu")
    if hidden_high_cpu:
        score += 3
        signals.append("hidden_path")

    if int(dyn.get("idle_surge_count", 0) or 0) > 0:
        score += 3
        signals.append("idle_surge_miner")
    if int(dyn.get("throttled_count", 0) or 0) > 0:
        score += 2
        signals.append("throttled_duty_cycle")
    if int(dyn.get("gpu_compute_sustained_count", 0) or 0) > 0 or (gpu_pid_active and (miner_network_hits or yara_hit_any or cmdline_hit_any)):
        score += 2
        signals.append("gpu_compute_miner")

    spoof_hits = [h for h in policy_hits if h.get("decision") in {"svchost_anomaly", "spoof"}]
    if spoof_hits:
        score += 3
        signals.append("identity_spoof")

    return score, signals


def _compact_list(items: List[Any], limit: int = 4) -> List[str]:
    cleaned = [str(x) for x in items if x]
    return cleaned[:limit]


def _build_reason_summary(
    is_cryptojacking: bool,
    confidence: float,
    suspicious_procs: List[Dict[str, Any]],
    miner_indicators: List[str],
    high_cpu_non_system: List[Dict[str, Any]],
    static_evidence_hits: List[Dict[str, Any]],
    threat_intel_hits: List[Dict[str, Any]],
    miner_network_hits: List[Dict[str, Any]],
    policy_hits: List[Dict[str, Any]],
    dynamic_evidence: Dict[str, Any],
    signal_labels: List[str],
    process_context: List[Dict[str, Any]],
    has_blacklist_hit: bool,
) -> Tuple[List[str], List[Dict[str, str]]]:
    reasons: List[str] = []
    details: List[Dict[str, str]] = []

    def add_reason(label: str, detail: str = ""):
        if label not in reasons:
            reasons.append(label)
        if detail:
            details.append({"label": label, "detail": detail})

    deny_hits = [h for h in policy_hits if h.get("decision") == "deny"]
    if has_blacklist_hit or deny_hits:
        rule_ids = _compact_list([h.get("rule_id") for h in deny_hits])
        detail = "Rules: " + ", ".join(rule_ids) if rule_ids else "Policy deny rule matched"
        add_reason("Blacklisted process", detail)

    if signal_labels and "cmdline_sigma_match" in signal_labels:
        cmd_snippets = _compact_list([p.get("cmdline") for p in process_context if p.get("cmdline")], 2)
        add_reason("CLI miner signature", "; ".join(s[:90] for s in cmd_snippets) or "Mining flags/pool URI in CLI")

    if signal_labels and "yara_signature_match" in signal_labels:
        rules = _compact_list([r for p in process_context for r in (p.get("yara_rules") or [])], 4)
        add_reason("YARA miner match", ", ".join(rules) or "RandomX/XMRig bytecode rule")

    svchost_hits = [h for h in policy_hits if h.get("decision") == "svchost_anomaly"]
    if svchost_hits:
        add_reason("Svchost anomaly", "Unexpected path, parent, or signature")

    spoof_hits = [h for h in policy_hits if h.get("decision") == "spoof"]
    if spoof_hits:
        add_reason("Identity spoofing", "Process name or path mismatch")

    if miner_network_hits:
        ports = set()
        names = []
        domains = []
        has_tls = False
        for hit in miner_network_hits:
            names.append(hit.get("name"))
            hit_detail = hit.get("detail") or {}
            for port in hit_detail.get("remote_ports", []) or []:
                try:
                    ports.add(int(port))
                except Exception:
                    continue
            domains.extend(hit_detail.get("resolved_domains") or [])
            if hit_detail.get("tls_stealth"):
                has_tls = True
        port_text = f"Ports: {', '.join(str(p) for p in sorted(ports)[:4])}" if ports else ""
        proc_text = f"Processes: {', '.join(_compact_list(names, 3))}" if names else ""
        domain_text = f"DNS: {', '.join(_compact_list(domains, 2))}" if domains else ""
        label = "Stealth TLS tunnel (:443)" if has_tls and not ports else "Mining pool traffic"
        add_reason(label, " | ".join(t for t in (port_text, domain_text, proc_text) if t) or "External pool connection")

    sustained_procs = dynamic_evidence.get("sustained_processes") if isinstance(dynamic_evidence, dict) else []
    if isinstance(sustained_procs, list):
        for s_item in sustained_procs:
            if s_item.get("idle_surge_detected"):
                add_reason(
                    "Idle-aware (AFK) surge",
                    f"{s_item.get('process')}: {s_item.get('mean_idle_cpu', 0):.1f}% idle vs {s_item.get('mean_active_cpu', 0):.1f}% active",
                )
                break
        for s_item in sustained_procs:
            if s_item.get("throttled_sustained"):
                add_reason(
                    "Throttled duty cycle",
                    f"{s_item.get('process')}: duty {int(round(float(s_item.get('duty_cycle_ratio', 0)) * 100))}% (compute/IO bound={bool(s_item.get('compute_io_bound'))})",
                )
                break

    gpu_procs = [p for p in process_context if p.get("gpu_compute_active")]
    if gpu_procs:
        gpu_desc = ", ".join(
            f"{p.get('name')} ({p.get('gpu_memory_mb', 0):.0f}MB VRAM)"
            for p in gpu_procs[:2]
        )
        add_reason("Per-PID GPU compute", gpu_desc)

    if threat_intel_hits:
        sources = []
        for hit in threat_intel_hits:
            sources.extend(hit.get("sources") or [])
        src_text = ", ".join(_compact_list(sources, 4))
        add_reason("Threat intel match", src_text or "Known malicious hash")

    if static_evidence_hits:
        indicators = []
        for hit in static_evidence_hits:
            indicators.extend(hit.get("indicators") or [])
        detail = ", ".join(_compact_list(indicators, 4))
        add_reason("Static indicators", detail or "Suspicious strings or imports")

    dynamic_score = int(dynamic_evidence.get("dynamic_score", 0) or 0)
    miner_like = int(dynamic_evidence.get("miner_like_network_count", 0) or 0)
    if dynamic_score >= 2 or miner_like >= 1:
        add_reason("Behavioral anomaly", f"Score {dynamic_score}, miner-like network {miner_like}")

    if suspicious_procs:
        names = _compact_list([p.get("name") for p in suspicious_procs], 3)
        add_reason("Suspicious process activity", ", ".join(names))

    if miner_indicators:
        add_reason("Miner keyword indicators", ", ".join(_compact_list(miner_indicators, 3)))

    if high_cpu_non_system:
        names = _compact_list([p.get("name") for p in high_cpu_non_system], 3)
        add_reason("High CPU non-system", ", ".join(names))

    if process_context:
        suspicious_paths = []
        unsigned = []
        for proc in process_context:
            path = str(proc.get("exe_path") or "")
            if path and _is_suspicious_path(path):
                suspicious_paths.append(path)
            signature_status = _norm_text(proc.get("signature_status"))
            if signature_status and signature_status not in {"valid"}:
                unsigned.append(proc.get("name") or path)
        if suspicious_paths:
            add_reason("Suspicious file path", ", ".join(_compact_list(suspicious_paths, 2)))
        if unsigned:
            add_reason("Unsigned binary", ", ".join(_compact_list(unsigned, 3)))

    if is_cryptojacking and confidence >= 0.75:
        add_reason("High-confidence detection", f"Confidence {confidence:.2f}")

    if signal_labels and "ml_attack" in signal_labels:
        add_reason("ML model verdict", "Model classified as cryptojacking")

    if not reasons:
        reasons.append("Multiple risk signals")

    return reasons[:6], details[:8]


def _extract_static_evidence(proc: dict) -> Tuple[bool, List[str], Dict[str, Any]]:
    static_data = proc.get("static_analysis") or {}
    if not isinstance(static_data, dict):
        return False, [], {}

    mining_keywords = [str(x).lower() for x in (static_data.get("mining_keywords") or [])]
    has_mining_keywords = bool(static_data.get("has_mining_keywords")) or any(
        _contains_miner_indicator(x) for x in mining_keywords
    )
    yara_matched = bool(static_data.get("yara_matched"))
    yara_rules = [str(x) for x in (static_data.get("yara_rules") or []) if x]
    yara_severity = str(static_data.get("yara_severity") or "none").lower()
    is_packed = bool(static_data.get("is_packed"))

    suspicious_imports = int(static_data.get("num_suspicious_imports") or 0)
    suspicious_strings = int(static_data.get("suspicious_string_count") or 0)
    has_urls = bool(static_data.get("has_suspicious_urls"))
    has_crypto = bool(static_data.get("has_crypto_address"))

    import_cluster = suspicious_imports >= 4
    string_cluster = suspicious_strings >= 12
    artifact_combo = import_cluster and string_cluster and has_urls and has_crypto
    static_hit = has_mining_keywords or yara_matched or artifact_combo
    indicators = []
    if yara_matched:
        indicators.extend([f"yara:{rule}" for rule in yara_rules[:4]] or ["yara_miner_match"])
    if has_mining_keywords:
        indicators.extend(mining_keywords[:6])
    if is_packed and static_hit:
        indicators.append("upx_packed_miner")
    if import_cluster:
        indicators.append("suspicious_import_cluster")
    if string_cluster:
        indicators.append("suspicious_string_cluster")
    if has_urls and (has_mining_keywords or yara_matched or artifact_combo):
        indicators.append("suspicious_pool_url")
    if has_crypto and (has_mining_keywords or yara_matched or artifact_combo):
        indicators.append("embedded_wallet_or_address")

    summary = {
        "has_mining_keywords": has_mining_keywords,
        "yara_matched": yara_matched,
        "yara_rules": yara_rules[:6],
        "yara_severity": yara_severity,
        "is_packed": is_packed,
        "suspicious_imports": suspicious_imports,
        "suspicious_string_count": suspicious_strings,
        "has_suspicious_urls": has_urls,
        "has_crypto_address": has_crypto,
        "import_cluster": import_cluster,
        "string_cluster": string_cluster,
        "artifact_combo": artifact_combo,
    }
    return static_hit, list(dict.fromkeys(indicators)), summary


def _extract_network_evidence(proc: Dict[str, Any]) -> Tuple[bool, List[str], Dict[str, Any]]:
    summary = proc.get("network_summary") or {}
    if not isinstance(summary, dict):
        summary = {}
    remote_ports = summary.get("remote_ports") or []
    ports: List[int] = []
    for port in remote_ports:
        try:
            ports.append(int(port))
        except Exception:
            continue

    established = _int_from_any(summary.get("established_count"), 0)
    external = bool(summary.get("has_external_connection"))
    unique_ips = _int_from_any(summary.get("unique_remote_ip_count"), 0)
    miner_ports = [p for p in ports if p in MINER_NETWORK_PORTS]
    common_service_ports = {53, 80, 123, 443, 8080, 8443}
    non_standard_ports = [p for p in ports if p not in common_service_ports]
    high_fanout = unique_ips >= 8
    low_fanout_persistent = (
        external
        and established >= 3
        and 1 <= unique_ips <= 3
        and bool(non_standard_ports)
    )

    resolved_domains = [str(d).lower() for d in (summary.get("resolved_domains") or []) if d]
    has_pool_domain = bool(summary.get("has_pool_domain"))
    has_tls_port = bool(summary.get("has_tls_external")) or any(p in TLS_TUNNEL_PORTS for p in ports)
    proc_name = _normalize_proc_name(proc.get("name"))
    sig_status = _norm_text(proc.get("signature_status"))
    exe_path = _norm_text(proc.get("exe_path"))
    proc_cpu = _to_float(proc.get("cpu_percent"), 0.0)
    gpu_active = bool(proc.get("gpu_compute_active"))

    tls_stealth = (
        external
        and established >= 1
        and 1 <= unique_ips <= 3
        and has_tls_port
        and proc_name not in KNOWN_BROWSER_NAMES
        and (sig_status != "valid" or _is_suspicious_path(exe_path))
        and (proc_cpu >= 10.0 or gpu_active or has_pool_domain)
    )

    network_hit = bool(miner_ports) or has_pool_domain or low_fanout_persistent or tls_stealth

    indicators: List[str] = []
    if miner_ports:
        indicators.append("miner_port_match")
    if has_pool_domain:
        indicators.append("dns_pool_domain_match")
    if tls_stealth:
        indicators.append("tls_stratum_tunnel")
    if low_fanout_persistent:
        indicators.append("low_fanout_persistent_outbound")
    if high_fanout and miner_ports:
        indicators.append("high_remote_ip_fanout")

    detail = {
        "remote_ports": sorted(list(set(miner_ports)))[:6],
        "all_ports": sorted(list(set(ports)))[:8],
        "non_standard_ports": sorted(list(set(non_standard_ports)))[:6],
        "external": external,
        "established_count": established,
        "unique_remote_ip_count": unique_ips,
        "resolved_domains": resolved_domains[:6],
        "has_pool_domain": has_pool_domain,
        "tls_stealth": tls_stealth,
        "remote_ips_sample": list(summary.get("remote_ips_sample") or [])[:4],
    }
    return network_hit, indicators, detail


def _analyze_svchost_masquerade(proc: Dict[str, Any]) -> Dict[str, Any]:
    proc_name = _normalize_proc_name(proc.get("name"))
    if proc_name != "svchost.exe":
        return {"is_svchost": False, "suspicious": False, "evidence": [], "detail": {}}

    policy = _load_process_policy()
    svchost_policy = policy.get("svchost_policy") if isinstance(policy, dict) else {}
    if not isinstance(svchost_policy, dict):
        svchost_policy = {}

    expected_paths = _safe_list(
        svchost_policy.get("expected_path_contains")
        or [
            "\\windows\\system32\\svchost.exe",
            "\\windows\\syswow64\\svchost.exe",
        ]
    )
    expected_parents = _safe_list(svchost_policy.get("expected_parent_names") or ["services.exe", "wininit.exe"])
    trusted_publishers = _safe_list(svchost_policy.get("trusted_publishers_contains") or ["microsoft"])

    signals = _process_signals(proc)
    path_ok = any(token in signals["path"] for token in expected_paths)
    parent_ok = signals["parent_name"] in expected_parents if expected_parents else True
    publisher_ok = any(token in signals["publisher"] for token in trusted_publishers) if trusted_publishers else True
    signature_ok = signals["signature_status"] == "valid" or bool(proc.get("is_trusted_signature"))

    network_hit, network_indicators, network_detail = _extract_network_evidence(proc)
    suspicious = (not path_ok) or (not parent_ok) or (not signature_ok) or (not publisher_ok) or network_hit

    evidence: List[str] = []
    if not path_ok:
        evidence.append("unexpected_svchost_path")
    if not parent_ok:
        evidence.append("unexpected_svchost_parent")
    if not signature_ok:
        evidence.append("invalid_or_missing_signature")
    if not publisher_ok:
        evidence.append("publisher_not_microsoft")
    evidence.extend(network_indicators)

    return {
        "is_svchost": True,
        "suspicious": suspicious,
        "evidence": list(dict.fromkeys(evidence)),
        "detail": {
            "path": signals["path"],
            "parent_name": signals["parent_name"],
            "signature_status": signals["signature_status"],
            "publisher": signals["publisher"],
            "network": network_detail,
        },
    }


def analyze_processes(
    processes: List[dict],
) -> Tuple[
    List[Dict[str, Any]],
    List[str],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
]:
    suspicious: List[Dict[str, Any]] = []
    miner_indicators: List[str] = []
    high_cpu_non_system: List[Dict[str, Any]] = []
    static_evidence_hits: List[Dict[str, Any]] = []
    threat_intel_hits: List[Dict[str, Any]] = []
    miner_network_hits: List[Dict[str, Any]] = []
    policy_hits: List[Dict[str, Any]] = []

    duplicate_dirs = _duplicate_name_paths(processes)

    for proc in processes:
        proc_name = _normalize_proc_name(proc.get("name"))
        proc_cpu = _to_float(proc.get("cpu_percent", 0))
        proc_memory = _to_float(proc.get("memory_percent", 0))
        exe_path = str(proc.get("exe_path") or "")
        exe_hash = _normalize_hash(proc.get("exe_hash") or (proc.get("static_analysis") or {}).get("file_sha256"))
        policy_eval = _evaluate_policy(proc)
        allow_hit = policy_eval["decision"] == "allow"
        deny_hit = policy_eval["decision"] == "deny"

        spoof_eval = _detect_spoof_attempt(proc, duplicate_dirs)
        has_spoof = bool(spoof_eval.get("is_spoof"))

        svchost_eval = _analyze_svchost_masquerade(proc)
        has_svchost_anomaly = bool(svchost_eval.get("is_svchost") and svchost_eval.get("suspicious"))

        source_text = f"{proc_name} {exe_path}".lower()
        name_or_path_indicator = _contains_miner_indicator(source_text)
        has_cmdline_hit, cmdline_rules = _analyze_cmdline(proc)
        has_static_hit, static_indicators, static_summary = _extract_static_evidence(proc)
        has_yara_match = bool(static_summary.get("yara_matched"))
        has_network_hit, network_indicators, network_detail = _extract_network_evidence(proc)
        gpu_compute_active = bool(proc.get("gpu_compute_active"))
        gpu_memory_mb = _to_float(proc.get("gpu_memory_mb"), 0.0)
        is_wsl_vm = proc_name in WSL_HOST_PROCESS_NAMES

        if proc_name in BENIGN_SYSTEM_PROCESS_NAMES and proc_name != "svchost.exe":
            if not (
                has_spoof
                or deny_hit
                or name_or_path_indicator
                or has_cmdline_hit
                or has_static_hit
                or has_network_hit
                or gpu_compute_active
            ):
                continue

        intel_result = {"known_malicious": False, "score": 0, "sources": [], "details": {}}
        if exe_hash and (
            proc_cpu >= 20
            or name_or_path_indicator
            or has_cmdline_hit
            or has_static_hit
            or has_network_hit
            or gpu_compute_active
        ):
            intel_result = _lookup_threat_intel(exe_hash)
        has_miner_indicator = (
            name_or_path_indicator
            or has_cmdline_hit
            or has_static_hit
            or has_network_hit
        )
        has_intel_hit = bool(intel_result.get("known_malicious"))
        suspicious_identity = (
            deny_hit
            or has_cmdline_hit
            or has_yara_match
            or has_svchost_anomaly
            or has_spoof
            or name_or_path_indicator
            or has_static_hit
            or has_intel_hit
        )

        # Allow-rules suppress noisy legit apps only when no suspicious evidence exists.
        if allow_hit and not (
            deny_hit
            or has_cmdline_hit
            or has_yara_match
            or has_svchost_anomaly
            or has_spoof
            or has_miner_indicator
            or has_intel_hit
            or has_network_hit
        ):
            continue

        risk_score = 0
        if deny_hit:
            risk_score += 4
        if has_cmdline_hit:
            risk_score += 4
        if has_yara_match:
            risk_score += 4
        if has_svchost_anomaly:
            risk_score += 4
        if has_intel_hit:
            risk_score += 3
        if has_static_hit and not has_yara_match:
            risk_score += 2
        if name_or_path_indicator:
            risk_score += 2
        if has_network_hit:
            risk_score += 2
            if network_detail.get("remote_ports") or network_detail.get("has_pool_domain"):
                risk_score += 2
        if gpu_compute_active and (
            has_network_hit or has_spoof or _is_suspicious_path(exe_path) or has_cmdline_hit or has_yara_match
        ):
            risk_score += 2
        if proc_cpu >= 50:
            risk_score += 1
        signature_status = _norm_text(proc.get("signature_status"))
        if signature_status in {"invalid", "nottrusted", "revoked", "unknownerror"} and proc_cpu >= 35:
            risk_score += 1
        if has_spoof:
            risk_score += 3

        if proc_cpu >= 35 and not is_wsl_vm:
            high_cpu_non_system.append(
                {
                    "name": proc.get("name", "unknown"),
                    "cpu": proc_cpu,
                    "memory": proc_memory,
                }
            )

        if has_network_hit:
            miner_network_hits.append(
                {
                    "name": proc.get("name", "unknown"),
                    "pid": proc.get("pid"),
                    "indicators": network_indicators,
                    "detail": network_detail,
                }
            )

        if deny_hit:
            policy_hits.append(
                {
                    "name": proc.get("name", "unknown"),
                    "pid": proc.get("pid"),
                    "decision": "deny",
                    "rule_id": policy_eval.get("rule_id"),
                    "matched_signals": policy_eval.get("matched_signals", []),
                }
            )

        # For WSL2 host VMs (vmmem), require corroborating miner network/CLI/GPU+network evidence.
        if is_wsl_vm and not (has_network_hit or has_cmdline_hit or has_yara_match or has_intel_hit):
            should_mark_suspicious = False
        else:
            should_mark_suspicious = (risk_score >= 4) or (
                proc_cpu >= 55 and (suspicious_identity or has_network_hit)
            )

        if should_mark_suspicious:
            miner_indicators.append(proc.get("name", "unknown"))
            evidence = []
            if name_or_path_indicator:
                evidence.append("miner_keyword_or_pool_match")
            if has_cmdline_hit:
                evidence.extend([f"cmdline:{r}" for r in cmdline_rules[:3]])
            if has_yara_match:
                evidence.extend([f"yara:{r}" for r in (static_summary.get("yara_rules") or [])[:3]])
            if has_static_hit:
                evidence.append("static_analysis_match")
            if has_intel_hit:
                evidence.append("threat_intel_match")
            if has_network_hit:
                evidence.append("miner_network_match")
            if gpu_compute_active:
                evidence.append("gpu_compute_pid")
            if deny_hit:
                evidence.append(f"policy_deny:{policy_eval.get('rule_id')}")
            if allow_hit:
                evidence.append(f"allow_rule_overridden:{policy_eval.get('rule_id')}")
            if has_svchost_anomaly:
                evidence.extend([f"svchost:{x}" for x in svchost_eval.get("evidence", [])])
            if has_spoof:
                evidence.extend([f"spoof:{x}" for x in spoof_eval.get("evidence", [])])

            suspicious_item = {
                "name": proc.get("name", "unknown"),
                "pid": proc.get("pid"),
                "create_time": proc.get("create_time"),
                "cpu": proc_cpu,
                "memory": proc_memory,
                "cmdline": proc.get("cmdline"),
                "gpu_compute_active": gpu_compute_active,
                "gpu_memory_mb": round(gpu_memory_mb, 2),
                "yara_rules": list(static_summary.get("yara_rules") or [])[:4],
                "cmdline_rules": cmdline_rules,
                "is_wsl_vm": is_wsl_vm,
                "evidence": ",".join(evidence) if evidence else "miner_signal",
                "vt_result": intel_result.get("details", {}).get("virustotal"),
                "intel_sources": intel_result.get("sources", []),
                "risk_score": risk_score,
            }
            suspicious.append(suspicious_item)
            if has_static_hit:
                static_evidence_hits.append(
                    {
                        "name": proc.get("name", "unknown"),
                        "indicators": static_indicators,
                        "summary": static_summary,
                    }
                )
            if has_svchost_anomaly:
                policy_hits.append(
                    {
                        "name": proc.get("name", "unknown"),
                        "pid": proc.get("pid"),
                        "decision": "svchost_anomaly",
                        "rule_id": "svchost_policy",
                        "matched_signals": svchost_eval.get("evidence", []),
                        "detail": svchost_eval.get("detail", {}),
                    }
                )
            if has_spoof:
                policy_hits.append(
                    {
                        "name": proc.get("name", "unknown"),
                        "pid": proc.get("pid"),
                        "decision": "spoof",
                        "rule_id": "identity_spoof",
                        "matched_signals": spoof_eval.get("evidence", []),
                        "detail": {
                            "path": _norm_text(proc.get("exe_path")),
                            "publisher": _norm_text(proc.get("publisher")),
                            "duplicate_paths": spoof_eval.get("duplicate_paths", []),
                        },
                    }
                )
            if allow_hit:
                policy_hits.append(
                    {
                        "name": proc.get("name", "unknown"),
                        "pid": proc.get("pid"),
                        "decision": "allow_overridden",
                        "rule_id": policy_eval.get("rule_id"),
                        "matched_signals": policy_eval.get("matched_signals", []),
                    }
                )
        if has_intel_hit:
            threat_intel_hits.append(
                {
                    "name": proc.get("name", "unknown"),
                    "exe_hash": exe_hash,
                    "sources": intel_result.get("sources", []),
                    "details": intel_result.get("details", {}),
                }
            )

    # Deduplicate indicators while preserving order.
    unique_indicators = list(dict.fromkeys(miner_indicators))
    return (
        suspicious,
        unique_indicators,
        high_cpu_non_system,
        static_evidence_hits,
        threat_intel_hits,
        miner_network_hits,
        policy_hits,
    )


def _should_emit_alert(
    is_cryptojacking: bool,
    confidence: float,
    cpu_percent: float,
    memory_percent: float,
    suspicious_procs: List[Dict[str, Any]],
    miner_indicators: List[str],
    high_cpu_non_system: List[Dict[str, Any]],
    static_evidence_hits: List[Dict[str, Any]],
    threat_intel_hits: List[Dict[str, Any]],
    miner_network_hits: List[Dict[str, Any]],
    policy_hits: List[Dict[str, Any]],
    dynamic_evidence: Dict[str, Any],
    risk_score: int,
    signal_count: int,
    has_blacklist_hit: bool,
) -> bool:
    if has_blacklist_hit:
        return True

    if not is_cryptojacking:
        return False

    if risk_score < ALERT_THRESHOLD_SCORE or signal_count < MIN_SIGNAL_COUNT:
        return False

    strong_identity_signal = bool(suspicious_procs or miner_indicators or threat_intel_hits or policy_hits)
    static_only_signal = bool(static_evidence_hits) and not strong_identity_signal
    network_signal = bool(miner_network_hits)
    if static_only_signal:
        # Suppress alerts caused only by noisy static signatures on legit binaries.
        return False
    if not (strong_identity_signal or network_signal):
        # High CPU alone should not alert anymore.
        return False

    if strong_identity_signal and confidence >= 0.75:
        return True
    if network_signal and confidence >= 0.75:
        return True

    dynamic_score = int(dynamic_evidence.get("dynamic_score", 0) or 0)
    evasion_triggered = (
        int(dynamic_evidence.get("idle_surge_count", 0) or 0) >= 1
        or int(dynamic_evidence.get("throttled_count", 0) or 0) >= 1
        or int(dynamic_evidence.get("gpu_compute_sustained_count", 0) or 0) >= 1
    )
    if (
        confidence >= 0.75
        and evasion_triggered
        and dynamic_score >= 3
        and (network_signal or int(dynamic_evidence.get("persistent_tls_count", 0) or 0) >= 1)
    ):
        return True

    # Dynamic fallback for unknown miners.
    heavy_non_system = sum(1 for p in high_cpu_non_system if p["cpu"] >= 50)
    miner_like_network_count = int(dynamic_evidence.get("miner_like_network_count", 0) or 0)
    return (
        confidence >= 0.80
        and cpu_percent >= 90
        and memory_percent >= 75
        and heavy_non_system >= 1
        and dynamic_score >= 3
        and miner_like_network_count >= 1
    )


WINDOWS_UNCOLLECTED_FEATURES = {"mem_cached", "mem_active", "cpu_iowait", "cpu_softirq"}


def _has_uncollected_linux_memory_counters(metrics: dict) -> bool:
    mem = metrics.get("memory")
    if not isinstance(mem, dict):
        return False
    used = _to_float(mem.get("used", mem.get("memory_used", 0.0)))
    pct = _to_float(mem.get("percent", mem.get("memory_percent", 0.0)))
    cached = _to_float(mem.get("cached", 0.0))
    active = _to_float(mem.get("active", 0.0))
    return (used > 0.0 or pct > 0.0) and cached == 0.0 and active == 0.0


def _compute_shap_importance(model_input: np.ndarray, raw_row: np.ndarray) -> Dict[str, Dict[str, float]]:
    if shap_explainer is None:
        return {}

    try:
        shap_values = shap_explainer.shap_values(model_input)
        if isinstance(shap_values, list):
            values = np.array(shap_values[-1])
        else:
            values = np.array(shap_values)

        if values.ndim == 3:
            values = values[0, :, -1]
        elif values.ndim == 2:
            values = values[0]
        elif values.ndim == 1:
            pass
        else:
            return {}

        out: Dict[str, Dict[str, float]] = {}
        for idx, feat in enumerate(feature_names[: len(values)]):
            out[feat] = {
                "value": round(float(raw_row[0][idx]), 4),
                "shap": round(float(values[idx]), 4),
            }
        return out
    except Exception as shap_err:
        print(f"SHAP computation error: {shap_err}")
        return {}


def perform_ml_inference(
    system_id: str,
    metrics: dict,
) -> tuple[
    bool,
    float,
    List[Dict[str, Any]],
    Dict[str, Dict[str, float]],
    List[str],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    Dict[str, Any],
]:
    cpu_percent = _extract_cpu_percent(metrics)
    memory_percent = _extract_memory_percent(metrics)
    processes = metrics.get("processes", [])
    (
        suspicious_procs,
        miner_indicators,
        high_cpu_non_system,
        static_evidence_hits,
        threat_intel_hits,
        miner_network_hits,
        policy_hits,
    ) = analyze_processes(processes)
    now = _safe_parse_timestamp(metrics.get("timestamp"))
    activity_block = metrics.get("activity") if isinstance(metrics.get("activity"), dict) else {}
    user_idle_seconds = _to_float(activity_block.get("user_idle_seconds"), 0.0)
    dynamic_evidence = {}
    if _behavior_monitor is not None:
        try:
            dynamic_evidence = _behavior_monitor.evaluate_system(
                system_id=system_id,
                processes=processes,
                now=now,
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                user_idle_seconds=user_idle_seconds,
            )
        except Exception as dyn_err:
            print(f"Dynamic behavior evaluation error: {dyn_err}")

    gpu_block = metrics.get("gpu") if isinstance(metrics.get("gpu"), dict) else {}
    gpu_util = _to_float(
        gpu_block.get("utilization_percent", gpu_block.get("engine_utilization_percent", 0.0))
    )
    max_non_sys_cpu = max(
        (p.get("cpu", 0.0) for p in high_cpu_non_system),
        default=0.0,
    )
    evasion_dynamic = bool(
        int(dynamic_evidence.get("idle_surge_count", 0) or 0) > 0
        or int(dynamic_evidence.get("throttled_count", 0) or 0) > 0
        or int(dynamic_evidence.get("gpu_compute_sustained_count", 0) or 0) > 0
    )
    network_or_tls = bool(
        miner_network_hits
        or int(dynamic_evidence.get("persistent_tls_count", 0) or 0) > 0
        or int(dynamic_evidence.get("pool_domain_count", 0) or 0) > 0
    )
    strong_miner_signal = bool(
        suspicious_procs
        or miner_indicators
        or threat_intel_hits
        or miner_network_hits
        or any(h.get("decision") == "deny" for h in policy_hits)
        or (evasion_dynamic and network_or_tls)
    )
    has_yara_or_cmdline = any(
        bool((p.get("static_analysis") or {}).get("yara_matched")) or _analyze_cmdline(p)[0]
        for p in processes
    )
    has_gpu_pid = any(bool(p.get("gpu_compute_active")) for p in processes)
    throttled_or_evasive_hit = bool(
        strong_miner_signal
        and (evasion_dynamic or has_yara_or_cmdline or bool(miner_network_hits) or has_gpu_pid)
        and (cpu_percent >= 10.0 or gpu_util >= 20.0 or has_gpu_pid or has_yara_or_cmdline)
    )

    if MODEL_LOADED and feature_names:
        try:
            raw_row = _build_model_row(metrics)
            if scaler is not None:
                scaler_input = raw_row
                if hasattr(scaler, "feature_names_in_"):
                    try:
                        import pandas as pd

                        scaler_input = pd.DataFrame(raw_row, columns=feature_names)
                    except Exception:
                        scaler_input = raw_row
                model_input = scaler.transform(scaler_input)
            else:
                model_input = raw_row

            prediction = ml_model.predict(model_input)[0]
            is_cryptojacking = _prediction_is_attack(prediction)

            confidence = 0.0
            if hasattr(ml_model, "predict_proba"):
                proba = ml_model.predict_proba(model_input)[0]
                confidence = _positive_probability(proba)
            elif hasattr(ml_model, "decision_function"):
                score = float(np.ravel(ml_model.decision_function(model_input))[0])
                confidence = 1.0 / (1.0 + np.exp(-score))
            else:
                confidence = 1.0 if is_cryptojacking else 0.0

            if _has_uncollected_linux_memory_counters(metrics):
                shap_map = _compute_shap_importance(model_input, raw_row)
                if shap_map:
                    clipped_p = float(np.clip(confidence, 1e-6, 1.0 - 1e-6))
                    raw_logit = float(np.log(clipped_p / (1.0 - clipped_p)))
                    uncollected_logit = 0.0
                    for feat in WINDOWS_UNCOLLECTED_FEATURES:
                        entry = shap_map.get(feat)
                        if entry and entry.get("value", 0.0) == 0.0:
                            uncollected_logit += float(entry.get("shap", 0.0))
                            entry["shap"] = 0.0
                    adj_logit = raw_logit - uncollected_logit
                    confidence = float(1.0 / (1.0 + np.exp(-np.clip(adj_logit, -20.0, 20.0))))

                has_compute_pressure = (
                    cpu_percent >= 55.0
                    or gpu_util >= 50.0
                    or max_non_sys_cpu >= 50.0
                    or strong_miner_signal
                )
                if not has_compute_pressure:
                    if confidence >= 0.50:
                        confidence = min(confidence * 0.45, 0.42)
                    is_cryptojacking = False
                elif (
                    cpu_percent >= 90.0
                    or ((cpu_percent >= 65.0 or gpu_util >= 80.0) and strong_miner_signal)
                    or throttled_or_evasive_hit
                ):
                    confidence = max(
                        confidence,
                        0.85 if strong_miner_signal or memory_percent >= 60.0 else 0.82,
                    )
                    is_cryptojacking = True
                else:
                    is_cryptojacking = confidence >= 0.50

                feat_importance = shap_map if is_cryptojacking else {}
            else:
                if throttled_or_evasive_hit:
                    confidence = max(confidence, 0.84)
                    is_cryptojacking = True
                feat_importance = _compute_shap_importance(model_input, raw_row) if is_cryptojacking else {}
            return (
                is_cryptojacking,
                float(confidence),
                suspicious_procs,
                feat_importance,
                miner_indicators,
                high_cpu_non_system,
                static_evidence_hits,
                threat_intel_hits,
                miner_network_hits,
                policy_hits,
                dynamic_evidence,
            )
        except Exception as err:
            print(f"ML inference error: {err}")

    # Heuristic fallback detection when the ML model is offline.
    heuristic_hit = cpu_percent >= 90 or memory_percent >= 80 or throttled_or_evasive_hit
    heuristic_conf = 0.85 if throttled_or_evasive_hit else (0.80 if heuristic_hit else 0.0)
    return (
        heuristic_hit,
        heuristic_conf,
        suspicious_procs,
        {},
        miner_indicators,
        high_cpu_non_system,
        static_evidence_hits,
        threat_intel_hits,
        miner_network_hits,
        policy_hits,
        dynamic_evidence,
    )


def _safe_parse_timestamp(timestamp_value) -> datetime:
    if not timestamp_value:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(str(timestamp_value).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return datetime.utcnow()


def _get_current_user(email: str, db: Session) -> User:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def _assert_system_access(user: User, system_id: str, db: Session):
    system = db.query(MonitoredSystem).filter(MonitoredSystem.system_id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")
    if user.role != "admin" and system.owner_email != user.email:
        raise HTTPException(status_code=403, detail="Not authorized")


@router.post("/batch")
async def receive_metrics_batch(
    batch: MetricsBatch,
    user: dict = Depends(verify_api_key),
    db: Session = Depends(get_db),
):
    """Receive metrics batch from agent, persist samples, and run inference."""
    if user.get("system_id") != batch.system_id:
        raise HTTPException(status_code=403, detail="Not authorized for this system")

    alerts_generated = []

    for metrics in batch.metrics:
        cpu = _extract_cpu_percent(metrics)
        mem = _extract_memory_percent(metrics)
        net = metrics.get("network", {})
        processes = metrics.get("processes", [])
        sample_time = _safe_parse_timestamp(metrics.get("timestamp"))

        # An agent retry can resend a sample whose response it never received.
        already_stored = (
            db.query(SystemMetric.id)
            .filter(SystemMetric.system_id == batch.system_id, SystemMetric.timestamp == sample_time)
            .first()
        )
        if already_stored:
            continue

        db_metric = SystemMetric(
            system_id=batch.system_id,
            timestamp=sample_time,
            cpu_percent=cpu,
            memory_percent=mem,
            network_bytes_sent=int(_to_float(net.get("bytes_sent", 0))),
            network_bytes_recv=int(_to_float(net.get("bytes_recv", 0))),
            processes_data=processes,
            raw_metrics=metrics,
        )
        db.add(db_metric)

        whitelist_hit, whitelist_reason = _check_whitelist(processes)
        if whitelist_hit:
            continue

        (
            is_cryptojacking,
            confidence,
            suspicious_procs,
            feat_importance,
            miner_indicators,
            high_cpu_non_system,
            static_evidence_hits,
            threat_intel_hits,
            miner_network_hits,
            policy_hits,
            dynamic_evidence,
        ) = perform_ml_inference(batch.system_id, metrics)

        risk_score, signal_labels = _compute_risk_score(
            is_cryptojacking=is_cryptojacking,
            confidence=confidence,
            processes=processes,
            miner_indicators=miner_indicators,
            threat_intel_hits=threat_intel_hits,
            miner_network_hits=miner_network_hits,
            policy_hits=policy_hits,
            dynamic_evidence=dynamic_evidence,
        )
        has_blacklist_hit = any(h.get("decision") == "deny" for h in policy_hits)
        candidate_alert = _should_emit_alert(
            is_cryptojacking=is_cryptojacking,
            confidence=confidence,
            cpu_percent=cpu,
            memory_percent=mem,
            suspicious_procs=suspicious_procs,
            miner_indicators=miner_indicators,
            high_cpu_non_system=high_cpu_non_system,
            static_evidence_hits=static_evidence_hits,
            threat_intel_hits=threat_intel_hits,
            miner_network_hits=miner_network_hits,
            policy_hits=policy_hits,
            dynamic_evidence=dynamic_evidence,
            risk_score=risk_score,
            signal_count=len(signal_labels),
            has_blacklist_hit=has_blacklist_hit,
        )
        should_alert = _update_sustained_state(
            batch.system_id,
            candidate_alert,
            has_blacklist_hit,
        )

        if should_alert:
            process_context = _build_process_context(processes, [p.get("name") for p in suspicious_procs])
            gpu_block = metrics.get("gpu", {}) if isinstance(metrics.get("gpu"), dict) else {}
            gpu_util = _to_float(gpu_block.get("utilization_percent", gpu_block.get("engine_utilization_percent", 0.0)))
            gpu_mem_used = _to_float(gpu_block.get("memory_used_mb", 0.0))
            gpu_mem_total = _to_float(gpu_block.get("memory_total_mb", 0.0))
            gpu_mem_pct = _to_float(gpu_block.get("memory_used_percent", 0.0))
            if gpu_mem_pct == 0.0 and gpu_mem_total > 0:
                gpu_mem_pct = (gpu_mem_used / gpu_mem_total) * 100.0
            reason_summary, reason_details = _build_reason_summary(
                is_cryptojacking=is_cryptojacking,
                confidence=confidence,
                suspicious_procs=suspicious_procs,
                miner_indicators=miner_indicators,
                high_cpu_non_system=high_cpu_non_system,
                static_evidence_hits=static_evidence_hits,
                threat_intel_hits=threat_intel_hits,
                miner_network_hits=miner_network_hits,
                policy_hits=policy_hits,
                dynamic_evidence=dynamic_evidence,
                signal_labels=signal_labels,
                process_context=process_context,
                has_blacklist_hit=has_blacklist_hit,
            )
            db_alert = Alert(
                system_id=batch.system_id,
                timestamp=_safe_parse_timestamp(metrics.get("timestamp")),
                alert_type="cryptojacking_detected",
                confidence=1.0 if has_blacklist_hit else confidence,
                detection_method="ml_model" if MODEL_LOADED else "heuristic",
                metrics={
                    "cpu_usage": cpu,
                    "memory_usage": mem,
                    "gpu_utilization": round(gpu_util, 2),
                    "gpu_memory_used_mb": round(gpu_mem_used, 2),
                    "gpu_memory_total_mb": round(gpu_mem_total, 2),
                    "gpu_memory_used_percent": round(gpu_mem_pct, 2),
                    "miner_indicators": miner_indicators,
                    "high_cpu_non_system_count": len(high_cpu_non_system),
                    "static_evidence_hits": static_evidence_hits,
                    "threat_intel_hits": threat_intel_hits,
                    "miner_network_hits": miner_network_hits,
                    "policy_hits": policy_hits,
                    "dynamic_evidence": dynamic_evidence,
                    "risk_score": risk_score,
                    "signal_labels": signal_labels,
                    "process_context": process_context,
                    "reason_summary": reason_summary,
                    "reason_details": reason_details,
                },
                suspicious_processes=[p["name"] for p in suspicious_procs],
                virustotal_results=threat_intel_hits,
                feature_importance=feat_importance,
                status="unread",
            )
            db.add(db_alert)
            db.flush()

            try:
                from services.notification_service import NotificationService

                if confidence >= NotificationService.CONFIDENCE_THRESHOLD:
                    import asyncio

                    asyncio.ensure_future(NotificationService.dispatch_alert(db_alert, db))
            except Exception as notif_err:
                print(f"Notification dispatch error: {notif_err}")

            alerts_generated.append(
                {
                    "alert_id": db_alert.id,
                    "system_id": batch.system_id,
                    "timestamp": db_alert.timestamp.isoformat(),
                    "alert_type": "cryptojacking_detected",
                    "confidence": confidence,
                    "detection_method": db_alert.detection_method,
                    "suspicious_processes": [p["name"] for p in suspicious_procs],
                    "miner_indicators": miner_indicators,
                    "static_evidence_hits": static_evidence_hits,
                    "threat_intel_hits": threat_intel_hits,
                    "miner_network_hits": miner_network_hits,
                    "policy_hits": policy_hits,
                    "dynamic_evidence": dynamic_evidence,
                    "risk_score": risk_score,
                    "signal_labels": signal_labels,
                    "reason_summary": reason_summary,
                    "reason_details": reason_details,
                    "status": "unread",
                }
            )
            print(f"ALERT: system={batch.system_id} confidence={confidence:.0%}")

    system = db.query(MonitoredSystem).filter(MonitoredSystem.system_id == batch.system_id).first()
    if system:
        system.status = "online"
        system.last_seen = datetime.utcnow()

    pending_commands_payload: List[Dict[str, Any]] = []
    try:
        from backend.models.agent_command import AgentCommand

        raw_pending = (
            db.query(AgentCommand)
            .filter(
                AgentCommand.system_id == batch.system_id,
                AgentCommand.status == "pending",
            )
            .order_by(AgentCommand.created_at.asc())
            .limit(5)
            .all()
        )
        if isinstance(raw_pending, list):
            now_dispatch = datetime.utcnow()
            for cmd in raw_pending:
                if isinstance(getattr(cmd, "id", None), int) and hasattr(cmd, "to_dict"):
                    cmd.status = "dispatched"
                    cmd.updated_at = now_dispatch
                    pending_commands_payload.append(cmd.to_dict())
    except Exception as cmd_err:
        print(f"Pending command fetch warning: {cmd_err}")

    db.commit()

    return {
        "status": "success",
        "metrics_received": len(batch.metrics),
        "model_used": MODEL_NAME if MODEL_LOADED else "heuristic",
        "alerts": alerts_generated,
        "pending_commands": pending_commands_payload,
    }


@router.get("/{system_id}")
async def get_system_metrics(
    system_id: str,
    limit: int = 100,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    current_user = _get_current_user(email, db)
    _assert_system_access(current_user, system_id, db)

    metrics = (
        db.query(SystemMetric)
        .filter(SystemMetric.system_id == system_id)
        .order_by(SystemMetric.timestamp.desc())
        .limit(limit)
        .all()
    )

    return {
        "system_id": system_id,
        "metrics_count": len(metrics),
        "metrics": [m.raw_metrics for m in reversed(metrics)],
    }


@router.get("/{system_id}/latest")
async def get_latest_metrics(
    system_id: str,
    email: str = Depends(verify_token),
    db: Session = Depends(get_db),
):
    current_user = _get_current_user(email, db)
    _assert_system_access(current_user, system_id, db)

    metric = (
        db.query(SystemMetric)
        .filter(SystemMetric.system_id == system_id)
        .order_by(SystemMetric.timestamp.desc())
        .first()
    )

    if not metric:
        raise HTTPException(status_code=404, detail="No metrics found")

    return metric.raw_metrics
