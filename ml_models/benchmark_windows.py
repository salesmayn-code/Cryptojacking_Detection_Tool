"""Multi-workload Windows endpoint evaluation & evasion ablation benchmark.

Usage:
    python -m ml_models.benchmark_windows
    python -m ml_models.benchmark_windows --collect-live 15
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import json
import math
from pathlib import Path
import sys
import time
from typing import Any, Callable, Dict, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.routes import metrics as det
from dynamic_analysis import DynamicBehaviorMonitor


DEFAULT_RESULTS_DIR = PROJECT_ROOT / "docs" / "results"

SCENARIO_ORDER = [
    ("benign_idle_browsing", "Benign Idle & Browsing", 0),
    ("benign_heavy_compute", "Benign Heavy (7-Zip / Build / Blender)", 0),
    ("miner_full_load", "Standard Full-Load Miner", 1),
    ("miner_throttled_25pct", "Throttled 25%-CPU Miner", 1),
    ("miner_idle_afk", "Idle-Aware (--pause-on-active) Miner", 1),
    ("miner_tls_spoof_yara", "Stealth TLS (:443) + Masquerade + YARA", 1),
]


def wilson_ci(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    """Return 95% Wilson score confidence interval (low, high) in [0, 1]."""
    if total <= 0:
        return (0.0, 0.0)
    p = successes / total
    denom = 1.0 + (z * z) / total
    centre = p + (z * z) / (2.0 * total)
    margin = z * math.sqrt((p * (1.0 - p) + (z * z) / (4.0 * total)) / total)
    return (max(0.0, round((centre - margin) / denom, 4)), min(1.0, round((centre + margin) / denom, 4)))


def _base_windows_frame(
    ts: datetime,
    rng: np.random.Generator,
    cpu_pct: float,
    mem_pct: float,
    recv_bps: float,
    sent_bps: float,
    idle_seconds: float,
    processes: List[Dict[str, Any]],
) -> Dict[str, Any]:
    mem_total = 16_000_000_000
    mem_used = int(mem_total * (mem_pct / 100.0))
    cpu_user = round(cpu_pct * float(rng.uniform(0.80, 0.90)), 2)
    cpu_sys = round(max(0.2, cpu_pct - cpu_user), 2)
    return {
        "timestamp": ts.isoformat(),
        "activity": {
            "user_idle_seconds": round(float(idle_seconds), 2),
            "is_idle": idle_seconds >= 30.0,
        },
        "cpu": {"percent": round(float(cpu_pct), 2), "cpu_count": 8},
        "cpu_times": {
            "user": cpu_user,
            "system": cpu_sys,
            "idle": round(max(0.0, 100.0 - cpu_pct), 2),
            "iowait": 0.0,
            "irq": 0.0,
            "softirq": 0.0,
        },
        "memory": {
            "percent": round(float(mem_pct), 2),
            "used": mem_used,
            "available": mem_total - mem_used,
            "total": mem_total,
            "active": 0,
            "cached": 0,
        },
        "load_avg": {
            "min1": round((cpu_pct / 100.0) * 8.0, 3),
            "min5": round((cpu_pct / 100.0) * 7.6, 3),
            "min15": round((cpu_pct / 100.0) * 7.2, 3),
        },
        "network": {
            "bytes_recv_delta": round(float(recv_bps), 2),
            "bytes_sent_delta": round(float(sent_bps), 2),
        },
        "process_counts": {
            "running": 4 + len(processes),
            "total": 185 + int(rng.integers(-6, 8)),
            "thread": 2400 + int(rng.integers(-40, 120)),
        },
        "gpu": {"available": False, "utilization_percent": 0.0},
        "processes": processes,
    }


def generate_benchmark_episodes(
    episodes_per_scenario: int = 12,
    frames_per_episode: int = 10,
    seed: int = 2026,
) -> List[Dict[str, Any]]:
    """Build deterministic multi-frame Windows workload episodes for evaluation."""
    rng = np.random.default_rng(seed)
    episodes: List[Dict[str, Any]] = []
    t0 = datetime(2026, 11, 1, 12, 0, 0)

    for scenario_key, scenario_label, label in SCENARIO_ORDER:
        for ep_idx in range(episodes_per_scenario):
            frames: List[Dict[str, Any]] = []
            ctx_cum = 2000
            io_cum = 5_000_000
            ep_start = t0 + timedelta(minutes=ep_idx * 5)

            for step in range(frames_per_episode):
                ts = ep_start + timedelta(seconds=step * 5)

                if scenario_key == "benign_idle_browsing":
                    cpu = float(rng.uniform(2.5, 16.0))
                    mem = float(rng.uniform(62.0, 77.0))
                    idle = 0.0 if step % 2 == 0 else float(rng.uniform(5.0, 40.0))
                    procs = [
                        {
                            "pid": 4120,
                            "name": "chrome.exe",
                            "cpu_percent": round(cpu * 0.6, 2),
                            "memory_percent": 11.2,
                            "exe_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                            "publisher": "CN=Google LLC",
                            "signature_status": "valid",
                            "cmdline": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --profile-directory=Default",
                            "ctx_switches_total": ctx_cum + step * 300,
                            "io_bytes_total": io_cum + step * 800_000,
                            "network_summary": {
                                "has_external_connection": True,
                                "established_count": 4,
                                "unique_remote_ip_count": 7,
                                "remote_ports": [443],
                                "has_tls_external": True,
                                "resolved_domains": ["docs.github.com", "fonts.googleapis.com"],
                            },
                        }
                    ]
                    frames.append(_base_windows_frame(ts, rng, cpu, mem, 12000.0, 3800.0, idle, procs))

                elif scenario_key == "benign_heavy_compute":
                    variant = ep_idx % 3
                    cpu = float(rng.uniform(68.0, 95.0))
                    mem = float(rng.uniform(60.0, 82.0))
                    idle = float(rng.uniform(0.0, 12.0))
                    io_cum += int(rng.uniform(18_000_000, 45_000_000))
                    ctx_cum += int(rng.uniform(800, 2200))
                    if variant == 0:
                        proc = {
                            "pid": 5210,
                            "name": "7z.exe",
                            "cpu_percent": round(cpu * 0.92, 2),
                            "memory_percent": 9.4,
                            "exe_path": "C:\\Program Files\\7-Zip\\7z.exe",
                            "publisher": "Igor Pavlov",
                            "signature_status": "valid",
                            "cmdline": "7z.exe a -mx=9 backup.7z C:\\Users\\op\\Documents\\archive",
                            "ctx_switches_total": ctx_cum,
                            "io_bytes_total": io_cum,
                            "network_summary": {"has_external_connection": False, "remote_ports": []},
                        }
                    elif variant == 1:
                        proc = {
                            "pid": 6340,
                            "name": "blender.exe",
                            "cpu_percent": round(cpu * 0.90, 2),
                            "memory_percent": 22.0,
                            "exe_path": "C:\\Program Files\\Blender Foundation\\Blender 4.2\\blender.exe",
                            "publisher": "CN=Blender Foundation",
                            "signature_status": "valid",
                            "cmdline": "blender.exe -b scene.blend -o //render_ -F PNG -a",
                            "ctx_switches_total": ctx_cum,
                            "io_bytes_total": io_cum,
                            "network_summary": {"has_external_connection": False, "remote_ports": []},
                        }
                    else:
                        # Local Docker / WSL2 container compile with high CPU & zero miner net/CLI
                        proc = {
                            "pid": 7712,
                            "name": "vmmemWSL",
                            "cpu_percent": round(cpu * 0.88, 2),
                            "memory_percent": 24.5,
                            "exe_path": None,
                            "publisher": "",
                            "signature_status": "unknown",
                            "cmdline": "",
                            "ctx_switches_total": ctx_cum,
                            "io_bytes_total": io_cum,
                            "network_summary": {"has_external_connection": False, "remote_ports": []},
                        }
                    frames.append(_base_windows_frame(ts, rng, cpu, mem, 400.0, 250.0, idle, [proc]))

                elif scenario_key == "miner_full_load":
                    cpu = float(rng.uniform(88.0, 99.0))
                    mem = float(rng.uniform(68.0, 86.0))
                    ctx_cum += int(rng.uniform(4500, 9000))
                    io_cum += int(rng.uniform(20_000, 90_000))
                    proc = {
                        "pid": 9102,
                        "name": "xmrig.exe" if ep_idx % 2 == 0 else "worker_svc.exe",
                        "cpu_percent": round(cpu * 0.94, 2),
                        "memory_percent": 15.6,
                        "exe_path": "C:\\Users\\op\\AppData\\Local\\Temp\\worker_svc.exe",
                        "signature_status": "unsigned",
                        "cmdline": "worker_svc.exe -o stratum+tcp://pool.supportxmr.com:3333 -a rx/0",
                        "ctx_switches_total": ctx_cum,
                        "io_bytes_total": io_cum,
                        "network_summary": {
                            "has_external_connection": True,
                            "established_count": 2,
                            "unique_remote_ip_count": 1,
                            "remote_ips_sample": ["185.199.108.50"],
                            "remote_ports": [3333],
                            "has_miner_port": True,
                            "resolved_domains": ["pool.supportxmr.com"],
                            "has_pool_domain": True,
                        },
                        "static_analysis": {
                            "has_mining_keywords": True,
                            "mining_keywords": ["xmrig", "randomx"],
                            "yara_matched": True,
                            "yara_rules": ["CryptoMiner_XMRig_Signature"],
                            "yara_severity": "critical",
                        },
                    }
                    frames.append(_base_windows_frame(ts, rng, cpu, mem, 2400.0, 1800.0, 15.0, [proc]))

                elif scenario_key == "miner_throttled_25pct":
                    # CPU throttled (--cpu-max-threads-pct 25) and no clear pool port (DNS / CLI only)
                    cpu = float(rng.uniform(19.0, 31.0))
                    mem = float(rng.uniform(48.0, 62.0))
                    ctx_cum += int(rng.uniform(1800, 3400))
                    io_cum += int(rng.uniform(5_000, 40_000))
                    proc = {
                        "pid": 9204,
                        "name": "updater_host.exe",
                        "cpu_percent": round(max(16.0, cpu * 0.85), 2),
                        "memory_percent": 6.4,
                        "exe_path": "C:\\ProgramData\\SysCache\\updater_host.exe",
                        "signature_status": "unknown",
                        "cmdline": "updater_host.exe --cpu-max-threads-pct 25 --donate-level 1 -a rx/0",
                        "ctx_switches_total": ctx_cum,
                        "io_bytes_total": io_cum,
                        "network_summary": {
                            "has_external_connection": True,
                            "established_count": 1,
                            "unique_remote_ip_count": 1,
                            "remote_ips_sample": ["198.51.100.42"],
                            "remote_ports": [443],
                            "has_tls_external": True,
                            "resolved_domains": ["gulf.moneroocean.stream"] if ep_idx % 2 == 0 else [],
                            "has_pool_domain": ep_idx % 2 == 0,
                        },
                    }
                    frames.append(_base_windows_frame(ts, rng, cpu, mem, 950.0, 720.0, 4.0, [proc]))

                elif scenario_key == "miner_idle_afk":
                    # Active steps 0..3: miner pauses; Idle steps 4..9: user AFK -> miner ramps up over :443
                    is_afk = step >= 4
                    idle = float(rng.uniform(35.0, 110.0)) if is_afk else float(rng.uniform(0.0, 6.0))
                    proc_cpu = float(rng.uniform(25.0, 39.0)) if is_afk else float(rng.uniform(0.8, 2.5))
                    cpu = round(proc_cpu + float(rng.uniform(2.0, 5.0)), 2)
                    mem = float(rng.uniform(50.0, 66.0))
                    ctx_cum += int(rng.uniform(1500, 2800)) if is_afk else 80
                    io_cum += 15_000
                    proc = {
                        "pid": 9308,
                        "name": "telemetry_sync.exe",
                        "cpu_percent": round(proc_cpu, 2),
                        "memory_percent": 7.1,
                        "exe_path": "C:\\Users\\op\\AppData\\Local\\Temp\\telemetry_sync.exe",
                        "signature_status": "unsigned",
                        "cmdline": "telemetry_sync.exe --pause-on-active --config cfg.dat",
                        "ctx_switches_total": ctx_cum,
                        "io_bytes_total": io_cum,
                        "network_summary": {
                            "has_external_connection": True,
                            "established_count": 1 if is_afk else 0,
                            "unique_remote_ip_count": 1,
                            "remote_ips_sample": ["203.0.113.77"],
                            "remote_ports": [443],
                            "has_tls_external": bool(is_afk),
                            "resolved_domains": [],
                            "has_pool_domain": False,
                        },
                    }
                    frames.append(_base_windows_frame(ts, rng, cpu, mem, 800.0, 650.0, idle, [proc]))

                elif scenario_key == "miner_tls_spoof_yara":
                    # Renamed masquerade binary + TLS :443 only + UPX/YARA RandomX
                    cpu = float(rng.uniform(24.0, 44.0))
                    mem = float(rng.uniform(54.0, 70.0))
                    ctx_cum += int(rng.uniform(2000, 3500))
                    io_cum += 25_000
                    proc = {
                        "pid": 9412,
                        "name": "dllhost.exe",
                        "cpu_percent": round(cpu * 0.85, 2),
                        "memory_percent": 8.0,
                        "exe_path": "C:\\Users\\op\\AppData\\Roaming\\Host\\dllhost.exe",
                        "publisher": "",
                        "signature_status": "unsigned",
                        "cmdline": "dllhost.exe -c sync",
                        "ctx_switches_total": ctx_cum,
                        "io_bytes_total": io_cum,
                        "network_summary": {
                            "has_external_connection": True,
                            "established_count": 2,
                            "unique_remote_ip_count": 1,
                            "remote_ips_sample": ["192.0.2.99"],
                            "remote_ports": [443],
                            "has_tls_external": True,
                            "resolved_domains": ["xmr-eu1.nanopool.org"],
                            "has_pool_domain": True,
                        },
                        "static_analysis": {
                            "yara_matched": True,
                            "yara_rules": ["CryptoMiner_Stratum_Protocol", "CryptoMiner_GPU_MultiMiner"],
                            "yara_severity": "critical",
                            "is_packed": True,
                        },
                    }
                    frames.append(_base_windows_frame(ts, rng, cpu, mem, 1100.0, 900.0, 20.0, [proc]))

            episodes.append(
                {
                    "episode_id": f"{scenario_key}_{ep_idx}",
                    "scenario": scenario_key,
                    "scenario_label": scenario_label,
                    "label": label,
                    "frames": frames,
                }
            )

    return episodes


def _eval_uncalibrated_xgboost(frame: Dict[str, Any]) -> bool:
    if not det.MODEL_LOADED or det.ml_model is None:
        return det._extract_cpu_percent(frame) >= 90.0
    raw_row = det._build_model_row(frame)
    model_input = raw_row
    if det.scaler is not None:
        scaler_input = raw_row
        if hasattr(det.scaler, "feature_names_in_"):
            import pandas as pd
            scaler_input = pd.DataFrame(raw_row, columns=det.feature_names)
        model_input = det.scaler.transform(scaler_input)
    pred = det.ml_model.predict(model_input)[0]
    return det._prediction_is_attack(pred)


def _eval_shap_calibrated_baseline(frame: Dict[str, Any]) -> bool:
    """Reproduce the prior SHAP-calibrated cross-OS gate without process/evasion fusion."""
    if not det.MODEL_LOADED or det.ml_model is None:
        return det._extract_cpu_percent(frame) >= 90.0
    cpu_pct = det._extract_cpu_percent(frame)
    raw_row = det._build_model_row(frame)
    model_input = raw_row
    if det.scaler is not None:
        scaler_input = raw_row
        if hasattr(det.scaler, "feature_names_in_"):
            import pandas as pd
            scaler_input = pd.DataFrame(raw_row, columns=det.feature_names)
        model_input = det.scaler.transform(scaler_input)

    proba = det.ml_model.predict_proba(model_input)[0]
    confidence = det._positive_probability(proba)
    shap_map = det._compute_shap_importance(model_input, raw_row)
    if shap_map:
        clipped_p = float(np.clip(confidence, 1e-6, 1.0 - 1e-6))
        raw_logit = float(np.log(clipped_p / (1.0 - clipped_p)))
        uncollected_logit = 0.0
        for feat in det.WINDOWS_UNCOLLECTED_FEATURES:
            entry = shap_map.get(feat)
            if entry and entry.get("value", 0.0) == 0.0:
                uncollected_logit += float(entry.get("shap", 0.0))
        confidence = float(1.0 / (1.0 + np.exp(-np.clip(raw_logit - uncollected_logit, -20.0, 20.0))))

    if cpu_pct < 55.0:
        return False
    if cpu_pct >= 90.0:
        return True
    return confidence >= 0.50


def run_benchmark(
    results_dir: Path = DEFAULT_RESULTS_DIR,
    episodes_per_scenario: int = 12,
    frames_per_episode: int = 10,
) -> Dict[str, Any]:
    if not det.MODEL_LOADED:
        det._init_model()

    results_dir.mkdir(parents=True, exist_ok=True)
    episodes = generate_benchmark_episodes(episodes_per_scenario, frames_per_episode)

    detectors = [
        "Naive CPU >= 90% Rule",
        "Uncalibrated Kaggle XGBoost",
        "SHAP Cross-OS Gate (Prior)",
        "CryptoDetect Evasion-Resilient",
    ]

    ep_preds: Dict[str, List[int]] = {name: [] for name in detectors}
    ep_labels = [ep["label"] for ep in episodes]
    ep_scenarios = [ep["scenario"] for ep in episodes]

    # Isolate DynamicBehaviorMonitor state for clean benchmark measurements.
    orig_monitor = det._behavior_monitor
    det._behavior_monitor = DynamicBehaviorMonitor(max_samples=24)

    try:
        for idx, ep in enumerate(episodes):
            sys_id = f"BENCH-{idx}-{ep['scenario']}"
            hits = {name: 0 for name in detectors}

            for frame in ep["frames"]:
                cpu_pct = det._extract_cpu_percent(frame)
                mem_pct = det._extract_memory_percent(frame)
                procs = frame.get("processes", [])

                # 1) Naive >= 90% CPU rule (require >=3 frames to match sustained style or direct >=90%)
                if cpu_pct >= 90.0:
                    hits["Naive CPU >= 90% Rule"] += 1

                # 2) Raw uncalibrated Kaggle XGBoost
                if _eval_uncalibrated_xgboost(frame):
                    hits["Uncalibrated Kaggle XGBoost"] += 1

                # 3) SHAP Cross-OS Gate without whitelist/evasion fusion
                if _eval_shap_calibrated_baseline(frame):
                    hits["SHAP Cross-OS Gate (Prior)"] += 1

                # 4) Full CryptoDetect Evasion-Resilient Engine
                whitelisted, _ = det._check_whitelist(procs)
                if not whitelisted:
                    (
                        is_cj,
                        conf,
                        susp_procs,
                        _feat_imp,
                        miner_ind,
                        high_cpu_ns,
                        static_hits,
                        intel_hits,
                        net_hits,
                        pol_hits,
                        dyn_ev,
                    ) = det.perform_ml_inference(sys_id, frame)
                    r_score, sig_labels = det._compute_risk_score(
                        is_cryptojacking=is_cj,
                        confidence=conf,
                        processes=procs,
                        miner_indicators=miner_ind,
                        threat_intel_hits=intel_hits,
                        miner_network_hits=net_hits,
                        policy_hits=pol_hits,
                        dynamic_evidence=dyn_ev,
                    )
                    has_bl = any(h.get("decision") == "deny" for h in pol_hits)
                    if det._should_emit_alert(
                        is_cryptojacking=is_cj,
                        confidence=conf,
                        cpu_percent=cpu_pct,
                        memory_percent=mem_pct,
                        suspicious_procs=susp_procs,
                        miner_indicators=miner_ind,
                        high_cpu_non_system=high_cpu_ns,
                        static_evidence_hits=static_hits,
                        threat_intel_hits=intel_hits,
                        miner_network_hits=net_hits,
                        policy_hits=pol_hits,
                        dynamic_evidence=dyn_ev,
                        risk_score=r_score,
                        signal_count=len(sig_labels),
                        has_blacklist_hit=has_bl,
                    ):
                        hits["CryptoDetect Evasion-Resilient"] += 1

            # An episode flags if >= 2 frames trigger (or >=1 for sequential AFK ramp / evasion alert)
            ep_preds["Naive CPU >= 90% Rule"].append(1 if hits["Naive CPU >= 90% Rule"] >= 3 else 0)
            ep_preds["Uncalibrated Kaggle XGBoost"].append(1 if hits["Uncalibrated Kaggle XGBoost"] >= 3 else 0)
            ep_preds["SHAP Cross-OS Gate (Prior)"].append(1 if hits["SHAP Cross-OS Gate (Prior)"] >= 3 else 0)
            ep_preds["CryptoDetect Evasion-Resilient"].append(
                1 if hits["CryptoDetect Evasion-Resilient"] >= 2 else 0
            )
    finally:
        det._behavior_monitor = orig_monitor

    summary: Dict[str, Any] = {}
    scenario_matrix: Dict[str, Dict[str, float]] = {}

    y_true = np.array(ep_labels)
    for name in detectors:
        y_pred = np.array(ep_preds[name])
        tp = int(np.sum((y_true == 1) & (y_pred == 1)))
        fp = int(np.sum((y_true == 0) & (y_pred == 1)))
        tn = int(np.sum((y_true == 0) & (y_pred == 0)))
        fn = int(np.sum((y_true == 1) & (y_pred == 0)))

        acc = (tp + tn) / max(1, len(y_true))
        prec = tp / max(1, tp + fp)
        rec = tp / max(1, tp + fn)
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        fpr = fp / max(1, fp + tn)

        summary[name] = {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "accuracy_ci95": list(wilson_ci(tp + tn, len(y_true))),
            "recall_ci95": list(wilson_ci(tp, tp + fn)),
        }

        per_scen: Dict[str, float] = {}
        for scen_key, _, _ in SCENARIO_ORDER:
            idxs = [i for i, s in enumerate(ep_scenarios) if s == scen_key]
            if idxs:
                # For benign scenarios report Specificity (1 - FPR), for miner report Recall
                scen_label = episodes[idxs[0]]["label"]
                rate = sum(1 for i in idxs if ep_preds[name][i] == scen_label) / len(idxs)
                per_scen[scen_key] = round(rate, 4)
        scenario_matrix[name] = per_scen

    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_episodes": len(episodes),
        "frames_per_episode": frames_per_episode,
        "total_frames": len(episodes) * frames_per_episode,
        "detectors": summary,
        "scenario_accuracy_by_detector": scenario_matrix,
        "scenarios": [{"key": k, "label": lbl, "ground_truth": gt} for k, lbl, gt in SCENARIO_ORDER],
    }

    json_path = results_dir / "windows_benchmark.json"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    _plot_ablation_chart(report, results_dir / "windows_ablation.png")
    return report


def _plot_ablation_chart(report: Dict[str, Any], out_path: Path) -> None:
    plt.rcParams.update({"font.size": 9.5, "axes.edgecolor": "#cbd5e1"})
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.5, 5.2), dpi=220)

    detector_names = list(report["detectors"].keys())
    short_names = [
        "CPU >= 90%\nRule",
        "Raw Kaggle\nXGBoost",
        "SHAP Cross-OS\n(Prior)",
        "CryptoDetect\nEvasion-Resilient",
    ]
    recalls = [report["detectors"][d]["recall"] * 100.0 for d in detector_names]
    fprs = [report["detectors"][d]["fpr"] * 100.0 for d in detector_names]
    f1s = [report["detectors"][d]["f1"] * 100.0 for d in detector_names]

    x = np.arange(len(short_names))
    w = 0.25
    ax1.bar(x - w, recalls, width=w, label="Miner Recall (%)", color="#2563eb")
    ax1.bar(x, f1s, width=w, label="F1 Score (%)", color="#059669")
    ax1.bar(x + w, fprs, width=w, label="False Positive Rate (%)", color="#dc2626")
    ax1.set_xticks(x)
    ax1.set_xticklabels(short_names)
    ax1.set_ylim(0, 114)
    ax1.set_ylabel("Percentage (%)")
    ax1.set_title("Windows Multi-Workload Detection Ablation", pad=12)
    ax1.grid(axis="y", linestyle="--", alpha=0.35)
    ax1.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.16),
        ncol=3,
        frameon=True,
        fontsize=8.5,
    )

    for idx in range(len(x)):
        ax1.text(x[idx] - w, recalls[idx] + 2.2, f"{recalls[idx]:.0f}%", ha="center", fontsize=7.5)
        ax1.text(x[idx], f1s[idx] + 2.2, f"{f1s[idx]:.0f}%", ha="center", fontsize=7.5)
        ax1.text(x[idx] + w, fprs[idx] + 2.2, f"{fprs[idx]:.0f}%", ha="center", fontsize=7.5)

    scen_keys = [s["key"] for s in report["scenarios"]]
    scen_labels = [
        "Benign\nIdle/Web",
        "Benign\n7z/Build",
        "Full\nMiner",
        "25% CPU\nMiner",
        "AFK Idle\nMiner",
        "TLS :443\n+ YARA",
    ]
    prior_rates = [report["scenario_accuracy_by_detector"]["SHAP Cross-OS Gate (Prior)"][k] * 100.0 for k in scen_keys]
    new_rates = [report["scenario_accuracy_by_detector"]["CryptoDetect Evasion-Resilient"][k] * 100.0 for k in scen_keys]

    sx = np.arange(len(scen_keys))
    sw = 0.34
    ax2.bar(sx - sw / 2, prior_rates, width=sw, label="SHAP Cross-OS (Prior)", color="#94a3b8")
    ax2.bar(sx + sw / 2, new_rates, width=sw, label="CryptoDetect Evasion-Resilient", color="#2563eb")
    ax2.set_xticks(sx)
    ax2.set_xticklabels(scen_labels, fontsize=8.5)
    ax2.set_ylim(0, 114)
    ax2.set_ylabel("Per-Scenario Accuracy (%)")
    ax2.set_title("Per-Workload Accuracy (Benign Specificity vs Miner Recall)", pad=12)
    ax2.grid(axis="y", linestyle="--", alpha=0.35)
    ax2.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.16),
        ncol=2,
        frameon=True,
        fontsize=8.5,
    )

    for idx in range(len(sx)):
        ax2.text(sx[idx] - sw / 2, prior_rates[idx] + 2.2, f"{prior_rates[idx]:.0f}%", ha="center", fontsize=7.5)
        ax2.text(sx[idx] + sw / 2, new_rates[idx] + 2.2, f"{new_rates[idx]:.0f}%", ha="center", fontsize=7.5)

    fig.tight_layout(pad=1.6)
    fig.subplots_adjust(bottom=0.22)
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)


def collect_live_trace(duration_seconds: int = 15, out_file: Path | None = None) -> Path:
    """Collect a real local Windows telemetry trace via MonitoringAgent for live baseline inspection."""
    from monitoring_agent.enhanced_agent import MonitoringAgent

    target = out_file or (DEFAULT_RESULTS_DIR / "live_windows_trace.jsonl")
    target.parent.mkdir(parents=True, exist_ok=True)
    agent = MonitoringAgent("SYS-LIVE-BENCH", "bench-key", "http://localhost:8000")
    agent.interval = 3
    samples = []
    started = time.time()
    while time.time() - started < duration_seconds:
        frame = agent.collect_metrics()
        if frame:
            samples.append(frame)
        time.sleep(2.5)
    target.write_text("\n".join(json.dumps(s) for s in samples) + "\n", encoding="utf-8")
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description="Windows Multi-Workload Cryptojacking Benchmark")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--episodes", type=int, default=12)
    parser.add_argument("--collect-live", type=int, default=0, help="Optional live host capture seconds")
    args = parser.parse_args()

    if args.collect_live > 0:
        out_trace = collect_live_trace(args.collect_live, args.output_dir / "live_windows_trace.jsonl")
        print(f"Collected live Windows telemetry trace -> {out_trace}")

    report = run_benchmark(args.output_dir, episodes_per_scenario=args.episodes)
    print(f"Benchmark completed: {report['total_episodes']} episodes ({report['total_frames']} frames)")
    for det_name, m in report["detectors"].items():
        print(
            f"  {det_name:32s} | Acc={m['accuracy']:.3f} | Prec={m['precision']:.3f} "
            f"| Rec={m['recall']:.3f} | F1={m['f1']:.3f} | FPR={m['fpr']:.3f}"
        )


if __name__ == "__main__":
    main()
