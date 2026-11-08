"""Integration and unit tests for the monitoring agent, ML pipeline, and API key security."""
import asyncio
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = ROOT / "monitoring_agent"
sys.path.insert(0, str(AGENT_DIR))


@pytest.fixture
def agent(monkeypatch, tmp_path):
    import enhanced_agent

    monkeypatch.delenv("AGENT_BATCH_SIZE", raising=False)
    monkeypatch.setattr(enhanced_agent, "CONFIG_DIR", tmp_path)
    return enhanced_agent.MonitoringAgent("SYS-TEST", "key", "http://localhost:8000")


def test_agent_uploads_every_30_seconds_with_10_second_heartbeats(agent):
    samples = [{"sample": i} for i in range(6)]
    for sample in samples:
        agent._queue_sample(sample)
    payloads = [agent._next_payload(count) for count in range(1, 7)]

    assert agent.interval * agent.batch_size == 30
    assert payloads[:5] == [None, [], None, [], None]
    assert payloads[5] == samples


def _run_agent_cycles(agent, monkeypatch, cycles, send_results):
    """Run the real agent loop with collection and upload stubbed; return uploads."""
    collected = iter(range(cycles))
    uploads = []
    outcomes = iter(send_results)

    def fake_collect():
        sample = next(collected)
        if sample == cycles - 1:
            agent.running = False
        return {"sample": sample}

    def fake_send(payload):
        if not payload:
            return True
        uploads.append(payload)
        return next(outcomes)

    agent.interval = 0
    monkeypatch.setattr(agent, "collect_metrics", fake_collect)
    monkeypatch.setattr(agent, "send_batch", fake_send)
    agent.run()
    return uploads


def test_failed_upload_is_retried_with_next_batch(agent, monkeypatch):
    uploads = _run_agent_cycles(agent, monkeypatch, 12, [False, True])

    assert [s["sample"] for s in uploads[0]] == list(range(6))
    assert [s["sample"] for s in uploads[1]] == list(range(12))
    assert agent.pending == []


def test_pending_samples_survive_restart(agent):
    import enhanced_agent

    agent._queue_sample({"sample": 1})
    restarted = enhanced_agent.MonitoringAgent("SYS-TEST", "key", "http://localhost:8000")
    other_system = enhanced_agent.MonitoringAgent("SYS-OTHER", "key", "http://localhost:8000")

    assert restarted.pending == [{"sample": 1}]
    assert other_system.pending == []


def test_pending_queue_keeps_newest_60_samples(agent):
    for sample in range(65):
        agent._queue_sample({"sample": sample})

    assert [s["sample"] for s in agent.pending] == list(range(5, 65))


def test_static_scan_does_not_block_and_result_arrives_later(agent, monkeypatch):
    import enhanced_agent

    release = threading.Event()
    finished = threading.Event()
    scans = []

    def slow_scan(exe_path, exe_hash):
        scans.append(exe_path)
        release.wait(timeout=10)
        agent._static_cache[exe_hash] = {"file_sha256": exe_hash}
        finished.set()

    monkeypatch.setattr(enhanced_agent, "STATIC_ANALYSIS_AVAILABLE", True)
    monkeypatch.setattr(agent, "_collect_static_evidence", slow_scan)

    started = time.perf_counter()
    assert agent._get_static_evidence_nowait("miner.exe", "abc") is None
    assert agent._get_static_evidence_nowait("miner.exe", "abc") is None
    assert time.perf_counter() - started < 1

    release.set()
    assert finished.wait(timeout=10)
    assert agent._get_static_evidence_nowait("miner.exe", "abc") == {"file_sha256": "abc"}
    assert scans == ["miner.exe"]


def test_file_hash_is_cached_until_the_file_changes(agent, tmp_path, monkeypatch):
    path = tmp_path / "program.exe"
    path.write_bytes(b"first")
    first = agent._file_hash(str(path))

    opened = []
    real_open = open
    monkeypatch.setattr("builtins.open", lambda *a, **k: opened.append(a[0]) or real_open(*a, **k))

    assert agent._file_hash(str(path)) == first
    assert opened == []

    path.write_bytes(b"changed")
    assert agent._file_hash(str(path)) != first
    assert opened == [str(path)]


def test_string_analysis_finds_each_indicator_type():
    from static_analysis.string_extractor import StringExtractor

    extractor = StringExtractor()
    address = "0x" + "a" * 40
    strings = ["plain text", f"send to {address}", "stratum+tcp://pool.example:3333", "XMRig 6.0", "see www.example.com now"]
    strings += [f"filler {i}" for i in range(extractor.ANALYSIS_BATCH_STRINGS)]
    strings.append("late monero string")

    analysis = extractor.analyze_strings(strings)

    assert ("ethereum_address", address) in analysis["crypto_addresses"]
    assert ("mining_pool", "stratum+tcp://") in analysis["crypto_addresses"]
    assert "stratum+tcp://pool.example:3333" not in analysis["mining_keywords"]
    assert {"xmrig", "stratum", "monero"} <= set(analysis["mining_keywords"])
    assert "www.example.com" in analysis["urls"]


def test_string_scan_limit_only_reads_the_start_of_a_file(tmp_path):
    from static_analysis.string_extractor import StringExtractor

    path = tmp_path / "big.bin"
    path.write_bytes(b"xmrig-near-start" + b"\x00" * 1000 + b"minerd-near-end")

    assert "minerd-near-end" not in StringExtractor(max_scan_bytes=100).extract_strings(str(path))
    assert "minerd-near-end" in StringExtractor().extract_strings(str(path))


def test_total_entropy_matches_the_known_value(tmp_path):
    from static_analysis.pe_analyzer import PEAnalyzer

    path = tmp_path / "bytes.bin"
    path.write_bytes(bytes(range(256)) * 10)
    assert PEAnalyzer()._calculate_total_entropy(str(path)) == 8.0

    path.write_bytes(b"ab" * 100)
    assert PEAnalyzer()._calculate_total_entropy(str(path)) == 1.0


def test_chunked_scan_matches_whole_file_scan_across_a_chunk_boundary(tmp_path, monkeypatch):
    from static_analysis.string_extractor import StringExtractor

    monkeypatch.setattr(StringExtractor, "CHUNK_BYTES", 1000)
    monkeypatch.setattr(StringExtractor, "CHUNK_OVERLAP_BYTES", 200)
    path = tmp_path / "program.exe"
    # The URL and keyword straddle the 1000-byte chunk boundary.
    path.write_bytes(b"\x00" * 985 + b"https://pool.example/a monero" + b"\x00" * 3000)

    whole = StringExtractor().extract_and_analyze(str(path))["analysis"]
    chunked = StringExtractor(max_scan_bytes=10_000).extract_and_analyze(str(path))["analysis"]

    assert "monero" in chunked["mining_keywords"]
    assert set(chunked["mining_keywords"]) == set(whole["mining_keywords"])
    assert set(whole["urls"]) <= set(chunked["urls"])


def test_entropy_limit_only_counts_the_start_of_a_file(tmp_path):
    from static_analysis.pe_analyzer import PEAnalyzer

    path = tmp_path / "program.exe"
    path.write_bytes(b"ab" * 500 + bytes(range(256)) * 100)

    assert PEAnalyzer(max_scan_bytes=1000)._calculate_total_entropy(str(path)) == 1.0
    assert PEAnalyzer()._calculate_total_entropy(str(path)) > 7


def test_process_detail_counts_refresh_every_30_seconds(agent, monkeypatch):
    import enhanced_agent

    scans = []
    real_iter = enhanced_agent.psutil.process_iter
    monkeypatch.setattr(
        enhanced_agent.psutil, "process_iter", lambda *a, **k: scans.append(1) or real_iter(*a, **k)
    )
    now = [1000.0]
    monkeypatch.setattr(enhanced_agent.time, "monotonic", lambda: now[0])

    first = agent._collect_process_counts()
    now[0] += 29
    assert agent._collect_process_counts()["thread"] == first["thread"]
    assert len(scans) == 1

    now[0] += 1
    agent._collect_process_counts()
    assert len(scans) == 2


def test_only_top_18_processes_get_detailed_lookups(agent, monkeypatch):
    import enhanced_agent

    def fake_proc(pid, cpu):
        proc = MagicMock()
        proc.info = {"pid": pid, "name": f"app{pid}.exe", "cpu_percent": cpu, "memory_percent": 0.0}
        proc.exe.return_value = None
        proc.create_time.return_value = 1000.0 + pid
        proc.parent.return_value = None
        proc.connections.return_value = []
        return proc

    procs = [fake_proc(pid, 5.0 + pid) for pid in range(30)]
    procs.append(fake_proc(99, 1.0))
    monkeypatch.setattr(enhanced_agent.psutil, "process_iter", lambda *a, **k: iter(procs))

    first = agent.filter_processes()
    second = agent.filter_processes()

    assert [p["pid"] for p in first] == list(range(29, 11, -1))
    assert first == second
    assert procs[0].exe.call_count == 0
    assert procs[29].exe.call_count == 2
    assert procs[29].parent.call_count == 1


def test_gpu_metrics_use_nvml_then_fall_back_to_nvidia_smi(agent, monkeypatch):
    fake_nvml = MagicMock()
    fake_nvml.nvmlDeviceGetMemoryInfo.return_value = MagicMock(used=1024 * 1024 * 512, total=1024 * 1024 * 1024)
    fake_nvml.nvmlDeviceGetUtilizationRates.return_value = MagicMock(gpu=25)
    monkeypatch.setitem(sys.modules, "pynvml", fake_nvml)
    smi_calls = []
    monkeypatch.setattr(agent, "_query_nvidia_smi", lambda: smi_calls.append(1) or (10.0, 100.0, 200.0))

    monkeypatch.setattr(agent, "_init_gpu_wmi", lambda: pytest.fail("WMI used despite NVML"))
    assert agent._collect_gpu_metrics()["source"] == "nvml"
    monkeypatch.setattr(agent, "_init_gpu_wmi", lambda: False)

    reading = agent._collect_gpu_metrics_nvidia()
    assert reading["source"] == "nvml"
    assert reading["utilization_percent"] == 25
    assert reading["memory_used_percent"] == 50
    assert smi_calls == []

    fake_nvml.nvmlDeviceGetUtilizationRates.side_effect = RuntimeError("driver reset")
    reading = agent._collect_gpu_metrics_nvidia()
    assert reading["source"] == "nvidia-smi"
    assert agent._collect_gpu_metrics_nvidia()["source"] == "nvidia-smi"
    assert fake_nvml.nvmlDeviceGetUtilizationRates.call_count == 3


def test_scan_limit_still_reads_imports_and_entropy():
    from static_analysis.pe_analyzer import PEAnalyzer

    full = PEAnalyzer().analyze_file(sys.executable)
    limited = PEAnalyzer(max_scan_bytes=32 * 1024 * 1024).analyze_file(sys.executable)

    assert limited["number_of_imports"] == full["number_of_imports"] > 0
    assert limited["suspicious_imports"] == full["suspicious_imports"]
    assert limited["total_entropy"] == full["total_entropy"]
    assert limited["sha256"] == full["sha256"]


def test_resent_sample_is_stored_once(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from backend import models  # noqa: F401
    from backend.database import Base
    from backend.models.metric import SystemMetric
    from backend.routes import metrics
    from backend.routes.metrics import MetricsBatch, receive_metrics_batch

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    monkeypatch.setattr(metrics, "MODEL_LOADED", False)

    sample = {
        "timestamp": "2026-11-05T10:00:00.123456",
        "cpu": {"percent": 10},
        "memory": {"percent": 10},
        "processes": [],
    }
    later = dict(sample, timestamp="2026-11-05T10:00:05.123456")
    user = {"system_id": "SYS-TEST"}
    for payload in ([sample], [sample, later]):
        asyncio.run(
            receive_metrics_batch(MetricsBatch(system_id="SYS-TEST", metrics=payload), user=user, db=db)
        )

    assert db.query(SystemMetric).count() == 2
    db.close()


def test_empty_batch_marks_system_online():
    from backend.routes.metrics import MetricsBatch, receive_metrics_batch

    system = MagicMock(status="offline", last_seen=None)
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = system

    result = asyncio.run(
        receive_metrics_batch(
            MetricsBatch(system_id="SYS-TEST", metrics=[]),
            user={"system_id": "SYS-TEST"},
            db=db,
        )
    )

    assert result["metrics_received"] == 0
    assert system.status == "online"
    assert system.last_seen is not None


@pytest.mark.parametrize(
    "cpu, memory, expected",
    [
        (90.0, 10.0, True),
        (10.0, 80.0, True),
        (89.9, 79.9, False),
    ],
)
def test_heuristic_fallback_thresholds(monkeypatch, cpu, memory, expected):
    from backend.routes import metrics

    monkeypatch.setattr(metrics, "MODEL_LOADED", False)
    result = metrics.perform_ml_inference(
        "SYS-FALLBACK",
        {"cpu": {"percent": cpu}, "memory": {"percent": memory}, "processes": []},
    )

    assert result[0] is expected
    assert result[1] == (0.80 if expected else 0.0)


def test_random_forest_uses_grid_search(monkeypatch, tmp_path):
    from ml_models import random_forest_model as rf
    from ml_models.feature_engineering import SELECTED_FEATURES

    rng = np.random.default_rng(42)
    labels = np.tile([0, 1], 200)
    data = rng.normal(size=(400, len(SELECTED_FEATURES))) + labels[:, None] * 3
    frame = pd.DataFrame(data, columns=SELECTED_FEATURES)
    frame["label"] = labels
    frame["timestamp"] = pd.date_range("2026-01-01", periods=len(frame), freq="5s")
    dataset = tmp_path / "data.csv"
    frame.to_csv(dataset, index=False)

    report_path = tmp_path / "report.txt"
    grid = {"n_estimators": [5, 10], "max_depth": [None, 3]}
    monkeypatch.setattr(rf, "SAVED_MODEL_PATH", tmp_path / "rf.pkl")
    monkeypatch.setattr(rf, "REPORT_PATH", report_path)
    monkeypatch.setattr(rf, "PARAM_GRID", grid)

    metrics = rf.train_random_forest(dataset)

    assert metrics["accuracy"] > 0.9
    assert (tmp_path / "rf.pkl").exists()
    assert "Best parameters:" in report_path.read_text(encoding="utf-8")


def _timed_frame():
    from ml_models.feature_engineering import SELECTED_FEATURES

    rng = np.random.default_rng(7)
    labels = np.array([0] * 400 + [1] * 100)
    data = rng.normal(size=(500, len(SELECTED_FEATURES))) + labels[:, None] * 3
    frame = pd.DataFrame(data, columns=SELECTED_FEATURES)
    frame["cpu_total"] = np.where(labels == 1, 97.0, 30.0) + rng.normal(size=500)
    frame["label"] = labels
    start = pd.Timestamp("2026-01-01")
    frame["timestamp"] = [start + pd.Timedelta(seconds=5 * i) for i in range(500)]
    return frame.sample(frac=1.0, random_state=1).reset_index(drop=True)


def test_chronological_split_tests_on_later_samples_of_each_class():
    from ml_models.splits import split_dataset

    train, val, test = split_dataset(_timed_frame())

    assert (len(train), len(val), len(test)) == (350, 75, 75)
    for label in (0, 1):
        latest_train = train[train["label"] == label]["timestamp"].max()
        latest_val = val[val["label"] == label]["timestamp"].max()
        assert latest_train < val[val["label"] == label]["timestamp"].min()
        assert latest_val < test[test["label"] == label]["timestamp"].min()


def test_split_rejects_unknown_strategy_and_missing_timestamp():
    from ml_models.splits import split_dataset

    frame = _timed_frame()
    with pytest.raises(ValueError):
        split_dataset(frame, "other")
    with pytest.raises(ValueError):
        split_dataset(frame.drop(columns="timestamp"))


def test_timestamp_is_never_a_model_feature():
    from ml_models.feature_engineering import SELECTED_FEATURES

    assert "timestamp" not in SELECTED_FEATURES
    assert len(SELECTED_FEATURES) == 20


def test_evaluation_writes_all_results(monkeypatch, tmp_path):
    from ml_models import evaluate_models as evaluation
    from ml_models import random_forest_model as rf
    from ml_models import xgboost_model as xgb
    from ml_models.splits import RANDOM

    dataset = tmp_path / "data.csv"
    _timed_frame().to_csv(dataset, index=False)
    models = tmp_path / "models"
    results_dir = tmp_path / "results"
    monkeypatch.setattr(rf, "PARAM_GRID", {"n_estimators": [5], "max_depth": [3]})
    monkeypatch.setattr(rf, "SAVED_MODEL_PATH", models / "random_forest.pkl")
    monkeypatch.setattr(rf, "REPORT_PATH", tmp_path / "rf.txt")
    monkeypatch.setattr(xgb, "SAVED_MODEL_PATH", models / "xgboost.pkl")
    monkeypatch.setattr(xgb, "REPORT_PATH", tmp_path / "xgb.txt")
    rf.train_random_forest(dataset)
    xgb.train_xgboost(dataset)

    random_results = rf.train_random_forest(dataset, RANDOM, save=False)
    results = evaluation.evaluate_models(
        {"Random Forest": lambda path: random_results},
        dataset_path=dataset,
        models_dir=models,
        results_dir=results_dir,
    )

    assert set(results["chronological"]) == {"XGBoost", "Random Forest", "CPU rule (baseline)"}
    assert np.array(results["confusion_matrices"]["XGBoost"]).sum() == 75
    assert len(results["shap_importance"]) == 20
    for name in ("metrics.json", "results.md", "confusion_matrix.png", "shap_importance.png"):
        assert (results_dir / name).stat().st_size > 0
    assert "Chronological test split" in (results_dir / "results.md").read_text(encoding="utf-8")


def test_agent_entry_point_loads_enhanced_agent():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import runpy, enhanced_agent;"
            "g = runpy.run_path('agent.py', run_name='not_main');"
            "assert g['main'] is enhanced_agent.main",
        ],
        cwd=AGENT_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, result.stderr


def test_agent_version_matches_auto_updater_and_backend():
    import auto_updater
    import enhanced_agent
    from backend.routes import agent as agent_routes

    assert enhanced_agent.AGENT_VERSION == "1.0"
    assert auto_updater.CURRENT_VERSION == enhanced_agent.AGENT_VERSION
    assert agent_routes.AGENT_LATEST_VERSION == enhanced_agent.AGENT_VERSION
    assert f"v{enhanced_agent.AGENT_VERSION}" in (enhanced_agent.__doc__ or "")


def test_api_key_is_hashed_at_rest_and_masked_after_registration():
    from fastapi import HTTPException
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from backend import models  # noqa: F401
    from backend.database import Base
    from backend.models.user import User
    from backend.routes.auth import (
        AgentValidateRequest,
        ProfileUpdate,
        UserLogin,
        UserRegister,
        agent_validate,
        get_profile,
        login,
        register,
        update_profile,
        verify_api_key,
    )

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()

    try:
        reg = asyncio.run(
            register(
                UserRegister(
                    email="apikey@test.com",
                    password="Password123!",
                    full_name="API Key User",
                ),
                db=db,
            )
        )
        raw_key = reg["user"]["api_key"]
        system_id = reg["user"]["system_id"]

        stored_user = db.query(User).filter(User.email == "apikey@test.com").first()
        assert stored_user is not None
        assert stored_user.api_key != raw_key
        assert stored_user.api_key.startswith("sha256$")
        assert stored_user.api_key == User.hash_api_key(raw_key)

        verified = verify_api_key(x_api_key=raw_key, db=db)
        assert verified["system_id"] == system_id
        assert verified["api_key"] != raw_key

        with pytest.raises(HTTPException):
            verify_api_key(x_api_key="wrong-key", db=db)

        valid_check = asyncio.run(
            agent_validate(
                AgentValidateRequest(system_id=system_id, api_key=raw_key),
                db=db,
            )
        )
        assert valid_check["valid"] is True

        logged_in = asyncio.run(
            login(UserLogin(email="apikey@test.com", password="Password123!"), db=db)
        )
        assert logged_in["user"]["api_key"] != raw_key
        assert "•" in logged_in["user"]["api_key"] or "*" in logged_in["user"]["api_key"]

        profile = asyncio.run(get_profile(email="apikey@test.com", db=db))
        assert profile["api_key"] != raw_key
        assert profile["api_key"] == logged_in["user"]["api_key"]

        from backend.routes.auth import regenerate_api_key

        updated = asyncio.run(
            update_profile(
                ProfileUpdate(full_name="Updated API Key User"),
                email="apikey@test.com",
                db=db,
            )
        )
        assert updated["user"]["api_key"] != raw_key
        assert updated["user"]["api_key"] == logged_in["user"]["api_key"]

        rotated = asyncio.run(regenerate_api_key(email="apikey@test.com", db=db))
        new_raw_key = rotated["api_key"]
        assert new_raw_key != raw_key
        assert not new_raw_key.startswith("sha256$")

        db.refresh(stored_user)
        assert stored_user.api_key == User.hash_api_key(new_raw_key)
        assert verify_api_key(x_api_key=new_raw_key, db=db)["system_id"] == system_id
        with pytest.raises(HTTPException):
            verify_api_key(x_api_key=raw_key, db=db)
    finally:
        db.close()


def test_agent_gui_shield_icon_and_key_masking():
    """Verify the redesigned tray agent icon generator, single-instance guard, and credential masking helper."""
    import sys

    agent_dir = str(Path(__file__).resolve().parents[1] / "monitoring_agent")
    if agent_dir not in sys.path:
        sys.path.insert(0, agent_dir)

    from agent_gui import SingleInstanceGuard, _mask_api_key, create_shield_icon

    icon = create_shield_icon(64)
    assert icon is not None
    assert icon.size == (64, 64)

    assert _mask_api_key("") == "Not configured"
    assert _mask_api_key("abcdef123456") == "••••••••••••3456"

    guard1 = SingleInstanceGuard()
    guard2 = SingleInstanceGuard()
    try:
        assert guard1.acquire() is True
        assert guard2.acquire() is False
        assert guard1.check_wakeup_signal() is True
        assert guard1.check_wakeup_signal() is False
    finally:
        guard2.release()
        guard1.release()


def test_windows_domain_shift_prevents_idle_false_positives_and_detects_miners():
    """Verify Linux-to-Windows telemetry adaptation suppresses mem_cached=0 false positives while catching miners."""
    from backend.routes import metrics

    if not metrics.MODEL_LOADED:
        metrics._init_model()
    assert metrics.MODEL_LOADED is True

    idle_windows = {
        "cpu": {"percent": 3.1},
        "cpu_times": {"user": 2.0, "system": 1.1, "idle": 96.9, "iowait": 0.0, "irq": 0.0, "softirq": 0.0},
        "memory": {
            "percent": 75.6,
            "used": 12_100_000_000,
            "available": 3_900_000_000,
            "active": 0,
            "cached": 0,
        },
        "load_avg": {"min1": 0.2, "min5": 0.2, "min15": 0.2},
        "network": {"bytes_recv_delta": 1500, "bytes_sent_delta": 800},
        "process_counts": {"running": 4, "total": 185, "thread": 2400},
        "processes": [],
    }
    idle_res = metrics.perform_ml_inference("SYS-WIN-IDLE", idle_windows)
    assert idle_res[0] is False
    assert idle_res[1] < 0.50

    moderate_windows = dict(
        idle_windows,
        cpu={"percent": 35.0},
        cpu_times={"user": 28.0, "system": 7.0, "idle": 65.0, "iowait": 0.0, "irq": 0.0, "softirq": 0.0},
        load_avg={"min1": 1.2, "min5": 1.1, "min15": 1.0},
    )
    mod_res = metrics.perform_ml_inference("SYS-WIN-MOD", moderate_windows)
    assert mod_res[0] is False
    assert mod_res[1] < 0.50

    miner_windows_high_ram = {
        "cpu": {"percent": 98.0},
        "cpu_times": {"user": 92.0, "system": 6.0, "idle": 2.0, "iowait": 0.0, "irq": 0.0, "softirq": 0.0},
        "memory": {
            "percent": 82.0,
            "used": 13_120_000_000,
            "available": 2_880_000_000,
            "active": 0,
            "cached": 0,
        },
        "load_avg": {"min1": 4.2, "min5": 4.0, "min15": 3.8},
        "network": {"bytes_recv_delta": 2400, "bytes_sent_delta": 1800},
        "process_counts": {"running": 8, "total": 190, "thread": 2450},
        "processes": [{"name": "xmrig.exe", "cpu_percent": 94.0, "memory_percent": 14.0}],
    }
    miner_res = metrics.perform_ml_inference("SYS-WIN-MINER1", miner_windows_high_ram)
    assert miner_res[0] is True
    assert miner_res[1] >= 0.80
    assert miner_res[3].get("mem_cached", {}).get("shap", 0.0) == 0.0

    miner_windows_32gb = dict(
        miner_windows_high_ram,
        memory={
            "percent": 45.0,
            "used": 14_400_000_000,
            "available": 17_600_000_000,
            "active": 0,
            "cached": 0,
        },
    )
    miner_32gb_res = metrics.perform_ml_inference("SYS-WIN-MINER2", miner_windows_32gb)
    assert miner_32gb_res[0] is True
    assert miner_32gb_res[1] >= 0.80




