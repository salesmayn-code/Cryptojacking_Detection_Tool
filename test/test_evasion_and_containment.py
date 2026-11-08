"""Tests for evasion-resilient cryptojacking detection, YARA scanning, active containment, and Windows benchmarking."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = ROOT / "monitoring_agent"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))


def test_yara_scanner_detects_miners_and_flags_upx_separately():
    from static_analysis.yara_scanner import YARA_AVAILABLE, YaraMinerScanner

    if not YARA_AVAILABLE:
        pytest.skip("yara-python is not installed")

    scanner = YaraMinerScanner()

    miner_blob = (
        b"XMRig 6.21 --donate-level=1 --cpu-max-threads-pct 25 "
        b"stratum+tcp://pool.supportxmr.com:3333 mining.subscribe mining.authorize "
        b"44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
    )
    res_miner = scanner.scan_bytes(miner_blob)
    assert res_miner["yara_matched"] is True
    assert "CryptoMiner_XMRig_Signature" in res_miner["miner_rules"]
    assert "CryptoMiner_Stratum_Protocol" in res_miner["miner_rules"]
    assert "CryptoMiner_Wallet_And_Pool_Config" in res_miner["miner_rules"]
    assert res_miner["max_severity"] == "critical"

    upx_only_pe = b"MZ" + b"\x00" * 60 + b"UPX0\x00\x00UPX1\x00\x00UPX!"
    res_upx = scanner.scan_bytes(upx_only_pe)
    assert res_upx["is_packed"] is True
    assert res_upx["packed_rules"] == ["Packer_UPX_Sections"]
    assert res_upx["yara_matched"] is False

    res_python = scanner.scan_file(sys.executable)
    assert res_python["yara_matched"] is False


def test_agent_nvml_per_pid_gpu_and_sanitized_cmdline(monkeypatch, tmp_path):
    import enhanced_agent

    monkeypatch.setattr(enhanced_agent, "CONFIG_DIR", tmp_path)
    agent = enhanced_agent.MonitoringAgent("SYS-GPU", "key", "http://localhost:8000")

    fake_nvml = MagicMock()
    fake_nvml.nvmlDeviceGetCount.return_value = 1
    fake_nvml.nvmlDeviceGetHandleByIndex.return_value = "handle0"
    fake_nvml.nvmlDeviceGetMemoryInfo.return_value = MagicMock(used=1024 * 1024 * 512, total=1024 * 1024 * 4096)
    fake_nvml.nvmlDeviceGetUtilizationRates.return_value = MagicMock(gpu=38)
    fake_proc = MagicMock(pid=4242, usedGpuMemory=512 * 1024 * 1024)
    fake_nvml.nvmlDeviceGetComputeRunningProcesses.return_value = [fake_proc]
    fake_nvml.nvmlDeviceGetGraphicsRunningProcesses.return_value = []
    monkeypatch.setitem(sys.modules, "pynvml", fake_nvml)

    reading = agent._query_nvml()
    assert reading is not None
    gpu_pids = agent._gpu_compute_pids
    assert 4242 in gpu_pids
    assert gpu_pids[4242] == pytest.approx(512.0, abs=0.5)

    mock_ps_proc = MagicMock()
    mock_ps_proc.cmdline.return_value = [
        "updater.exe",
        "--donate-level",
        "1",
        "--password",
        "secret_wallet_pass",
        "--api-access-token=tok999",
        "-a",
        "rx/0",
    ]
    sanitized = agent._safe_proc_cmdline(mock_ps_proc)
    assert "secret_wallet_pass" not in sanitized
    assert "tok999" not in sanitized
    assert "--password <redacted>" in sanitized
    assert "--api-access-token=<redacted>" in sanitized
    assert "--donate-level 1" in sanitized


def test_dynamic_monitor_throttled_afk_and_persistent_tls():
    from dynamic_analysis import DynamicBehaviorMonitor

    monitor = DynamicBehaviorMonitor(max_samples=24)
    t0 = datetime(2026, 11, 1, 10, 0, 0)

    # 1. Throttled ~22% CPU miner over 6 samples with high ctx switches + low IO + :443 TLS
    throttled_proc = {
        "pid": 8801,
        "name": "svc_host_helper.exe",
        "exe_path": "C:\\ProgramData\\Helper\\svc_host_helper.exe",
        "cpu_percent": 22.0,
        "memory_percent": 5.5,
        "network_summary": {
            "has_external_connection": True,
            "established_count": 1,
            "unique_remote_ip_count": 1,
            "remote_ports": [443],
            "has_tls_external": True,
        },
    }
    ev = {}
    for i in range(6):
        sample = dict(
            throttled_proc,
            ctx_switches_total=1000 + i * 1400,
            io_bytes_total=500_000 + i * 25_000,
        )
        ev = monitor.evaluate_system(
            "SYS-THROT", [sample], t0 + timedelta(seconds=i * 5), cpu_percent=26.0, memory_percent=52.0
        )

    assert ev["throttled_count"] >= 1
    assert ev["persistent_tls_count"] >= 1
    assert ev["sustained_processes"][0]["compute_io_bound"] is True
    assert ev["sustained_processes"][0]["duty_cycle_ratio"] >= 0.60

    # 2. Idle-aware ("--pause-on-active") surge when user goes AFK
    afk_proc = {
        "pid": 8802,
        "name": "idle_worker.exe",
        "exe_path": "C:\\Users\\op\\AppData\\Local\\Temp\\idle_worker.exe",
        "memory_percent": 6.0,
        "network_summary": {"has_external_connection": False, "remote_ports": []},
    }
    for i in range(3):
        monitor.evaluate_system(
            "SYS-AFK",
            [dict(afk_proc, cpu_percent=1.2)],
            t0 + timedelta(seconds=i * 5),
            cpu_percent=5.0,
            memory_percent=48.0,
            user_idle_seconds=2.0,
        )
    for i in range(3, 6):
        ev_afk = monitor.evaluate_system(
            "SYS-AFK",
            [dict(afk_proc, cpu_percent=30.0)],
            t0 + timedelta(seconds=i * 5),
            cpu_percent=34.0,
            memory_percent=50.0,
            user_idle_seconds=60.0,
        )

    assert ev_afk["idle_surge_count"] >= 1
    assert ev_afk["sustained_processes"][0]["idle_surge_detected"] is True
    assert ev_afk["sustained_processes"][0]["mean_idle_cpu"] >= 20.0
    assert ev_afk["sustained_processes"][0]["mean_active_cpu"] < 5.0


def test_masquerading_wsl_and_evasion_inference(monkeypatch):
    from backend.routes import metrics
    from dynamic_analysis import DynamicBehaviorMonitor

    if not metrics.MODEL_LOADED:
        metrics._init_model()

    isolated = DynamicBehaviorMonitor(max_samples=24)
    monkeypatch.setattr(metrics, "_behavior_monitor", isolated)

    # Genuine System32 dllhost.exe must remain benign
    legit_dllhost = {
        "pid": 1100,
        "name": "dllhost.exe",
        "cpu_percent": 18.0,
        "memory_percent": 1.2,
        "exe_path": "C:\\Windows\\System32\\dllhost.exe",
        "publisher": "CN=Microsoft Windows, O=Microsoft Corporation",
        "signature_status": "valid",
        "network_summary": {"has_external_connection": False, "remote_ports": []},
    }
    res_legit = metrics.analyze_processes([legit_dllhost])
    assert res_legit[0] == []

    # Masqueraded dllhost.exe in AppData with TLS :443 + YARA must NOT be skipped
    fake_dllhost = {
        "pid": 9911,
        "name": "dllhost.exe",
        "create_time": 1700000000.0,
        "cpu_percent": 22.0,
        "memory_percent": 7.5,
        "exe_path": "C:\\Users\\op\\AppData\\Roaming\\Host\\dllhost.exe",
        "publisher": "",
        "signature_status": "unsigned",
        "cmdline": "dllhost.exe --cpu-max-threads-pct 25 -a rx/0",
        "network_summary": {
            "has_external_connection": True,
            "established_count": 1,
            "unique_remote_ip_count": 1,
            "remote_ports": [443],
            "remote_ips_sample": ["198.51.100.77"],
            "has_tls_external": True,
            "resolved_domains": ["xmr-eu1.nanopool.org"],
            "has_pool_domain": True,
        },
        "static_analysis": {
            "yara_matched": True,
            "yara_rules": ["CryptoMiner_XMRig_Signature"],
            "yara_severity": "critical",
        },
    }
    frame = {
        "timestamp": "2026-11-08T10:00:00",
        "activity": {"user_idle_seconds": 10.0, "is_idle": False},
        "cpu": {"percent": 24.5},
        "cpu_times": {"user": 20.0, "system": 4.5, "idle": 75.5, "iowait": 0.0, "irq": 0.0, "softirq": 0.0},
        "memory": {
            "percent": 58.0,
            "used": 9_000_000_000,
            "available": 7_000_000_000,
            "active": 0,
            "cached": 0,
        },
        "load_avg": {"min1": 1.8, "min5": 1.6, "min15": 1.4},
        "network": {"bytes_recv_delta": 1200, "bytes_sent_delta": 900},
        "process_counts": {"running": 5, "total": 180, "thread": 2300},
        "processes": [fake_dllhost],
    }

    inf = metrics.perform_ml_inference("SYS-MASQ", frame)
    assert inf[0] is True
    assert inf[1] >= 0.80
    risk, sigs = metrics._compute_risk_score(
        is_cryptojacking=inf[0],
        confidence=inf[1],
        processes=[fake_dllhost],
        miner_indicators=inf[4],
        threat_intel_hits=inf[7],
        miner_network_hits=inf[8],
        policy_hits=inf[9],
        dynamic_evidence=inf[10],
    )
    assert risk >= metrics.ALERT_THRESHOLD_SCORE
    assert {"cmdline_sigma_match", "yara_signature_match", "tls_stealth_tunnel", "dns_pool_domain", "identity_spoof"} <= set(sigs)

    # WSL2 benign high CPU vs corroborated WSL2 pool activity
    wsl_benign = {
        "pid": 7710,
        "name": "vmmemWSL",
        "cpu_percent": 82.0,
        "memory_percent": 22.0,
        "network_summary": {"has_external_connection": False, "remote_ports": []},
    }
    assert metrics.analyze_processes([wsl_benign])[0] == []

    wsl_miner = {
        "pid": 7711,
        "name": "vmmemWSL",
        "cpu_percent": 76.0,
        "memory_percent": 18.0,
        "network_summary": {
            "has_external_connection": True,
            "established_count": 1,
            "unique_remote_ip_count": 1,
            "remote_ports": [3333],
            "has_pool_domain": True,
            "resolved_domains": ["pool.supportxmr.com"],
        },
    }
    assert len(metrics.analyze_processes([wsl_miner])[0]) == 1

    # Benign 7-Zip compression should pass allowlist
    seven_zip = {
        "pid": 5210,
        "name": "7z.exe",
        "cpu_percent": 85.0,
        "memory_percent": 8.0,
        "exe_path": "C:\\Program Files\\7-Zip\\7z.exe",
        "publisher": "Igor Pavlov",
        "signature_status": "valid",
        "network_summary": {"has_external_connection": False, "remote_ports": []},
    }
    wl, reason = metrics._check_whitelist([seven_zip])
    assert wl is True
    assert reason.startswith("policy_allow:")

    # Benign Chrome browsing on :443 should NOT flag stealth TLS or alert
    chrome = {
        "pid": 4120,
        "name": "chrome.exe",
        "cpu_percent": 24.0,
        "memory_percent": 12.0,
        "exe_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "publisher": "CN=Google LLC",
        "signature_status": "valid",
        "network_summary": {
            "has_external_connection": True,
            "established_count": 4,
            "unique_remote_ip_count": 7,
            "remote_ports": [443],
            "has_tls_external": True,
            "resolved_domains": ["github.com"],
        },
    }
    assert metrics.analyze_processes([chrome])[5] == []


def test_containment_queue_api_lifecycle_and_guardrails():
    from backend import models  # noqa: F401
    from backend.database import Base, get_db
    from backend.main import app
    from backend.models.agent_command import AgentCommand
    from backend.models.alert import Alert
    from backend.models.audit_log import AuditLog
    from backend.models.system import MonitoredSystem
    from backend.models.user import User
    from backend.routes.auth import create_access_token, pwd_context

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)
        db = TestingSessionLocal()

        owner_raw_key = "owner-agent-raw-key-123456"
        owner = User(
            email="soc_owner@test.com",
            hashed_password=pwd_context.hash("Pass123!"),
            full_name="SOC Owner",
            system_id="SYS-SOC-1",
            api_key=User.hash_api_key(owner_raw_key),
            role="user",
        )
        other = User(
            email="other_user@test.com",
            hashed_password=pwd_context.hash("Pass123!"),
            full_name="Other User",
            system_id="SYS-OTHER-1",
            api_key=User.hash_api_key("other-raw-key-123456"),
            role="user",
        )
        sys_owner = MonitoredSystem(system_id="SYS-SOC-1", system_name="WS-01", owner_email="soc_owner@test.com", status="online")
        sys_other = MonitoredSystem(system_id="SYS-OTHER-1", system_name="WS-02", owner_email="other_user@test.com", status="online")
        db.add_all([owner, other, sys_owner, sys_other])
        db.commit()

        alert = Alert(
            system_id="SYS-SOC-1",
            timestamp=datetime.utcnow(),
            alert_type="cryptojacking_detected",
            confidence=0.96,
            detection_method="ml_model",
            metrics={
                "process_context": [
                    {
                        "name": "worker_svc.exe",
                        "pid": 9102,
                        "create_time": 1700001234.5,
                        "exe_path": "C:\\Users\\op\\AppData\\Local\\Temp\\worker_svc.exe",
                        "exe_hash": "a" * 64,
                        "remote_ips_sample": ["198.51.100.42"],
                    }
                ]
            },
            suspicious_processes=["worker_svc.exe"],
            status="unread",
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        alert_id = alert.id
        db.close()

        owner_token = create_access_token({"sub": "soc_owner@test.com", "role": "user"})
        other_token = create_access_token({"sub": "other_user@test.com", "role": "user"})
        owner_headers = {"Authorization": f"Bearer {owner_token}"}
        other_headers = {"Authorization": f"Bearer {other_token}"}

        # 1. Cross-user authorization check
        resp_forbidden = client.post(
            f"/api/alerts/{alert_id}/actions",
            json={"action": "suspend_process"},
            headers=other_headers,
        )
        assert resp_forbidden.status_code == 403

        # 2. Protected OS binary guardrail
        resp_os = client.post(
            f"/api/alerts/{alert_id}/actions",
            json={
                "action": "kill_process_tree",
                "pid": 512,
                "process_name": "csrss.exe",
                "exe_path": "C:\\Windows\\System32\\csrss.exe",
            },
            headers=owner_headers,
        )
        assert resp_os.status_code == 400

        # 3. Private/loopback IP firewall guardrail
        resp_local_ip = client.post(
            f"/api/alerts/{alert_id}/actions",
            json={"action": "block_ip", "remote_ip": "127.0.0.1"},
            headers=owner_headers,
        )
        assert resp_local_ip.status_code == 400

        resp_priv_ip = client.post(
            f"/api/alerts/{alert_id}/actions",
            json={"action": "block_ip", "remote_ip": "192.168.1.10"},
            headers=owner_headers,
        )
        assert resp_priv_ip.status_code == 400

        # 3b. Valid public IP firewall queue succeeds
        resp_pub_ip = client.post(
            f"/api/alerts/{alert_id}/actions",
            json={"action": "block_ip", "remote_ip": "93.184.216.34"},
            headers=owner_headers,
        )
        assert resp_pub_ip.status_code == 200
        assert resp_pub_ip.json()["command"]["target_payload"]["remote_ip"] == "93.184.216.34"

        # 4. Queue suspend command
        resp_queue = client.post(
            f"/api/alerts/{alert_id}/actions",
            json={"action": "suspend_process"},
            headers=owner_headers,
        )
        assert resp_queue.status_code == 200
        cmd_id = resp_queue.json()["command"]["id"]
        assert resp_queue.json()["command"]["status"] == "pending"

        # 5. Heartbeat metric batch atomically claims pending commands -> dispatched
        resp_hb = client.post(
            "/api/metrics/batch",
            json={"system_id": "SYS-SOC-1", "metrics": []},
            headers={"X-API-Key": owner_raw_key},
        )
        assert resp_hb.status_code == 200
        pending = resp_hb.json()["pending_commands"]
        assert len(pending) == 2
        susp_pending = next(c for c in pending if c["id"] == cmd_id)
        assert susp_pending["target_payload"]["pid"] == 9102

        # Second heartbeat must not re-dispatch already claimed command
        resp_hb2 = client.post(
            "/api/metrics/batch",
            json={"system_id": "SYS-SOC-1", "metrics": []},
            headers={"X-API-Key": owner_raw_key},
        )
        assert resp_hb2.status_code == 200
        assert resp_hb2.json()["pending_commands"] == []

        # 6. Agent reports completion
        resp_res = client.post(
            f"/api/agent/commands/{cmd_id}/result",
            json={"status": "completed", "result_data": {"pid": 9102, "state": "suspended"}},
            headers={"X-API-Key": owner_raw_key},
        )
        assert resp_res.status_code == 200
        assert resp_res.json()["command"]["status"] == "completed"

        # 7. Operator sees completion + audit log entry
        resp_list = client.get(f"/api/alerts/{alert_id}/actions", headers=owner_headers)
        assert resp_list.status_code == 200
        cmds = resp_list.json()["commands"]
        assert len(cmds) == 2
        susp_listed = next(c for c in cmds if c["id"] == cmd_id)
        assert susp_listed["status"] == "completed"
        assert susp_listed["result_data"]["state"] == "suspended"

        # 8. System persistence audit endpoint
        resp_pa = client.post("/api/systems/SYS-SOC-1/persistence-audit", headers=owner_headers)
        assert resp_pa.status_code == 200
        assert resp_pa.json()["command"]["action"] == "audit_persistence"

        # 9. Deleting alert detaches linked commands without FK failure
        resp_del = client.delete(f"/api/alerts/{alert_id}", headers=owner_headers)
        assert resp_del.status_code == 200

        db_check = TestingSessionLocal()
        try:
            detached = db_check.query(AgentCommand).filter(AgentCommand.id == cmd_id).first()
            assert detached is not None
            assert detached.alert_id is None
            assert db_check.query(AuditLog).filter(AuditLog.action == "containment.suspend_process").count() == 1
        finally:
            db_check.close()
    finally:
        app.dependency_overrides.clear()


def test_agent_executor_toctou_quarantine_firewall_and_persistence(monkeypatch, tmp_path):
    import enhanced_agent

    monkeypatch.setattr(enhanced_agent, "CONFIG_DIR", tmp_path)
    agent = enhanced_agent.MonitoringAgent("SYS-EXEC", "key", "http://localhost:8000")
    agent.quarantine_dir = tmp_path / "quarantine"

    # 1. Anti-TOCTOU create_time reuse protection
    reused_proc = MagicMock()
    reused_proc.name.return_value = "worker.exe"
    reused_proc.create_time.return_value = 9000.0
    monkeypatch.setattr(enhanced_agent.psutil, "Process", lambda pid: reused_proc)

    status, _, err = agent.execute_containment_command(
        {
            "action": "suspend_process",
            "target_payload": {
                "pid": 1234,
                "create_time": 1000.0,
                "process_name": "worker.exe",
            },
        }
    )
    assert status == "failed"
    assert "reuse detected" in err.lower()

    # 2. Protected path cannot be quarantined even without PID
    status, _, err = agent.execute_containment_command(
        {
            "action": "quarantine_binary",
            "target_payload": {
                "process_name": "csrss.exe",
                "exe_path": "C:\\Windows\\System32\\csrss.exe",
            },
        }
    )
    assert status == "failed"
    assert "protected" in err.lower()

    # 3. Genuine quarantine with hash match moves binary & writes companion metadata
    sample_dir = tmp_path / "drop"
    sample_dir.mkdir(parents=True, exist_ok=True)
    miner_bin = sample_dir / "hidden_miner.exe"
    payload = b"MZ-fake-miner-binary"
    miner_bin.write_bytes(payload)
    expected_sha = hashlib.sha256(payload).hexdigest()

    # Mismatched hash must refuse quarantine
    status_bad, _, err_bad = agent.execute_containment_command(
        {
            "action": "quarantine_binary",
            "target_payload": {
                "process_name": "hidden_miner.exe",
                "exe_path": str(miner_bin),
                "exe_hash": "0" * 64,
            },
        }
    )
    assert status_bad == "failed"
    assert "sha-256" in err_bad.lower()
    assert miner_bin.exists()

    # Valid hash quarantines binary + metadata JSON
    status_ok, data_ok, err_ok = agent.execute_containment_command(
        {
            "action": "quarantine_binary",
            "target_payload": {
                "process_name": "hidden_miner.exe",
                "exe_path": str(miner_bin),
                "exe_hash": expected_sha,
            },
        }
    )
    assert err_ok is None
    assert status_ok == "completed"
    assert not miner_bin.exists()
    q_path = Path(data_ok["quarantine_path"])
    assert q_path.exists()
    meta_path = q_path.with_suffix(".json")
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["sha256"] == expected_sha

    # 4. Block IP list-args netsh invocation + local IP guard
    status_local, _, _ = agent.execute_containment_command(
        {"action": "block_ip", "target_payload": {"remote_ip": "10.0.0.5"}}
    )
    assert status_local == "failed"

    recorded_cmds = []

    def fake_run(cmd, **kwargs):
        recorded_cmds.append((cmd, kwargs))
        return MagicMock(returncode=0, stdout="Ok.", stderr="")

    monkeypatch.setattr(enhanced_agent.os, "name", "nt")
    monkeypatch.setattr(enhanced_agent.subprocess, "run", fake_run)
    status_fw, fw_data, fw_err = agent.execute_containment_command(
        {"action": "block_ip", "target_payload": {"remote_ip": "93.184.216.34"}}
    )
    assert fw_err is None
    assert status_fw == "completed"
    assert fw_data["blocked_ip"] == "93.184.216.34"
    assert recorded_cmds[0][0][:4] == ["netsh", "advfirewall", "firewall", "add"]
    assert "shell" not in recorded_cmds[0][1]

    # 5. Persistence scoring
    susp_entry = agent._score_persistence_entry(
        "HKCU\\Run", "SysUpdater", "C:\\Users\\op\\AppData\\Local\\Temp\\xmrig.exe --donate-level 1"
    )
    assert susp_entry["suspicious"] is True
    assert len(susp_entry["reasons"]) >= 2

    clean_entry = agent._score_persistence_entry(
        "Service(Running)", "AudioSrv", "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted"
    )
    assert clean_entry["suspicious"] is False


def test_windows_ablation_benchmark_produces_metrics_and_chart(tmp_path):
    from ml_models.benchmark_windows import run_benchmark

    report = run_benchmark(results_dir=tmp_path, episodes_per_scenario=2, frames_per_episode=6)
    assert (tmp_path / "windows_benchmark.json").stat().st_size > 0
    assert (tmp_path / "windows_ablation.png").stat().st_size > 0

    evasion = report["detectors"]["CryptoDetect Evasion-Resilient"]
    naive = report["detectors"]["Naive CPU >= 90% Rule"]
    assert evasion["recall"] >= 0.90
    assert evasion["fpr"] == 0.0
    assert evasion["f1"] > naive["f1"]
