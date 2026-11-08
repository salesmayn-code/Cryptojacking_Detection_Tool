"""Runtime behavioral monitor for cryptojacking-oriented process patterns."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Deque, Dict, List, Tuple

MINER_NETWORK_PORTS = {3333, 3334, 4444, 5555, 6666, 7777, 9999, 14433, 14444}
TLS_TUNNEL_PORTS = {443, 8443}
KNOWN_BROWSER_NAMES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "iexplore.exe",
    "teams.exe",
    "ms-teams.exe",
    "onedrive.exe",
    "discord.exe",
    "slack.exe",
    "spotify.exe",
}


@dataclass
class ProcessWindowSample:
    cpu_percent: float
    memory_percent: float
    miner_network_hit: bool
    timestamp: datetime
    user_idle_seconds: float = 0.0
    tls_external: bool = False
    pool_domain_hit: bool = False
    ctx_switches: int = 0
    io_bytes: int = 0
    gpu_compute_active: bool = False


class DynamicBehaviorMonitor:
    """Keep per-system sliding telemetry windows and extract evasion-resilient miner behaviors."""

    def __init__(self, max_samples: int = 24):
        self.max_samples = max_samples
        self._history: Dict[str, Dict[str, Deque[ProcessWindowSample]]] = defaultdict(dict)

    @staticmethod
    def _process_key(proc: Dict[str, Any]) -> str:
        name = str(proc.get("name") or "unknown").strip().lower()
        exe_hash = str(proc.get("exe_hash") or "").strip().lower()
        exe_path = str(proc.get("exe_path") or "").strip().lower()
        if exe_hash:
            return f"{name}|{exe_hash}"
        if exe_path:
            return f"{name}|{exe_path}"
        return name

    def _window_for(self, system_id: str, proc_key: str) -> Deque[ProcessWindowSample]:
        sys_state = self._history[system_id]
        if proc_key not in sys_state:
            sys_state[proc_key] = deque(maxlen=self.max_samples)
        return sys_state[proc_key]

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _safe_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def observe(
        self,
        system_id: str,
        process: Dict[str, Any],
        now: datetime,
        user_idle_seconds: float = 0.0,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Record one process sample and return sustained/evasion indicators + forensics."""
        proc_key = self._process_key(process)
        window = self._window_for(system_id, proc_key)

        name_norm = str(process.get("name") or "unknown").strip().lower()
        cpu = self._safe_float(process.get("cpu_percent"), 0.0)
        mem = self._safe_float(process.get("memory_percent"), 0.0)
        net_summary = process.get("network_summary") or {}
        if not isinstance(net_summary, dict):
            net_summary = {}

        remote_ports = net_summary.get("remote_ports") or []
        parsed_ports = [self._safe_int(p, -1) for p in remote_ports if str(p).isdigit()]
        miner_network_hit = any(p in MINER_NETWORK_PORTS for p in parsed_ports)
        pool_domain_hit = bool(net_summary.get("has_pool_domain"))
        has_external = bool(net_summary.get("has_external_connection"))
        established = self._safe_int(net_summary.get("established_count"), 0)
        unique_ips = self._safe_int(net_summary.get("unique_remote_ip_count"), 0)
        tls_external = (
            has_external
            and established >= 1
            and 1 <= unique_ips <= 4
            and (bool(net_summary.get("has_tls_external")) or any(p in TLS_TUNNEL_PORTS for p in parsed_ports))
            and name_norm not in KNOWN_BROWSER_NAMES
        )

        ctx_switches = max(0, self._safe_int(process.get("ctx_switches_total"), 0))
        io_bytes = max(0, self._safe_int(process.get("io_bytes_total"), 0))
        gpu_active = bool(process.get("gpu_compute_active"))

        window.append(
            ProcessWindowSample(
                cpu_percent=cpu,
                memory_percent=mem,
                miner_network_hit=miner_network_hit or pool_domain_hit,
                timestamp=now,
                user_idle_seconds=max(0.0, self._safe_float(user_idle_seconds, 0.0)),
                tls_external=tls_external,
                pool_domain_hit=pool_domain_hit,
                ctx_switches=ctx_switches,
                io_bytes=io_bytes,
                gpu_compute_active=gpu_active,
            )
        )

        if len(window) < 3:
            return False, {}

        samples = list(window)
        recent = samples[-3:]
        sustained_cpu = all(s.cpu_percent >= 45.0 for s in recent)
        sustained_miner_network = sum(1 for s in recent if s.miner_network_hit) >= 2
        avg_cpu = sum(s.cpu_percent for s in recent) / len(recent)
        avg_mem = sum(s.memory_percent for s in recent) / len(recent)

        # Low-CPU / pulsing miner detection over wider window (>= 6 samples).
        active_15 = [s for s in samples if s.cpu_percent >= 15.0]
        duty_ratio = len(active_15) / len(samples)
        throttled_sustained = False
        compute_to_io_bound = False
        if len(samples) >= 6:
            ctx_delta = max(0, samples[-1].ctx_switches - samples[0].ctx_switches)
            io_delta_mb = max(0.0, (samples[-1].io_bytes - samples[0].io_bytes) / (1024 * 1024))
            # High thread scheduling activity vs minimal disk reads/writes (RandomX memory-hard loop).
            if ctx_delta >= 4000 and io_delta_mb < 10.0:
                compute_to_io_bound = True

            if duty_ratio >= 0.60 and (
                compute_to_io_bound
                or sum(1 for s in samples if s.miner_network_hit) >= 2
                or sum(1 for s in samples if s.tls_external) >= 3
                or any(s.gpu_compute_active for s in recent)
            ):
                throttled_sustained = True

        # Idle-aware ("--pause-on-active") mining surge detection.
        idle_samples = [s for s in samples if s.user_idle_seconds >= 30.0]
        active_user_samples = [s for s in samples if s.user_idle_seconds < 15.0]
        idle_surge = False
        mean_idle_cpu = 0.0
        mean_active_cpu = 0.0
        if len(idle_samples) >= 2 and len(active_user_samples) >= 2:
            mean_idle_cpu = sum(s.cpu_percent for s in idle_samples) / len(idle_samples)
            mean_active_cpu = sum(s.cpu_percent for s in active_user_samples) / len(active_user_samples)
            if mean_idle_cpu >= 20.0 and mean_idle_cpu >= max(mean_active_cpu * 2.5, mean_active_cpu + 15.0):
                idle_surge = True

        # Persistent TLS external flow tracking on non-browser executables.
        persistent_tls = sum(1 for s in samples[-6:] if s.tls_external) >= 3
        pool_domain_seen = any(s.pool_domain_hit for s in samples[-6:])

        gpu_sustained = sum(1 for s in recent if s.gpu_compute_active) >= 2

        if sustained_cpu or throttled_sustained or idle_surge or gpu_sustained:
            return True, {
                "process": process.get("name", "unknown"),
                "avg_cpu_last3": round(avg_cpu, 2),
                "avg_mem_last3": round(avg_mem, 2),
                "miner_network_sustained": sustained_miner_network or pool_domain_seen,
                "throttled_sustained": throttled_sustained,
                "idle_surge_detected": idle_surge,
                "mean_idle_cpu": round(mean_idle_cpu, 2),
                "mean_active_cpu": round(mean_active_cpu, 2),
                "duty_cycle_ratio": round(duty_ratio, 3),
                "compute_io_bound": compute_to_io_bound,
                "persistent_tls_socket": persistent_tls,
                "pool_domain_hit": pool_domain_seen,
                "gpu_compute_sustained": gpu_sustained,
                "samples": len(window),
            }

        if persistent_tls or pool_domain_seen:
            return False, {
                "process": process.get("name", "unknown"),
                "persistent_tls_socket": persistent_tls,
                "pool_domain_hit": pool_domain_seen,
                "samples": len(window),
            }

        return False, {}

    def evaluate_system(
        self,
        system_id: str,
        processes: List[Dict[str, Any]],
        now: datetime,
        cpu_percent: float,
        memory_percent: float,
        user_idle_seconds: float = 0.0,
    ) -> Dict[str, Any]:
        """Generate dynamic evidence bundle for the current metrics frame."""
        sustained = []
        miner_like_network_count = 0
        throttled_count = 0
        idle_surge_count = 0
        persistent_tls_count = 0
        pool_domain_count = 0
        gpu_compute_sustained_count = 0

        for proc in processes:
            hit, detail = self.observe(system_id, proc, now, user_idle_seconds=user_idle_seconds)
            if detail.get("persistent_tls_socket"):
                persistent_tls_count += 1
            if detail.get("pool_domain_hit"):
                pool_domain_count += 1
            if hit:
                sustained.append(detail)
                if detail.get("miner_network_sustained"):
                    miner_like_network_count += 1
                if detail.get("throttled_sustained"):
                    throttled_count += 1
                if detail.get("idle_surge_detected"):
                    idle_surge_count += 1
                if detail.get("gpu_compute_sustained"):
                    gpu_compute_sustained_count += 1

        pressure = cpu_percent >= 85.0 and memory_percent >= 70.0
        dynamic_score = (
            (2 if pressure else 0)
            + min(len(sustained), 2)
            + min(miner_like_network_count, 2)
            + (2 if idle_surge_count > 0 else 0)
            + (1 if throttled_count > 0 else 0)
            + (1 if (persistent_tls_count > 0 or pool_domain_count > 0) else 0)
        )
        return {
            "system_pressure": pressure,
            "sustained_processes": sustained,
            "sustained_count": len(sustained),
            "miner_like_network_count": miner_like_network_count,
            "throttled_count": throttled_count,
            "idle_surge_count": idle_surge_count,
            "persistent_tls_count": persistent_tls_count,
            "pool_domain_count": pool_domain_count,
            "gpu_compute_sustained_count": gpu_compute_sustained_count,
            "user_idle_seconds": round(max(0.0, float(user_idle_seconds or 0.0)), 2),
            "dynamic_score": dynamic_score,
        }
