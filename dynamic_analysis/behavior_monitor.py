"""Runtime behavioral monitor for cryptojacking-oriented process patterns."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Deque, Dict, List, Tuple


@dataclass
class ProcessWindowSample:
    cpu_percent: float
    memory_percent: float
    miner_network_hit: bool
    timestamp: datetime


class DynamicBehaviorMonitor:
    """Keep short per-system windows and extract dynamic miner-like behaviors."""

    def __init__(self, max_samples: int = 8):
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

    def observe(self, system_id: str, process: Dict[str, Any], now: datetime) -> Tuple[bool, Dict[str, Any]]:
        """Record one process sample and return sustained-usage indicator + details."""
        proc_key = self._process_key(process)
        window = self._window_for(system_id, proc_key)

        cpu = float(process.get("cpu_percent") or 0.0)
        mem = float(process.get("memory_percent") or 0.0)
        net_summary = process.get("network_summary") or {}
        remote_ports = net_summary.get("remote_ports") or []
        miner_network_hit = any(int(p) in {3333, 3334, 4444, 5555, 6666, 7777, 9999, 14433, 14444} for p in remote_ports if str(p).isdigit())
        window.append(
            ProcessWindowSample(
                cpu_percent=cpu,
                memory_percent=mem,
                miner_network_hit=miner_network_hit,
                timestamp=now,
            )
        )

        if len(window) < 3:
            return False, {}

        recent = list(window)[-3:]
        sustained_cpu = all(s.cpu_percent >= 45.0 for s in recent)
        sustained_miner_network = sum(1 for s in recent if s.miner_network_hit) >= 2
        avg_cpu = sum(s.cpu_percent for s in recent) / len(recent)
        avg_mem = sum(s.memory_percent for s in recent) / len(recent)

        if sustained_cpu:
            return True, {
                "process": process.get("name", "unknown"),
                "avg_cpu_last3": round(avg_cpu, 2),
                "avg_mem_last3": round(avg_mem, 2),
                "miner_network_sustained": sustained_miner_network,
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
    ) -> Dict[str, Any]:
        """Generate dynamic evidence bundle for the current metrics frame."""
        sustained = []
        miner_like_network_count = 0
        for proc in processes:
            hit, detail = self.observe(system_id, proc, now)
            if hit:
                sustained.append(detail)
                if detail.get("miner_network_sustained"):
                    miner_like_network_count += 1

        pressure = cpu_percent >= 85.0 and memory_percent >= 70.0
        return {
            "system_pressure": pressure,
            "sustained_processes": sustained,
            "sustained_count": len(sustained),
            "miner_like_network_count": miner_like_network_count,
            "dynamic_score": (2 if pressure else 0) + min(len(sustained), 2) + min(miner_like_network_count, 2),
        }
