"""
CryptoDetect Monitoring Agent v9.0
- Tray-compatible monitoring engine used by agent_gui.py
- Emits host telemetry fields for 20-feature ML inference
- Keeps legacy keys for backward compatibility
"""
import psutil
import json
import hashlib
import requests
import time
import sys
import os
import subprocess
import ipaddress
import queue
import threading
from datetime import datetime
from pathlib import Path

# Optional Windows-only imports
try:
    import ctypes
    HAS_CTYPES = True
except ImportError:
    HAS_CTYPES = False


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

try:
    from static_analysis.pe_analyzer import PEAnalyzer
    from static_analysis.string_extractor import StringExtractor
    STATIC_ANALYSIS_AVAILABLE = True
except Exception:
    PEAnalyzer = None
    StringExtractor = None
    STATIC_ANALYSIS_AVAILABLE = False


try:
    from auto_updater import CURRENT_VERSION as AGENT_VERSION
except Exception:
    AGENT_VERSION = "9.0"

CONFIG_DIR = Path.home() / ".cryptodetect"
CONFIG_FILE = CONFIG_DIR / "config.json"


class MonitoringAgent:
    def __init__(self, system_id, api_key, api_url="http://localhost:8000", verbose=False):
        self.system_id = system_id
        self.api_key = api_key
        self.api_url = api_url.rstrip('/')
        self.metrics_dir = CONFIG_DIR / "metrics"
        self.metrics_dir.mkdir(parents=True, exist_ok=True)
        self.max_entries = 60
        self.interval = 5
        # Upload every 30 seconds (6 samples at 5 seconds each). Override with AGENT_BATCH_SIZE.
        self.batch_size = max(1, int(os.getenv("AGENT_BATCH_SIZE", "6")))
        # An empty batch every 10 seconds keeps last_seen inside the 30-second offline window.
        self.heartbeat_cycles = 2
        # Samples wait here, on disk, until the backend confirms it received them.
        self.pending_file = self.metrics_dir / f"pending_{system_id}.json"
        self.pending = self._load_pending()
        self.verbose = verbose
        self.running = False
        self._last_net_snapshot = None
        self._last_net_ts = None
        self._cpu_load_history = []
        self._max_load_samples = 180
        self._static_cache = {}
        self._signature_cache = {}
        self._hash_cache = {}
        self._static_queue = queue.Queue()
        self._static_queued = set()
        self._static_lock = threading.Lock()
        self._static_worker = None
        # Limits each file scan's CPU and memory; large programs are only partly searched.
        max_scan_bytes = 32 * 1024 * 1024
        self._pe_analyzer = PEAnalyzer(max_scan_bytes) if STATIC_ANALYSIS_AVAILABLE else None
        self._string_extractor = StringExtractor(max_scan_bytes) if STATIC_ANALYSIS_AVAILABLE else None
        self._miner_ports = {3333, 3334, 4444, 5555, 6666, 7777, 9999, 14433, 14444}
        self._gpu_wmi_initialized = False
        self._gpu_wmi = None
        self._nvml = None
        self._nvml_handle = None
        self._parent_cache = {}
        self._process_detail_counts = None
        self._process_detail_time = 0.0
        # Prime psutil non-blocking CPU percent sampler for accurate deltas.
        psutil.cpu_percent(interval=None)

    def _log(self, message):
        if self.verbose:
            print(message)

    @staticmethod
    def _normalize_name(value):
        return str(value or "").strip().lower()

    @staticmethod
    def _normalize_hash(value):
        text = str(value or "").strip().lower()
        if len(text) == 64 and all(c in "0123456789abcdef" for c in text):
            return text
        return ""

    @staticmethod
    def _windows_startupinfo():
        """Create hidden-window startup info for subprocesses on Windows."""
        if os.name != "nt":
            return None, 0
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        return startupinfo, creationflags

    @staticmethod
    def _safe_local_ip(ip_text):
        try:
            ip_obj = ipaddress.ip_address(str(ip_text))
            return (
                ip_obj.is_loopback
                or ip_obj.is_private
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
            )
        except Exception:
            return False

    def _get_signature_info(self, exe_path, exe_hash):
        if not exe_path or not os.path.exists(exe_path):
            return {
                "signature_status": "unknown",
                "publisher": "",
                "is_trusted_signature": False,
            }

        cache_key = self._normalize_hash(exe_hash) or str(exe_path).lower()
        cached = self._signature_cache.get(cache_key)
        if cached:
            return cached

        result = {
            "signature_status": "unknown",
            "publisher": "",
            "is_trusted_signature": False,
        }
        if os.name != "nt":
            self._signature_cache[cache_key] = result
            return result

        escaped_path = str(exe_path).replace("'", "''")
        command = (
            "$sig = Get-AuthenticodeSignature -FilePath '{0}' -ErrorAction SilentlyContinue; "
            "$status = if ($sig) {{ [string]$sig.Status }} else {{ 'UnknownError' }}; "
            "$subject = if ($sig -and $sig.SignerCertificate) {{ [string]$sig.SignerCertificate.Subject }} else {{ '' }}; "
            "Write-Output ($status + '||' + $subject)"
        ).format(escaped_path)
        try:
            startupinfo, creationflags = self._windows_startupinfo()
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=6,
                startupinfo=startupinfo,
                creationflags=creationflags,
            )
            if completed.returncode == 0:
                output = (completed.stdout or "").strip().splitlines()
                line = output[-1] if output else ""
                if "||" in line:
                    status_raw, publisher_raw = line.split("||", 1)
                    status = str(status_raw).strip() or "unknown"
                    publisher = str(publisher_raw).strip()
                    status_norm = status.lower()
                    result = {
                        "signature_status": status_norm,
                        "publisher": publisher,
                        "is_trusted_signature": status_norm in {"valid"},
                    }
        except Exception:
            pass

        self._signature_cache[cache_key] = result
        return result

    def _get_parent_process_info(self, proc):
        parent_pid = None
        parent_name = ""
        try:
            parent = proc.parent()
            if parent:
                parent_pid = parent.pid
                parent_name = parent.name() or ""
        except Exception:
            parent_pid = None
            parent_name = ""
        return {
            "parent_pid": parent_pid,
            "parent_name": parent_name,
        }

    def _get_process_network_summary(self, proc):
        summary = {
            "connection_count": 0,
            "established_count": 0,
            "unique_remote_ip_count": 0,
            "remote_ips_sample": [],
            "remote_ports": [],
            "has_external_connection": False,
            "has_miner_port": False,
        }
        try:
            connections = proc.connections(kind="inet")
        except Exception:
            return summary

        remote_ips = set()
        remote_ports = set()
        established = 0
        has_external = False
        has_miner_port = False

        for conn in connections:
            raddr = getattr(conn, "raddr", None)
            if not raddr:
                continue
            ip = getattr(raddr, "ip", None)
            port = getattr(raddr, "port", None)
            if ip:
                remote_ips.add(str(ip))
                if not self._safe_local_ip(ip):
                    has_external = True
            if port:
                try:
                    port_int = int(port)
                    remote_ports.add(port_int)
                    if port_int in self._miner_ports:
                        has_miner_port = True
                except Exception:
                    pass
            if str(getattr(conn, "status", "")).upper() == "ESTABLISHED":
                established += 1

        summary["connection_count"] = len(connections)
        summary["established_count"] = established
        summary["unique_remote_ip_count"] = len(remote_ips)
        summary["remote_ips_sample"] = sorted(list(remote_ips))[:6]
        summary["remote_ports"] = sorted(list(remote_ports))[:8]
        summary["has_external_connection"] = has_external
        summary["has_miner_port"] = has_miner_port
        return summary

    def _collect_static_evidence(self, exe_path, exe_hash):
        if not STATIC_ANALYSIS_AVAILABLE:
            return None
        if not exe_path or not os.path.exists(exe_path):
            return None

        cache_key = exe_hash or exe_path
        if cache_key in self._static_cache:
            return self._static_cache[cache_key]

        try:
            pe_features = self._pe_analyzer.analyze_file(exe_path) if self._pe_analyzer else None
            str_features = self._string_extractor.extract_and_analyze(exe_path) if self._string_extractor else None
        except Exception:
            self._static_cache[cache_key] = None
            return None

        result = {
            "has_mining_keywords": False,
            "mining_keywords": [],
            "has_crypto_address": False,
            "has_suspicious_urls": False,
            "suspicious_string_count": 0,
            "num_suspicious_imports": 0,
            "suspicious_imports": [],
            "file_sha256": exe_hash,
            "total_entropy": None,
        }

        if str_features and str_features.get("analysis"):
            analysis = str_features["analysis"]
            mk = analysis.get("mining_keywords", []) or []
            result["has_mining_keywords"] = len(mk) > 0
            result["mining_keywords"] = mk[:10]
            result["has_crypto_address"] = len(analysis.get("crypto_addresses", []) or []) > 0
            result["has_suspicious_urls"] = len(analysis.get("urls", []) or []) > 0
            result["suspicious_string_count"] = int(analysis.get("suspicious_count", 0) or 0)

        if pe_features:
            suspicious_imports = pe_features.get("suspicious_imports", []) or []
            result["num_suspicious_imports"] = len(suspicious_imports)
            result["suspicious_imports"] = suspicious_imports[:8]
            result["total_entropy"] = pe_features.get("total_entropy")
            if not result["file_sha256"]:
                result["file_sha256"] = pe_features.get("sha256")

        self._static_cache[cache_key] = result
        return result

    def _get_static_evidence_nowait(self, exe_path, exe_hash):
        """Return cached evidence, or None while a background thread scans the file."""
        if not STATIC_ANALYSIS_AVAILABLE or not exe_path:
            return None

        cache_key = exe_hash or exe_path
        if cache_key in self._static_cache:
            return self._static_cache[cache_key]

        with self._static_lock:
            if cache_key not in self._static_queued:
                self._static_queued.add(cache_key)
                self._static_queue.put((cache_key, exe_path, exe_hash))
            if self._static_worker is None or not self._static_worker.is_alive():
                self._static_worker = threading.Thread(target=self._run_static_worker, daemon=True)
                self._static_worker.start()
        return None

    def _run_static_worker(self):
        while True:
            try:
                cache_key, exe_path, exe_hash = self._static_queue.get(timeout=30)
            except queue.Empty:
                return
            try:
                self._collect_static_evidence(exe_path, exe_hash)
            finally:
                with self._static_lock:
                    self._static_queued.discard(cache_key)

    def filter_processes(self):
        processes = []
        benign_processes = {
            "system idle process", "system", "registry", "smss.exe", "csrss.exe",
            "wininit.exe", "services.exe", "lsass.exe", "dwm.exe",
            "winlogon.exe", "fontdrvhost.exe", "sihost.exe", "taskhostw.exe",
            "runtimebroker.exe", "searchindexer.exe",
        }
        candidates = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                name_norm = self._normalize_name(info.get('name'))
                if name_norm in benign_processes:
                    continue
                cpu_percent = float(info.get('cpu_percent') or 0.0)
                memory_percent = float(info.get('memory_percent') or 0.0)
                is_svchost = name_norm == "svchost.exe"
                if cpu_percent > 4.0 or memory_percent > 4.0 or is_svchost:
                    candidates.append((proc, info, cpu_percent, memory_percent))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Only the top 18 are reported, so only they need the slower per-process lookups.
        candidates.sort(key=lambda c: c[2], reverse=True)
        parent_cache = {}
        for proc, info, cpu_percent, memory_percent in candidates[:18]:
            try:
                try:
                    exe_path = proc.exe()
                    exe_hash = self._file_hash(exe_path)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    exe_path = None
                    exe_hash = None
                try:
                    create_time = float(proc.create_time())
                except (psutil.AccessDenied, psutil.NoSuchProcess, ValueError, TypeError):
                    create_time = None
                process_key = (info['pid'], create_time)
                parent_info = self._parent_cache.get(process_key)
                if parent_info is None:
                    parent_info = self._get_parent_process_info(proc)
                parent_cache[process_key] = parent_info
                signature_info = self._get_signature_info(exe_path, exe_hash)
                net_summary = self._get_process_network_summary(proc)
                static_evidence = None
                if cpu_percent >= 20.0:
                    static_evidence = self._get_static_evidence_nowait(exe_path, exe_hash)
                processes.append({
                    'pid': info['pid'],
                    'name': info['name'],
                    'cpu_percent': round(cpu_percent, 2),
                    'memory_percent': round(memory_percent, 2),
                    'exe_path': exe_path,
                    'exe_hash': exe_hash,
                    'create_time': create_time,
                    'parent_pid': parent_info.get("parent_pid"),
                    'parent_name': parent_info.get("parent_name"),
                    'signature_status': signature_info.get("signature_status", "unknown"),
                    'publisher': signature_info.get("publisher", ""),
                    'is_trusted_signature': bool(signature_info.get("is_trusted_signature", False)),
                    'network_summary': net_summary,
                    'static_analysis': static_evidence,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        self._parent_cache = parent_cache
        return processes

    def _file_hash(self, filepath):
        if not filepath or not os.path.exists(filepath):
            return None
        try:
            stat = os.stat(filepath)
            cache_key = (filepath, stat.st_mtime_ns, stat.st_size)
            if cache_key in self._hash_cache:
                return self._hash_cache[cache_key]
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            self._hash_cache[cache_key] = sha256.hexdigest()
            return self._hash_cache[cache_key]
        except:
            return None

    def _collect_load_avg(self, cpu_percent):
        try:
            min1, min5, min15 = os.getloadavg()
            return {
                'min1': round(float(min1), 4),
                'min5': round(float(min5), 4),
                'min15': round(float(min15), 4)
            }
        except Exception:
            cpu_count = max(psutil.cpu_count() or 1, 1)
            load_point = (float(cpu_percent) / 100.0) * cpu_count

            self._cpu_load_history.append(load_point)
            if len(self._cpu_load_history) > self._max_load_samples:
                self._cpu_load_history = self._cpu_load_history[-self._max_load_samples:]

            def _ema(window_samples):
                if not self._cpu_load_history:
                    return 0.0
                recent = self._cpu_load_history[-window_samples:]
                alpha = 2.0 / (len(recent) + 1.0)
                ema = recent[0]
                for sample in recent[1:]:
                    ema = alpha * sample + (1.0 - alpha) * ema
                return ema

            return {
                'min1': round(_ema(12), 4),
                'min5': round(_ema(60), 4),
                'min15': round(_ema(180), 4)
            }

    def _collect_network_stats(self):
        net = psutil.net_io_counters()
        now = time.time()

        sent_delta = 0.0
        recv_delta = 0.0
        if self._last_net_snapshot is not None and self._last_net_ts is not None:
            elapsed = max(now - self._last_net_ts, 1e-6)
            sent_delta = max(0.0, (net.bytes_sent - self._last_net_snapshot.bytes_sent) / elapsed)
            recv_delta = max(0.0, (net.bytes_recv - self._last_net_snapshot.bytes_recv) / elapsed)

        self._last_net_snapshot = net
        self._last_net_ts = now

        return {
            'bytes_sent': net.bytes_sent,
            'bytes_recv': net.bytes_recv,
            'bytes_sent_delta': round(sent_delta, 4),
            'bytes_recv_delta': round(recv_delta, 4),
            'packets_sent': net.packets_sent,
            'packets_recv': net.packets_recv,
        }

    def _init_gpu_wmi(self):
        if self._gpu_wmi_initialized:
            return self._gpu_wmi is not None
        self._gpu_wmi_initialized = True
        if os.name != "nt":
            self._gpu_wmi = None
            return False
        try:
            import pythoncom
            import win32com.client

            pythoncom.CoInitialize()
            locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            self._gpu_wmi = locator.ConnectServer(".", "root\\CIMV2")
            return True
        except Exception:
            self._gpu_wmi = None
            return False

    @staticmethod
    def _safe_wmi_float(value, default=0.0):
        try:
            return float(value)
        except Exception:
            return default

    def _query_nvml(self):
        """Read the first NVIDIA GPU in-process; return None if NVML can't be used."""
        if self._nvml_handle is False:
            return None
        try:
            if self._nvml_handle is None:
                import pynvml

                pynvml.nvmlInit()
                self._nvml = pynvml
                self._nvml_handle = pynvml.nvmlDeviceGetHandleByIndex(0)
            memory = self._nvml.nvmlDeviceGetMemoryInfo(self._nvml_handle)
            utilization = self._nvml.nvmlDeviceGetUtilizationRates(self._nvml_handle)
            return float(utilization.gpu), memory.used / (1024 * 1024), memory.total / (1024 * 1024)
        except Exception:
            self._nvml_handle = False
            return None

    def _query_nvidia_smi(self):
        try:
            startupinfo, creationflags = self._windows_startupinfo()
            completed = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=utilization.gpu,memory.used,memory.total",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=4,
                startupinfo=startupinfo,
                creationflags=creationflags,
            )
            if completed.returncode != 0:
                return None
            line = (completed.stdout or "").strip().splitlines()[0:1]
            if not line:
                return None
            parts = [p.strip() for p in line[0].split(",")]
            if len(parts) < 3:
                return None
            return float(parts[0]), float(parts[1]), float(parts[2])
        except Exception:
            return None

    def _collect_gpu_metrics_nvidia(self):
        reading = self._query_nvml()
        source = "nvml"
        if reading is None:
            reading = self._query_nvidia_smi()
            source = "nvidia-smi"
        if reading is None:
            return None
        return self._format_nvidia_metrics(reading, source)

    @staticmethod
    def _format_nvidia_metrics(reading, source):
        util, mem_used, mem_total = reading
        mem_percent = (mem_used / mem_total * 100.0) if mem_total > 0 else 0.0
        return {
            "available": True,
            "source": source,
            "utilization_percent": round(util, 2),
            "engine_utilization_percent": round(util, 2),
            "memory_used_mb": round(mem_used, 2),
            "memory_total_mb": round(mem_total, 2),
            "memory_used_percent": round(mem_percent, 2),
            "adapter_count": 1,
            "engine_utilization_by_type": {},
        }

    def _collect_gpu_metrics(self):
        # NVML is far cheaper than WMI, so WMI is only used on machines without it.
        reading = self._query_nvml()
        if reading is not None:
            return self._format_nvidia_metrics(reading, "nvml")

        if not self._init_gpu_wmi():
            fallback = self._collect_gpu_metrics_nvidia()
            if fallback:
                return fallback
            return {"available": False, "source": "wmi"}

        engine_values = []
        engine_by_type = {}
        adapter_count = 0
        mem_used = 0.0
        mem_total = 0.0

        try:
            engine_rows = self._gpu_wmi.ExecQuery(
                "SELECT Name, UtilizationPercentage FROM Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine"
            )
            for row in engine_rows:
                util = self._safe_wmi_float(getattr(row, "UtilizationPercentage", 0.0), 0.0)
                if util < 0:
                    continue
                engine_values.append(util)
                name = str(getattr(row, "Name", "") or "").lower()
                marker = "engtype_"
                idx = name.find(marker)
                if idx >= 0:
                    eng = name[idx + len(marker):]
                    eng = eng.split("_")[0]
                    prev = engine_by_type.get(eng, 0.0)
                    engine_by_type[eng] = max(prev, util)
        except Exception:
            engine_values = []

        try:
            mem_rows = self._gpu_wmi.ExecQuery(
                "SELECT DedicatedUsage, DedicatedLimit, SharedUsage, SharedLimit FROM Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory"
            )
            for row in mem_rows:
                adapter_count += 1
                dedicated_used = self._safe_wmi_float(getattr(row, "DedicatedUsage", 0.0), 0.0)
                dedicated_limit = self._safe_wmi_float(getattr(row, "DedicatedLimit", 0.0), 0.0)
                shared_used = self._safe_wmi_float(getattr(row, "SharedUsage", 0.0), 0.0)
                shared_limit = self._safe_wmi_float(getattr(row, "SharedLimit", 0.0), 0.0)
                mem_used += max(dedicated_used, 0.0) + max(shared_used, 0.0)
                mem_total += max(dedicated_limit, 0.0) + max(shared_limit, 0.0)
        except Exception:
            adapter_count = adapter_count or 0

        if not engine_values and mem_total <= 0:
            try:
                video_rows = self._gpu_wmi.ExecQuery(
                    "SELECT Name, AdapterRAM FROM Win32_VideoController"
                )
                for row in video_rows:
                    adapter_count += 1
                    mem_total += max(0.0, self._safe_wmi_float(getattr(row, "AdapterRAM", 0.0), 0.0))
            except Exception:
                pass

        utilization = max(engine_values) if engine_values else 0.0
        mem_used_mb = mem_used / (1024 * 1024) if mem_used > 0 else 0.0
        mem_total_mb = mem_total / (1024 * 1024) if mem_total > 0 else 0.0
        mem_percent = (mem_used / mem_total * 100.0) if mem_total > 0 else 0.0

        source = "wmi"
        if mem_total_mb <= 0:
            fallback = self._collect_gpu_metrics_nvidia()
            if fallback:
                if utilization <= 0:
                    utilization = fallback.get("utilization_percent", utilization)
                mem_used_mb = fallback.get("memory_used_mb", mem_used_mb)
                mem_total_mb = fallback.get("memory_total_mb", mem_total_mb)
                mem_percent = fallback.get("memory_used_percent", mem_percent)
                adapter_count = max(adapter_count, int(fallback.get("adapter_count", 0) or 0))
                source = "wmi+nvidia-smi"

        available = bool(engine_values or mem_total_mb)
        if not available:
            fallback = self._collect_gpu_metrics_nvidia()
            if fallback:
                return fallback

        return {
            "available": available,
            "source": source,
            "utilization_percent": round(utilization, 2),
            "engine_utilization_percent": round(utilization, 2),
            "memory_used_mb": round(mem_used_mb, 2),
            "memory_total_mb": round(mem_total_mb, 2),
            "memory_used_percent": round(mem_percent, 2),
            "adapter_count": adapter_count,
            "engine_utilization_by_type": {
                k: round(v, 2) for k, v in sorted(engine_by_type.items(), key=lambda x: x[0])
            },
        }

    def _collect_process_counts(self):
        total = len(psutil.pids())

        # Per-process status and thread counts are slow on Windows, so refresh them every 30 seconds.
        now = time.monotonic()
        if self._process_detail_counts is None or now - self._process_detail_time >= 30:
            running = 0
            thread_total = 0
            for proc in psutil.process_iter(['status', 'num_threads']):
                try:
                    status = proc.info.get('status')
                    if status == psutil.STATUS_RUNNING:
                        running += 1
                    thread_total += int(proc.info.get('num_threads') or 0)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            self._process_detail_counts = (running, thread_total)
            self._process_detail_time = now

        running, thread_total = self._process_detail_counts
        if thread_total <= 0:
            thread_total = total

        return {
            'running': running,
            'total': total,
            'thread': thread_total,
        }

    def collect_metrics(self):
        try:
            cpu_percent = round(psutil.cpu_percent(interval=None), 2)
            cpu_count = psutil.cpu_count() or 1
            cpu_times = psutil.cpu_times_percent(interval=None)
            memory = psutil.virtual_memory()
            network = self._collect_network_stats()
            process_counts = self._collect_process_counts()
            load_avg = self._collect_load_avg(cpu_percent)
            gpu_metrics = self._collect_gpu_metrics()

            return {
                'timestamp': datetime.now().isoformat(),
                'cpu': {
                    'percent': cpu_percent,
                    'cpu_percent': cpu_percent,
                    'cpu_count': cpu_count,
                },
                'cpu_times': {
                    'user': round(float(getattr(cpu_times, 'user', 0.0)), 4),
                    'system': round(float(getattr(cpu_times, 'system', 0.0)), 4),
                    'idle': round(float(getattr(cpu_times, 'idle', 0.0)), 4),
                    'iowait': round(float(getattr(cpu_times, 'iowait', 0.0)), 4),
                    'irq': round(float(getattr(cpu_times, 'interrupt', getattr(cpu_times, 'irq', 0.0))), 4),
                    'softirq': round(float(getattr(cpu_times, 'softirq', 0.0)), 4),
                },
                'memory': {
                    'percent': round(float(memory.percent), 2),
                    'memory_percent': round(float(memory.percent), 2),
                    'used': int(memory.used),
                    'memory_used': int(memory.used),
                    'total': int(memory.total),
                    'memory_total': int(memory.total),
                    'available': int(memory.available),
                    'active': int(getattr(memory, 'active', 0) or 0),
                    'cached': int(getattr(memory, 'cached', 0) or 0),
                },
                'load_avg': load_avg,
                'network': network,
                'process_counts': process_counts,
                'processes': self.filter_processes(),
                'gpu': gpu_metrics,
            }
        except Exception as e:
            print(f"  [ERROR] Collecting metrics: {e}")
            return None

    def save_local(self, metrics):
        json_file = self.metrics_dir / f"metrics_{datetime.now().strftime('%Y%m%d')}.json"
        try:
            data = []
            if json_file.exists():
                with open(json_file, 'r') as f:
                    data = json.load(f)
            data.append(metrics)
            data = data[-self.max_entries:]
            with open(json_file, 'w') as f:
                json.dump(data, f)
            return data
        except:
            return []

    def _load_pending(self):
        try:
            data = json.loads(self.pending_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        return data[-self.max_entries:] if isinstance(data, list) else []

    def _save_pending(self):
        try:
            self.pending_file.write_text(json.dumps(self.pending), encoding="utf-8")
        except OSError as e:
            print(f"  [ERROR] Could not save pending metrics: {e}")

    def _queue_sample(self, metrics):
        self.pending = (self.pending + [metrics])[-self.max_entries:]
        self._save_pending()

    def _mark_sent(self, sent_count):
        self.pending = self.pending[sent_count:]
        self._save_pending()

    def _next_payload(self, count):
        """Return samples to upload this cycle, [] for a heartbeat, or None to send nothing."""
        if count % self.batch_size == 0:
            return list(self.pending)
        if count % self.heartbeat_cycles == 0:
            return []
        return None

    def send_batch(self, metrics_batch):
        try:
            resp = requests.post(
                f"{self.api_url}/api/metrics/batch",
                json={'system_id': self.system_id, 'metrics': metrics_batch},
                headers={'X-API-Key': self.api_key},
                timeout=30 if metrics_batch else 10
            )
            if resp.status_code == 200:
                result = resp.json()
                model = result.get('model_used', '?')
                if metrics_batch:
                    self._log(f"  [SENT] {len(metrics_batch)} metrics | Model: {model}")
                if result.get('alerts'):
                    for a in result['alerts']:
                        confidence_pct = a.get('confidence', 0) * 100
                        reasons = a.get('reason_summary') or []
                        reason_text = ", ".join([str(r) for r in reasons[:3] if r])
                        print(f"  [ALERT] Cryptojacking detected! Confidence: {confidence_pct:.1f}%")
                        procs = a.get('suspicious_processes', [])
                        if procs:
                            print(f"          Processes: {', '.join(procs)}")
                        if reason_text:
                            print(f"          Reasons: {reason_text}")
                        if HAS_CTYPES:
                            try:
                                flags = 0x30 | 0x00040000 | 0x00010000 | 0x00001000
                                message = (
                                    f"Cryptojacking detected!\n"
                                    f"Confidence: {confidence_pct:.1f}%\n"
                                    f"Reasons: {reason_text or 'See dashboard for details'}"
                                )
                                ctypes.windll.user32.MessageBoxW(
                                    0,
                                    message,
                                    "CryptoDetect Alert",
                                    flags,
                                )
                            except:
                                pass
                return True
            elif resp.status_code == 401:
                print("  [AUTH ERROR] Invalid credentials: your System ID or API Key is wrong")
                return "auth_error"
            elif resp.status_code == 403:
                print("  [AUTH ERROR] Not authorized for this system")
                return "auth_error"
            else:
                print(f"  [ERROR] Server returned {resp.status_code}: {resp.text[:80]}")
                return False
        except requests.exceptions.ConnectionError:
            print(f"  [OFFLINE] Cannot reach backend at {self.api_url}")
            return False
        except Exception as e:
            print(f"  [ERROR] {e}")
            return False

    def stop(self):
        self.running = False

    def run(self):
        print(f"\n{'='*60}")
        print("  MONITORING ACTIVE")
        print(f"  System:   {self.system_id}")
        print(f"  Backend:  {self.api_url}")
        print(f"  Interval: {self.interval}s collect, {self.batch_size * self.interval}s send")
        print("  Console output: alerts/errors only (use --verbose for metrics)")
        print(f"{'='*60}\n")

        count = 0
        auth_failures = 0
        self.running = True

        while self.running:
            loop_started = time.time()
            try:
                m = self.collect_metrics()
                if m:
                    self.save_local(m)
                    self._queue_sample(m)
                    count += 1
                    payload = self._next_payload(count)
                    if payload is not None:
                        result = self.send_batch(payload)
                        if result is True and payload:
                            self._mark_sent(len(payload))
                        if result == "auth_error":
                            auth_failures += 1
                            if auth_failures >= 1:
                                print("\n  [FATAL] Authentication failed. Update your System ID/API Key and restart.")
                                delete_config()
                                input("  Press Enter to exit...")
                                self.running = False
                                return
                        else:
                            auth_failures = 0

                elapsed = time.time() - loop_started
                time.sleep(max(0.0, self.interval - elapsed))
            except KeyboardInterrupt:
                print("\n  [STOP] Agent stopped by user")
                self.running = False
                break
            except Exception as e:
                print(f"  [ERROR] {e}")
                elapsed = time.time() - loop_started
                time.sleep(max(0.0, self.interval - elapsed))

        print("\n  [STOP] Monitoring loop exited")


import base64

def save_config(system_id, api_key, api_url):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config = {
        'system_id': system_id,
        'api_key': api_key,
        'api_url': api_url,
        'configured_at': datetime.now().isoformat()
    }
    config_bytes = json.dumps(config).encode('utf-8')
    encoded = base64.b64encode(config_bytes).decode('utf-8')
    with open(CONFIG_FILE, 'w') as f:
        f.write(encoded)
    print(f"  [OK] Config saved to {CONFIG_FILE}")


def load_config():
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                content = f.read()
                if content.strip().startswith('{'):
                    # Legacy plaintext config
                    config = json.loads(content)
                    return config
                else:
                    decoded = base64.b64decode(content).decode('utf-8')
                    return json.loads(decoded)
        except:
            return None
    return None


def delete_config():
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
        print("  [OK] Old config deleted")


def resolve_agent_config(api_key, api_url):
    """Resolve system_id from API key and validate backend connectivity."""
    print(f"\n  Testing connection to {api_url}...")
    try:
        # First check if backend is reachable
        resp = requests.get(f"{api_url}/health", timeout=5)
        if resp.status_code != 200:
            print(f"  [FAIL] Backend not responding (status {resp.status_code})")
            return None
        print(f"  [OK] Backend is running")

        # Resolve system from API key
        resp = requests.get(
            f"{api_url}/api/auth/agent/bootstrap",
            headers={'X-API-Key': api_key},
            timeout=5
        )
        if resp.status_code == 200:
            data = resp.json()
            system_id = data.get('system_id')
            if not system_id:
                print("  [FAIL] Backend did not return a system ID")
                return None
            print(f"  [OK] API key verified. System ID: {system_id}")
            return {
                'system_id': system_id,
                'api_key': api_key,
                'api_url': api_url
            }
        elif resp.status_code == 401:
            print(f"  [FAIL] Invalid API Key")
            return None
        else:
            print(f"  [FAIL] Bootstrap failed ({resp.status_code}): {resp.text[:80]}")
            return None
    except requests.exceptions.ConnectionError:
        print(f"  [FAIL] Cannot connect to {api_url}")
        print(f"         Make sure the backend is running: python main.py")
        return None
    except Exception as e:
        print(f"  [FAIL] {e}")
        return None


def prompt_credentials():
    """Interactive API key entry"""
    print(f"\n  Enter your API key from the website after registration:\n")
    api_key = input("  API Key:   ").strip()
    api_url = input("  Backend URL [http://localhost:8000]: ").strip() or "http://localhost:8000"
    return api_key, api_url


def main():
    print(f"\n{'='*60}")
    print(f"  CRYPTODETECT MONITORING AGENT v{AGENT_VERSION}")
    print(f"  Real-time Cryptojacking Detection")
    print(f"{'='*60}")

    # Check for command-line args (silent mode)
    if len(sys.argv) >= 2:
        # Usage: agent.exe --api-key YYY [--api-url ZZZ] [--system-id XXX]
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument('--system-id', '-s')
        parser.add_argument('--api-key', '-k')
        parser.add_argument('--api-url', '-u', default='http://localhost:8000')
        parser.add_argument('--reset', action='store_true')
        parser.add_argument('--verbose', action='store_true')
        args = parser.parse_args()

        if args.reset:
            delete_config()
            print("  Config reset. Run again to configure.")
            return

        if args.api_key:
            resolved = resolve_agent_config(args.api_key, args.api_url)
            if resolved:
                system_id = args.system_id or resolved['system_id']
                save_config(system_id, args.api_key, args.api_url)
                agent = MonitoringAgent(system_id, args.api_key, args.api_url, verbose=args.verbose)
                agent.run()
            else:
                print("\n  Could not connect. Check backend and credentials.")
                input("  Press Enter to exit...")
            return

    # Interactive mode - always give user a choice
    config = load_config()

    if config:
        print(f"\n  Found saved configuration:")
        print(f"    System ID: {config.get('system_id', '?')}")
        print(f"    Backend:   {config.get('api_url', '?')}")
        print(f"    Saved:     {config.get('configured_at', '?')}")
        print()

        choice = input("  Use saved config? (Y = use, N = new setup, R = reset): ").strip().upper()

        if choice == 'R':
            delete_config()
            config = None
        elif choice == 'N':
            config = None

    if config:
        system_id = config.get('system_id')
        api_key = config.get('api_key')
        api_url = config.get('api_url', 'http://localhost:8000')

        if not api_key:
            print("  [ERROR] Saved config is missing API key. Reconfigure required.")
            delete_config()
            config = None
    else:
        # Fresh setup
        while True:
            api_key, api_url = prompt_credentials()

            if not api_key:
                print("  [ERROR] API Key is required!")
                retry = input("  Try again? (Y/n): ").strip().lower()
                if retry == 'n':
                    return
                continue

            resolved = resolve_agent_config(api_key, api_url)
            if resolved:
                system_id = resolved['system_id']
                save_config(system_id, api_key, api_url)
                break
            else:
                print()
                retry = input("  Connection failed. Try again? (Y/n): ").strip().lower()
                if retry == 'n':
                    input("  Press Enter to exit...")
                    return

    # Final connection test for saved config
    resolved = resolve_agent_config(api_key, api_url)
    if not resolved:
        print(f"\n  Cannot connect with saved credentials.")
        choice = input("  Enter new credentials? (Y/n): ").strip().lower()
        if choice != 'n':
            delete_config()
            while True:
                api_key, api_url = prompt_credentials()
                resolved = resolve_agent_config(api_key, api_url)
                if resolved:
                    system_id = resolved['system_id']
                    save_config(system_id, api_key, api_url)
                    break
                retry = input("  Try again? (Y/n): ").strip().lower()
                if retry == 'n':
                    input("  Press Enter to exit...")
                    return
        else:
            input("  Press Enter to exit...")
            return
    else:
        system_id = resolved['system_id']
        if config and config.get('system_id') != system_id:
            save_config(system_id, api_key, api_url)

    # Start monitoring
    agent = MonitoringAgent(system_id, api_key, api_url, verbose=False)
    agent.run()


if __name__ == "__main__":
    main()
