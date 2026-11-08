"""
CryptoDetect Monitoring Agent v1.0
- Tray-compatible monitoring engine used by agent_gui.py
- Emits host telemetry fields for 20-feature ML inference
- Keeps legacy keys for backward compatibility
"""
import shutil
import csv
import io
import re
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
    from static_analysis.yara_scanner import YaraMinerScanner
    YARA_SCANNER_AVAILABLE = True
except Exception:
    YaraMinerScanner = None
    YARA_SCANNER_AVAILABLE = False


try:
    from auto_updater import CURRENT_VERSION as AGENT_VERSION
except Exception:
    AGENT_VERSION = "1.0"

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
        self._yara_scanner = YaraMinerScanner(max_scan_bytes) if YARA_SCANNER_AVAILABLE else None
        self._miner_ports = {3333, 3334, 4444, 5555, 6666, 7777, 9999, 14433, 14444}
        self._tls_miner_ports = {443, 8443}
        self._pool_domain_keywords = (
            "supportxmr", "minexmr", "nanopool", "2miners", "moneroocean",
            "hashvault", "herominers", "c3pool", "unmineable", "f2pool",
            "ethermine", "nicehash", "poolin", "antpool", "kryptex", "xmrpool",
        )
        self._monitored_spoof_names = {
            "svchost.exe", "dllhost.exe", "conhost.exe", "taskhostw.exe",
            "spoolsv.exe", "runtimebroker.exe", "searchindexer.exe", "sihost.exe", "dwm.exe",
        }
        self._wsl_process_names = {"vmmem", "vmmemwsl", "wsl.exe", "wslhost.exe"}
        self._suspicious_path_tokens = (
            "\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\windows\\temp\\",
            "\\programdata\\", "\\users\\public\\", "\\$recycle",
        )
        self._gpu_wmi_initialized = False
        self._gpu_wmi = None
        self._nvml = None
        self._nvml_handle = None
        self._gpu_compute_pids = {}
        self._dns_cache_map = {}
        self._dns_cache_time = 0.0
        self._parent_cache = {}
        self._process_detail_counts = None
        self._process_detail_time = 0.0
        self.quarantine_dir = CONFIG_DIR / "quarantine"
        self._active_command_ids = set()
        self._command_lock = threading.Lock()
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

    def _get_user_idle_seconds(self):
        """Return seconds since last keyboard/mouse input on Windows, or 0.0."""
        if os.name != "nt" or not HAS_CTYPES:
            return 0.0
        try:
            class _LASTINPUTINFO(ctypes.Structure):
                _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

            lii = _LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(_LASTINPUTINFO)
            if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
                tick_now = ctypes.windll.kernel32.GetTickCount()
                idle_ms = (int(tick_now) - int(lii.dwTime)) & 0xFFFFFFFF
                return round(max(0.0, idle_ms / 1000.0), 2)
        except Exception:
            pass
        return 0.0

    def _get_dns_cache_map(self):
        """Return cached {ip: [domains]} mapping from Windows DNS Client cache."""
        now = time.monotonic()
        if self._dns_cache_map and (now - self._dns_cache_time) < 30.0:
            return self._dns_cache_map
        if os.name != "nt":
            self._dns_cache_time = now
            return self._dns_cache_map

        mapping = {}
        try:
            startupinfo, creationflags = self._windows_startupinfo()
            cmd = (
                "Get-DnsClientCache | Where-Object { $_.Data } | "
                "Select-Object -First 250 Entry, Data | ConvertTo-Json -Compress"
            )
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=4,
                startupinfo=startupinfo,
                creationflags=creationflags,
            )
            if completed.returncode == 0 and (completed.stdout or "").strip():
                rows = json.loads(completed.stdout.strip())
                if isinstance(rows, dict):
                    rows = [rows]
                if isinstance(rows, list):
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        ip_val = str(row.get("Data") or "").strip()
                        domain_val = str(row.get("Entry") or "").strip().lower()
                        if not ip_val or not domain_val:
                            continue
                        try:
                            ipaddress.ip_address(ip_val)
                        except ValueError:
                            continue
                        mapping.setdefault(ip_val, set()).add(domain_val)
        except Exception:
            pass

        self._dns_cache_map = {ip: sorted(list(domains))[:4] for ip, domains in mapping.items()}
        self._dns_cache_time = now
        return self._dns_cache_map

    def _matches_pool_domain(self, domain_name):
        lowered = str(domain_name or "").lower()
        return any(kw in lowered for kw in self._pool_domain_keywords) or lowered.startswith("pool.")

    def _get_process_network_summary(self, proc):
        summary = {
            "connection_count": 0,
            "established_count": 0,
            "unique_remote_ip_count": 0,
            "remote_ips_sample": [],
            "remote_ports": [],
            "has_external_connection": False,
            "has_miner_port": False,
            "resolved_domains": [],
            "has_pool_domain": False,
            "has_tls_external": False,
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
        has_tls_port = False

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
                    if port_int in self._tls_miner_ports:
                        has_tls_port = True
                except Exception:
                    pass
            if str(getattr(conn, "status", "")).upper() == "ESTABLISHED":
                established += 1

        resolved_domains = []
        has_pool_domain = False
        if has_external and remote_ips:
            dns_map = self._get_dns_cache_map()
            seen_domains = set()
            for ip in sorted(remote_ips):
                for domain in dns_map.get(ip, []):
                    if domain not in seen_domains:
                        seen_domains.add(domain)
                        resolved_domains.append(domain)
                    if self._matches_pool_domain(domain):
                        has_pool_domain = True

        summary["connection_count"] = len(connections)
        summary["established_count"] = established
        summary["unique_remote_ip_count"] = len(remote_ips)
        summary["remote_ips_sample"] = sorted(list(remote_ips))[:6]
        summary["remote_ports"] = sorted(list(remote_ports))[:8]
        summary["has_external_connection"] = has_external
        summary["has_miner_port"] = has_miner_port
        summary["resolved_domains"] = resolved_domains[:6]
        summary["has_pool_domain"] = has_pool_domain
        summary["has_tls_external"] = bool(has_external and established > 0 and has_tls_port)
        return summary

    def _collect_static_evidence(self, exe_path, exe_hash):
        if not (STATIC_ANALYSIS_AVAILABLE or YARA_SCANNER_AVAILABLE):
            return None
        if not exe_path or not os.path.exists(exe_path):
            return None

        cache_key = exe_hash or exe_path
        if cache_key in self._static_cache:
            return self._static_cache[cache_key]

        try:
            pe_features = self._pe_analyzer.analyze_file(exe_path) if self._pe_analyzer else None
            str_features = self._string_extractor.extract_and_analyze(exe_path) if self._string_extractor else None
            yara_features = self._yara_scanner.scan_file(exe_path) if self._yara_scanner else None
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
            "yara_matched": False,
            "yara_rules": [],
            "yara_severity": "none",
            "is_packed": False,
            "packed_rules": [],
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

        if yara_features:
            result["yara_matched"] = bool(yara_features.get("yara_matched"))
            result["yara_rules"] = list(yara_features.get("miner_rules") or [])[:8]
            result["yara_severity"] = str(yara_features.get("max_severity") or "none")
            result["is_packed"] = bool(yara_features.get("is_packed"))
            result["packed_rules"] = list(yara_features.get("packed_rules") or [])[:4]

        self._static_cache[cache_key] = result
        return result

    def _get_static_evidence_nowait(self, exe_path, exe_hash):
        """Return cached evidence, or None while a background thread scans the file."""
        if not (STATIC_ANALYSIS_AVAILABLE or YARA_SCANNER_AVAILABLE) or not exe_path:
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

    @staticmethod
    def _safe_proc_cmdline(proc):
        """Extract sanitized, bounded CLI string without leaking secrets or mocks."""
        try:
            raw = proc.cmdline()
        except Exception:
            return ""
        if not isinstance(raw, (list, tuple)):
            return ""
        cleaned_tokens = []
        redact_next = False
        sensitive_flags = {"--password", "--secret", "--api-access-token", "--http-access-token", "--token"}
        for item in raw:
            if not isinstance(item, str):
                continue
            token = item.strip()
            if not token:
                continue
            lowered = token.lower()
            if redact_next:
                cleaned_tokens.append("<redacted>")
                redact_next = False
                continue
            if lowered in sensitive_flags:
                cleaned_tokens.append(token)
                redact_next = True
                continue
            if any(lowered.startswith(flag + "=") for flag in sensitive_flags):
                flag_name = token.split("=", 1)[0]
                cleaned_tokens.append(f"{flag_name}=<redacted>")
                continue
            cleaned_tokens.append(token)
        joined = " ".join(cleaned_tokens)
        return joined[:512]

    @staticmethod
    def _safe_proc_counters(proc):
        """Return (ctx_switches_total, io_bytes_total) safely coerced from ints."""
        ctx_total = 0
        io_total = 0
        try:
            ctx = proc.num_ctx_switches()
            if ctx is not None:
                v = getattr(ctx, "voluntary", 0)
                iv = getattr(ctx, "involuntary", 0)
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    ctx_total += max(0, int(v))
                if isinstance(iv, (int, float)) and not isinstance(iv, bool):
                    ctx_total += max(0, int(iv))
        except Exception:
            pass
        try:
            io_c = proc.io_counters()
            if io_c is not None:
                rb = getattr(io_c, "read_bytes", 0)
                wb = getattr(io_c, "write_bytes", 0)
                if isinstance(rb, (int, float)) and not isinstance(rb, bool):
                    io_total += max(0, int(rb))
                if isinstance(wb, (int, float)) and not isinstance(wb, bool):
                    io_total += max(0, int(wb))
        except Exception:
            pass
        return ctx_total, io_total

    @staticmethod
    def _is_suspicious_cmdline_text(cmdline):
        if not cmdline:
            return False
        lowered = cmdline.lower()
        strong_tokens = (
            "stratum+tcp://", "stratum+ssl://", "stratum+udp://", "stratum2+tcp://",
            "--donate-level", "--cpu-max-threads-pct", "--pause-on-active",
            "rx/0", "cryptonight", "xmrig", "randomx", "moneroocean", "supportxmr", "minexmr",
        )
        return any(tok in lowered for tok in strong_tokens)

    def _is_suspicious_path_local(self, exe_path):
        if not exe_path:
            return False
        lowered = str(exe_path).lower()
        return any(tok in lowered for tok in self._suspicious_path_tokens)

    def filter_processes(self):
        processes = []
        core_kernel_benign = {
            "system idle process", "system", "registry", "smss.exe", "csrss.exe",
            "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe", "fontdrvhost.exe",
        }
        gpu_compute_pids = dict(self._gpu_compute_pids or {})
        candidates = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                name_norm = self._normalize_name(info.get('name'))
                if name_norm in core_kernel_benign:
                    continue
                pid_val = info.get('pid')
                cpu_percent = float(info.get('cpu_percent') or 0.0)
                memory_percent = float(info.get('memory_percent') or 0.0)
                is_svchost = name_norm == "svchost.exe"
                is_wsl = name_norm in self._wsl_process_names
                is_gpu_compute = isinstance(pid_val, int) and pid_val in gpu_compute_pids
                is_masquerade_alias = (name_norm in self._monitored_spoof_names) and (
                    cpu_percent >= 2.0 or memory_percent >= 2.0
                )
                if cpu_percent > 4.0 or memory_percent > 4.0 or is_svchost or is_wsl or is_gpu_compute or is_masquerade_alias:
                    candidates.append((proc, info, cpu_percent, memory_percent, is_gpu_compute))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Only the top 18 are reported, so only they need the slower per-process lookups.
        candidates.sort(key=lambda c: (1 if c[4] else 0, c[2]), reverse=True)
        parent_cache = {}
        for proc, info, cpu_percent, memory_percent, is_gpu_compute in candidates[:18]:
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
                cmdline = self._safe_proc_cmdline(proc)
                ctx_switches_total, io_bytes_total = self._safe_proc_counters(proc)
                gpu_mem_mb = round(float(gpu_compute_pids.get(info['pid'], 0.0) or 0.0), 2)

                need_static_scan = (
                    cpu_percent >= 20.0
                    or is_gpu_compute
                    or self._is_suspicious_cmdline_text(cmdline)
                    or net_summary.get("has_miner_port")
                    or net_summary.get("has_pool_domain")
                    or (self._is_suspicious_path_local(exe_path) and (cpu_percent >= 4.0 or net_summary.get("has_external_connection")))
                )
                static_evidence = None
                if need_static_scan:
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
                    'cmdline': cmdline,
                    'ctx_switches_total': ctx_switches_total,
                    'io_bytes_total': io_bytes_total,
                    'gpu_compute_active': is_gpu_compute,
                    'gpu_memory_mb': gpu_mem_mb,
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

            compute_pids = {}
            for fn_name in ("nvmlDeviceGetComputeRunningProcesses", "nvmlDeviceGetGraphicsRunningProcesses"):
                fn = getattr(self._nvml, fn_name, None)
                if not callable(fn):
                    continue
                try:
                    entries = fn(self._nvml_handle)
                    if not isinstance(entries, (list, tuple)):
                        continue
                    for entry in entries:
                        pid_val = getattr(entry, "pid", None)
                        if isinstance(pid_val, int) and not isinstance(pid_val, bool):
                            mem_raw = getattr(entry, "usedGpuMemory", 0)
                            if isinstance(mem_raw, (int, float)) and not isinstance(mem_raw, bool) and 0 <= mem_raw < 512 * (1024 ** 3):
                                mem_mb = float(mem_raw) / (1024 * 1024)
                            else:
                                mem_mb = 0.0
                            compute_pids[pid_val] = max(compute_pids.get(pid_val, 0.0), mem_mb)
                except Exception:
                    continue
            self._gpu_compute_pids = compute_pids

            return float(utilization.gpu), memory.used / (1024 * 1024), memory.total / (1024 * 1024)
        except Exception:
            self._nvml_handle = False
            self._gpu_compute_pids = {}
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
            user_idle_seconds = self._get_user_idle_seconds()

            return {
                'timestamp': datetime.now().isoformat(),
                'activity': {
                    'user_idle_seconds': user_idle_seconds,
                    'is_idle': user_idle_seconds >= 30.0,
                },
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

    def _is_protected_containment_target(self, process_name, exe_path):
        name_norm = self._normalize_name(process_name)
        path_norm = os.path.realpath(str(exe_path)).lower() if exe_path else ""
        protected_prefixes = (
            "\\windows\\system32\\",
            "\\windows\\syswow64\\",
            "\\windows\\winsxs\\",
            "/usr/bin/",
            "/bin/",
            "/sbin/",
        )
        protected_names = {
            "system", "system idle process", "registry", "smss.exe", "csrss.exe",
            "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe",
            "dwm.exe", "explorer.exe", "cryptodetect-agent-v1.exe", "cryptodetect-agent-v9.exe",
        }
        if "cryptodetect" in name_norm:
            return True
        if path_norm and any(pref in path_norm.replace("/", "\\") for pref in protected_prefixes):
            return True
        if name_norm in protected_names and not path_norm:
            return True
        return False

    def _verify_target_process(self, pid, expected_create_time=None, expected_name=None):
        if pid is None:
            return None, "Missing target PID"
        try:
            proc = psutil.Process(int(pid))
            actual_name = self._normalize_name(proc.name())
            if expected_name and actual_name and actual_name != self._normalize_name(expected_name):
                return None, f"Process name mismatch at PID {pid} (expected {expected_name}, found {actual_name})"
            if expected_create_time is not None:
                actual_ct = float(proc.create_time())
                if abs(actual_ct - float(expected_create_time)) > 2.5:
                    return None, f"PID {pid} reuse detected (create_time mismatch)"
            return proc, None
        except psutil.NoSuchProcess:
            return None, f"Process PID {pid} is no longer running"
        except psutil.AccessDenied:
            return None, f"Access denied inspecting PID {pid}"
        except Exception as exc:
            return None, f"Failed resolving PID {pid}: {exc}"

    @staticmethod
    def _score_persistence_entry(category, name, location):
        loc_lower = str(location or "").lower()
        name_lower = str(name or "").lower()
        reasons = []
        suspicious_path_tokens = (
            "\\temp\\", "\\appdata\\", "\\programdata\\", "\\users\\public\\",
            "/tmp/", "/dev/shm/",
        )
        suspicious_cmd_tokens = (
            "xmrig", "stratum", "randomx", "cryptonight", "minexmr", "supportxmr",
            "-enc", "-encodedcommand", "mshta", "wscript", "regsvr32", "donate-level",
        )
        for tok in suspicious_path_tokens:
            if tok in loc_lower:
                reasons.append(f"path:{tok.strip(os.sep)}")
        for tok in suspicious_cmd_tokens:
            if tok in loc_lower or tok in name_lower:
                reasons.append(f"indicator:{tok}")
        return {
            "category": str(category),
            "name": str(name),
            "target": str(location)[:260],
            "location": str(location)[:260],
            "suspicious": len(reasons) > 0,
            "reasons": reasons[:5],
        }

    def _audit_windows_persistence(self):
        findings = []
        scanned_sources = []
        counts = {
            "registry_run": 0,
            "scheduled_tasks": 0,
            "non_system_services": 0,
            "startup_items": 0,
            "wsl_running_distros": 0,
        }

        if os.name == "nt":
            # 1. Registry Run / RunOnce (HKCU + HKLM)
            try:
                import winreg

                scanned_sources.append("registry_run")
                run_paths = [
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
                ]
                for hive, subkey, label in run_paths:
                    try:
                        with winreg.OpenKey(hive, subkey) as key:
                            count = winreg.QueryInfoKey(key)[1]
                            counts["registry_run"] += count
                            for idx in range(count):
                                val_name, val_data, _ = winreg.EnumValue(key, idx)
                                entry = self._score_persistence_entry(label, val_name, val_data)
                                if entry["suspicious"]:
                                    findings.append(entry)
                    except OSError:
                        continue
            except Exception:
                pass

            # 2. Scheduled Tasks (CSV parsed cleanly)
            try:
                scanned_sources.append("scheduled_tasks")
                startupinfo, creationflags = self._windows_startupinfo()
                completed = subprocess.run(
                    ["schtasks", "/query", "/fo", "CSV", "/v"],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    startupinfo=startupinfo,
                    creationflags=creationflags,
                )
                if completed.returncode == 0 and completed.stdout:
                    reader = csv.DictReader(io.StringIO(completed.stdout))
                    for row in reader:
                        task_name = str(row.get("TaskName") or "").strip()
                        task_run = str(row.get("Task To Run") or "").strip()
                        if not task_run or "\\Microsoft\\Windows\\" in task_name:
                            continue
                        counts["scheduled_tasks"] += 1
                        entry = self._score_persistence_entry("ScheduledTask", task_name, task_run)
                        if entry["suspicious"]:
                            findings.append(entry)
            except Exception:
                pass

            # 3. Startup folders
            try:
                scanned_sources.append("startup_folders")
                startup_dirs = [
                    Path(os.getenv("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
                    Path(os.getenv("ProgramData", "C:\\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
                ]
                for sdir in startup_dirs:
                    if not sdir.is_dir():
                        continue
                    for item in sdir.iterdir():
                        counts["startup_items"] += 1
                        entry = self._score_persistence_entry("StartupFolder", item.name, str(item))
                        findings.append(entry)
            except Exception:
                pass

            # 4. Windows Services running outside Windows\\System32
            try:
                scanned_sources.append("windows_services")
                startupinfo, creationflags = self._windows_startupinfo()
                svc_cmd = (
                    "Get-CimInstance Win32_Service | "
                    "Where-Object { $_.PathName -and $_.PathName -notmatch 'Windows\\\\System32' } | "
                    "Select-Object -First 80 Name, State, PathName | ConvertTo-Json -Compress"
                )
                completed = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", svc_cmd],
                    capture_output=True,
                    text=True,
                    timeout=6,
                    startupinfo=startupinfo,
                    creationflags=creationflags,
                )
                if completed.returncode == 0 and (completed.stdout or "").strip():
                    rows = json.loads(completed.stdout.strip())
                    if isinstance(rows, dict):
                        rows = [rows]
                    if isinstance(rows, list):
                        counts["non_system_services"] = len(rows)
                        for row in rows:
                            entry = self._score_persistence_entry(
                                f"Service({row.get('State', '?')})",
                                row.get("Name"),
                                row.get("PathName"),
                            )
                            if entry["suspicious"]:
                                findings.append(entry)
            except Exception:
                pass

            # 5. Active WSL2 instances
            try:
                scanned_sources.append("wsl2")
                startupinfo, creationflags = self._windows_startupinfo()
                completed = subprocess.run(
                    ["wsl", "-l", "--running", "-q"],
                    capture_output=True,
                    timeout=3,
                    startupinfo=startupinfo,
                    creationflags=creationflags,
                )
                if completed.returncode == 0 and completed.stdout:
                    decoded = completed.stdout.decode("utf-16-le", errors="ignore").strip()
                    distros = [line.strip().replace("\x00", "") for line in decoded.splitlines() if line.strip().replace("\x00", "")]
                    counts["wsl_running_distros"] = len(distros)
                    for distro in distros:
                        findings.append({
                            "category": "WSL2_Running",
                            "name": distro,
                            "target": f"wsl -d {distro}",
                            "location": f"wsl -d {distro}",
                            "suspicious": True,
                            "reasons": ["active_headless_linux_subsystem"],
                        })
            except Exception:
                pass

        suspicious_entries = [f for f in findings if f.get("suspicious")]
        return {
            "scanned_sources": scanned_sources,
            "counts": counts,
            "findings": findings[:40],
            "suspicious_entries": suspicious_entries[:40],
            "total_findings": len(findings),
            "suspicious_count": len(suspicious_entries),
            "audited_at": datetime.utcnow().isoformat(),
        }

    def execute_containment_command(self, cmd):
        """Execute a signed/queued SOC containment command safely and return (status, result_data, error_message)."""
        action = str(cmd.get("action") or "").strip().lower()
        target = cmd.get("target_payload") or {}
        pid = target.get("pid")
        create_time = target.get("create_time")
        process_name = target.get("process_name")
        exe_path = target.get("exe_path")
        exe_hash = target.get("exe_hash")
        remote_ip = target.get("remote_ip")

        if action == "suspend_process":
            proc, err = self._verify_target_process(pid, create_time, process_name)
            if err:
                return "failed", {}, err
            try:
                proc.suspend()
                return "completed", {"pid": proc.pid, "process_name": process_name, "state": "suspended"}, None
            except Exception as exc:
                return "failed", {}, f"Failed to suspend PID {pid}: {exc}"

        if action == "resume_process":
            proc, err = self._verify_target_process(pid, create_time, process_name)
            if err:
                return "failed", {}, err
            try:
                proc.resume()
                return "completed", {"pid": proc.pid, "process_name": process_name, "state": "resumed"}, None
            except Exception as exc:
                return "failed", {}, f"Failed to resume PID {pid}: {exc}"

        if action == "kill_process_tree":
            if self._is_protected_containment_target(process_name, exe_path):
                return "failed", {}, "Refused: protected system binary cannot be killed"
            proc, err = self._verify_target_process(pid, create_time, process_name)
            if err:
                return "failed", {}, err
            try:
                children = proc.children(recursive=True)
                for child in reversed(children):
                    try:
                        child.terminate()
                    except Exception:
                        pass
                proc.terminate()
                _, alive = psutil.wait_procs([proc] + children, timeout=3)
                for p in alive:
                    try:
                        p.kill()
                    except Exception:
                        pass
                return "completed", {
                    "pid": proc.pid,
                    "process_name": process_name,
                    "terminated_children": len(children),
                    "killed_children": len(children),
                }, None
            except Exception as exc:
                return "failed", {}, f"Failed killing process tree PID {pid}: {exc}"

        if action == "quarantine_binary":
            if not exe_path:
                return "failed", {}, "Missing exe_path for quarantine"
            real_path = os.path.realpath(str(exe_path))
            if self._is_protected_containment_target(process_name, real_path):
                return "failed", {}, "Refused: protected system file cannot be quarantined"
            if not os.path.isfile(real_path):
                return "failed", {}, f"Binary no longer present on disk: {real_path}"
            actual_hash = self._file_hash(real_path)
            if exe_hash and actual_hash and actual_hash.lower() != str(exe_hash).strip().lower():
                return "failed", {}, "Refused: binary SHA-256 changed since alert was recorded"

            if pid is not None:
                proc, _ = self._verify_target_process(pid, create_time, process_name)
                if proc is not None:
                    try:
                        for child in reversed(proc.children(recursive=True)):
                            child.kill()
                        proc.kill()
                        proc.wait(timeout=3)
                    except Exception:
                        pass

            try:
                self.quarantine_dir.mkdir(parents=True, exist_ok=True)
                stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(real_path))
                short_hash = (actual_hash or "nohash")[:12]
                dest_path = self.quarantine_dir / f"{stamp}_{short_hash}_{safe_name}.quarantined"
                shutil.move(real_path, str(dest_path))
                meta_path = dest_path.with_suffix(".json")
                meta_path.write_text(
                    json.dumps(
                        {
                            "original_path": real_path,
                            "sha256": actual_hash,
                            "process_name": process_name,
                            "quarantined_at": datetime.utcnow().isoformat(),
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                return "completed", {
                    "original_path": real_path,
                    "quarantine_path": str(dest_path),
                    "quarantined_path": str(dest_path),
                    "sha256": actual_hash,
                }, None
            except Exception as exc:
                return "failed", {}, f"Quarantine move failed: {exc}"

        if action == "block_ip":
            if not remote_ip:
                return "failed", {}, "Missing remote_ip to block"
            try:
                ip_obj = ipaddress.ip_address(str(remote_ip).strip())
            except ValueError:
                return "failed", {}, f"Invalid remote IP: {remote_ip}"
            if (
                ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local
                or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified
            ):
                return "failed", {}, f"Refused to block local/private IP {ip_obj}"
            if os.name != "nt":
                return "failed", {}, "Windows Firewall netsh requires Windows host"
            safe_rule = f"CryptoDetect_Block_{str(ip_obj).replace(':', '_')}"
            try:
                startupinfo, creationflags = self._windows_startupinfo()
                completed = subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={safe_rule}", "dir=out", "action=block",
                        f"remoteip={ip_obj}", "enable=yes",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    startupinfo=startupinfo,
                    creationflags=creationflags,
                )
                if completed.returncode != 0:
                    err_txt = (completed.stderr or completed.stdout or "Requires Administrator privilege").strip()
                    return "failed", {}, f"Firewall block failed: {err_txt}"
                return "completed", {"rule_name": safe_rule, "blocked_ip": str(ip_obj)}, None
            except Exception as exc:
                return "failed", {}, f"Firewall execution error: {exc}"

        if action == "audit_persistence":
            try:
                audit_result = self._audit_windows_persistence()
                return "completed", audit_result, None
            except Exception as exc:
                return "failed", {}, f"Persistence audit failed: {exc}"

        return "failed", {}, f"Unsupported containment action: {action}"

    def _report_command_result(self, command_id, status, result_data, error_message):
        try:
            requests.post(
                f"{self.api_url}/api/agent/commands/{command_id}/result",
                json={
                    "status": status,
                    "result_data": result_data or {},
                    "error_message": error_message,
                },
                headers={"X-API-Key": self.api_key},
                timeout=10,
            )
        except Exception as exc:
            self._log(f"  [CMD] Failed reporting result for command {command_id}: {exc}")

    def _process_pending_commands(self, commands):
        if not isinstance(commands, list) or not commands:
            return
        for cmd in commands:
            cmd_id = cmd.get("command_id") or cmd.get("id")
            if cmd_id is None:
                continue
            with self._command_lock:
                if cmd_id in self._active_command_ids:
                    continue
                self._active_command_ids.add(cmd_id)
            try:
                status, result_data, error_message = self.execute_containment_command(cmd)
                self._report_command_result(cmd_id, status, result_data, error_message)
            finally:
                with self._command_lock:
                    self._active_command_ids.discard(cmd_id)

    def _poll_commands_async(self):
        def _worker():
            try:
                resp = requests.get(
                    f"{self.api_url}/api/agent/commands/{self.system_id}",
                    headers={"X-API-Key": self.api_key},
                    timeout=8,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    cmds = data.get("commands") or []
                    if cmds:
                        self._process_pending_commands(cmds)
            except Exception:
                pass

        threading.Thread(target=_worker, daemon=True).start()

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
                pending_cmds = result.get("pending_commands") or []
                if pending_cmds:
                    threading.Thread(
                        target=self._process_pending_commands,
                        args=(pending_cmds,),
                        daemon=True,
                    ).start()
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
