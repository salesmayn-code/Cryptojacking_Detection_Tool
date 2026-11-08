# Cryptojacking Detection Research Landscape, Industry Response, & CryptoDetect Improvement Roadmap

**Prepared:** November 8, 2026  
**Codebase Audited:** `d:\Projects\Universities\FYP\Cryptojacking_Detection_Tool`

---

## 1. Reality Check: What Already Exists Online (Literature & Open-Source)

Before positioning **CryptoDetect** for academic publication or research, it is critical **not** to claim *"nothing like this exists."* Peer reviewers will immediately reject an unsubstantiated novelty claim because prior work exists across three separate silos — **browser detectors**, **kernel/low-level binary tracers**, and **SOC/EDR telemetry rules**.

What **is** rare in open source — and where CryptoDetect's strength lies — is combining **all of these in one deployable Windows endpoint platform** (live tray agent + FastAPI scoring engine + XAI SHAP dashboard + PDF/CSV auditing + alerting).

### A. Landmark Academic Systems
| System / Paper | Target Domain | Core Detection Mechanism | Strengths | Known Limitations |
|---|---|---|---|---|
| **MineSweeper** *(Konoth et al.)* | Browser (JS) | Domain blocklists + static heuristic matching | Very fast, trivial deployment | Bypassed by domain rotation and script minification |
| **SEISMIC** *(Wang et al., ESORICS 2018)* | Browser (WebAssembly) | In-lined Reference Monitors (IRMs) watching Wasm opcode/semantic signatures | Resilient against JS obfuscation | Runtime instrumentation overhead slows pages |
| **Outguard** *(Kharraz et al., WWW 2019)* | Browser (JS + Wasm) | Instrumented browser CPU profiling + network traces fed to SVM | High TPR (97.9%) across Alexa 1M crawl | Vulnerable to CPU throttling & loop mimicry |
| **MinerRay** *(Romano et al., ASE 2020)* | Browser (JS + Wasm) | Control-Flow Graph (CFG) crypto-math semantics + checks whether user gesture spawned worker | Catches unseen zero-day web miners | Heavy CFG parsing; browser-only scope |
| **CryptojackingTrap** *(Chahoki et al., IEEE TIFS)* | Host binaries | Assembly/debugger memory access trace correlated with P2P/Stratum traffic | High resilience to packing and throttling | Heavyweight debugger attachment; binary-focused |
| **Cryptic Bytes** *(Harnes & Morrison, arXiv 2024)* | Browser Wasm (Attack/Eval) | `Tigress`, `wasm-mutate`, `emcc-obf` obfuscation benchmarks | Proved static/signature Wasm detectors still fail against obfuscated miners | Offensive evaluation study |
| **HPC Cryptominer Detection** *(2024–2025 arXiv / MDPI)* | Host CPU | Hardware Performance Counters (IPC, L1/L2/L3 cache misses, TLB misses, branch mispredictions) + RF/SVM/NN | Detects **throttled** RandomX/CryptoNight loops within ~5s | Requires PMU/kernel driver privileges (VTune / perf) |
| **JA4 / JA4+ Encrypted TLS Analysis** *(Brno / CNSM 2024–2025)* | Network TLS | `ClientHello` cipher/extension/ALPN fingerprints + XGBoost/CatBoost | Identifies TLS-wrapped C2 / mining stacks (`>98%` accuracy) without decryption | Network sensor / PCAP / ETW TLS visibility needed |
| **Kaggle Timeseries + ML Benchmarks** *(Jayasinghe; Faieq & Rasheed, IJSSE 2026; CryptojackGuard)* | Linux VM telemetry | Glances 20-feature OS telemetry + RF, XGBoost, SHAP, Transformers | High accuracy inside the single source Linux VM benchmark | Single-VM capture, severe Linux-to-Windows domain shift, lacks throttled miners and benign stress controls |

### B. How Open-Source & Enterprise Blue Teams Actually Deal With Cryptojacking
Enterprise SOCs map cryptojacking under **MITRE ATT&CK T1496 (Resource Hijacking)** and **T1496.001 (Compute Hijacking)**:
1. **Detection Stack (Wazuh / Velociraptor / Falco / Sysmon / Microsoft Defender):**
   - **Sysmon Event ID 1 (Process Creation) + Sigma Rules:** Flags CLI flags (`-o stratum+tcp://`, `-o stratum+ssl://`, `--donate-level`, `--algo`, `--cpu-max-threads-pct`, `--pause-on-active`) and binaries running from temp/public folders (`C:\Users\Public\`, `%TEMP%`, `%APPDATA%`).
   - **Sysmon Event ID 3 / Netflow:** Long-lived outbound TCP flows on pool ports (`3333`, `4444`, `5555`, `14444`, or HTTPS `:443` / `:80` over TLS).
   - **YARA Memory + Disk Hunts:** `Velociraptor` (`Windows.Detection.Yara.Process`) and `Wazuh` scan active process RAM and dropped files for RandomX / XMRig byte patterns even when binaries are renamed (`svchost.exe`).
   - **ETW & ETWTI (Event Tracing for Windows — Threat Intelligence):** Kernel-level visibility into process hollowing and reflective DLL injection (`OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) that miners use when running fileless in RAM.
   - **eBPF / WSL2 Visibility:** Attackers hide ELF binaries inside WSL2 (`vmmem`) or Docker Desktop containers on Windows where native Windows `psutil` only sees hypervisor memory/CPU.

2. **How SecOps Remediates Cryptojacking (Detection Alone Is Insufficient):**
   Killing `xmrig.exe` manually almost always fails because attackers attach **watchdogs, scheduled tasks, or Windows services** that immediately respawn the miner. Standard NIST SP 800-61 incident response follows four steps:
   1. **Containment:** Suspend process or kill the **full process tree** (parent + children), isolate endpoint network or block pool IP/domain via Windows Firewall.
   2. **Forensic Preservation:** Capture executable hash, command line, memory/process snapshot, parent PID, and remote socket before wiping artifacts.
   3. **Persistence Eradication:** Audit and remove rogue Scheduled Tasks (`schtasks`), Windows Services (Event ID `7045`), Registry Run keys (`HKLM\...\Run`), WMI event consumers, startup scripts, and infected WSL2 containers.
   4. **Recovery & Hardening:** Rotate credentials/API keys and patch the initial access vector (exposed RDP, SQL/Docker API, cracked software, or compromised developer dependencies).

---

## 2. Honest Audit of CryptoDetect Right Now (Strengths vs. Research Blind Spots)

### What CryptoDetect Already Does Well
- **Full-stack Windows Architecture:** Single-instance tray agent (`monitoring_agent/agent_gui.py` + `enhanced_agent.py`), disk-backed 60-sample FIFO retry queue, NVML GPU querying, SHA-256 hashed API keys, FastAPI + SQLAlchemy backend, and React security console with SHAP attribution bars.
- **Impersonation & Multi-Signal Gate:** Checks `svchost.exe` path/parent/publisher/Authenticode signature (`backend/routes/metrics.py`), duplicate executable name anomalies, VirusTotal/MalwareBazaar SHA-256 lookups, static PE/string extraction (`static_analysis/`), and sustained 3-sample sliding windows (`dynamic_analysis/behavior_monitor.py`).
- **Genuine Cross-OS Innovation Already Built:** Unlike naive Kaggle models that blindly fire false positives when deployed from Linux Glances telemetry to Windows `psutil`, `backend/routes/metrics.py` detects uncollected Windows counters (`WINDOWS_UNCOLLECTED_FEATURES`: `mem_cached`, `mem_active`, `cpu_iowait`, `cpu_softirq`) and applies **runtime SHAP log-odds marginalization** plus compute-pressure gating (`_has_uncollected_linux_memory_counters`, lines 1537–1701).

### 6 Concrete Gaps Limiting Research Novelty & Real-World Defense
1. **Blind to Throttled, Duty-Cycled, and User-Idle ("AFK") Miners:**
   - `enhanced_agent.py` only inspects candidates with `cpu > 4.0` or `mem > 4.0`, triggers static scanning only at `cpu >= 20.0%` (`enhanced_agent.py:386`), and `DynamicBehaviorMonitor` requires 3 consecutive samples `>= 45.0%` (`behavior_monitor.py:66`).
   - *Evasion:* Running `xmrig --cpu-max-threads-pct 20 --pause-on-active` or pulsing 20s-on / 10s-off completely bypasses current thresholds.
   - Furthermore, the agent **does not inspect `proc.cmdline()`**, missing `-o stratum+`, `--donate-level`, `--pause-on-active`, and wallet addresses in command lines (which even Sigma rules catch immediately).
2. **Encrypted Stratum-over-TLS (`:443`) & XMRig-Proxy Blind Spot:**
   - `_miner_ports` checks fixed cleartext pool ports (`3333, 4444, 5555, ...`). Miners using `--tls` on port `443` or `80` avoid `has_miner_port = True`.
3. **`yara-python` Is Installed (`requirements.txt:21`) But Unused:**
   - `static_analysis/` relies on hand-coded strings/entropy rather than curated YARA signatures for RandomX constants, packed UPX/Themida miners, or in-memory process scanning (`proc_mem` / PE sections).
4. **No Active Containment / Response Workflow:**
   - The console detects and alerts, but cannot isolate a mining process, suspend/kill a process tree, quarantine an unsigned executable, add a Windows Firewall outbound rule, or audit persistence (`schtasks` / Registry Run / Services / WSL2).
5. **No Hardware/Microarchitectural Telemetry or GPU Process Attribution:**
   - NVML reports host GPU load (`monitoring_agent/enhanced_agent.py`), yet does not list per-PID GPU compute processes (`nvmlDeviceGetComputeRunningProcesses`), nor track Windows user idle time (`GetLastInputInfo`) or voluntary/involuntary context switch patterns.
6. **Dataset Validity Ceiling (Kaggle Linux Dataset Alone):**
   - Achieving 1.0000 on Jayasinghe's 95,310-row Linux dataset does **not** prove generalization on modern Windows 10/11 endpoints under legitimate heavy workloads (Visual Studio builds, Docker, Blender, video encoding) vs. throttled/TLS XMRig.

---

## 3. High-Impact Research Directions & Feature Upgrades

If you want to publish a research paper *and* make CryptoDetect stand out among open-source tools, focus on **three tightly connected contributions**:

### Research Contribution 1: Cross-OS SHAP Log-Odds Domain Adaptation & Calibration (Formalize What You Already Started!)
- **Thesis:** Public Linux telemetry benchmarks (e.g., Kaggle's 95k Glances dataset) fail catastrophically on Windows endpoints due to missing kernel memory/CPU counters (`mem_cached`, `mem_active`, `cpu_iowait`, `cpu_softirq`).
- **Actionable Upgrade + Experiment:**
  - Collect a real **Windows Endpoint Evaluation Benchmark** (on your 16-thread PC) covering 5 workloads:
    1. Idle / Office / Browsing,
    2. Legitimate heavy compute (7-Zip, Python/MSVC compile, Blender/FFmpeg, Chrome heavy tabs),
    3. Unthrottled XMRig (`100%`),
    4. **Throttled / Evasive XMRig** (`25%` threads, duty-cycled, `--pause-on-active`, `--tls` port 443),
    5. GPU miner simulation / OpenCL load.
  - Benchmark **Naive Linux XGBoost/RF** vs. **SHAP Log-Odds Marginalized Model** vs. **Target-Domain Fine-Tuned Calibration** (e.g., isotonic/Platt calibration or DANN/feature alignment). Showing exact FPR/FNR reduction across Windows workloads creates a rigorous, honest IEEE/ACM/applied-ML paper!

### Research Contribution 2: Evasion-Resilient Telemetry (Beating Throttling, Idle-Awareness, Stratum-TLS, & Fileless Execution)
- **Add to `monitoring_agent/enhanced_agent.py`:**
  1. **User-Idle Correlation (`GetLastInputInfo`):** Measure seconds since last mouse/keyboard input in every 5s frame (`user_idle_sec`). Flag processes whose CPU increases sharply *only when `user_idle_sec > 30`* and drops to ~0% on input! (Solves `--pause-on-active` evasion!)
  2. **Command-Line & Parent-Child Lineage Telemetry (`proc.cmdline()`):** Capture sanitized command-line arguments + parent executable path for suspicious candidates; apply Sigma-equivalent rules in `metrics.py` even at `5%` CPU.
  3. **Spectral / Sustained Low-Load Sliding Window (`max_samples=24`, 2 minutes):** Instead of requiring `>= 45%` for 3 samples, track *variance, duty-cycle ratio, low disk-I/O-per-CPU-second*, and *context-switch velocity* per process over 12–24 intervals to catch `20%–35%` throttled miners without flagging short bursty compilers.
  4. **YARA Disk + Safe Memory Rules (`yara-python`):** Wire `yara-python==4.5.0` into `static_analysis/yara_scanner.py` with curated RandomX / Stratum / wallet / UPX-packer rules, scanning suspicious binaries on disk and (optionally under admin privileges) suspicious process memory.
  5. **Encrypted Flow & DNS Pool Correlation:** Correlate outbound TLS (`:443`) sockets with Windows DNS client cache / known pool domain IP ranges + persistent long-lived connection duration + low bytes-per-second periodicity (`rx/tx` job keepalives) so `--tls` no longer blinds the detector.
  6. **NVML Per-Process GPU Attribution & WSL2 Awareness:** Query `nvmlDeviceGetComputeRunningProcesses` to attribute CUDA/GPU mining directly to a specific PID, and inspect `vmmem` / `wsl.exe` behavior.

### Research Contribution 3: Human-in-the-Loop Active Remediation & Persistence Eradication (Closing the SOC Loop)
- **Add to `backend/` + `monitoring_agent/` + React Alerts Console:**
  1. **Two-Way Containment Command Queue (Signed & Audited):** Operators can click **"Suspend Process"** (safely freezes suspect process in RAM without losing evidence or crashing dependencies), **"Kill Process Tree"**, or **"Quarantine Binary"** (moves locked binary + logs SHA-256 + blocks pool IP via Windows Firewall `netsh`).
  2. **Windows Persistence Auditor:** On alert triage, inspect and report Scheduled Tasks (`schtasks`), Run registry keys, unsigned Services, and Startup folder payloads linked to the flagged executable or parent command.
  3. **Playbook Audit Trail:** Log every analyst response action in `AuditLog` alongside the SHAP explanation, bridging explainable detection with auditable containment.

---

## Key Citations for Literature Review
1. **Faieq, A. K., & Rasheed, M. M. (2026).** *"Cybersecurity Approaches to Cryptojacking Detection: A Computer Application Perspective."* IJSSE, 16(1), 112. (Evaluates Random Forest/SVM/MLP on the 95,312-row Kaggle cryptojacking dataset).
2. **Jayasinghe, K.** *Cryptojacking Attack Timeseries Dataset (Version 1).* Kaggle (CC0 Public Domain; 80,851 normal / 14,461 cryptojacking telemetry rows).
3. **Kharraz, A., et al. (2019).** *"Outguard: Detecting In-Browser Covert Cryptocurrency Mining in the Wild."* The Web Conference (WWW '19), Best Paper.
4. **Wang, W., et al. (2018).** *"SEISMIC: SEcure In-lined Script Monitors for Interrupting Cryptojacks."* ESORICS 2018.
5. **Romano, A., et al. (2020).** *"MinerRay: Semantics-Aware Analysis for Ever-Evolving Cryptojacking Detection."* IEEE/ACM ASE 2020.
6. **Chahoki, A. Z., et al.** *"CryptojackingTrap"* (Evasion-resilient debugger/memory hash & P2P trace correlation).
7. **Harnes, H., & Morrison, D. (2024).** *"Cryptic Bytes: WebAssembly Obfuscation for Evading Cryptojacking Detection."* arXiv preprint.
8. **MITRE ATT&CK® T1496 (Resource Hijacking) & T1496.001 (Compute Hijacking).** MITRE Corporation.
9. **CNSM / Brno TLS JA4+ Studies (2024–2025).** Encrypted malicious TLS classification via JA4 / JA4S / JA4X with XGBoost/CatBoost.

