# CryptoDetect System Architecture & Technical Workflow Specification

**System Version:** v1.0  
**Target Environment:** Windows 10/11 Workstations (Endpoint) & Cross-Platform Linux/Windows Server (Backend)  
**Document Classification:** Engineering Design & Workflow Specification  

---

## 1. High-Level Architectural Overview

CryptoDetect implements a zero-trust, defense-in-depth endpoint security architecture structured across four decoupled tiers:

```
+--------------------------------------------------------------------------------------------------+
|                                    CRYPTODETECT TIERED TOPOLOGY                                   |
+------------------------------------+------------------------------------+------------------------+
| 1. Endpoint Sensor & Actuator Tier | 2. Ingestion & Analytics Tier      | 3. Security Analyst UI |
| (CryptoDetect-Agent-v1.exe)        | (FastAPI, SQLAlchemy, ML, SHAP)    | (React 19 Security Web)|
| - 5s In-Process NVML & psutil      | - Dynamic Cross-OS Feature Adapt.  | - Live Metrics Horizon |
| - Win32 User-Idle Tracking         | - 24-Sample Duty-Cycle Evaluation  | - SHAP Attribution Bars|
| - 60-Sample Outage Buffer          | - XGBoost & Random Forest Ensemble | - Active Containment   |
| - Anti-TOCTOU Command Executor     | - Authenticated Command Queue      | - Persistence Triage   |
+------------------------------------+------------------------------------+------------------------+
```

---

## 2. Component Architecture Diagram

The component diagram below visualizes the physical separation between sensor data collection, analytical processing, and operator response:

```mermaid
flowchart TB
    subgraph HostEndpoint ["Monitored Windows Host (CryptoDetect-Agent-v1.exe)"]
        direction TB
        subgraph Sensors ["Telemetry Sensors"]
            S1["psutil Host Engine\n(CPU, RAM, Disks, Sockets)"]
            S2["In-Process NVML Engine\n(Per-PID CUDA Compute)"]
            S3["Win32 GetLastInputInfo\n(User-Idle Duration)"]
            S4["DNS Client Cache\n+ TLS :443 Tracker"]
        end

        subgraph LocalPipeline ["Local Agent Pipeline"]
            LP1["Process Resource Filter\n(CPU >= 4% or RAM >= 4%)\nTop 18 Candidates"]
            LP2["Disk-Backed JSON Ring Buffer\n(~/.cryptodetect/cache/pending_*.json)\nCapped at 60 Samples (5 Min)"]
            LP3["Static Scanner & YARA Engine\n(PE Headers, RandomX, UPX)"]
        end

        subgraph Actuators ["Agent Containment Actuators"]
            ACT1["Anti-TOCTOU Process Guard\n(create_time Verification)"]
            ACT2["Forensic Quarantine Vault\n(~/.cryptodetect/quarantine)"]
            ACT3["Windows Firewall Controller\n(netsh advfirewall)"]
            ACT4["Host Persistence Auditor\n(schtasks, Registry, Services, WSL2)"]
        end
    end

    subgraph BackendServer ["FastAPI Analytics & Command Backend"]
        direction TB
        B_ING["Metrics Ingestion Gateway\n(/api/metrics)"]
        B_POL["Process Policy & Masquerade Filter\n(process_policy.json)"]
        B_SHAP["Cross-OS SHAP Log-Odds Margin\n(Linux -> Windows Adaptation)"]
        B_ML["Ensemble Behavioral ML\n(Random Forest + XGBoost)"]
        B_TEMP["Dynamic Behavior Monitor\n(24-Sample Duty-Cycle / IO-Ratio)"]
        B_ALERT["Threat Aggregator\n(3-Sample Persistence Gate)"]
        B_QUEUE["Authenticated Command Queue\n(AgentCommand ORM Model)"]
        B_DB[(SQLite / PostgreSQL\nSQLAlchemy Engine)]
    end

    subgraph SOCDashboard ["React 19 Security Operations Console"]
        UI_DASH["Live System Telemetry\n(60-Sample Visual Horizon)"]
        UI_SHAP["Explainable AI View\n(Real-time SHAP Waterfalls)"]
        UI_QUEUE["Active SOC Containment Panel\n(Signed Operator Directives)"]
    end

    %% Data Flows
    S1 & S2 & S3 & S4 --> LP1
    LP1 --> LP2
    LP1 -.->|CPU >= 20%| LP3
    LP2 -->|HTTP/JSON Batch Every 30s| B_ING
    
    B_ING --> B_DB
    B_ING --> B_POL
    B_POL --> B_SHAP
    B_SHAP --> B_ML
    B_ML --> B_TEMP
    B_TEMP --> B_ALERT
    B_ALERT --> B_DB
    
    B_ALERT --> UI_DASH & UI_SHAP
    UI_QUEUE -->|Operator Authorized Action| B_QUEUE
    B_QUEUE -->|Dispatched on 10s Heartbeat| ACT1 & ACT2 & ACT3 & ACT4
    ACT1 & ACT2 & ACT3 & ACT4 -->|Execution Outcome & Forensics| B_QUEUE
```

---

## 3. End-to-End Operational Lifecycle Sequence

The sequence diagram illustrates the communication flow across agent startup, telemetry streaming, multi-signal inference, alert generation, and containment dispatch:

```mermaid
sequenceDiagram
    autonumber
    actor Operator as SOC Analyst
    participant UI as React 19 Console
    participant Backend as FastAPI Backend
    participant DB as Database (SQLAlchemy)
    participant Agent as Windows Agent (v1.0)
    participant OS as Windows Kernel / APIs

    Note over Agent, OS: Phase 1: Registration & Telemetry Loop
    Agent->>Backend: POST /api/systems/register (Hostname, OS, Hardware)
    Backend->>DB: Store System & Issue SHA-256 Hashed API Key
    Backend-->>Agent: Return system_id & Plaintext Key
    
    loop Every 5 Seconds
        Agent->>OS: Query psutil, NVML per-PID, GetLastInputInfo, DNS Cache
        Agent->>Agent: Buffer 5s Sample in Local JSON Ring Buffer (FIFO)
    end

    Note over Agent, Backend: Phase 2: Telemetry Batching & Heartbeats
    loop Every 10 Seconds
        Agent->>Backend: GET /api/systems/{id}/heartbeat
        Backend-->>Agent: HTTP 200 (Online status updated)
    end

    loop Every 30 Seconds
        Agent->>Backend: POST /api/metrics (Batch of 6 Samples)
        Backend->>DB: Insert Telemetry Samples (Deduplicated)
        Backend->>Backend: Evaluate Policy Rules & Path Masquerading
        alt Uncollected Linux Features Detected
            Backend->>Backend: Compute SHAP Log-Odds Marginalization
            Backend->>Backend: Apply Compute-Pressure Gating
        end
        Backend->>Backend: Predict XGBoost + Random Forest Probabilities
        Backend->>Backend: Update 24-Sample Temporal Sliding Window
        
        opt Threat Criteria Satisfied (3 Sustained Samples)
            Backend->>DB: Create Incident Alert (Severity: High/Critical)
            Backend->>UI: Push Notification & Update Dashboard
        end
        Backend-->>Agent: HTTP 200 (Acknowledged, Pending Samples Cleared)
    end

    Note over Operator, Agent: Phase 3: Active Incident Triage & Containment
    Operator->>UI: Review Alert Details & SHAP Explanation Bars
    Operator->>UI: Authorize Containment Action (e.g. Kill Process Tree)
    UI->>Backend: POST /api/alerts/{id}/actions (action: kill_process_tree, pid, create_time)
    Backend->>DB: Enqueue AgentCommand (Status: Pending)
    
    Agent->>Backend: GET /api/agent/commands/{system_id} (Claim Command)
    Backend->>DB: Update Command Status to 'Dispatched'
    Backend-->>Agent: Return Command Payload with Target Metadata

    Agent->>OS: Verify Anti-TOCTOU: Process(pid).create_time() == expected
    alt Verification Succeeded
        Agent->>OS: Terminate Recursive Process Tree (Parent + Children)
        Agent->>Backend: POST /api/agent/commands/{cmd_id}/result (status: completed)
        Backend->>DB: Update Command Status to 'Completed' & Audit Log
        Backend-->>UI: Real-Time Status: Threat Neutralized
    else Verification Failed (PID Reused by OS)
        Agent->>Backend: POST /api/agent/commands/{cmd_id}/result (status: failed, reason: TOCTOU mismatch)
        Backend->>DB: Mark Command Failed & Flag Security Warning
    end
```

---

## 4. Evasion Detection Subsystems

### 4.1 Win32 `GetLastInputInfo` Idle-Surge Correlation
Miners implementing `--pause-on-active` or duty-cycling evade static rules by halting calculation when user activity is detected. The endpoint agent samples:
$$\text{user\_idle\_seconds} = \frac{\text{GetTickCount}() - \text{GetLastInputInfo.dwTime}}{1000}$$

```mermaid
stateDiagram-v2
    [*] --> ActiveUserSession: User Mouse/Keyboard Event Detected
    ActiveUserSession --> MonitoringState: user_idle_seconds < 30
    MonitoringState --> ActiveUserSession: User Active (Miner Idle / Throttled)
    
    MonitoringState --> IdleSurgeState: user_idle_seconds >= 30
    IdleSurgeState --> CorroborateDivergence: Process CPU surges by >= 15%
    CorroborateDivergence --> RaiseIdleAwareAnomaly: No foreground user window active
    RaiseIdleAwareAnomaly --> [*]: Flag Candidate for Evasion Alarm
```

### 4.2 24-Sample Temporal Duty-Cycle & Context-Switch/I/O Tracking
To distinguish sustained, throttled miners ($20\%\text{--}35\%$ CPU) from legitimate bursty development tools (compilers, code indexers, test runners), the `DynamicBehaviorMonitor` maintains a 24-sample sliding history (representing a 2-minute time horizon):
1. **Duty-Cycle Score:**
   $$\text{DutyCycle} = \frac{\sum_{i=1}^{N} \mathbb{I}(\text{CPU}_i \ge 15.0\%)}{N}$$
   Where miners exhibit $\text{DutyCycle} \ge 0.80$ with extremely low variance ($\sigma_{\text{CPU}} \le 4.5\%$).
2. **Context-Switch to Disk-I/O Ratio:**
   $$\text{ComputePurityRatio} = \frac{\Delta\text{ContextSwitches}}{\Delta\text{DiskReadBytes} + \Delta\text{DiskWriteBytes} + 1}$$
   Cryptominers spend $>99\%$ of CPU cycles cycling in RAM hashing buffers without reading/writing disk files, whereas compilers and archivers (7-Zip) maintain heavy disk read/write throughput.

### 4.3 Encrypted Stratum-over-TLS (:443) & DNS Pool Tracking
Attackers frequently run miners with `--tls` on port 443, bypassing cleartext port monitors (`3333`, `4444`, `14444`). CryptoDetect correlates three signals:
1. **DNS Client Cache Inspection:** Queries PowerShell `Get-DnsClientCache` to extract recently resolved domains matching known pool lists (e.g., `*.supportxmr.com`, `*.nanopool.org`, `*.minexmr.com`).
2. **Persistent Sockets:** Flags processes maintaining active outbound connections to remote port 443 with connection lifetimes exceeding 60 seconds that are **not** attributed to known web browsers or signed software.
3. **Paced Low-Byte Flows:** Tracks periodic bidirectional payload transfers characteristic of Stratum JSON-RPC job submissions ($100\text{--}500\text{ bytes}$ per packet with fixed keepalive intervals).

### 4.4 In-Process NVML GPU Attribution
Standard OS monitors track only aggregate GPU load. The CryptoDetect agent utilizes Python NVML bindings (`pynvml`) in-process:
1. Resolves all active CUDA compute engines via `nvmlDeviceGetComputeRunningProcesses`.
2. Binds memory footprint and compute engine utilization directly to candidate PIDs.
3. Automatically triggers high-priority alerts if an unsigned binary running out of `%TEMP%` or `%APPDATA%` consumes $>100\text{ MB}$ of VRAM.

---

## 5. Authenticated Closed-Loop Containment Engine

### 5.1 Agent Command State Machine

```mermaid
stateDiagram-v2
    [*] --> Pending: Operator Enqueues Action via REST API
    Pending --> Dispatched: Agent Claims Command via /api/agent/commands
    
    Dispatched --> AntiTOCTOUCheck: Agent Inspects Target Process
    AntiTOCTOUCheck --> ExecutingAction: PID & create_time Match Exactly
    AntiTOCTOUCheck --> ExecutionFailed: Process create_time Mismatch (PID Reused)
    
    ExecutingAction --> Completed: Subsystem Returns Success (Kill/Quarantine/Firewall)
    ExecutingAction --> ExecutionFailed: OS Kernel Permission Denied
    
    Completed --> [*]: Log Immutable Audit Entry & Notify UI
    ExecutionFailed --> [*]: Log Security Alert & Notify UI
```

### 5.2 Anti-TOCTOU Safeguards
To prevent Time-of-Check to Time-of-Use race conditions where a killed malicious process is replaced by an innocent application that happened to receive the same PID from the Windows kernel:
```python
# Verification Logic in monitoring_agent/enhanced_agent.py
def _verify_target_process(self, pid, expected_create_time=None, expected_name=None):
    if not psutil.pid_exists(pid):
        return False, "PID no longer exists"
    proc = psutil.Process(pid)
    if expected_create_time is not None:
        if abs(proc.create_time() - float(expected_create_time)) > 0.5:
            return False, "Process create_time mismatch (PID reallocated by OS)"
    if expected_name is not None:
        if proc.name().lower() != expected_name.lower():
            return False, "Process name mismatch"
    return True, proc
```

### 5.3 Quarantine Vault Architecture
When `quarantine_binary` executes:
1. **File Move:** Relocates binary from target directory to `~/.cryptodetect/quarantine/<sha256>.quarantine`.
2. **ACL Stripping:** Removes execute permissions (`icacls <file> /deny Everyone:(X)`).
3. **Forensic Manifest:** Writes `<sha256>.json` containing original path, file size, SHA-256 digest, isolation timestamp, and parent process command line.

### 5.4 Windows Host Persistence Auditor
Triggered on demand or automatically post-containment, scanning five operational vectors:
- **Scheduled Tasks:** Queries `schtasks /query /fo CSV /v` for tasks referencing unsigned binaries or invoking hidden PowerShell commands (`-WindowStyle Hidden -EncodedCommand`).
- **Registry Run Keys:** Enumerates `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` and `HKCU\...`.
- **Windows Services:** Queries `win32_service` via WMI for services configured with `Automatic` start whose binary path resides outside `%SystemRoot%\System32`.
- **Startup Directory:** Audits `.lnk` shortcuts and `.bat` files in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`.
- **WSL2 Hypervisor:** Inspects running distributions via `wsl.exe -l -v` to ensure attackers are not executing Linux miners inside `vmmem`.

---

## 6. Technical Data Schemas

### 6.1 Telemetry Metric Payload (`/api/metrics`)
```json
{
  "system_id": "SYS-9B21FA4E",
  "timestamp": "2026-11-08T15:30:00Z",
  "metrics": {
    "cpu_percent": 34.2,
    "memory_percent": 58.1,
    "load_min1": 2.75,
    "load_min5": 2.10,
    "load_min15": 1.95,
    "user_idle_seconds": 142.5,
    "active_process_count": 218,
    "gpu_metrics": {
      "available": true,
      "gpu_count": 1,
      "gpu_utilization": 88.0,
      "gpu_memory_used_mb": 2048,
      "compute_processes": [
        {"pid": 14208, "process_name": "xmrig.exe", "used_memory_mb": 1850}
      ]
    },
    "dns_miner_pool_detected": true,
    "top_processes": [
      {
        "pid": 14208,
        "name": "xmrig.exe",
        "cpu_percent": 24.8,
        "memory_percent": 4.2,
        "create_time": 1794129000.12,
        "exe_path": "C:\\Users\\Public\\xmrig.exe",
        "exe_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "cmdline": "--cpu-max-threads-pct 25 --pause-on-active -o stratum+ssl://pool.supportxmr.com:443",
        "has_miner_port": false,
        "has_stealth_tls": true,
        "idle_surge_divergence": true,
        "yara_matches": ["RandomX_VM_Init", "Stratum_JSON_RPC"]
      }
    ]
  }
}
```

### 6.2 Containment Action Payload (`/api/alerts/{id}/actions`)
```json
{
  "action": "kill_process_tree",
  "pid": 14208,
  "create_time": 1794129000.12,
  "process_name": "xmrig.exe",
  "exe_path": "C:\\Users\\Public\\xmrig.exe",
  "exe_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "remote_ip": "198.51.100.42"
}
```

