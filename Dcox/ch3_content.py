content = r"""
---

# Chapter 3: System Overview

This chapter provides a detailed explanation of the internal workings of the CryptoDetect system. The platform identifies cryptojacking activity by analyzing system metrics and process behavior in real time. It consists of a FastAPI backend hosting ML models (XGBoost and Random Forest), a React-based frontend dashboard, a lightweight Windows monitoring agent (CryptoDetect Agent v7.0), and VirusTotal/MalwareBazaar API integration for threat intelligence.

## 3.1 Architectural Design

### 3.1.1 High-Level Overview

The system follows a client-server distributed architecture consisting of four core layers:

- **Frontend (React Web Application):** A cyber-security-themed dashboard that provides users with live metrics (CPU, Memory, Network) via Recharts area charts, alert management with SHAP explainability, notification channel management, and PDF/CSV report generation. It communicates with the backend via JWT-authenticated REST API calls.
- **Backend (FastAPI):** The central processing unit that handles all system logic. It manages user authentication (JWT + bcrypt), coordinates ML inference (XGBoost/Random Forest on a 20-feature vector), runs multi-signal process analysis (miner keyword detection, process policy engine, svchost masquerade detection, identity spoofing detection), queries VirusTotal and MalwareBazaar APIs for hash-based threat intelligence, generates cryptojacking alerts with SHAP explainability, and dispatches multi-channel notifications (Email via SMTP, WhatsApp via Twilio).
- **Monitoring Agent (Windows .exe - CryptoDetect Agent v7.0):** A lightweight background service running as a system tray application on the user's Windows machine. It collects real-time system metrics every 5 seconds (CPU, Memory, Network I/O, process metadata, Authenticode signatures, SHA-256 hashes, per-process network summaries, and static PE analysis for high-CPU processes), buffers data locally in a rolling JSON file (max 60 entries), and sends batched data to the backend using API Key authentication.
- **Database Layer (SQLite / PostgreSQL via SQLAlchemy):** Stores all persistent data including: User accounts, System IDs and API Keys, MonitoredSystem records with online/offline status, SystemMetric time-series data, Alert records with confidence scores and SHAP data, Report metadata, NotificationChannel records with OTP verification state, and AuditLog entries.

### 3.1.2 Workflow Overview

The step-by-step process when a user onboards and the agent begins monitoring:

1. **User Registration:** The user registers on the React web dashboard. The backend generates a unique System ID (format: SYS-XXXXXXXX) and API Key (32-byte URL-safe token). A MonitoredSystem record is auto-created.
2. **Agent Setup:** The user downloads the CryptoDetect Agent v7.0 (.exe) and configures it via the tray GUI or CLI with their System ID and API Key. The agent validates credentials against POST /api/auth/agent/validate before starting.
3. **Real-Time Data Collection:** The agent runs in the background collecting CPU %, CPU times, memory %, network I/O deltas, process metadata (including SHA-256 hashes, Authenticode signatures, per-process network summaries), and static PE analysis for high-CPU processes every 5 seconds.
4. **Batch Transmission:** Every 5 seconds (or configurable batch size), the agent sends collected metrics to POST /api/metrics/batch, authenticated via X-API-Key header.
5. **Backend Processing:** The backend validates the API Key, persists metrics to the database, extracts a 20-feature vector, runs XGBoost/RF inference, performs multi-signal process analysis (miner keywords, process policy, svchost masquerade, identity spoofing, network evidence), queries VirusTotal and MalwareBazaar for hash reputation, computes a composite risk score, and applies the sustained-detection gate.
6. **Alert Generation and Multi-Channel Notification:** If cryptojacking is confirmed (sustained gate passed, confidence >= 0.70), the system creates an Alert record with SHAP feature importance data and dispatches notifications via Email (SMTP), WhatsApp (Twilio API), and returns the alert in the batch response for local Windows desktop MessageBox display.
7. **Alert Management:** The user reviews the alert on the dashboard, viewing the SHAP feature importance chart, suspicious process details, and VirusTotal/MalwareBazaar threat intelligence results.

## 3.2 Data Design

This section describes how data is structured, stored, and transferred within the system.

### 3.2.1 Entity-Relationship Diagram (ERD)

The data structure centers around users, their monitored systems, system metrics, alerts, reports, notification channels, and audit logs.

**Key Entities:**
- **User:** Stores user credentials, email, full name, hashed password, unique System ID, API Key, role, profile picture URL, and password update timestamp.
- **MonitoredSystem:** Represents the user's registered device with system ID, name, description, owner email (FK to User), status (online/offline), last_seen timestamp, and device info JSON.
- **SystemMetric:** Logs performance data (CPU %, memory %, network bytes sent/received, processes JSON, raw metrics JSON) attached to specific timestamps, indexed by system_id and timestamp.
- **Alert:** Generated when cryptojacking is confirmed. Contains confidence score, detection method (ml_model or heuristic), metrics JSON, suspicious processes list, VirusTotal results, SHAP feature importance data, and status (unread).
- **Report:** Represents user-generated statistical summaries of system metrics over a defined period, stored as PDF or CSV files.
- **NotificationChannel:** Stores verified email/WhatsApp targets with OTP verification state (verify_code, code_expires, verified, enabled).
- **AuditLog:** Records all sensitive platform actions with actor email, action type, target type, target ID, details JSON, and timestamp.

```plantuml
@startuml ERD_CryptoDetect
skinparam linetype ortho
skinparam entity {
  BackgroundColor #F0F4FF
  BorderColor #4F6BED
}

entity "User" as User {
  * id : Integer <<PK>>
  --
  * email : String <<unique>>
  * full_name : String
  * hashed_password : String
  * system_id : String <<unique>>
  * api_key : String <<unique>>
  * role : String
  profile_picture_url : String
  password_updated_at : DateTime
  * created_at : DateTime
}

entity "MonitoredSystem" as System {
  * id : Integer <<PK>>
  --
  * system_id : String <<unique>>
  * system_name : String
  system_description : Text
  * owner_email : String <<FK -> User.email>>
  * status : String
  last_seen : DateTime
  device_info : JSON
  * created_at : DateTime
}

entity "SystemMetric" as Metric {
  * id : Integer <<PK>>
  --
  * system_id : String <<FK -> MonitoredSystem.system_id>>
  * timestamp : DateTime
  cpu_percent : Float
  memory_percent : Float
  network_bytes_sent : Integer
  network_bytes_recv : Integer
  processes_data : JSON
  raw_metrics : JSON
  * created_at : DateTime
}

entity "Alert" as Alert {
  * id : Integer <<PK>>
  --
  * system_id : String <<FK -> MonitoredSystem.system_id>>
  * timestamp : DateTime
  * alert_type : String
  * confidence : Float
  detection_method : String
  metrics : JSON
  suspicious_processes : JSON
  virustotal_results : JSON
  feature_importance : JSON
  * status : String
  * created_at : DateTime
}

entity "Report" as Report {
  * id : Integer <<PK>>
  --
  * system_id : String <<FK -> MonitoredSystem.system_id>>
  * owner_email : String
  * start_date : DateTime
  * end_date : DateTime
  * metrics : JSON
  * format : String
  * status : String
  * file_path : String
  * file_type : String
  * size_bytes : Integer
  * created_at : DateTime
}

entity "NotificationChannel" as NotifChannel {
  * id : Integer <<PK>>
  --
  * user_email : String <<FK -> User.email>>
  * channel_type : String
  * target : String
  verified : Boolean
  verify_code : String
  code_expires : DateTime
  enabled : Boolean
  * created_at : DateTime
}

entity "AuditLog" as Audit {
  * id : Integer <<PK>>
  --
  * actor_email : String
  * action : String
  target_type : String
  target_id : String
  details : JSON
  ip_address : String
  * timestamp : DateTime
}

User ||--o{ System : "owns"
User ||--o{ NotifChannel : "has"
System ||--o{ Metric : "has"
System ||--o{ Alert : "generates"
System ||--o{ Report : "has"
@enduml
```

### 3.2.2 Data Flow Diagram (DFD)

The data flow maps the journey of metrics from the user's computer to the frontend dashboard:

```plantuml
@startuml DFD_CryptoDetect
skinparam backgroundColor #FAFAFA
skinparam componentStyle rectangle

actor "System User" as User
component "CryptoDetect Agent v7.0\n(Windows .exe)" as Agent
component "FastAPI Backend" as Backend
database "SQLite Database\n(PostgreSQL ready)" as DB
component "ML Pipeline\n(XGBoost / Random Forest)" as ML
component "VirusTotal API" as VT
component "MalwareBazaar API" as MB
component "React Dashboard" as Dashboard
component "Email SMTP\n(aiosmtplib)" as Email
component "WhatsApp\n(Twilio API)" as WhatsApp

User --> Agent : Installs and configures\nwith System ID + API Key
Agent --> Agent : Collects metrics every 5s\n(CPU, Memory, Network, Processes,\nSHA-256 hashes, PE analysis)
Agent --> Backend : POST /api/metrics/batch\n(X-API-Key header)
Backend --> DB : Persist SystemMetric record
Backend --> ML : 20-feature vector for inference
ML --> Backend : prediction + confidence + SHAP values
Backend --> VT : Hash reputation lookup
Backend --> MB : Hash reputation lookup
VT --> Backend : detection ratio result
MB --> Backend : signature and tags result
Backend --> DB : Save Alert record if confirmed
Backend --> Agent : Return alerts in response
Agent --> User : Windows MessageBox notification
Backend --> Email : Send email alert (confidence >= 0.70)
Backend --> WhatsApp : Send WhatsApp alert (confidence >= 0.70)
Dashboard --> Backend : JWT-authenticated API calls
Backend --> Dashboard : Metrics, Alerts, SHAP data, System status
@enduml
```

## 3.3 Domain Model

The domain model captures the main conceptual entities in the detection platform and their relationships.

- A **User** owns a **MonitoredSystem**.
- The **MonitoredSystem** receives **MetricsBatch** objects from the **MonitoringAgent**.
- Each **MetricsBatch** contains **Metrics** with **Process** records, digital signature data, and network summaries.
- The **MLModel** analyzes these Metrics with a 20-feature vector. If suspicious Processes are identified and the model returns high confidence, an **Alert** is generated for the **MonitoredSystem**.
- The **NotificationService** dispatches the **Alert** to verified **NotificationChannels** (Email/WhatsApp).
- The **AuditLog** records all sensitive actions performed by Users or the System.

### 3.3.1 Class Diagram

```plantuml
@startuml ClassDiagram_CryptoDetect
skinparam classBackgroundColor #F0F4FF
skinparam classBorderColor #4F6BED

class User {
  +id: int
  +email: str
  +full_name: str
  +hashed_password: str
  +system_id: str
  +api_key: str
  +role: str
  +profile_picture_url: str
  +created_at: datetime
  +generate_system_id(): str
  +generate_api_key(): str
}

class MonitoredSystem {
  +id: int
  +system_id: str
  +system_name: str
  +owner_email: str
  +status: str
  +last_seen: datetime
  +device_info: dict
  +update_heartbeat(): void
  +resolve_status(): str
}

class SystemMetric {
  +id: int
  +system_id: str
  +timestamp: datetime
  +cpu_percent: float
  +memory_percent: float
  +network_bytes_sent: int
  +network_bytes_recv: int
  +processes_data: list
  +raw_metrics: dict
}

class MonitoringAgent {
  +system_id: str
  +api_key: str
  +api_url: str
  +interval: int = 5
  +max_entries: int = 60
  +collect_metrics(): dict
  +filter_processes(): list
  +send_batch(batch: list): bool
  +save_local(metrics: dict): list
  +run(): void
  +stop(): void
}

class MLPipeline {
  +model: XGBClassifier
  +scaler: StandardScaler
  +feature_names: list
  +shap_explainer: TreeExplainer
  +extract_features(metrics: dict): ndarray
  +predict(features: ndarray): tuple
  +compute_shap(features: ndarray): dict
}

class ProcessAnalyzer {
  +miner_keywords: set
  +miner_ports: set
  +analyze_processes(processes: list): tuple
  +detect_svchost_masquerade(proc: dict): dict
  +detect_identity_spoofing(proc: dict): dict
  +evaluate_policy(proc: dict): dict
  +lookup_threat_intel(hash: str): dict
}

class Alert {
  +id: int
  +system_id: str
  +timestamp: datetime
  +alert_type: str
  +confidence: float
  +detection_method: str
  +suspicious_processes: list
  +feature_importance: dict
  +virustotal_results: list
  +status: str
}

class NotificationService {
  +CONFIDENCE_THRESHOLD: float = 0.70
  +dispatch_alert(alert: Alert, db): void
  +send_email_alert(to: str, alert: Alert): void
  +send_whatsapp_alert(to: str, alert: Alert): void
}

class NotificationChannel {
  +id: int
  +user_email: str
  +channel_type: str
  +target: str
  +verified: bool
  +verify_code: str
  +code_expires: datetime
  +enabled: bool
}

class Report {
  +id: int
  +system_id: str
  +start_date: datetime
  +end_date: datetime
  +format: str
  +file_path: str
  +status: str
}

class AuditLog {
  +id: int
  +actor_email: str
  +action: str
  +target_type: str
  +target_id: str
  +details: dict
  +timestamp: datetime
}

class AutoUpdater {
  +api_url: str
  +CURRENT_VERSION: str
  +CHECK_INTERVAL: int = 3600
  +check_for_update(): dict
  +download_update(url: str, checksum: str): Path
  +apply_update(new_exe: Path): void
  +start_background_checker(): Thread
}

User "1" --> "1" MonitoredSystem : owns
User "1" --> "*" NotificationChannel : has
MonitoredSystem "1" --> "*" SystemMetric : records
MonitoredSystem "1" --> "*" Alert : generates
MonitoredSystem "1" --> "*" Report : has
MonitoringAgent --> SystemMetric : produces
MonitoringAgent --> AutoUpdater : uses
MLPipeline --> Alert : creates
ProcessAnalyzer --> Alert : contributes to
NotificationService --> NotificationChannel : queries
NotificationService --> Alert : dispatches
@enduml
```

## 3.4 Design Models

### 3.4.1 Activity Diagram

The primary activity describes the alert generation process: the backend receives a batch of metrics from the agent, validates the API key, processes the metrics through the ML and process analysis pipelines, applies the sustained-detection gate, and if cryptojacking is confirmed, saves the alert and dispatches notifications.

```plantuml
@startuml ActivityDiagram_AlertGeneration
skinparam backgroundColor #FAFAFA
start
:Agent collects metrics every 5 seconds;
:Agent saves to local rolling cache (max 60 entries);
:Agent sends POST /api/metrics/batch with X-API-Key;
if (API Key valid?) then (yes)
  :Persist SystemMetric record to DB;
  :Update system last_seen (heartbeat);
  :Check whitelist / trust score >= 70;
  if (Whitelist hit and no suspicious evidence?) then (yes)
    :Skip detection for this batch;
  else (no)
    :Extract 20-feature vector from metrics;
    if (ML model loaded?) then (yes)
      :Run XGBoost/RF predict + predict_proba;
      :Compute SHAP feature importance values;
    else (no)
      :Heuristic fallback: CPU >= 90% + memory/process thresholds;
    endif
    :Run multi-signal process analysis;
    note right
      - Miner keyword/path matching
      - Process policy (allow/deny rules)
      - svchost masquerade detection
      - Identity spoofing detection
      - Static PE analysis evidence
      - Network miner port detection
      - VirusTotal/MalwareBazaar lookup
    end note
    :Compute composite risk score;
    if (risk score >= threshold AND signal count >= min?) then (yes)
      :Update sustained-detection state;
      if (3 consecutive positives AND cooldown elapsed?) then (yes)
        :Create Alert record in DB (confidence, SHAP, processes);
        if (confidence >= 0.70?) then (yes)
          :Dispatch Email alert via SMTP;
          :Dispatch WhatsApp alert via Twilio;
        endif
        :Return alert in batch response;
        :Agent displays Windows MessageBox;
      else (no)
        :Accumulate detection state (no alert yet);
      endif
    else (no)
      :Reset sustained detection counter;
    endif
  endif
else (no)
  :Return 401 Unauthorized;
  :Agent logs auth failure and stops;
endif
stop
@enduml
```

### 3.4.2 State Transition Diagram

The system tracks the condition of a monitored endpoint using the following states:

- **Offline:** The system is registered but the agent is not sending data, or the connection has timed out (last_seen older than the configured threshold, default 30 seconds).
- **Online:** The agent is actively transmitting metric batches. The system is updated to Online on every successful POST /api/metrics/batch.
- **Detecting:** A transitional internal state where ML inference and multi-signal analysis are actively running on incoming batches.
- **Alerted:** Cryptojacking is confirmed (sustained gate passed, confidence >= 0.70). The alert record is created and notifications dispatched.
- **Acknowledged:** The user has reviewed the alert via the dashboard.

```plantuml
@startuml StateDiagram_MonitoredSystem
skinparam backgroundColor #FAFAFA
skinparam state {
  BackgroundColor #F0F4FF
  BorderColor #4F6BED
}

[*] --> Offline : System registered\nAgent not yet connected

Offline --> Online : Agent sends POST /api/metrics/batch\n(heartbeat received)

Online --> Offline : No heartbeat within 30s\n(background sweeper marks offline)

Online --> Detecting : Metrics received\nML inference running

Detecting --> Online : Detection result negative\n(normal activity)

Detecting --> Alerted : Detection confirmed\n(sustained gate passed, confidence >= 0.70)

Alerted --> Acknowledged : User reviews alert\non dashboard

Acknowledged --> Online : System returns to\nnormal monitoring

Alerted --> Offline : Agent stops sending\n(heartbeat timeout)
@enduml
```

### 3.4.3 Sequence Diagram

```plantuml
@startuml SequenceDiagram_MetricsBatch
skinparam backgroundColor #FAFAFA
skinparam sequence {
  ArrowColor #4F6BED
  LifeLineBorderColor #4F6BED
  ParticipantBackgroundColor #F0F4FF
}

actor "User" as User
participant "CryptoDetect Agent v7.0" as Agent
participant "FastAPI Backend" as Backend
participant "ML Pipeline" as ML
participant "Process Analyzer" as PA
participant "VirusTotal/MalwareBazaar" as TI
participant "Notification Service" as NS
participant "SQLite DB" as DB

User -> Agent : Launch agent (System ID + API Key)
Agent -> Backend : GET /api/auth/agent/validate
Backend --> Agent : {valid: true, system_name: ...}
Agent -> Agent : Start monitoring loop (every 5s)

loop Every 5 seconds
  Agent -> Agent : collect_metrics()
  note right of Agent
    CPU %, CPU times, memory, network deltas,
    process list with SHA-256 hashes,
    Authenticode signatures, network summaries,
    static PE analysis (high CPU procs)
  end note
  Agent -> Agent : save_local(metrics) - rolling cache
end

Agent -> Backend : POST /api/metrics/batch\n{system_id, metrics[]}\nX-API-Key: <key>
Backend -> Backend : verify_api_key()
Backend -> DB : INSERT SystemMetric records
Backend -> Backend : UPDATE MonitoredSystem.last_seen, status=online
Backend -> ML : extract_features(metrics) -> 20-feature vector
ML -> ML : xgboost.predict() + predict_proba()
ML -> ML : shap_explainer.shap_values()
ML --> Backend : (is_cryptojacking, confidence, feat_importance)
Backend -> PA : analyze_processes(processes)
PA -> TI : lookup_threat_intel(exe_hash)
TI --> PA : {known_malicious, score, sources}
PA --> Backend : (suspicious_procs, miner_indicators, policy_hits, network_hits)
Backend -> Backend : compute_risk_score()
Backend -> Backend : _update_sustained_state()

alt Alert triggered (sustained gate passed)
  Backend -> DB : INSERT Alert record
  Backend -> NS : dispatch_alert(alert)
  NS -> NS : Send Email via SMTP
  NS -> NS : Send WhatsApp via Twilio
  Backend --> Agent : {alerts: [{confidence, processes, ...}]}
  Agent -> User : Windows MessageBox notification
else No alert
  Backend --> Agent : {alerts: []}
end
@enduml
```

### 3.4.4 Component Diagram

```plantuml
@startuml ComponentDiagram_CryptoDetect
skinparam backgroundColor #FAFAFA
skinparam component {
  BackgroundColor #F0F4FF
  BorderColor #4F6BED
}

package "Windows Endpoint" {
  component "CryptoDetect Agent v7.0\n(enhanced_agent.py)" as Agent
  component "Agent Tray GUI\n(agent_gui.py)" as GUI
  component "Auto Updater\n(auto_updater.py)" as Updater
  component "Static PE Analyzer\n(static_analysis/)" as PE
  component "Local Config\n(~/.cryptodetect/config.json)" as Config
  component "Local Metric Cache\n(~/.cryptodetect/metrics/)" as Cache
}

package "FastAPI Backend (Python 3.10+)" {
  component "Auth Router\n(/api/auth)" as AuthR
  component "Metrics Router\n(/api/metrics)" as MetricsR
  component "Alerts Router\n(/api/alerts)" as AlertsR
  component "Reports Router\n(/api/reports)" as ReportsR
  component "Notifications Router\n(/api/notifications)" as NotifR
  component "Agent Router\n(/api/agent)" as AgentR
  component "Audit Router\n(/api/admin)" as AuditR
  component "ML Pipeline\n(XGBoost + RF + SHAP)" as MLP
  component "Process Analyzer\n(multi-signal)" as ProcA
  component "Notification Service\n(Email + WhatsApp)" as NS
  component "Verification Service\n(OTP)" as VS
}

database "SQLite Database\n(cryptojacking.db)" as DB

package "External APIs" {
  component "VirusTotal API" as VT
  component "MalwareBazaar API" as MB
  component "Twilio WhatsApp API" as Twilio
  component "SMTP Email Server" as SMTP
}

package "React Frontend (React 19)" {
  component "Auth Pages\n(Login / Register)" as AuthUI
  component "Dashboard\n(Metrics Charts)" as DashUI
  component "Alerts Panel\n(SHAP Explainability)" as AlertUI
  component "Notifications Manager\n(OTP Verification)" as NotifUI
  component "Reports Manager\n(PDF/CSV Download)" as ReportUI
}

Agent --> Config : reads/writes credentials
Agent --> Cache : rolling metric cache
Agent --> MetricsR : POST /api/metrics/batch\n(X-API-Key)
GUI --> Agent : start/stop monitoring
GUI --> Updater : check/apply updates
Agent --> PE : static analysis on high-CPU procs
Updater --> AgentR : GET /api/agent/status\nGET /api/agent/download

MetricsR --> MLP : feature extraction + inference
MetricsR --> ProcA : process analysis pipeline
MetricsR --> DB : persist metrics + alerts
ProcA --> VT : hash reputation lookup
ProcA --> MB : hash reputation lookup
MetricsR --> NS : dispatch_alert() if confirmed
NS --> SMTP : email notification
NS --> Twilio : WhatsApp notification
NotifR --> VS : OTP generation + verification

AuthUI --> AuthR : POST /api/auth/register, /login
DashUI --> MetricsR : GET /api/metrics/{system_id}
AlertUI --> AlertsR : GET /api/alerts
NotifUI --> NotifR : manage notification channels
ReportUI --> ReportsR : generate + download reports

MetricsR --> DB
AlertsR --> DB
ReportsR --> DB
AuthR --> DB
AuditR --> DB
@enduml
```

### 3.4.5 System Architecture

The overarching system architecture implements a **lightweight-edge and heavy-cloud strategy**. By shifting the intensive machine learning inference, hash verification, and multi-signal analysis entirely to the centralized FastAPI backend, the Windows monitoring agent maintains a negligible footprint (less than 2% CPU and less than 50MB RAM). This design allows the backend to scale independently, manage multiple endpoints efficiently, and seamlessly serve data to the React frontend via RESTful APIs.

The database layer uses SQLite for development and single-server deployment, with a clean migration pathway to PostgreSQL via the DATABASE_URL environment variable and SQLAlchemy ORM — no code changes required for migration.

The agent ships as a self-contained Windows .exe (compiled via PyInstaller) with a built-in auto-update mechanism, ensuring all deployed agents can be updated centrally without requiring users to manually download and reinstall.

## 3.5 Mockups

The user interface embraces a modern cyber-security aesthetic featuring a dark background with neon accents. Key screens include:

- **Authentication Pages:** Clean login and registration forms. Registration provides the user with their unique System ID and API Key, along with instructions for downloading and configuring the monitoring agent.
- **Dashboard Hub:** A hero section displaying the overall system status (Online/Offline with last-seen timestamp), current CPU/Memory load, and a counter of unread alerts.
- **Monitoring Charts:** Live-updating Recharts area charts showing real-time trends for CPU usage, memory consumption, and network traffic (bytes sent/received per second).
- **Alerts Table:** A comprehensive data grid listing all generated alerts with timestamps, ML confidence percentages, detection method (ml_model or heuristic), flagged process names, and a drilldown view showing SHAP feature importance breakdown and VirusTotal/MalwareBazaar threat intelligence results.
- **Notification Channels:** A management panel for adding and verifying Email and WhatsApp notification channels via OTP, with enable/disable toggles.
- **Reports:** A form for generating and downloading PDF or CSV reports for selected systems and date ranges.
- **Agent Console (Tray GUI):** A Windows system tray application with a context menu for Start/Stop Monitoring, Configure, Check for Updates, View Logs, Open Dashboard, and Exit.
"""

with open(r'C:\FYP\fyp\Dcox\FYP_Final_Document.md', 'a', encoding='utf-8') as f:
    f.write(content)
print('Chapter 3 written OK')
