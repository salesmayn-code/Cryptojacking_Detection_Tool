content = r"""
---

# Chapter 2: Software Requirements Specification (SRS)

## 2.1 List of Features

- Users can register/login; each account gets a unique System ID and API Key to securely connect monitored endpoints.
- Real-time monitoring agent collects CPU, memory, network I/O, process metadata, digital signatures, and static PE data every 5 seconds.
- Interactive web dashboard with live metric charts, alert management, SHAP explainability, and report generation.
- Backend analyzes metrics using a trained XGBoost/Random Forest ML model with a 20-feature pipeline and assigns a confidence score to each alert.
- Multi-channel notifications: Email (SMTP), WhatsApp (Twilio API), and Windows desktop MessageBox.
- OTP-verified notification channel onboarding (6-digit, 10-minute expiry).
- PDF/CSV report generation and download.
- Automated agent self-update with SHA-256 checksum verification.
- Full audit log for all sensitive platform actions.
- System tray GUI agent: Start/Stop monitoring, Configure, Check for Updates, View Logs.

## 2.2 Functional Requirements

### 2.2.1 User and System Authentication

- **FR1:** The system shall allow users to register and manage their accounts via a web dashboard (POST /api/auth/register), auto-generating a unique System ID and API Key upon registration.
- **FR2:** The system shall provide a secure JWT-based login mechanism (HS256, bcrypt password hashing) returning an access token for dashboard sessions.
- **FR3:** The backend shall validate agent credentials (System ID, API Key) via the X-API-Key header before accepting any metric data.
- **FR4:** The system shall support an API-key-only bootstrap flow (GET /api/auth/agent/bootstrap) for headless/CLI agent setup.
- **FR5:** The system shall allow users to update their profile, change their password, and upload a profile picture (max 2MB).

### 2.2.2 Real-Time Monitoring and Data Collection

- **FR6:** The Monitoring Agent shall collect host metrics every 5 seconds including CPU %, CPU times (user/system/idle/iowait/irq), memory usage, network I/O bytes (sent/received deltas per second), packet counts, load averages, and process counts.
- **FR7:** The agent shall filter and enumerate processes exceeding 4% CPU or 4% memory, excluding known benign system processes.
- **FR8:** The agent shall capture per-process metadata: PID, name, CPU %, memory %, executable path, SHA-256 file hash, parent PID/name, Authenticode signature status, and publisher name.
- **FR9:** The agent shall collect per-process network summaries including connection count, established connections, unique remote IPs, remote ports, and flags for external connections and known miner pool ports (3333, 4444, 5555, 6666, 7777, 9999, 14433, 14444).
- **FR10:** The agent shall perform static PE binary analysis (mining keywords, crypto addresses, suspicious URLs, entropy, suspicious import counts) for processes using 20% or more CPU.
- **FR11:** The agent shall maintain a local rolling cache of the last 60 metric entries per day in a Base64-encoded local JSON file to prevent data loss during network outages.

### 2.2.3 Data Ingestion and System Health

- **FR12:** The backend shall provide a batch ingestion endpoint (POST /api/metrics/batch) to receive metric data from agents, persisting each entry as a SystemMetric database record.
- **FR13:** The system shall implement a heartbeat mechanism: every successful batch upload updates the system last_seen timestamp and sets status to online.
- **FR14:** A background sweeper task shall automatically mark systems as offline if they fail to report within a configurable threshold (default: 30 seconds).

### 2.2.4 Cryptojacking Detection (ML and Heuristics)

- **FR15:** The system shall extract a 20-feature vector from incoming metrics and run inference using a trained XGBoost (primary) or Random Forest (fallback) model.
- **FR16:** The system shall implement a heuristic fallback detection (CPU >= 90% with high-CPU process count >= 1 or memory >= 80%) when the ML model is unavailable.
- **FR17:** The system shall run a multi-signal process analysis pipeline covering: miner keyword matching, process policy (allow/deny rules), svchost masquerade detection, identity spoofing detection, static PE evidence, and per-process network analysis.
- **FR18:** The system shall compute a composite risk score from weighted signals and apply a sustained-detection gate (3 consecutive positive batches, 300-second cooldown) before generating an alert.
- **FR19:** The system shall provide SHAP (SHapley Additive exPlanations) feature importance values for each detection, stored alongside the alert record.

### 2.2.5 Alerting and Multi-Channel Notifications

- **FR20:** The system shall generate an alert record whenever cryptojacking activity is confirmed, storing confidence score, detection method, suspicious process names, SHAP data, and threat intelligence results.
- **FR21:** The system shall send real-time email notifications via SMTP (aiosmtplib) to verified email channels when confidence >= 0.70.
- **FR22:** The system shall send WhatsApp notifications via the Twilio API to verified WhatsApp channels when confidence >= 0.70.
- **FR23:** The system shall implement a 6-digit OTP verification flow (10-minute expiry) for onboarding new notification channels.
- **FR24:** The Monitoring Agent shall display a local Windows desktop notification (MessageBox) when an alert is returned in the batch response.

### 2.2.6 Agent Management and Updates

- **FR25:** The system shall provide an automated self-update mechanism: the agent polls GET /api/agent/status hourly, downloads the new binary, verifies its SHA-256 checksum, performs an in-place binary swap, and relaunches.
- **FR26:** The backend shall serve the latest agent binary via GET /api/agent/download and expose version metadata via GET /api/agent/status.
- **FR27:** The tray-based agent GUI shall allow users to Start/Stop monitoring, Configure credentials, Check for Updates, View Logs, and Open Dashboard.

### 2.2.7 Frontend Visualization

- **FR28:** The web dashboard shall visualize real-time and historical CPU, memory, and network metrics using interactive Recharts area charts.
- **FR29:** The frontend shall display a list of all active and past alerts including confidence score, detection method, suspicious processes, and SHAP feature importance breakdown.
- **FR30:** The frontend shall enforce authenticated-only access, redirecting unauthenticated users to the login page.

### 2.2.8 Reporting and Audit

- **FR31:** The system shall generate on-demand PDF (ReportLab) and CSV (pandas) reports for selected systems, date ranges, and metric types.
- **FR32:** The system shall maintain a full audit log of sensitive actions (registration, password change, system create/update/delete) accessible via GET /api/admin/audit.

## 2.3 Non-Functional Requirements

### 2.3.1 Performance Requirements

- The system shall process and visualize collected metrics in real-time, with dashboard updates every 5 seconds.
- The ML inference pipeline (feature extraction, model predict, SHAP computation) shall complete in under 1 second per batch.
- The FastAPI endpoints shall maintain response times under 500ms under normal concurrent load.

### 2.3.2 Reliability Requirements

- The monitoring agent shall maintain stable operation during continuous long-running sessions without crashes or data loss, supported by the local rolling cache (max 60 entries).
- The backend sweeper shall reliably mark systems offline within 30 seconds of missed heartbeats.
- The agent auto-updater shall include rollback support: if the binary swap fails, the previous executable is restored.

### 2.3.3 Scalability Requirements

- The SQLite database shall be replaceable with PostgreSQL via a single DATABASE_URL environment variable change using SQLAlchemy ORM.
- The system architecture shall support future expansion for additional ML models, data sources, and notification channels without major redesign.

### 2.3.4 Usability Requirements

- The dashboard shall present all system metrics, graphs, and alert results in an intuitive cyber-security-themed dark interface.
- The monitoring agent shall be distributable as a standalone Windows .exe requiring no Python installation.
- The tray GUI shall provide a one-click Start/Stop monitoring experience with visual status feedback.

### 2.3.5 Security Requirements

- All API keys shall be stored and validated server-side; they are never exposed in plain text after registration.
- JWT tokens shall be signed with a configurable secret key using HS256 with configurable expiry (default 30 minutes).
- Agent configuration (System ID, API Key) shall be stored locally in a Base64-encoded config file.
- Notification channels shall require OTP verification before receiving alerts.
- The threat intel cache uses a thread-safe lock to prevent race conditions in concurrent batch processing.

### 2.3.6 Accuracy Requirements

- The ML models (Random Forest, XGBoost) shall achieve at least 90% classification accuracy on the test dataset.
- Precision and recall shall be prioritized over raw accuracy to minimize false negatives.
- The sustained-detection gate (3 consecutive positives + 300s cooldown) shall minimize false-positive alert fatigue.

## 2.4 Use Cases

### 2.4.1 Use Case 1: User Authentication and Account Management

**Actors:** User, Backend System

This use case describes how a user registers, logs in, manages their profile, and obtains the API Key/System ID credentials required to connect monitoring agents.

| Field | Detail |
|---|---|
| Preconditions | Backend server is running; user has a valid email address |
| Main Flow | 1. User submits registration form -> 2. System generates System ID and API Key -> 3. System creates MonitoredSystem record -> 4. JWT token returned -> 5. User can update profile, change password, upload picture |
| Postconditions | User account in DB with credentials; JWT issued |

```plantuml
@startuml UC1_Authentication
left to right direction
skinparam packageStyle rectangle
actor "User" as User
actor "Backend System" as System
rectangle "User Authentication and Account Management" {
  usecase "Register Account" as UC1
  usecase "Login" as UC2
  usecase "View and Update Profile" as UC3
  usecase "Change Password" as UC4
  usecase "Upload Profile Picture" as UC5
  usecase "Generate System ID" as UC6
  usecase "Generate API Key" as UC7
  usecase "Issue JWT Token" as UC8
  usecase "Validate Password via bcrypt" as UC9
}
User --> UC1
User --> UC2
User --> UC3
User --> UC4
User --> UC5
UC1 ..> UC6 : <<include>>
UC1 ..> UC7 : <<include>>
UC1 ..> UC8 : <<include>>
UC2 ..> UC9 : <<include>>
UC2 ..> UC8 : <<include>>
System --> UC6
System --> UC7
System --> UC8
System --> UC9
@enduml
```

### 2.4.2 Use Case 2: Real-Time Metric Collection

**Actors:** Monitoring Agent, Host Operating System

This use case describes how the monitoring agent collects system-level and process-level telemetry every 5 seconds.

```plantuml
@startuml UC2_MetricCollection
left to right direction
skinparam packageStyle rectangle
actor "Monitoring Agent" as Agent
actor "Host OS" as OS
rectangle "Real-Time Metric Collection" {
  usecase "Collect Host Metrics every 5s" as UC1
  usecase "Collect CPU Percent and CPU Times" as UC2
  usecase "Collect Memory Usage" as UC3
  usecase "Collect Network IO Deltas" as UC4
  usecase "Enumerate and Filter Processes" as UC5
  usecase "Compute SHA-256 Hash" as UC6
  usecase "Check Authenticode Signature" as UC7
  usecase "Collect Process Network Summary" as UC8
  usecase "Run Static PE Analysis" as UC9
  usecase "Save to Local Rolling Cache" as UC10
}
Agent --> UC1
Agent --> UC10
UC1 ..> UC2 : <<include>>
UC1 ..> UC3 : <<include>>
UC1 ..> UC4 : <<include>>
UC1 ..> UC5 : <<include>>
UC5 ..> UC6 : <<include>>
UC5 ..> UC7 : <<include>>
UC5 ..> UC8 : <<include>>
UC5 ..> UC9 : <<extend>>
OS --> UC2
OS --> UC3
OS --> UC4
OS --> UC5
@enduml
```

### 2.4.3 Use Case 3: Data Ingestion and Heartbeat

**Actors:** Monitoring Agent, Backend System

This use case describes how metric batches are uploaded, persisted, and used as an implicit heartbeat.

```plantuml
@startuml UC3_DataIngestion
left to right direction
skinparam packageStyle rectangle
actor "Monitoring Agent" as Agent
actor "Backend System" as Backend
rectangle "Data Ingestion and Heartbeat" {
  usecase "Send Metrics Batch POST /api/metrics/batch" as UC1
  usecase "Validate API Key and System Ownership" as UC2
  usecase "Persist Metric Records to DB" as UC3
  usecase "Update System Heartbeat last_seen" as UC4
  usecase "Set System Status Online" as UC5
  usecase "Sweep Offline Systems background" as UC6
  usecase "Return Inference Results and Alerts" as UC7
}
Agent --> UC1
UC1 ..> UC2 : <<include>>
UC1 ..> UC3 : <<include>>
UC1 ..> UC4 : <<include>>
UC4 ..> UC5 : <<include>>
UC1 ..> UC7 : <<include>>
Backend --> UC6
@enduml
```

### 2.4.4 Use Case 4: Cryptojacking Detection (ML and Heuristics)

**Actors:** Backend System, ML Model

This use case describes the multi-layered detection pipeline.

```plantuml
@startuml UC4_Detection
left to right direction
skinparam packageStyle rectangle
actor "Backend System" as Backend
actor "ML Model XGBoost or RF" as ML
rectangle "Cryptojacking Detection" {
  usecase "Extract 20-Feature Vector" as UC1
  usecase "Sanitize and Validate Feature Bounds" as UC2
  usecase "Run ML Inference predict plus proba" as UC3
  usecase "Heuristic Fallback CPU>=90%" as UC4
  usecase "Multi-Signal Process Analysis" as UC5
  usecase "Check Miner Keywords and Ports" as UC6
  usecase "Evaluate Process Policy allow/deny" as UC7
  usecase "Detect svchost Masquerade" as UC8
  usecase "Detect Identity Spoofing" as UC9
  usecase "Compute Risk Score and Signals" as UC10
  usecase "Apply Sustained Detection Gate" as UC11
}
Backend --> UC1
Backend --> UC5
Backend --> UC10
Backend --> UC11
UC1 ..> UC2 : <<include>>
UC2 ..> UC3 : <<include>>
UC3 ..> UC4 : <<extend>>
UC5 ..> UC6 : <<include>>
UC5 ..> UC7 : <<include>>
UC5 ..> UC8 : <<include>>
UC5 ..> UC9 : <<include>>
ML --> UC3
@enduml
```

### 2.4.5 Use Case 5: SHAP Explainability

**Actors:** Backend System, User (Dashboard)

```plantuml
@startuml UC5_SHAP
left to right direction
skinparam packageStyle rectangle
actor "Backend System" as Backend
actor "User Dashboard" as User
rectangle "SHAP Explainability" {
  usecase "Initialize SHAP TreeExplainer" as UC1
  usecase "Compute SHAP Values per Feature" as UC2
  usecase "Attach Feature Importance to Alert" as UC3
  usecase "View Feature Importance Chart" as UC4
}
Backend --> UC1
Backend --> UC2
Backend --> UC3
UC2 ..> UC1 : <<include>>
UC3 ..> UC2 : <<include>>
User --> UC4
UC4 ..> UC3 : <<include>>
@enduml
```

### 2.4.6 Use Case 6: Alerting and Multi-Channel Notifications

**Actors:** Backend System, User, Monitoring Agent

```plantuml
@startuml UC6_Alerting
left to right direction
skinparam packageStyle rectangle
actor "Backend System" as Backend
actor "User" as User
actor "Monitoring Agent" as Agent
rectangle "Alerting and Notifications" {
  usecase "Create Alert Record in DB" as UC1
  usecase "Lookup Verified Notification Channels" as UC2
  usecase "Send Email Alert via SMTP" as UC3
  usecase "Send WhatsApp Alert via Twilio" as UC4
  usecase "Display Windows Desktop Notification" as UC5
  usecase "OTP Verify New Channel" as UC6
  usecase "Return Alert in Batch Response" as UC7
}
Backend --> UC1
Backend --> UC2
Backend --> UC7
UC1 ..> UC2 : <<include>>
UC2 ..> UC3 : <<extend>>
UC2 ..> UC4 : <<extend>>
UC7 ..> UC5 : <<include>>
Agent --> UC5
User --> UC6
@enduml
```

### 2.4.7 Use Case 7: Agent Management and Self-Update

**Actors:** User, Monitoring Agent, Backend System

```plantuml
@startuml UC7_AgentManagement
left to right direction
skinparam packageStyle rectangle
actor "User" as User
actor "Monitoring Agent" as Agent
actor "Backend System" as Backend
rectangle "Agent Management and Self-Update" {
  usecase "Configure Agent System ID and API Key" as UC1
  usecase "Validate Credentials /api/auth/agent/validate" as UC2
  usecase "Start Monitoring" as UC3
  usecase "Stop Monitoring" as UC4
  usecase "Open Dashboard in Browser" as UC5
  usecase "Check for Updates /api/agent/status" as UC6
  usecase "Download New Binary /api/agent/download" as UC7
  usecase "Verify SHA-256 Checksum" as UC8
  usecase "Apply Binary Swap and Relaunch" as UC9
}
User --> UC1
User --> UC3
User --> UC4
User --> UC5
UC1 ..> UC2 : <<include>>
UC3 ..> UC2 : <<include>>
Agent --> UC6
UC6 ..> UC7 : <<extend>>
UC7 ..> UC8 : <<include>>
UC8 ..> UC9 : <<include>>
Backend --> UC6
Backend --> UC7
@enduml
```

### 2.4.8 Use Case 8: Forensic and Threat Intelligence Integration

**Actors:** Backend System, VirusTotal API, MalwareBazaar API

```plantuml
@startuml UC8_ThreatIntel
left to right direction
skinparam packageStyle rectangle
actor "Backend System" as Backend
actor "VirusTotal API" as VT
actor "MalwareBazaar API" as MB
rectangle "Threat Intelligence" {
  usecase "Lookup Process Hash Reputation" as UC1
  usecase "Check Local Cache TTL 6h" as UC2
  usecase "Query VirusTotal File Info" as UC3
  usecase "Evaluate VT Detection Ratio >=3 engines" as UC4
  usecase "Query MalwareBazaar Sample Info" as UC5
  usecase "Check Miner Signature or Tags" as UC6
  usecase "Cache Result" as UC7
}
Backend --> UC1
UC1 ..> UC2 : <<include>>
UC2 ..> UC3 : <<extend>>
UC3 ..> UC4 : <<include>>
UC2 ..> UC5 : <<extend>>
UC5 ..> UC6 : <<include>>
UC1 ..> UC7 : <<include>>
VT --> UC3
MB --> UC5
@enduml
```

### 2.4.9 Use Case 9: Reporting

**Actors:** User, Backend System

```plantuml
@startuml UC9_Reporting
left to right direction
skinparam packageStyle rectangle
actor "User" as User
actor "Backend System" as Backend
rectangle "Reporting" {
  usecase "Request Report Generation" as UC1
  usecase "Validate Access and Date Range" as UC2
  usecase "Query Metric Records" as UC3
  usecase "Generate CSV with pandas" as UC4
  usecase "Generate PDF with ReportLab" as UC5
  usecase "Persist Report Metadata" as UC6
  usecase "Download Report File" as UC7
  usecase "List All Reports" as UC8
}
User --> UC1
User --> UC7
User --> UC8
UC1 ..> UC2 : <<include>>
UC1 ..> UC3 : <<include>>
UC3 ..> UC4 : <<extend>>
UC3 ..> UC5 : <<extend>>
UC4 ..> UC6 : <<include>>
UC5 ..> UC6 : <<include>>
Backend --> UC3
Backend --> UC6
@enduml
```

### 2.4.10 Use Case 10: Audit Logging

**Actors:** Backend System, Admin

```plantuml
@startuml UC10_AuditLogging
left to right direction
skinparam packageStyle rectangle
actor "Backend System" as Backend
actor "Admin" as Admin
rectangle "Audit Logging" {
  usecase "Log User Registration" as UC1
  usecase "Log Password Change" as UC2
  usecase "Log System Create Update Delete" as UC3
  usecase "Persist Audit Log Entry" as UC4
  usecase "Query Audit Logs GET /api/admin/audit" as UC5
}
Backend --> UC1
Backend --> UC2
Backend --> UC3
UC1 ..> UC4 : <<include>>
UC2 ..> UC4 : <<include>>
UC3 ..> UC4 : <<include>>
Admin --> UC5
@enduml
```

### 2.4.11 Use Case 11: Frontend Dashboard Visualization

**Actors:** User, Backend System

```plantuml
@startuml UC11_Dashboard
left to right direction
skinparam packageStyle rectangle
actor "User" as User
actor "Backend System" as Backend
rectangle "Frontend Dashboard" {
  usecase "Login and Enforce Authenticated Session" as UC1
  usecase "View System Status Online or Offline" as UC2
  usecase "View Real-Time Metric Charts" as UC3
  usecase "View Alerts List confidence and method" as UC4
  usecase "View Alert SHAP Explainability" as UC5
  usecase "Manage Notification Channels" as UC6
  usecase "Verify Channel via OTP" as UC7
  usecase "Generate and Download Reports" as UC8
  usecase "Toggle Dark or Light Theme" as UC9
}
User --> UC1
User --> UC2
User --> UC3
User --> UC4
User --> UC5
User --> UC6
User --> UC8
User --> UC9
UC6 ..> UC7 : <<include>>
UC4 ..> UC5 : <<extend>>
Backend --> UC2
Backend --> UC3
Backend --> UC4
Backend --> UC8
@enduml
```

## 2.5 Software Development Plan

### 2.5.1 Development Methodology

The Agile methodology was followed. Development proceeded in iterative sprints, each focusing on a specific goal, allowing iterative improvement and regular feedback.

### 2.5.2 Phases of Development

**Phase 1: Research and Requirement Analysis** — Identify all cryptojacking attack vectors and related studies. Define functional and technical requirements. Select APIs (VirusTotal, MalwareBazaar) and plan the data collection pipeline.

**Phase 2: Data Collection and Feature Engineering** — Implement data collection from a real-world Kaggle cryptojacking dataset. Perform static analysis using PE analysis and string extraction. Extract and engineer the 20-feature vector pipeline.

**Phase 3: ML Model Development** — Train XGBoost and Random Forest models. Perform hyperparameter tuning with GridSearchCV. Evaluate results (accuracy, precision, recall, F1). Integrate SHAP TreeExplainer for feature importance.

**Phase 4: Backend and Agent Development** — Implement FastAPI backend with all routes (auth, metrics, alerts, reports, notifications, audit, agent). Develop the CryptoDetect Monitoring Agent v7.0 with tray GUI, auto-updater, static PE analysis, and network analysis modules.

**Phase 5: Frontend Development and Integration** — Develop the React dashboard. Integrate with backend REST APIs. Implement real-time metric charts, alert management, notification channel management, and report generation.

**Phase 6: Testing, Optimization, and Documentation** — Conduct performance and security testing. Optimize model accuracy and reduce false positives via the sustained-detection gate.

**Phase 7: Deployment** — Package the monitoring agent as a Windows .exe via PyInstaller. Deploy the backend and frontend. Finalize documentation.
"""

with open(r'C:\FYP\fyp\Dcox\FYP_Final_Document.md', 'a', encoding='utf-8') as f:
    f.write(content)
print('Chapter 2 written OK')
