# CryptoDetect — Cryptojacking Detection Tool

A full-stack detection system for unauthorized cryptocurrency mining on
workstations. A Windows monitoring agent streams CPU, memory, process, and
network telemetry to a FastAPI backend; machine-learning models score the
telemetry and raise alerts; a React dashboard gives users and administrators
visibility into monitored systems, alerts, reports, and audit logs.

The platform includes a reproducible machine-learning pipeline with shared
feature engineering, Random Forest and XGBoost training scripts, chronological
evaluation reports, and pre-trained model artifacts for immediate local execution.

## Screenshots

| Dashboard | Monitoring |
| --- | --- |
| ![CryptoDetect dashboard](docs/screenshots/dashboard.png) | ![System monitoring](docs/screenshots/monitoring.png) |

| Alerts | Reports |
| --- | --- |
| ![Alerts](docs/screenshots/alerts.png) | ![Reports](docs/screenshots/reports.png) |

Screenshots use the local demo dataset and seeded data.

## Architecture

```text
Windows monitoring agent (psutil)
        │  metrics + process snapshots (HTTP)
        ▼
FastAPI backend ── SQLAlchemy ──► SQLite (default) / PostgreSQL
        │
        ├── JWT authentication and role-aware routes
        ├── ML scoring (Random Forest / XGBoost artifacts)
        ├── alert, notification, report, and audit services
        └── REST API for the dashboard
                │
                ▼
React dashboard (Create React App)
```

Supporting pipelines:

- `static_analysis/` — PE inspection, string extraction, YARA miner/packer signatures
  (`yara_scanner.py`), and feature building for executable samples.
- `dynamic_analysis/` — 24-sample runtime behavior monitoring for throttled duty cycles,
  idle-surge evasion, persistent TLS sockets, and GPU compute activity.
- `data_collection/` — VirusTotal and MalwareBazaar clients plus sample
  management for dataset assembly.

## Components

### Monitoring agent

`monitoring_agent/agent.py` starts the agent implemented in `enhanced_agent.py`.
It samples CPU, per-PID NVML GPU compute, memory, network (including DNS Client
cache pool correlation and TLS port tracking), Win32 `GetLastInputInfo` idle
duration, sanitized process command lines, and process snapshots every 5 seconds.
It keeps a local cache of 60 entries, uploads a batch every 30 seconds, sends a
heartbeat every 10 seconds, and executes operator-approved containment and
persistence-audit commands (`suspend_process`, `resume_process`,
`kill_process_tree`, `quarantine_binary`, `block_ip`, and `audit_persistence`)
returned by the backend. Samples stay queued on disk until the backend confirms
them; during an outage the newest 60 samples are kept. `agent_gui.py`,
`build_exe.py`, and the auto-updater provide the single-instance packaged
Windows tray experience.

### API backend

FastAPI application (`backend/main.py`) with routers for:

| Router | Responsibility |
|---|---|
| `/api/auth` | Registration, login, JWT issuance, profile and password changes |
| `/api/systems` | Monitored-system registration, agent validation, heartbeats, persistence audits |
| `/api/metrics` | Metric ingestion, evasion-resilient ML/policy scoring, command dispatch |
| `/api/alerts` | Alert listing, acknowledgement, feature importance, containment actions |
| `/api/reports` | Report generation and download |
| `/api/notifications` | Per-user notification channels and preferences |
| `/api/admin` | Audit logs |
| `/api/agent` | Agent version metadata, executable download, command result callbacks |

The database layer defaults to SQLite at `backend/cryptojacking.db` and accepts
a PostgreSQL URL through `DATABASE_URL`. Alembic migrations are included.

### Machine-learning pipeline

- `ml_models/feature_engineering/feature_pipeline.py` defines the shared
  selected-feature set.
- `ml_models/preprocess_kaggle_data.py` prepares the normal and anomalous
  datasets.
- `ml_models/random_forest_model.py` trains and evaluates a Random Forest
  classifier.
- `ml_models/xgboost_model.py` trains and evaluates an XGBoost classifier.
- `ml_models/train_all_models.py` runs preprocessing, both training jobs, and
  writes a comparison report plus model metadata.
- `ml_models/benchmark_windows.py` evaluates naive CPU thresholds, uncalibrated
  XGBoost, SHAP cross-OS gating, and the evasion-resilient engine across 72
  multi-workload Windows episodes (`docs/results/results.md`).

Training expects the source CSV files under `ml_models/datasets/` and writes
artifacts to `ml_models/saved_models/`. Pre-trained lightweight artifacts are
included under `ml_models/saved_models/` so the API runs full ML + SHAP scoring
locally out of the box; raw dataset CSVs are excluded from version control.
Metrics, confusion matrices, SHAP plots, and Windows workload ablation results
are written to `docs/results/`.

### Dataset

The behavioral models use the
[Cryptojacking Attack Timeseries Dataset](https://www.kaggle.com/datasets/keshanijayasinghe/cryptojacking-attack-timeseries-dataset)
by Keshani Jayasinghe (Kaggle, version 1, CC0: Public Domain). It records a
server instance's performance metrics during normal operation and during a
cryptojacking attack.

| Class | File | Samples |
|---|---|---:|
| Normal | `final-normal-data-set.csv` | 80,851 |
| Cryptojacking | `final-anormal-data-set.csv` | 14,461 |
| **Total** | | **95,312** |

Cryptojacking samples make up about 15% of the data. Sample counts are as
reported by
[Faieq and Rasheed (2026)](https://doi.org/10.18280/ijsse.160112). Preprocessing
drops any rows with missing values, so the final count can be slightly lower.

### Evaluation method

Telemetry samples close in time are highly similar, so a random split can put
near-duplicates in both the training and test sets and inflate scores. The
models are trained and tested on a chronological split: each class is divided
by time into 70% train, 15% validation, and 15% test. Random-split scores are
reported only for comparison, alongside a baseline rule that uses `cpu_total`
alone.

### Known limitations

- **Training and deployment environments differ.** The base Kaggle dataset comes
  from a Linux server, while the monitoring agent runs on Windows. `cpu_iowait`,
  `cpu_softirq`, `mem_active`, and `mem_cached` are 0 on Windows, and
  `load_min1`, `load_min5`, and `load_min15` are estimated from CPU usage.
  Runtime inference mitigates this via SHAP cross-OS log-odds calibration
  combined with Windows process, YARA, CLI, idle-correlation, DNS, and TLS
  heuristics.
- **Network features measure different traffic.** The dataset records loopback
  traffic (`network_lo_*`), while the agent reports interface counters
  alongside per-process socket and DNS Client cache intelligence.
- **Benchmark evaluation.** See [`docs/results/results.md`](docs/results/results.md)
  for both the original chronological Kaggle split and the 72-episode Windows
  multi-workload evasion ablation benchmark (`python -m ml_models.benchmark_windows`).
  Real endpoint workloads should still be validated locally with `--collect-live`.

### Dashboard

The React front end provides login and registration, user and administrator
dashboards, live system monitoring, alert management with an authenticated
human-in-the-loop Active SOC Containment Queue (`Suspend`, `Kill`, `Quarantine`,
`Block IP`, and `Scan Persistence`), reports, profile and notification
settings, and an audit-log view for administrators.

## Tech stack

| Layer | Technology |
|---|---|
| Agent | Python, psutil, requests, pystray, pynvml, PyInstaller |
| Backend | FastAPI, SQLAlchemy, Alembic, Pydantic, python-jose, passlib |
| Machine learning | scikit-learn, XGBoost, pandas, NumPy, SHAP |
| Analysis | yara-python, pefile, BeautifulSoup |
| Notifications | SMTP, Twilio |
| Database | SQLite (default), PostgreSQL (via `DATABASE_URL`) |
| Frontend | React 19, React Router, Axios, Recharts, Socket.IO client |
| Testing | pytest, pytest-cov, httpx |

## Repository layout

```text
backend/                FastAPI app, models, routes, services, containment queue
monitoring_agent/       Windows telemetry agent, containment executor, GUI/EXE build
ml_models/              feature engineering, training, Windows benchmark & evaluation
static_analysis/        PE inspection, string extraction, YARA miner/packer scanner
dynamic_analysis/       multi-frame duty-cycle, AFK, TLS, and GPU behavior monitor
data_collection/        threat-intelligence API clients and sample manager
src/                    React dashboard & SOC containment UI
test/                   unit, integration, evasion/containment, and system tests
```

## Getting started

**Prerequisites:** Python 3.10–3.11, Node.js 18+, and pip. The monitoring agent
targets Windows; the backend and dashboard are platform-independent.

### 1. Backend

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Create a `.env` file in the repository root:

```dotenv
SECRET_KEY="replace-with-a-random-secret"
DATABASE_URL="sqlite:///backend/cryptojacking.db"
# DATABASE_URL="postgresql://user:password@localhost:5432/cryptodetect"
API_HOST="0.0.0.0"
API_PORT="8000"
DEBUG="True"
```

Start the API from the repository root:

```powershell
python -m uvicorn backend.main:app --reload --port 8000
```

Interactive API documentation is available at `http://localhost:8000/docs`.

### 2. Dashboard

```powershell
npm install
$env:REACT_APP_API_URL="http://localhost:8000"
npm start
```

The dashboard runs at `http://localhost:3000`.

### 3. Monitoring agent

```powershell
python monitoring_agent/agent.py --api-key <API_KEY> --api-url http://localhost:8000
```

Set `AGENT_BATCH_SIZE` to change how many 5-second samples go in each upload
(default 6, which is every 30 seconds).

## Training the models

Place `final-anormal-data-set.csv` and `final-normal-data-set.csv` in
`ml_models/datasets/`, then run:

```powershell
python -m ml_models.train_all_models
```

Individual models can be trained with `python -m ml_models.random_forest_model`
or `python -m ml_models.xgboost_model`. Outputs are written under
`ml_models/evaluation/` and `ml_models/saved_models/`.

To serve a custom artifact, set `RANDOM_FOREST_MODEL_PATH` and/or
`XGBOOST_MODEL_PATH` to the model file locations.

## Tests

```powershell
pytest test/ -v
```

The suite is organized into unit tests for authentication and ML helpers,
API integration tests, performance checks, and an end-to-end system flow.

## Configuration

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | JWT signing key; replace the development default |
| `DATABASE_URL` | SQLAlchemy connection string; defaults to local SQLite |
| `API_URL` | Backend URL used by the agent |
| `AGENT_UPDATE_INTERVAL` | Agent sampling interval in seconds |
| `RANDOM_FOREST_MODEL_PATH`, `XGBOOST_MODEL_PATH` | Custom model artifacts |
| `ALERT_THRESHOLD_SCORE`, `ALERT_MIN_SIGNAL_COUNT`, `ALERT_SUSTAINED_REQUIRED` | Alert scoring thresholds |
| `ALERT_COOLDOWN_SECONDS` | Minimum interval between duplicate alerts |
| `VIRUSTOTAL_API_KEY`, `MALWAREBAZAAR_API_KEY` | Optional threat-intelligence lookups |
| `SMTP_*`, `EMAIL_FROM` | Outbound email notifications |
| `TWILIO_*` | Optional WhatsApp notifications |
| `VERIFICATION_DEV_MODE` | Development verification behavior for system registration |

## Notes

- CORS currently allows all origins in `backend/main.py`; restrict this before
  exposing the API publicly.
- The development default for `SECRET_KEY` must be replaced in any deployed
  environment.
- Raw training datasets and compiled Windows `.exe` bundles are excluded from version control.
