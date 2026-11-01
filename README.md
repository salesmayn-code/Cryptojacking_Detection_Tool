# CryptoDetect — Cryptojacking Detection Tool

A full-stack detection system for unauthorized cryptocurrency mining on
workstations. A Windows monitoring agent streams CPU, memory, process, and
network telemetry to a FastAPI backend; machine-learning models score the
telemetry and raise alerts; a React dashboard gives users and administrators
visibility into monitored systems, alerts, reports, and audit logs.

The project combines a final-year capstone implementation with a documented
machine-learning pipeline: shared feature engineering, separate Random Forest
and XGBoost training scripts, evaluation reports, and saved model artifacts.

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

- `static_analysis/` — PE inspection, string extraction, and feature building
  for executable samples.
- `dynamic_analysis/` — runtime behavior monitoring.
- `data_collection/` — VirusTotal and MalwareBazaar clients plus sample
  management for dataset assembly.

## Components

### Monitoring agent

`monitoring_agent/agent.py` collects system metrics with `psutil` at a
configurable interval and posts them to the backend. It buffers failed
submissions and retries them, and supports a system identifier supplied on the
command line. `agent_gui.py`, `build_exe.py`, and the auto-updater provide the
packaged Windows agent experience.

### API backend

FastAPI application (`backend/main.py`) with routers for:

| Router | Responsibility |
|---|---|
| `/api/auth` | Registration, login, JWT issuance, profile and password changes |
| `/api/systems` | Monitored-system registration, agent validation, heartbeats |
| `/api/metrics` | Metric ingestion and retrieval |
| `/api/alerts` | Alert listing, acknowledgement, and feature-importance details |
| `/api/reports` | Report generation and download |
| `/api/notifications` | Per-user notification channels and preferences |
| `/api/admin` | Audit logs |
| `/api/agent` | Agent version metadata and executable download |

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

Training expects the source CSV files under `ml_models/datasets/` and writes
artifacts to `ml_models/saved_models/`. Datasets and trained artifacts are not
committed to the repository.

### Dashboard

The React front end provides login and registration, user and administrator
dashboards, live system monitoring, alert management, reports, profile and
notification settings, and an audit-log view for administrators.

## Tech stack

| Layer | Technology |
|---|---|
| Agent | Python, psutil, requests, pystray, PyInstaller |
| Backend | FastAPI, SQLAlchemy, Alembic, Pydantic, python-jose, passlib |
| Machine learning | scikit-learn, XGBoost, pandas, NumPy, SHAP |
| Analysis | yara-python, pefile, BeautifulSoup |
| Notifications | SMTP, Twilio |
| Database | SQLite (default), PostgreSQL (via `DATABASE_URL`) |
| Frontend | React 19, React Router, Axios, Recharts, Socket.IO client |
| Testing | pytest, pytest-cov, httpx |

## Repository layout

```text
backend/                FastAPI app, models, routes, services
monitoring_agent/       Windows telemetry agent and packaging scripts
ml_models/              feature engineering, training, evaluation
static_analysis/        PE and string analysis
dynamic_analysis/       runtime behavior monitoring
data_collection/        threat-intelligence API clients and sample manager
src/                    React dashboard
test/                   unit, integration, performance, and system tests
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
$env:API_URL="http://localhost:8000"
python monitoring_agent/agent.py <SYSTEM_ID>
```

The agent posts a metrics snapshot every `AGENT_UPDATE_INTERVAL` seconds
(default 5) and retries buffered snapshots when the API is unavailable.

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
- Model datasets and binaries are intentionally excluded from version control.
