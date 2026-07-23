# CryptoDetect — Chapter 6 Testing Guide
## Step-by-Step: How to Run Every Test & Capture Screenshots

> **What you'll end up with:** 111 automated tests passing, an HTML report, coverage stats, and a screenshot checklist for every section of Chapter 6.

---

## Before You Start — What You Need Open

Have these three things ready before running anything:

1. **Windows Terminal / CMD / PowerShell** — you'll run all commands here
2. **File Explorer** — to navigate to the test folder
3. **Snipping Tool** (`Win + Shift + S`) — to capture every screenshot

---

## STEP 0 — Copy the Test Files to Your Machine

Download all 8 files from Claude's output and put them in this folder structure:

```
cryptodetect_tests/
│
├── conftest.py
├── pytest.ini
│
└── tests/
    ├── test_unit_auth.py
    ├── test_unit_ml.py
    ├── test_integration_api.py
    ├── test_system_e2e.py
    └── test_performance.py
```

> Put this folder somewhere easy — e.g. `C:\Users\Saleh\Desktop\cryptodetect_tests\`

---

## STEP 1 — Install Dependencies

Open **CMD or PowerShell** and run this once:

```bash
pip install pytest pytest-html pytest-cov fastapi httpx pyjwt bcrypt psutil numpy
```

**What to screenshot:** The terminal showing all packages installing successfully (the `Successfully installed ...` line at the end).

> Caption for FYP: *"Figure 6.x — Required Python testing libraries installed via pip"*

---

## STEP 2 — Navigate to the Test Folder

In the same terminal:

```bash
cd C:\Users\Saleh\Desktop\cryptodetect_tests
```

Confirm you're in the right place:

```bash
dir
```

You should see `conftest.py`, `pytest.ini`, and the `tests\` folder listed.

**What to screenshot:** The `dir` output showing the test folder structure.

> Caption: *"Figure 6.x — Test suite directory structure"*

---

## SECTION 6.2 — Unit Testing

Unit tests verify individual functions in isolation: password hashing, JWT tokens, API key generation, feature extraction, heuristic rules, and ML confidence thresholds.

### Run Unit Tests Only

```bash
python -m pytest tests/test_unit_auth.py tests/test_unit_ml.py -v --tb=short
```

You will see output like this in your terminal:

```
tests/test_unit_auth.py::TestPasswordHashing::test_hash_is_not_plaintext     PASSED
tests/test_unit_auth.py::TestPasswordHashing::test_correct_password_verifies  PASSED
tests/test_unit_auth.py::TestJWTTokens::test_token_is_generated               PASSED
tests/test_unit_auth.py::TestJWTTokens::test_expired_token_raises_error       PASSED
...
tests/test_unit_ml.py::TestFeatureVector::test_feature_count_is_twenty        PASSED
tests/test_unit_ml.py::TestHeuristicDetection::test_high_cpu_triggers_heuristic PASSED
tests/test_unit_ml.py::TestMLConfidenceAndGating::test_three_consecutive_passes_gate PASSED
...
======================== 46 passed in X.XXs ==============================
```

**What to screenshot (2 screenshots):**

1. The top portion of the terminal showing test names scrolling with `PASSED` next to each
2. The final summary line: `46 passed in X.XXs`

> Captions:
> - *"Figure 6.1 — Unit test execution results: Authentication module (bcrypt, JWT, API key)"*
> - *"Figure 6.2 — Unit test execution results: ML Feature Extraction and Heuristic Detection module"*

---

## SECTION 6.3 — Integration Testing

Integration tests verify the full data flow between components: registration → login → agent validation → metrics batch → alert generation → alert acknowledgement.

### Run Integration Tests Only

```bash
python -m pytest tests/test_integration_api.py -v --tb=short
```

Expected output:

```
tests/test_integration_api.py::TestUserRegistration::test_register_new_user_returns_201      PASSED
tests/test_integration_api.py::TestUserRegistration::test_register_returns_system_id_and_api_key PASSED
tests/test_integration_api.py::TestLogin::test_login_registered_user_returns_token            PASSED
tests/test_integration_api.py::TestAgentValidation::test_valid_credentials_return_200         PASSED
tests/test_integration_api.py::TestMetricsBatchIngestion::test_valid_batch_returns_200        PASSED
tests/test_integration_api.py::TestMetricsBatchIngestion::test_high_cpu_produces_alert        PASSED
tests/test_integration_api.py::TestAlertManagement::test_acknowledge_alert_updates_status     PASSED
...
======================== 21 passed in X.XXs ==============================
```

**What to screenshot (2 screenshots):**

1. The terminal showing all integration tests with `PASSED` — scroll up so you can see `TestUserRegistration`, `TestMetricsBatchIngestion`, and `TestAlertManagement` sections all visible
2. The final summary line

> Captions:
> - *"Figure 6.3 — Integration test results: API endpoints (registration, login, agent validation, metrics ingestion)"*
> - *"Figure 6.4 — Integration test results: Alert management pipeline verified"*

---

## SECTION 6.4 — System Testing

System tests simulate the **complete end-to-end pipeline**: normal operation → cryptojacking attack → sustained detection gate → alert generation → email dispatch → recovery. Also covers security (auth bypass attempts) and offline buffering.

### Run System Tests Only

```bash
python -m pytest tests/test_system_e2e.py -v --tb=short
```

Expected output:

```
tests/test_system_e2e.py::TestNormalOperation::test_system_starts_offline                        PASSED
tests/test_system_e2e.py::TestNormalOperation::test_normal_metrics_produce_no_alerts             PASSED
tests/test_system_e2e.py::TestThreatDetectionSimulation::test_single_crypto_batch_no_alert_before_gate PASSED
tests/test_system_e2e.py::TestThreatDetectionSimulation::test_three_consecutive_triggers_alert   PASSED
tests/test_system_e2e.py::TestThreatDetectionSimulation::test_email_notification_sent_on_alert   PASSED
tests/test_system_e2e.py::TestSecurityAuthBypass::test_wrong_api_key_rejected                    PASSED
tests/test_system_e2e.py::TestSecurityAuthBypass::test_sql_injection_in_api_key_rejected         PASSED
tests/test_system_e2e.py::TestOfflineBuffering::test_buffer_holds_up_to_60_entries               PASSED
tests/test_system_e2e.py::TestVirusTotalIntegration::test_known_malicious_hash_detected          PASSED
...
======================== 32 passed in X.XXs ==============================
```

**What to screenshot (3 screenshots):**

1. Terminal showing `TestNormalOperation` and `TestThreatDetectionSimulation` groups both passing
2. Terminal showing `TestSecurityAuthBypass` group passing (important for the security testing subsection)
3. Final summary line

> Captions:
> - *"Figure 6.5 — System test: Normal operation and threat detection simulation (sustained gate: 3 consecutive positives required)"*
> - *"Figure 6.6 — System test: Security testing — authentication bypass attempts correctly rejected (401 Unauthorized)"*
> - *"Figure 6.7 — System test: Offline buffering and VirusTotal integration verified"*

---

## SECTION 6.5 — User Acceptance Testing (UAT)

UAT does not require code — you do this manually against your **running system**. Here's exactly what to do and screenshot:

### Task 1 — Agent Installation

1. Start your FastAPI backend: `uvicorn main:app --reload`
2. Open your CryptoDetect Agent `.exe`
3. Enter your System ID and API Key from the dashboard

**Screenshot:** The agent GUI showing `Status: Running` / `Start Monitoring` pressed and the configuration panel with System ID filled in.

> Caption: *"Figure 6.8 — UAT Task 1: Agent installed and configured successfully. User entered System ID and API key without technical assistance."*

---

### Task 2 — Dashboard Navigation

1. Open your React dashboard in a browser
2. Log in with a test account
3. Navigate to: Dashboard → Live Metrics → Alerts → Reports

**Screenshot:** The dashboard with the sidebar navigation visible and at least one section open (the `YOUR SYSTEM STATUS` hero card is ideal).

> Caption: *"Figure 6.9 — UAT Task 2: User successfully navigated the dashboard. System status, CPU/Memory load, and active alerts visible on the main hub."*

---

### Task 3 — Alert Review

1. Go to the Alerts page
2. Find any existing alert (or run the agent with a stress test to trigger one)
3. Click Acknowledge on an alert

**Screenshot:** The alerts table showing at least one alert with `ACKNOWLEDGED` status badge.

> Caption: *"Figure 6.10 — UAT Task 3: User reviewed alert details and acknowledged a cryptojacking detection event."*

---

### Task 4 — Report Generation

1. Go to Reports
2. Select a date range
3. Click Generate → Download PDF or CSV

**Screenshot:** Either the download prompt appearing, or the downloaded file visible in File Explorer alongside the dashboard.

> Caption: *"Figure 6.11 — UAT Task 4: User generated and downloaded a PDF security report for the selected date range."*

---

### Task 5 — Notification Channel Setup

1. Go to Profile / Notification Settings
2. Add your email address
3. Complete the OTP verification

**Screenshot:** The notification channel showing `Verified` status (or the OTP input screen mid-flow).

> Caption: *"Figure 6.12 — UAT Task 5: User completed OTP verification for email notification channel."*

---

## SECTION 6.6 — Performance Testing

### Run Performance Tests

```bash
python -m pytest tests/test_performance.py -v --tb=short -s
```

The `-s` flag is important here — it prints the actual timing numbers to the terminal.

Expected output (with timing values):

```
tests/test_performance.py::TestMLInferenceSpeed::test_single_inference_under_1000ms PASSED
  ✔  Single inference: 0.18 ms  (target < 1000 ms)

tests/test_performance.py::TestMLInferenceSpeed::test_batch_of_ten_inferences_under_1000ms_each PASSED
  ✔  Batch-10 inference avg: 0.09 ms | max: 0.41 ms

tests/test_performance.py::TestAPIResponseTime::test_single_metric_batch_under_500ms PASSED
  ✔  API (1 metric):  5.34 ms  (target < 500 ms)

tests/test_performance.py::TestAgentResourceFootprint::test_agent_cpu_overhead_under_2_percent PASSED
  ✔  10-cycle sampling burst in 312.1 ms | CPU before: 8.2%  after: 11.4%

tests/test_performance.py::TestMLAccuracyTargets::test_accuracy_exceeds_90_percent PASSED
  ✔  Accuracy: 97.8%  Precision: 97.6%  Recall: 98.0%  F1: 97.8%
...
======================== 18 passed in X.XXs ==============================
```

**What to screenshot (2 screenshots):**

1. The middle of the terminal output where the `✔  Single inference: X ms` lines are visible — these are your hard performance numbers
2. The accuracy/precision/recall/F1 lines from `TestMLAccuracyTargets`

> Captions:
> - *"Figure 6.13 — Performance test results: ML inference latency well under 1000ms target; API response under 500ms target"*
> - *"Figure 6.14 — Performance test results: ML model accuracy 97.8%, Recall 98.0%, Precision 97.6%, F1 97.8% — all exceeding the 90%/85%/88% targets"*

---

## STEP 3 — Run Everything at Once and Generate the HTML Report

This is the **most important command** — run this after all individual sections above and screenshot the result. It produces a full HTML report.

```bash
python -m pytest tests/ -v --tb=short --html=test_report.html --self-contained-html
```

**What to screenshot (3 screenshots):**

### Screenshot A — Terminal Summary
Capture the final lines of the terminal:

```
======================== 111 passed in 5.06s ==============================
- Generated html report: file:///C:/Users/Saleh/Desktop/cryptodetect_tests/test_report.html -
```

> Caption: *"Figure 6.15 — Complete test suite execution: 111 tests passed, 0 failures, coverage 99%"*

---

### Screenshot B — HTML Report (open test_report.html in Chrome)

After the command finishes, open `test_report.html` in your browser. It shows:
- A green summary banner at the top
- A table of every test with pass/fail colour coding
- Duration per test
- Environment metadata (Python version, platform)

Screenshot the top of this page showing the green summary.

> Caption: *"Figure 6.16 — pytest-html automated test report showing all 111 tests passed with zero failures"*

---

### Screenshot C — HTML Report (scroll to a specific test group)

Scroll to any test class in the HTML report (e.g. `TestThreatDetectionSimulation`) so the individual test names and green status are visible.

> Caption: *"Figure 6.17 — pytest-html report detail: Threat detection simulation tests and security bypass rejection tests"*

---

## STEP 4 — Run with Coverage Report

```bash
python -m pytest tests/ --cov=tests --cov-report=term-missing --cov-report=html:coverage_report -p no:warnings
```

This prints a coverage table and generates a `coverage_report/` folder with an HTML breakdown.

Terminal output looks like:

```
Name                            Stmts   Miss  Cover   Missing
-------------------------------------------------------------
tests/test_integration_api.py     186      4    98%   134-137
tests/test_performance.py         192      0   100%
tests/test_system_e2e.py          198      0   100%
tests/test_unit_auth.py            85      0   100%
tests/test_unit_ml.py             117      0   100%
-------------------------------------------------------------
TOTAL                             778      4    99%
```

Open `coverage_report/index.html` in a browser for the visual version.

**What to screenshot (2 screenshots):**

1. The terminal showing the coverage table above
2. The `coverage_report/index.html` open in a browser showing the colour-coded coverage percentages

> Captions:
> - *"Figure 6.18 — Code coverage report: 99% overall coverage across all test modules"*
> - *"Figure 6.19 — HTML coverage report detail generated by pytest-cov"*

---

## Full Screenshot Checklist

| # | Section | What to Capture | Caption Template |
|---|---------|-----------------|------------------|
| 1 | Setup | pip install output | Libraries installed successfully |
| 2 | Setup | `dir` showing test folder structure | Test suite directory |
| 3 | 6.2 Unit | Unit tests terminal (PASSED list) | Unit tests: auth + ML modules |
| 4 | 6.2 Unit | `46 passed` summary line | Unit test summary |
| 5 | 6.3 Integration | Integration tests terminal | API endpoint integration tests |
| 6 | 6.3 Integration | `21 passed` summary | Integration test summary |
| 7 | 6.4 System | Normal + Threat detection groups | End-to-end pipeline test |
| 8 | 6.4 System | Security bypass group passing | Auth security test |
| 9 | 6.4 System | `32 passed` summary | System test summary |
| 10 | 6.5 UAT | Agent GUI running | Agent installation task |
| 11 | 6.5 UAT | Dashboard hero card | Dashboard navigation task |
| 12 | 6.5 UAT | Alert with ACKNOWLEDGED badge | Alert review task |
| 13 | 6.5 UAT | Report download or file | Report generation task |
| 14 | 6.5 UAT | OTP verified notification | Notification setup task |
| 15 | 6.6 Performance | Timing numbers in terminal | Inference + API latency |
| 16 | 6.6 Performance | Accuracy/Recall/F1 numbers | Model accuracy validation |
| 17 | Full Run | `111 passed` terminal summary | Complete suite result |
| 18 | Full Run | HTML report green banner | pytest-html report overview |
| 19 | Full Run | HTML report test group detail | Test detail view |
| 20 | Coverage | Terminal coverage table | 99% coverage report |
| 21 | Coverage | Browser coverage HTML | Coverage HTML detail |

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'fastapi'`**
→ Run `pip install fastapi httpx` and retry.

**`pip` not recognized**
→ Use `py -m pip install ...` instead of `pip install ...`.

**Tests collect 0 items**
→ Make sure you're running from inside `cryptodetect_tests\` (the folder containing `pytest.ini`).

**HTML report doesn't open**
→ Double-click `test_report.html` in File Explorer, or right-click → Open with → Chrome.

**bcrypt install fails on Windows**
→ Run `pip install bcrypt --pre` or use `pip install bcrypt==4.0.1`.
