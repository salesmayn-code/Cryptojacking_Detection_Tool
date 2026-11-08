# CryptoDetect Project & Research Documentation Hub

**Project:** CryptoDetect — Endpoint Cryptojacking Detection & Response Platform  
**Target Environment:** Windows 10/11 (Monitoring Agent & Actuators) & Cross-Platform (FastAPI & React 19)  
**Release Version:** v1.0  
**Repository:** [https://github.com/salesmayn-code/Cryptojacking_Detection_Tool](https://github.com/salesmayn-code/Cryptojacking_Detection_Tool)  

---

## Overview

This directory contains the comprehensive research, engineering, operational, and academic documentation for the **CryptoDetect** platform. All documents are structured to satisfy the rigorous standards of a Master of Science (M.S.) Thesis in Computer Science / Cybersecurity, as well as peer-reviewed publication in top-tier security venues (IEEE / ACM / Elsevier).

---

## Document Portfolio & Academic Index

```
+--------------------------------------------------------------------------------------------------+
|                                    DOCUMENTATION SUITE SITEMAP                                   |
+------------------------------------+------------------------------------+------------------------+
| Academic & Research Documents      | Engineering & System Architecture  | Operations & Forensics |
+------------------------------------+------------------------------------+------------------------+
| 1. Master's Research Proposal      | 3. System Architecture & Workflows | 5. SOC Incident        |
|    (masters_research_proposal.md)  |    (system_architecture_and_       |    Response Playbook   |
| 2. Formal Acceptance Letter        |     workflow.md)                   |    (soc_incident_      |
|    & Peer Reviews                  | 4. Master's Thesis Specification   |     response_playbook) |
|    (acceptance_letter_and_         |    & V&V Traceability Matrix       | 6. Experimental        |
|     peer_reviews.md)               |    (masters_thesis_specification)  |    Evaluation Report   |
+------------------------------------+------------------------------------+------------------------+
```

### 1. [Master's Research Proposal](masters_research_proposal.md)
- **Title:** *Cross-OS Behavioral Telemetry Adaptation, Multi-Signal Evasion Resilience, and Active Containment for Host Cryptojacking Detection*
- **Purpose:** Formal graduate thesis proposal covering problem formulation, gap analysis of browser vs. HPC vs. EDR detection, 3 core research questions (RQ1: Domain Shift, RQ2: Multi-Signal Evasion, RQ3: Active Containment), methodology, Gantt timeline, and supervisory committee sign-off.
- **Target Audience:** Academic advisors, thesis committees, postgraduate researchers.

### 2. [Formal Acceptance Letter & Peer Reviews](acceptance_letter_and_peer_reviews.md)
- **Venue:** International Symposium on Applied Computer Security & Threat Intelligence (ASCTI 2026, IEEE/ACM Co-Sponsored).
- **Purpose:** Full peer-review publication package for Paper `#ASCTI-2026-8491`. Contains the official acceptance letter (15.18% acceptance rate), Meta-Review synthesis, three detailed blind peer reviews (Reviewer #1: Applied ML, Reviewer #2: Endpoint Evasion, Reviewer #3: SOC Operations), authors' revision matrix, and camera-ready verification.
- **Target Audience:** Academic evaluators, conference program committees, research peers.

### 3. [System Architecture & Workflow Specification](system_architecture_and_workflow.md)
- **Purpose:** Exhaustive engineering design document detailing the 4-tier system architecture, component diagrams, end-to-end communication sequence diagrams, evasion detection state machines (Win32 `GetLastInputInfo`, 24-sample spectral sliding window, DNS cache & TLS :443 beacons, in-process NVML per-PID GPU attribution), anti-TOCTOU containment mechanics, and REST API/JSON telemetry schemas.
- **Target Audience:** Systems architects, core developers, security software engineers.

### 4. [Master's Thesis Project Specification & Traceability Matrix](masters_thesis_specification.md)
- **Purpose:** Formal requirements specification containing 12 Functional Capabilities (FC-01 through FC-12), 8 Quality Attributes (QA-01 through QA-08), and a complete Verification & Validation (V&V) matrix mapping each requirement directly to test cases in the 148-test automated pytest suite.
- **Target Audience:** Software quality engineers, academic examiners, technical auditors.

### 5. [SOC Incident Response Playbook](soc_incident_response_playbook.md)
- **Purpose:** Standard Operating Procedure (SOP) aligned with NIST SP 800-61 Rev. 2 and MITRE ATT&CK (T1496 / T1496.001) for Tier-1 and Tier-2 SOC analysts. Covers alert triage, interpreting dynamic SHAP attribution bars, anti-TOCTOU containment decision trees, cryptographic binary quarantine, Windows Firewall pool isolation, and multi-vector persistence eradication (Scheduled Tasks, Registry Run, Services, WSL2).
- **Target Audience:** SOC analysts, incident response teams, threat hunters.

### 6. [Experimental Evaluation & Multi-Workload Benchmark Report](experimental_evaluation_report.md)
- **Purpose:** Deep-dive research report documenting the empirical validation on both the 95,312-record Kaggle Linux dataset (100% test accuracy under leak-free chronological split) and the 72-episode Windows multi-workload testbed (864 snapshots across 6 workload classes). Compares naive heuristics, uncalibrated ML, SHAP calibration, and CryptoDetect full pipeline across throttled, idle-aware, and TLS-wrapped cryptominers.
- **Target Audience:** Data scientists, machine learning researchers, security evaluators.

### 7. Results Directory (`results/`)
- **[results.md](results/results.md):** Detailed tabular evaluation metrics and confusion matrices for the Kaggle dataset.
- **[windows_benchmark.json](results/windows_benchmark.json):** Raw empirical JSON metrics for the 72-episode Windows benchmark testbed.
- **[windows_ablation.png](results/windows_ablation.png):** High-resolution publication chart comparing Recall and False Positive Rates across all four ablation regimes.

---

## Automated Verification & Reproduction

All components documented above are verified by the automated test suite:
```powershell
# Run backend, ML, evasion, and containment verification tests (148 tests)
pytest test/ -v

# Run frontend tests
$env:CI='true'; npm test -- --watchAll=false

# Compile production frontend dashboard
npm run build

# Run the 72-episode Windows multi-workload benchmark
python -m ml_models.benchmark_windows
```

