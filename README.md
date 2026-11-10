# Chronica: Digital Forensics Incident Timeline & Evidence Collection Tool

**AIORI-3 Cybersecurity Problem Statement PS-013: Incident Timeline and Evidence Collection for Small Teams**

[![Test Suite](https://img.shields.io/badge/pytest-266%20passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.14-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()
[![Offline](https://img.shields.io/badge/operation-100%25%20offline-success.svg)]()

---

## 1. Problem Statement & Real-World Mission

Small IT teams and solo incident responders often face severe challenges during cyber intrusions. When investigating an active incident across Linux servers, web gateways, backend applications, and firewalls, evidence is fragmented across logs with:
- Drifting and desynchronized host clocks.
- Inconsistent and mixed time zones (UTC, EDT, IST, local naive).
- Yearless BSD syslog timestamps.
- Corrupted, truncated, or dropped lines.
- Quiet intervals that may look like log clearing.
- Disconnected event identifiers.

**Chronica** is a lightweight, offline-first digital forensics workbench that ingests multi-source logs, preserves pristine raw evidence with cryptographic SHA-256 digests, normalizes timestamps to UTC, correlates events across systems, estimates clock offsets using robust median statistics, flags evidence gaps, and produces publication-ready incident reports in PDF, Markdown, CSV, and JSON.

### Foundational Forensic Principle
> **Treat evidence bytes, parsed fields, timing normalizations, clock-skew corrections, and conclusions as distinct entities.**
> Chronica never overwrites original logs, never turns an estimate into a fact, and never guesses unrecorded data silently.

---

## 2. Key Capabilities & Implemented Features

| Module | Forensic Feature | Implementation Details |
|---|---|---|
| **Evidence Ingestion** | Multi-file preservation & archives | Read-only local storage, path traversal protection (`../`), .gz/.zip decompression, bomb guards. |
| **Integrity Engine** | Cryptographic verification | Pre-ingestion SHA-256 streaming hashing (64KB chunks), structured JSON manifest, 1-click re-verification audit. |
| **Audit Chain Ledger** | Tamper-evident chain of custody | Cryptographically linked SHA-256 hash chain (`audit_chain.jsonl`) recording ingestion, verification, annotations, and exports. |
| **Log Parsers** | Multi-format ecosystem | RFC 3164 BSD & RFC 5424 Syslog, JSONL, Apache/Nginx, CSV Firewall, Linux `auditd`, Windows Event Logs (CSV/JSON), and Custom Named-Group Regex. |
| **Format Detection** | Explainable autodetection | Transparent heuristic scoring sample lines against parser signatures with confidence scores. |
| **Normalization** | Robust UTC conversion | Microsecond precision, explicit offset conversion, yearless BSD syslog rollover tracking (`Dec -> Jan`), and DST fold ambiguity detection. |
| **Clock-Skew Engine** | Offset & drift estimation | Multi-key anchor discovery (`REQUEST_ID`, `SESSION_ID`, `INVESTIGATOR_CONFIRMED`), robust median statistics, MAD spread, Theil-Sen linear drift rate (`ppm`), and causal latency guard. |
| **Heuristics & Threat Hunting** | Explainable forensic leads | Deterministic heuristics mapped to MITRE ATT&CK techniques: Brute Force then Success, Privilege Escalation, Sensitive Data Export, and Log/Clock Tampering. |
| **Timeline Explorer** | Multi-axis chronology & inspector | Sorting by Normalized UTC, Corrected UTC, or Original sequence; interactive Plotly swimlanes with coverage gap bands; 3-column forensic inspector. |
| **Annotations & Bookmarks** | Persistent investigator notes | Pinning (`⭐`), forensic tagging (Initial Access, Lateral Movement, etc.), per-event analyst notes persisted to SQLite and Audit Ledger. |
| **Search & Filtering** | Conjunctive faceted search | Regex keyword querying, negative search (`NOT`), CIDR subnet matching (`192.168.1.0/24`), instant filtered export bar. |
| **Diagnostics & Gaps** | 9-category taxonomy | Quantifies quiet period gaps (Category F), parse failures (Category A), integrity mismatches (Category H). Explicit denominators. |
| **Export Engine** | Publication-grade reports | ReportLab PDF (XML escaped), 17+1 Section Markdown (cell escaped), RFC 4180 CSV, structured JSON. |
| **Synthetic Suite** | 3 reproducible scenarios | Scenario 1 Clean Baseline, Scenario 2 Clock Skew (+180s), Scenario 3 Degraded Evidence; automated quantitative benchmark evaluator. |


---

## 3. Architecture & Data Flow

```mermaid
flowchart TD
    RawLogs["Raw Log Files"] --> Hash["Pre-Ingestion SHA-256 Hashing"]
    Hash --> Store["Preserved Evidence Store (Read-Only)"]
    Hash --> Manifest["Evidence Manifest (manifest.json)"]
    Store --> Detect["Explainable Format Detector"]
    Detect --> Parsers["Syslog, JSONL, Apache/Nginx, CSV Parsers"]
    Parsers --> Norm["UTC Timestamp Normalizer"]
    Norm --> DB[("SQLite Event Database")]
    DB --> Skew["Anchor Discovery & Median Skew Estimator"]
    Skew --> Assembler["Timeline Assembler & Deterministic Sorter"]
    Assembler --> Gap["Diagnostic Gap Taxonomy (A - I)"]
    Assembler --> Search["Full-Text & Faceted Search"]
    Search --> UI["Streamlit Interactive Dashboard"]
    Gap --> UI
    UI --> Export["Reports (PDF, Markdown, CSV, JSON)"]
```

---

## 4. Requirements & Installation

Chronica runs completely offline on standard hardware without external cloud APIs, SIEM subscriptions, or administrative privileges.

### System Requirements
- Python 3.11, 3.12, 3.13, or 3.14
- Operating System: Windows, Linux, or macOS

### Installation Steps

1. Clone or navigate to the repository directory:
   ```bash
   cd chronica
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 5. Launch & Usage Guide

### Launching the Application
Run the following command from the repository root:

```bash
python -m streamlit run app.py
```


Open your web browser at **`http://localhost:8501`**.

---

### Step-by-Step Investigator Workflows

#### 1. Create an Investigation
- Open **📂 Case Management** in the sidebar.
- Enter a unique **Case ID** (e.g., `case_2026_q3_triage`) and **Investigation Title**.
- Select the baseline case timezone (e.g. `UTC`). Click **Create Case Workspace**.

#### 2. Import & Preserve Evidence Files
- Navigate to **📁 Evidence Ingestion**.
- Upload one or more log files (Syslog, JSONL, Apache/Nginx, CSV).
- Select **Auto-Detect Format (Explainable)** or choose an explicit parser.
- Click **🚀 Ingest, Hash & Parse Evidence**.
- Chronica hashes files with SHA-256 before parsing and saves a pristine read-only copy in the investigation directory.

#### 3. Verify Cryptographic SHA-256 Integrity
- Navigate to **🔒 Evidence Integrity (SHA-256)**.
- Review recorded digests in the manifest.
- Click **🔄 Verify All Evidence Now**.
- Chronica re-hashes every on-disk file, displaying green `✅ VERIFIED` or red `❌ MISMATCH` badges.

#### 4. Explore the Chronological Timeline
- Navigate to **⏱️ Timeline Explorer**.
- Toggle sorting:
  - **Normalized UTC**: Standard UTC chronological order.
  - **Clock-Corrected UTC**: Synchronized order with host clock offsets subtracted.
  - **Original Line Sequence**: Pristine acquisition order.
- Select any event in the **Event Detail Inspector** to inspect raw lines, parsed fields, normalization flags, and source provenance.

#### 5. Search & Filter
- Navigate to **🔍 Search & Filter**.
- Enter keyword queries or filter by Host, User, IP, Severity, and Category.
- Filter criteria operate conjunctively (AND logic) on actual event data.

#### 6. Inspect Clock-Skew Offsets
- Navigate to **⏳ Clock-Skew Analysis**.
- Chronica uses the documented sign convention:
  $$\text{offset} = \text{target\_clock} - \text{reference\_clock}$$
  $$\text{corrected\_time} = \text{target\_time} - \text{offset}$$
- Inspect the anchor table linking events by shared `request_id` or `session_id`.
- Chronica requires $\ge 2$ confirmed anchors; single anchors are marked `INCONCLUSIVE_INSUFFICIENT_ANCHORS`.

#### 7. Inspect Gaps & Diagnostics
- Navigate to **⚠️ Gaps & Diagnostics**.
- Inspect coverage rates (with explicit denominators).
- Review findings across taxonomy categories A through I (corrupted lines, quiet period gaps, unrecorded years).

#### 8. Export Investigation Reports
- Navigate to **📑 Reports & Export**.
- Download:
  - **PDF Report**: Publication-grade PDF with tables, metrics, and disclaimers.
  - **Markdown Report**: 17-section incident report conforming to hackathon standards.
  - **CSV Timeline**: Standard forensic spreadsheet.
  - **JSON Case**: Machine-readable case backup.

---

## 6. Running the Automated Test Suite

Chronica features a 3-tier automated test suite covering unit, integration, and end-to-end functionality:

```bash
python -m pytest -v
```

### Verified Test Summary:
```text
tests/end_to_end/test_scenarios_e2e.py (3 tests) PASSED
tests/end_to_end/test_ui_app.py (2 tests) PASSED
tests/integration/test_investigation_lifecycle.py (1 test) PASSED
tests/integration/test_tamper_detection.py (1 test) PASSED
tests/unit/test_archive_bomb_remediation.py (6 tests) PASSED
tests/unit/test_atomic_ingest_remediation.py (6 tests) PASSED
tests/unit/test_audit_chain_remediation.py (7 tests) PASSED
tests/unit/test_auditd_real_samples.py (4 tests) PASSED
tests/unit/test_backup_restore_and_cli_remediation.py (6 tests) PASSED
tests/unit/test_clock_skew.py (9 tests) PASSED
tests/unit/test_clock_skew_remediation.py (5 tests) PASSED
tests/unit/test_correlation_remediation.py (3 tests) PASSED
tests/unit/test_database_and_diagnostics_aggregation_remediation.py (7 tests) PASSED
tests/unit/test_decoding_and_raw_text.py (5 tests) PASSED
tests/unit/test_devsecops_remediation.py (7 tests) PASSED
tests/unit/test_diagnostics.py (2 tests) PASSED
tests/unit/test_exports.py (4 tests) PASSED
tests/unit/test_filename_sanitization_and_determinism_remediation.py (5 tests) PASSED
tests/unit/test_hashing_and_manifest.py (8 tests) PASSED
tests/unit/test_heuristics_remediation.py (6 tests) PASSED
tests/unit/test_manifest_verification_remediation.py (6 tests) PASSED
tests/unit/test_new_parsers_and_features.py (54 tests) PASSED
tests/unit/test_normalization.py (9 tests) PASSED
tests/unit/test_normalization_remediation.py (8 tests) PASSED
tests/unit/test_packaging_and_config.py (7 tests) PASSED
tests/unit/test_parsers.py (9 tests) PASSED
tests/unit/test_passphrase_gate_and_security_remediation.py (5 tests) PASSED
tests/unit/test_performance_heuristics_remediation.py (5 tests) PASSED
tests/unit/test_readme_and_synthetic_jitter_remediation.py (6 tests) PASSED
tests/unit/test_report_injection_remediation.py (4 tests) PASSED
tests/unit/test_search_and_filter.py (5 tests) PASSED
tests/unit/test_search_cql_remediation.py (9 tests) PASSED
tests/unit/test_security_and_escaping.py (22 tests) PASSED
tests/unit/test_syslog_real_samples.py (7 tests) PASSED
tests/unit/test_tamper_lab_remediation.py (3 tests) PASSED
tests/unit/test_web_and_firewall_parsers.py (10 tests) PASSED

============================= 266 passed =============================
```


---

## 7. Generating & Benchmarking Synthetic Scenarios

Chronica provides three reproducible synthetic scenarios:
- **Scenario 1 (Clean Baseline):** Nginx web log, Linux auth.log, and JSONL app log with pristine timestamps.
- **Scenario 2 (Clock Skew & TZ Mismatch):** Host B has a known $+180.0\text{s}$ clock skew and EDT ($-04:00$) timezone; correlated anchors restore true physical sequence.
- **Scenario 3 (Degraded Evidence):** Malformed JSON, corrupted timestamp, missing user/IP fields, 45-minute coverage gap, duplicate candidate, and inconclusive skew.

### Generate / Reset Scenarios via CLI:
```bash
python scripts/generate_scenarios.py
```

### Run Quantitative Benchmark Suite:
```bash
python scripts/run_evaluation.py
```

### Benchmark Results Overview:
- **Scenario 2 Offset Error:** **0.00s** ($+180.00\text{s}$ ground truth vs $+180.00\text{s}$ estimated).
- **Post-Correction Timing Residual:** **0.00s** (exact synchronization recovery).
- **Kendall's Tau Concordance:** $0.926 - 0.989$.
- **Scenario 3 Robustness:** $100\%$ graceful handling of malformed records; 18 distinct diagnostic findings identified.

---

## 8. Forensic Disclaimers & Legal Notice

1. **Research Prototype:** Chronica is designed for small IT teams, defenders, and educational research. Findings must be corroborated before formal judicial submission.
2. **Hash Guarantee:** A matching SHA-256 hash certifies that the file has not been modified since collection. It does not certify that logs were genuine when originally created.
3. **Quiet Periods:** Logging quiet intervals represent lack of records, not proof of malicious log clearing.
