# Chronica Enterprise Investigator User Guide

**Triage, Investigation & Digital Forensics Manual for Chronica DFIR**

---

## 1. Getting Started & Launching Chronica

### Prerequisites
- Python 3.11+ (Python 3.14 compatible)
- Operating System: Windows, Linux, or macOS

### Launching the Web UI
Open a terminal in the project root directory and run:

```bash
streamlit run app.py
```

The web dashboard will launch at `http://localhost:8501`.

### Headless CLI Execution
For automated pipelines, air-gapped forensic scripts, and headless servers:

```bash
python scripts/chronica_cli.py --case-id case_2026_leak --title "Incident Triage" --ingest /path/to/logs/ --output-dir ./output/
```

---

## 2. Platform Architecture & Navigation Rail

Chronica is structured around 11 enterprise modules organized into three functional groups:

### Group 1: Operations & Hunting
1. **Security Overview**: Executive KPI grid, 7-Stage MITRE ATT&CK Matrix strip, and behavioral threat lead cards.
2. **Event Discovery & Timeline**: Tri-state UTC sorting, field facet filters, paginated event stream, and deep document inspector.
3. **Threat Hunting & Topology**: CQL search expressions, IP/CIDR filtering, concentric 4-ring radial entity link graph, and cross-source correlation clusters.
4. **Payload & IOC Analyzer**: Forensic transformation engine (Shannon entropy, Base64/Hex/URL decoding, Defang/Refang, IOC extraction).

### Group 2: Forensic Engines
5. **Log Acquisition & Parsers**: Multi-file log, directory, and archive bundle ingestion (`.zip`, `.tar.gz`, `.tgz`), format autodetection, live regex extraction preview, and 7 native parsers.
6. **Evidence Integrity & Ledger**: Cryptographic SHA-256 baseline verification, append-only hash-chained audit ledger, and controlled tamper simulation lab.
7. **Clock-Skew Synchronization**: Transitive 2-hop clock offset estimation ($A \leftrightarrow B \leftrightarrow C$), MAD spread calculation, latency guardrails, timing delta waterfall chart, and manual anchor linker.
8. **Diagnostics & Gap Taxonomy**: 9-category evidence gap taxonomy (A through I) with explicit denominators and coverage metrics.

### Group 3: Reporting & System
9. **Forensic Reports & Export**: Multi-format exports including publication-grade PDF, 18-section Markdown, CSV timeline spreadsheet, and structured JSON case backups.
10. **Synthetic Benchmark Suite**: Automated quantitative evaluation across 3 standardized benchmark scenarios (Clean Baseline, Clock Skew, Degraded Evidence).
11. **Workspace & System Specs**: Case workspace switcher, system environment specifications, and configuration parameters.

---

## 3. Supported Log Formats & Parsers

Chronica features 7 native, explainable log parsers:
1. **RFC 3164 / 5424 Syslog**: Linux `/var/log/syslog`, `/var/log/messages`, `/var/log/auth.log` with automatic Dec->Jan BSD year rollover tracking.
2. **JSON Lines (Structured)**: CloudWatch, Suricata EVE, audit JSON streams with automatic field normalization.
3. **Web Access Logs**: Apache / Nginx combined and common access logs with response code and byte-size tracking.
4. **CSV Firewall Logs**: Multi-vendor CSV firewall streams with header row detection and port/action parsing.
5. **Linux auditd Event Logs**: `/var/log/audit/audit.log` syscall and execution records with hex proctitle decoding.
6. **Windows Security Event Logs**: Event IDs 4624 (Logon), 4625 (Failed Logon), 1102 (Log Cleared), 4616 (Time Change).
7. **Custom Named Regex**: Investigator-defined regular expressions with named capture groups (`(?P<timestamp>...)`, `(?P<host>...)`, `(?P<user>...)`, `(?P<message>...)`).

---

## 4. Typical Investigation Workflow

### Step 1: Create or Select an Investigation Workspace
1. In the left navigation rail, use the **Active Case Workspace** selector or switch cases in **Workspace & System Specs**.
2. Select your baseline timezone for naive timestamps (e.g., `UTC` or `America/New_York`).

### Step 2: Ingest & Preserve Evidence Artifacts
1. Navigate to **Log Acquisition & Parsers**.
2. Drag and drop log files, `.gz` compressed logs, or `.zip` / `.tar.gz` bundles.
3. Choose **Auto-Detect Format** or assign a specific parser mode.
4. Click **Ingest, Hash & Parse Evidence**. Chronica hashes the raw bytes, preserves the artifact, and logs the action to the audit chain.

### Step 3: Cryptographic Evidence Integrity & Audit Chain
1. Navigate to **Evidence Integrity & Ledger**.
2. Verify SHA-256 baselines across all preserved evidence.
3. Verify the cryptographic hash chain of `audit_chain.jsonl`.
4. Test tamper detection using the **Controlled 1-Byte Tamper Simulation Lab**.

### Step 4: Cross-Host Clock-Skew Synchronization
1. Navigate to **Clock-Skew Synchronization**.
2. Chronica analyzes shared anchors (request IDs, session IDs, manual links) and computes direct and transitive 2-hop clock offsets with MAD spreads.
3. Review the **Transaction Latency Waterfall** chart and host offset estimates.

### Step 5: Timeline Analysis & Threat Hunting
1. In **Event Discovery & Timeline**, sort by **Clock-Corrected UTC** to review the true physical sequence of events.
2. In **Threat Hunting & Topology**, use Chronica Query Language (CQL):
   - `host:web-01,web-02 user:admin severity:CRITICAL,ERROR after:2026-10-12T10:00:00Z NOT cron`
3. Inspect the entity link graph to discover lateral movement and cross-host attacker paths.

### Step 6: Generate Multi-Format Incident Reports
1. Navigate to **Forensic Reports & Export**.
2. Download the verified PDF, 18-Section Markdown, CSV Timeline, or JSON Case Backup.
