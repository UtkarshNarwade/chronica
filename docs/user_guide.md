# Chronica Investigator User Guide

**Step-by-Step Triage & Investigation Manual for AIORI-3 PS-013**

---

## 1. Getting Started & Launching Chronica

### Prerequisites
- Python 3.11+ (Python 3.14 compatible)
- Operating System: Windows, Linux, or macOS

### Launching the Application
Open a terminal in the project root directory and run:

```bash
streamlit run app.py
```

The web dashboard will launch at `http://localhost:8501`.

---

## 2. Typical Investigation Workflow

### Step 1: Create or Select an Investigation
1. Navigate to **📂 Case Management** in the sidebar.
2. Enter a unique **Case ID** (e.g., `case_2026_finance_leak`) and **Investigation Title**.
3. Select the default **Baseline Timezone** for naive logs (e.g., `UTC` or `America/New_York`).
4. Click **Create Case Workspace**.

### Step 2: Ingest & Preserve Evidence Files
1. Navigate to **📁 Evidence Ingestion**.
2. Drag and drop or browse to select your log files (multi-file upload is supported).
3. Select your parser mode:
   - **Auto-Detect Format**: Evaluates sample lines against regex signatures and reports an explainable confidence score.
   - **Explicit Format**: Manually assign `Syslog`, `JSONL`, `Web Access`, or `CSV Firewall`.
4. Click **🚀 Ingest, Hash & Parse Evidence**.
5. Chronica calculates the SHA-256 digest *before* parsing, saves a read-only copy in the case evidence directory, and updates the manifest.

### Step 3: Verify Cryptographic Evidence Integrity
1. Navigate to **🔒 Evidence Integrity (SHA-256)**.
2. Review the recorded SHA-256 digests.
3. Click **🔄 Verify All Evidence Now** to re-hash on-disk files.
4. Green badges (`VERIFIED`) confirm zero post-collection alteration. If a file was modified or deleted, Chronica displays a red `MISMATCH` or `UNAVAILABLE` badge.

### Step 4: Explore the Chronological Timeline
1. Navigate to **⏱️ Timeline Explorer**.
2. Select your sorting axis:
   - **Normalized UTC**: Chronological order based on UTC-converted timestamps.
   - **Clock-Corrected UTC**: Chronological order adjusted for measured host clock offsets.
   - **Original Line Sequence**: Preserves file-by-file raw capture order.
3. Use the **Event Detail Inspector** to inspect raw lines, parsed fields, inferred years, and provenance.

### Step 5: Perform Multi-Faceted Search & Filtering
1. Navigate to **🔍 Search & Filter**.
2. Enter keyword search terms (e.g. `POST /api`, `root`, `denied`).
3. Apply combinatorial filters by Host, User, IP, Severity, and Category.
4. Check **Show only records with data-quality warnings** to isolate anomalous logs.

### Step 6: Inspect Clock-Skew Offsets & Anchor Pairs
1. Navigate to **⏳ Clock-Skew Analysis**.
2. Review the **Host Clock Offset Estimates** table.
3. Check the anchor count, median offset, and MAD spread.
4. If anchor evidence is insufficient (< 2 anchors), Chronica marks the host `INCONCLUSIVE_INSUFFICIENT_ANCHORS` rather than guessing an unscientific correction.

### Step 7: Review Data-Quality Gaps & Diagnostics
1. Navigate to **⚠️ Gaps & Diagnostics**.
2. Review parsing coverage metrics (with explicit denominators).
3. Inspect active findings across taxonomy categories A through I:
   - Category A: Parse failure
   - Category C: Timestamp failure
   - Category D: Timestamp ambiguity (assumed timezone/year)
   - Category F: Quiet period coverage gaps
   - Category G: Unresolved clock skew
   - Category H: Integrity violation alerts

### Step 8: Export Complete Incident Reports
1. Navigate to **📑 Reports & Export**.
2. Choose from 4 functional download formats:
   - **PDF Report**: Publication-grade PDF with tables, metrics, and disclaimers.
   - **Markdown Report**: Comprehensive 17-section incident report conforming to hackathon requirements.
   - **CSV Timeline**: Standard forensic spreadsheet for external analysis.
   - **JSON Case**: Machine-readable case backup containing metadata, manifest, and events.
