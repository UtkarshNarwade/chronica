# Chronica 5-Minute Mentor Demonstration Script

**AIORI-3 PS-013: Incident Timeline and Evidence Collection for Small Teams**

---

## Demonstration Sequence Overview

| Time | Segment | What to Show in the UI | Key Talking Points |
|---|---|---|---|
| **0:00 - 0:45** | **The Problem & Case Overview** | Dashboard & Case Management | Small IT teams face logs with drifting clocks, missing years, and separate timezones. Chronica unifies them without altering original evidence. |
| **0:45 - 1:30** | **Evidence Integrity & Tamper Detection** | Evidence Integrity (SHA-256) | Show pre-ingestion SHA-256 manifest. Click **Simulate 1-Byte Tampering** and run **Verify All Evidence** to show immediate `MISMATCH` detection. |
| **1:30 - 2:45** | **Scenario 2: Clock Skew Correction** | Load Scenario 2 & Clock-Skew Analysis | Show that Host B clock is +180s fast and uses EDT (-0400). Show discovered anchor pairs (`req-tx-201..204`). Show median offset estimation of exactly +180.0s. |
| **2:45 - 3:45** | **Timeline Explorer & Provenance** | Timeline Explorer | Toggle between **Normalized UTC** and **Clock-Corrected UTC**. Open the **Event Detail Inspector** to show exact source file and line number provenance. |
| **3:45 - 4:30** | **Scenario 3: Degraded Evidence & Gaps** | Load Scenario 3 & Gaps & Diagnostics | Show that malformed lines are not discarded. Show Category A, C, F (45-min quiet period), and G (inconclusive skew from 1 anchor). |
| **4:30 - 5:00** | **Forensic Reports Export** | Reports & Export | Download the generated **PDF Report** and **Markdown Report** with all 17 required forensic sections. |

---

## Detailed Step-by-Step Script

### Segment 1: Ingestion & Integrity
1. Open Chronica at `http://localhost:8501`.
2. Point out the **Dashboard** metric cards: Evidence Files, Total Events, Integrity Status, Parsing Success Rate, and Diagnostics.
3. Open **Evidence Integrity (SHA-256)**:
   - *"Before parsing begins, Chronica calculates SHA-256 digests and locks the files in read-only preservation storage."*
4. Click **Simulate 1-Byte File Tampering**:
   - Re-click **Verify All Evidence Now**.
   - Show the bright red `❌ MISMATCH` badge and the corresponding Category H diagnostic finding.

### Segment 2: Clock Skew & Timezones (Scenario 2)
1. Navigate to **🧪 Synthetic Scenarios & Benchmark**.
2. Click **Load Scenario 2**.
3. Open **⏳ Clock-Skew Analysis**:
   - *"Host `db-backend-02` was recording in Eastern Daylight Time (-04:00) with a clock running 3 minutes (+180s) fast."*
   - Show the **Host Clock Offset Estimates** table: Chronica calculated the median of 4 shared request IDs (`req-tx-201..204`) and found the exact +180.00s offset with 0.0s spread.
4. Open **⏱️ Timeline Explorer**:
   - Under **Normalized UTC**, show that the DB query appears at 10:03:00, which looks like it took 3 minutes to run after the gateway request.
   - Switch to **Clock-Corrected UTC**: The DB query aligns to 10:00:00, restoring true causal physical sequence!
   - Highlight the event inspector drawer: pristine raw text and original timestamp are preserved intact.

### Segment 3: Honesty with Degraded Evidence (Scenario 3)
1. Navigate to **🧪 Synthetic Scenarios & Benchmark** and click **Load Scenario 3**.
2. Open **⚠️ Gaps & Diagnostics**:
   - Point out that Chronica **did not crash or drop records**.
   - Point out **Category F (Coverage Gap)**: A 45-minute silence between 11:15 and 12:00. Note: *"Chronica explicitly documents that quiet periods do not prove malicious log clearing."*
   - Point out **Category G**: Host `host-sensor-99` only had 1 anchor. Chronica refused to make an unscientific guess and marked it `INCONCLUSIVE_INSUFFICIENT_ANCHORS`.

### Segment 4: 1-Click Multi-Format Reporting
1. Navigate to **📑 Reports & Export**.
2. Click **📥 Download Report (PDF)**:
   - Open the generated PDF: professional ReportLab layout with tables, summary metrics, and forensic limitation disclaimers.
3. Click **📥 Download Report (Markdown)**:
   - Show the 17 numbered sections ready for case filing.
