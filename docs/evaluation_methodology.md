# Chronica Evaluation Methodology & Benchmark Results

**Measurement Protocols and Quantitative Verification for AIORI-3 PS-013**

---

## 1. Evaluation Principles

To maintain scientific integrity:
1. **Answer Keys Stored Separately:** Synthetic ground-truth files are stored in `synthetic_data/scenario_definitions/` and are never accessed by Chronica during normal parsing or analysis.
2. **Explicit Denominators:** All percentage metrics explicitly state their base denominator (e.g., % of total encountered records vs % of successfully parsed records).
3. **No Fabricated Benchmarks:** Triage time savings are represented as a repeatable protocol rather than invented numbers.

---

## 2. Quantitative Measurement Formulas

### A. Parsing Coverage Metrics
- **Parsing Success Rate:**
  $$\text{Success Rate} = \frac{\text{Successfully Parsed Records}}{\text{Total Records Encountered}} \times 100$$
- **Timestamp Usability Rate:**
  $$\text{Usability Rate} = \frac{\text{Records with Usable Timestamps}}{\text{Successfully Parsed Records}} \times 100$$
- **Assumption Rate:**
  $$\text{Assumption Rate} = \frac{\text{Timestamps Requiring Assumptions}}{\text{Records with Usable Timestamps}} \times 100$$

### B. Clock-Skew Offset Estimation Error
- **Absolute Estimation Error:**
  $$E_{\text{skew}} = |\text{Estimated Offset} - \text{Ground Truth Offset}| \quad (\text{seconds})$$
- **Timing Residual Error (Pre-Correction vs Post-Correction):**
  $$\text{Residual} = \frac{1}{N} \sum_{i=1}^N |t_{\text{reconstructed}, i} - t_{\text{true}, i}|$$

### C. Event Ordering Metrics
- **Pairwise Ordering Accuracy:**
  For all pairs $(e_i, e_j)$ where $t_{\text{true}, i} < t_{\text{true}, j}$:
  $$\text{Accuracy} = \frac{\text{Concordant Pairs}}{\text{Total Comparable Pairs}} \times 100$$
- **Kendall's Tau Rank Correlation:**
  $$\tau = \frac{C - D}{\sqrt{(C + D + T_x)(C + D + T_y)}}$$
  Where $C$ is concordant pairs, $D$ is discordant (inverted) pairs, and $T$ accounts for ties.

---

## 3. Measured Benchmark Results Across Synthetic Scenarios

The benchmark was executed using `python scripts/run_evaluation.py`. Results reflect actual measured performance:

### Scenario 1: Clean Baseline
- **Total Records:** 11
- **Parsing Success Rate:** 100.0% (11/11)
- **Usable Timestamps:** 100.0% (11/11)
- **Clock Skew Error:** 1.12s (due to sub-second logging delay)
- **Pairwise Ordering Accuracy:** 94.55%
- **Kendall's Tau:** 0.972
- **Diagnostic Findings:** 4 (all Category D: BSD syslog year inferred as 2026)

### Scenario 2: Clock Skew (+180.0s) & Time-Zone Mismatch
- **Total Records:** 8
- **Parsing Success Rate:** 100.0% (8/8)
- **Known Ground Truth Offset:** +180.00s
- **Chronica Estimated Offset:** +180.00s
- **Absolute Offset Error:** **0.00s** (Exact convergence via median anchor estimation)
- **Pre-Correction Mean Residual:** 180.00s
- **Post-Correction Mean Residual:** **0.00s** (Complete timing recovery)
- **Pairwise Ordering Accuracy:** 85.71% (Ties on identical transactions)
- **Kendall's Tau:** 0.926

### Scenario 3: Degraded Evidence
- **Total Records:** 12
- **Parsing Success Rate:** 91.67% (11/12 parsed; 1 malformed JSON record isolated)
- **Failed Records:** 8.33% (1/12)
- **Usable Timestamps:** 90.91% (10/11 parsed)
- **Host `host-sensor-99` Skew Status:** `INCONCLUSIVE_INSUFFICIENT_ANCHORS` (Correctly refused to correct from 1 anchor)
- **Diagnostic Findings Generated:** 18 total:
  - 1 Parse failure (Category A)
  - 2 Timestamp failures (Category C)
  - 7 Timestamp ambiguities (Category D)
  - 2 Missing-field warnings (Category E)
  - 2 Coverage gaps (Category F: 45-min quiet period)
  - 3 Unresolved clock skews (Category G)
  - 1 Duplicate candidate (Category I)

---

## 4. Human-in-the-Loop Triage Evaluation Protocol

### Protocol Boundaries
- **Start Definition:** Investigator opens raw log files or initiates case creation in Chronica.
- **End Definition:** Investigator writes answers to all 5 checklist objectives and exports the triage report.

### Task Objectives Checklist
1. **Task 1:** Identify initial unauthorized web endpoint access (client IP, URI, HTTP status, request ID).
2. **Task 2:** Identify correlating SSH authentication attempt (username, source IP, auth method).
3. **Task 3:** Correlate backend database query execution via shared request ID.
4. **Task 4:** Determine true physical sequence between SSH login and DB transaction by accounting for clock offset.
5. **Task 5:** Verify evidence integrity of all collected logs.

### Measurement Template

```markdown
| Trial Arm | Investigator ID | Start Time | End Time | Duration (s) | Accurate Findings (/5) |
|---|---|---|---|---|---|
| Manual (grep/awk/editor) | [PENDING_TRIAL] | --:--:-- | --:--:-- | [UNMEASURED] | [ /5] |
| Tool-Assisted (Chronica) | [PENDING_TRIAL] | --:--:-- | --:--:-- | [UNMEASURED] | [ /5] |
```

> **Forensic Integrity Notice:** In accordance with Section 6.E of the engineering guidelines, duration fields remain unpopulated until actual empirical trials with human subjects are conducted under observation.
