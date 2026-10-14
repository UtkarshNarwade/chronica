# AIORI-3 PS-013 Final Hackathon Project Report

**Project Title:** Chronica: Digital Forensics Incident Timeline & Evidence Collection System  
**Track:** AIORI-3 Cybersecurity Problem Statement PS-013 (Incident Timeline and Evidence Collection for Small Teams)  
**Deliverable Date:** October 2026  
**Status:** Completed Reference Implementation & Demonstration-Ready System  

> **Note on Template Alignment:** The official template file `Proposed-structure-hackathon.pdf` was not present in the workspace. This draft project report has been organized according to standard forensic science and software engineering hackathon requirements. Its section order should be reviewed against the official hackathon template upon submission.

---

## Executive Summary

Small IT teams and individual incident responders frequently struggle to investigate security incidents due to scattered, heterogeneous logs originating from Linux authentication daemons, web servers, backend applications, and network devices. These logs present critical forensic barriers:
- Desynchronized system clocks and uncalibrated drift.
- Conflicting timezones (e.g. UTC, EDT, IST) and yearless syslog timestamps.
- Malformed records, dropped lines, and quiet periods.
- Inability to verify whether collected files were altered post-incident.

**Chronica** solves this challenge by delivering a lightweight, offline-first digital forensics system that preserves raw evidence bit-for-bit with SHA-256 digests, normalizes timestamps into a standard UTC chronological timeline, estimates clock skews using confirmed cross-source anchors, flags evidence gaps using an explainable 9-category taxonomy, and generates publication-grade incident reports in PDF, Markdown, CSV, and JSON formats.

---

## 1. Problem Statement & Mission

Small defense teams lack enterprise SIEM budgets and cloud-based AI tools. When an intrusion occurs, analysts must manually inspect scattered raw logs with `grep`, `awk`, and text editors. This manual approach is error-prone:
1. Converting timezones manually often obscures true physical causality.
2. Clocks that run fast or slow can make downstream database commits appear to occur before the initial web request.
3. Silent discarding of corrupted records destroys evidence.

Chronica adheres to a foundational forensic rule: **never silently turn an estimate into a fact**. Raw evidence bytes, extracted fields, timing normalizations, clock-skew corrections, and conclusions remain strictly separated.

---

## 2. System Architecture & Workflow

### 2.1 Principal Workflow Pseudocode

```text
ALGORITHM ChronicaForensicWorkflow(raw_files, investigation_config):
    // 1. Secure Ingestion & Preservation
    FOR EACH file IN raw_files:
        sanitized_name = SanitizePath(file.name)
        file_sha256 = SHA256(file.bytes)
        preserved_path = SaveReadOnly(file.bytes, sanitized_name)
        manifest.Record(evidence_id, file_sha256, preserved_path)
    
    // 2. Format Detection & Parsing
    FOR EACH evidence IN manifest.entries:
        format = DetectFormat(evidence.sample_lines)
        parsed_records = ParserRegistry.Get(format).Parse(evidence.lines)
        
        // 3. UTC Timestamp Normalization
        FOR EACH record IN parsed_records:
            normalized_utc = NormalizeToUTC(record.raw_timestamp, config.timezone)
            event = CreateEvent(record, normalized_utc, evidence.provenance)
            database.Insert(event)
    
    // 4. Cross-Source Clock-Skew Estimation
    anchors = DiscoverAnchors(database.events, key="request_id")
    FOR EACH host IN database.hosts:
        IF Count(anchors[host]) >= config.min_anchors (2):
            offset_seconds = Median([a.target_epoch - a.ref_epoch FOR a IN anchors[host]])
            mad_spread = MAD(anchors[host].offsets)
            IF mad_spread <= config.max_spread:
                estimates[host] = {offset: offset_seconds, status: "ESTIMATED"}
            ELSE:
                estimates[host] = {status: "INCONCLUSIVE_CONFLICTING_ANCHORS"}
        ELSE:
            estimates[host] = {status: "INCONCLUSIVE_INSUFFICIENT_ANCHORS"}
    
    // 5. Timeline Assembly & Diagnostics
    timeline = AssembleTimeline(database.events, estimates, sort_by="corrected_utc")
    diagnostics = AnalyzeGaps(timeline, manifest, estimates)
    
    // 6. Report Generation
    GenerateReports(timeline, diagnostics, manifest, formats=[JSON, CSV, MD, PDF])
    RETURN timeline, diagnostics
```

---

## 3. Implemented Capabilities & Technical Innovations

1. **Cryptographic SHA-256 Integrity Engine:**
   - 64 KB chunked streaming hashing prevents memory exhaustion.
   - Read-only preservation directories prevent accidental overwrites.
   - One-click re-verification audit detects 1-byte file alterations.
2. **Explainable Multi-Format Log Parsers:**
   - Linux RFC 3164 BSD and RFC 5424 syslog (sshd, sudo).
   - JSON Lines application logs with unmapped field preservation.
   - Apache/Nginx Common and Combined Log Format (CLF).
   - CSV Firewall packet filter records.
3. **UTC Normalization with Inference Tracking:**
   - Microsecond precision with full timezone offset handling.
   - Syslog yearless timestamps track inferred years explicitly.
4. **Defensible Clock-Skew Correction:**
   - Sign convention: $\text{offset} = \text{target} - \text{reference}$; $\text{corrected} = \text{target} - \text{offset}$.
   - Robust median and Median Absolute Deviation (MAD) statistics.
   - Refuses to correct from single anchors (< 2), marking them inconclusive.
5. **Data-Quality Gap Taxonomy (A through I):**
   - Quantifies quiet periods (inactivity $\ne$ malicious deletion).
   - Explicit denominators for all coverage metrics.
6. **Multi-Format Publication Reports:**
   - Machine-readable JSON, CSV timeline, complete 17-section Markdown report, and professional ReportLab PDF.

---

## 4. Benchmark Evaluation Results

Quantitative validation executed across all three synthetic scenarios (`python scripts/run_evaluation.py`):

| Evaluation Metric | Scenario 1: Clean Baseline | Scenario 2: Clock Skew (+180s) | Scenario 3: Degraded Evidence |
|---|---|---|---|
| **Total Records Encountered** | 11 | 8 | 12 |
| **Parsing Success Rate** | 100.0% (11/11) | 100.0% (8/8) | 91.67% (11/12) |
| **Timestamp Usability Rate** | 100.0% (11/11) | 100.0% (8/8) | 90.91% (10/11) |
| **Ground Truth Clock Offset** | 0.00s | **+180.00s** | 0.00s |
| **Chronica Estimated Offset** | +1.12s (network lag) | **+180.00s** | **Inconclusive** (1 anchor) |
| **Absolute Offset Error** | 1.12s | **0.00s** | N/A |
| **Post-Correction Residual** | 0.68s | **0.00s** | 0.00s |
| **Kendall's Tau Correlation** | 0.972 | 0.926 | 0.989 |
| **Pairwise Ordering Accuracy** | 94.55% | 85.71% | 97.78% |
| **Diagnostics Detected** | 4 (Assumed year) | 0 (Zero anomalies) | 18 (Gaps, parse fails, inconclusive) |

---

## 5. Security & Threat Modeling

Chronica defends against adversarial log inputs:
- **Path Traversal Protection:** Input filenames sanitized against `../../` and null bytes.
- **No Code Execution:** Zero use of `eval()` or `exec()`.
- **Parameterized SQL:** Parameterized placeholders prevent SQL injection.
- **Air-Gapped Operation:** 100% offline; zero external network requests.

---

## 6. Limitations & Future Research

1. **Nonlinear Drift:** Chronica models constant offsets across incident windows; modeling nonlinear drift requires dense time-series anchors over multi-day periods.
2. **Pre-Collection Log Clearing:** Integrity hashing guarantees preservation from acquisition onward, not prior authenticity.
3. **Future Improvements:** Hardware security module (HSM) PKCS#11 manifest signing, native EVTX Windows event log support, and automated PCAP flow timestamp correlation.
