# Chronica Forensic Limitations & Boundary Disclaimers

**Documented Boundaries for AIORI-3 PS-013**

---

## 1. What Chronica Guarantees vs What It Does Not

| Capability | What Chronica Guarantees | What Chronica CANNOT Guarantee |
|---|---|---|
| **Cryptographic Hashing** | SHA-256 digest accurately reflects the exact bytes acquired at ingestion time. | Does NOT prove logs were authentic when written or that an attacker did not tamper with files prior to collection. |
| **Timestamp Normalization** | Timestamps with timezone offsets are mathematically converted to UTC. Naive or yearless timestamps explicitly record inference flags. | Does NOT resolve unrecorded local timezones if investigator provides an incorrect assumption. |
| **Clock-Skew Offset Correction** | Estimates constant time offsets using the median of confirmed shared anchors (e.g. shared request/session IDs). | Does NOT account for nonlinear clock drift or transient virtualization hypervisor pause spikes unless sufficient anchor time-series exist. |
| **Coverage Gap Analysis** | Quantifies quiet intervals exceeding a configurable threshold (e.g. > 30 minutes). | Does NOT prove malicious log clearing or tampering; silence can result from maintenance, network filtering, or rotation. |
| **Evidence Preservation** | Stored evidence files are set to read-only where the host OS supports it, and re-verification detects single-bit alterations. | Read-only attributes alone do not prevent modification by a privileged root/admin user on the forensic workstation. |

---

## 2. Implemented Features vs Intentionally Excluded Features

### Implemented Features
- Real cryptographic SHA-256 hashing before parsing.
- Byte-for-byte evidence preservation in dedicated evidence stores.
- Automated re-verification with tamper detection.
- Four distinct log parsers: Linux syslog/auth.log, JSON Lines, Apache/Nginx web access, CSV firewall.
- Explainable format autodetection heuristic with confidence scores.
- Robust UTC normalization with microsecond precision.
- Inferred year tracking for yearless BSD syslog logs.
- Robust median-based clock-skew estimation with MAD spread calculation.
- Inconclusive marking for insufficient (< 2) or conflicting anchors.
- Chronological timeline sorting by Normalized UTC, Corrected UTC, or Original sequence.
- Multi-attribute conjunctive search and filtering.
- 9-category evidence gap taxonomy (A through I) with explicit denominators.
- Case management with isolated case storage and SQLite persistence.
- Complete multi-format export (JSON, CSV, 17-section Markdown, ReportLab PDF).
- 3 synthetic test scenarios with ground-truth answer keys stored separately.
- Automated benchmark suite measuring parsing coverage, offset estimation errors, and Kendall's tau.
- 46 automated unit, integration, and end-to-end tests passing in 0.57s.

### Intentionally Excluded Features
- **External AI / LLM APIs:** Excluded to ensure 100% offline air-gapped operation and prevent data leakage of confidential logs.
- **Live Endpoint Agent Collection:** Excluded because PS-013 specifies forensic timeline analysis of collected files, not endpoint detection and response (EDR).
- **Automated Root Cause / Threat Attribution:** Excluded because attributing an attack to a specific actor or determining malicious intent from raw logs alone is forensically unsound and prone to hallucination.
- **Unverified Linear Drift Extrapolation:** Linear drift requires dense observations over days; extrapolating drift from few points introduces false precision. Chronica honestly labels insufficient observations as inconclusive.
