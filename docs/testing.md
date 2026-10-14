# Chronica Automated Testing Strategy & Test Execution Guide

**Quality Assurance & Verification Suite for AIORI-3 PS-013**

---

## 1. Test Architecture Overview

Chronica includes a 3-tier automated test suite built with `pytest`:
- **Unit Tests (`tests/unit/`)**: Verify discrete algorithmic components (cryptographic hashing, parsing, timestamp normalization, median clock skew, search filtering, report export).
- **Integration Tests (`tests/integration/`)**: Test filesystem and database lifecycle, case isolation, and tamper detection alerts.
- **End-to-End Tests (`tests/end_to_end/`)**: Execute complete ingest-to-report workflows on the three reproducible synthetic scenarios.

---

## 2. Test Execution Commands

To execute the entire test suite:

```bash
python -m pytest -v
```

To run a specific test category:

```bash
# Unit tests
python -m pytest tests/unit -v

# Integration tests
python -m pytest tests/integration -v

# End-to-end scenario tests
python -m pytest tests/end_to_end -v
```

---

## 3. Test Coverage Matrix

| Test Module | Test Name | Purpose / Verified Behavior |
|---|---|---|
| `test_hashing_and_manifest.py` | `test_sha256_known_bytes` | Cryptographic SHA-256 matches NIST standard test vectors. |
| `test_hashing_and_manifest.py` | `test_sha256_file_matches_bytes` | File stream hashing matches in-memory hashing byte-for-byte. |
| `test_hashing_and_manifest.py` | `test_sha256_changes_on_single_bit_flip` | Single byte change generates completely distinct SHA-256 digest (avalanche effect). |
| `test_hashing_and_manifest.py` | `test_evidence_collector_preserves_pristine_copy` | Byte-for-byte untouched evidence file written to disk. |
| `test_hashing_and_manifest.py` | `test_evidence_collector_sanitizes_unsafe_path` | Rejects directory traversal tokens (`../../etc/passwd`). |
| `test_hashing_and_manifest.py` | `test_evidence_collector_enforces_size_limit` | Enforces configured maximum file size limit. |
| `test_hashing_and_manifest.py` | `test_verification_detects_tampering` | Re-hashing detects 1-byte alteration as `MISMATCH`. |
| `test_hashing_and_manifest.py` | `test_verification_detects_missing_file` | Missing on-disk file flagged as `UNAVAILABLE`. |
| `test_parsers.py` | `test_syslog_rfc3164_ssh_login` | Extracts user, IP, port, PID, and yearless warning from auth.log. |
| `test_parsers.py` | `test_syslog_sudo_command` | Extracts sudo user, target user, and command executed. |
| `test_parsers.py` | `test_jsonl_parser_valid` | Maps JSON attributes to canonical fields and extra_fields. |
| `test_parsers.py` | `test_jsonl_parser_malformed_syntax` | Corrupted JSON line flagged `MALFORMED` without crashing parser. |
| `test_parsers.py` | `test_web_access_combined_format` | Parses Apache/Nginx combined format, status code, and request ID. |
| `test_parsers.py` | `test_csv_firewall_parser` | Ingests CSV firewall records and skips header rows cleanly. |
| `test_parsers.py` | `test_parser_registry_autodetection` | Explainable autodetection confirms format and score. |
| `test_normalization.py` | `test_different_offsets_same_instant_normalize_identically` | Same physical instant in UTC, EDT, and IST normalizes to identical UTC ISO string. |
| `test_normalization.py` | `test_syslog_yearless_timestamp` | Inferred year documented and marked `year_inferred=True`. |
| `test_clock_skew.py` | `test_robust_median_offset_estimation` | Accurately calculates median offset and MAD spread from anchors. |
| `test_clock_skew.py` | `test_insufficient_anchors_inconclusive` | Rejects correction when anchors < min_anchors (`INCONCLUSIVE`). |
| `test_clock_skew.py` | `test_conflicting_anchors_inconclusive` | Rejects correction when anchor spread exceeds threshold. |
| `test_clock_skew.py` | `test_clock_correction_application_preserves_originals` | Preserves original timestamp and normalized UTC while setting corrected time. |
| `test_search_and_filter.py` | `test_combined_filters` | Conjunctive filtering across text, user, and category. |
| `test_diagnostics.py` | `test_coverage_statistics_calculation` | Validates coverage rates with explicit denominators. |
| `test_diagnostics.py` | `test_diagnostic_taxonomy_detection` | Detects findings across categories A through I. |
| `test_exports.py` | `test_markdown_export_has_all_17_sections` | Confirms report contains all 17 required section headers. |
| `test_exports.py` | `test_pdf_export_generates_valid_pdf` | Confirms ReportLab generates valid `%PDF-` document. |
| `test_investigation_lifecycle.py` | `test_investigation_lifecycle_isolation` | Confirms complete isolation between separate cases. |
| `test_tamper_detection.py` | `test_tamper_detection_triggers_diagnostic_alert` | Tampering triggers Category H diagnostic finding. |
| `test_scenarios_e2e.py` | `test_scenario_1_e2e` | End-to-end ingestion and reporting on Scenario 1. |
| `test_scenarios_e2e.py` | `test_scenario_2_e2e_clock_skew` | End-to-end estimation of +180s offset on Scenario 2. |
| `test_scenarios_e2e.py` | `test_scenario_3_e2e_degraded_evidence` | End-to-end handling of corrupted/truncated Scenario 3. |

---

## 4. Test Results Summary

```text
============================= test session starts =============================
platform win32 -- Python 3.14.3, pytest-9.1.1, pluggy-1.6.0
collected 46 items

tests/end_to_end/test_scenarios_e2e.py ... [  6%]
tests/integration/test_investigation_lifecycle.py . [  8%]
tests/integration/test_tamper_detection.py . [ 10%]
tests/unit/test_clock_skew.py ...... [ 23%]
tests/unit/test_diagnostics.py .. [ 28%]
tests/unit/test_exports.py .... [ 36%]
tests/unit/test_hashing_and_manifest.py ........ [ 54%]
tests/unit/test_normalization.py ....... [ 69%]
tests/unit/test_parsers.py ........ [ 89%]
tests/unit/test_search_and_filter.py ..... [100%]

============================= 46 passed in 0.57s ==============================
```
