# PROGRESS LEDGER (the agent appends; never rewrites history)

## Iteration log
<!-- one block per iteration, copy this block -->
### Iteration 1 | Finding: T0-1 | Started: 2026-11-09T16:56:00+05:30
- Reproduction test: `pip install -e .[dev]`
- Failing output (real, pasted):
```text
ERROR: file:///C:/Users/UTKARSH/.gemini/antigravity/scratch/chronica does not appear to be a Python project: neither 'setup.py' nor 'pyproject.toml' found.
```
- Change summary (files, why):
  - Created `pyproject.toml` specifying build-system, project metadata, pinned dependencies, optional `[dev]` dependencies (pytest, ruff, mypy), and ruff/mypy configurations.
  - Updated `requirements.txt` to remove pytest from runtime dependencies.
  - Created `requirements-dev.txt` for development installs.
  - Added `tests/unit/test_packaging_and_config.py` asserting project structure, runtime vs dev dependency isolation, and importability.
- New test result (real, pasted):
```text
tests/unit/test_packaging_and_config.py::test_pyproject_toml_structure PASSED [ 33%]
tests/unit/test_packaging_and_config.py::test_requirements_txt_excludes_dev_dependencies PASSED [ 66%]
tests/unit/test_packaging_and_config.py::test_src_package_importability PASSED [100%]
============================== 3 passed in 0.08s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 130 passed in 6.34s =============================
```
- Commit: 25c840b fix(T0-1): add pyproject.toml, dev requirements, and ruff/mypy configs
- Status: DONE
- Notes and surprises:
  `pip install -e .[dev]` successfully built and installed editable chronica wheel. Mypy on Windows has an AppLocker/Application Control block for its C-extension DLL locally, but ruff runs cleanly and mypy config is established in pyproject.toml for CI.

### Iteration 2 | Finding: T0-2 | Started: 2026-11-09T17:10:00+05:30
- Reproduction test: `tests/unit/test_packaging_and_config.py::test_ci_workflow_specification`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_packaging_and_config.py::test_ci_workflow_specification
AssertionError: CI workflow file .github/workflows/ci.yml must exist
assert False
where False = exists()
```
- Change summary (files, why):
  - Created `.github/workflows/ci.yml` defining GitHub Actions CI workflow triggered on push/PR to main.
  - Configured test matrix for Python 3.11 and 3.12 with checkout, pip install, ruff linting, non-blocking mypy, and pytest execution.
  - Added tests in `test_packaging_and_config.py` verifying file existence, matrix targets, steps, and YAML syntax integrity.
- New test result (real, pasted):
```text
tests/unit/test_packaging_and_config.py::test_ci_workflow_specification PASSED [ 80%]
tests/unit/test_packaging_and_config.py::test_ci_workflow_yaml_syntax PASSED [100%]
============================== 5 passed in 0.09s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 132 passed in 7.52s =============================
```
- Commit: 95f99f8 fix(T0-2): add GitHub Actions CI workflow for Python 3.11 and 3.12
- Status: DONE
- Notes and surprises:
  GitHub Actions CI workflow created with matrix across Python 3.11 and 3.12, with continue-on-error for mypy in initial phase as specified in acceptance.

### Iteration 3 | Finding: T0-3 | Started: 2026-11-09T17:13:00+05:30
- Reproduction test: `tests/unit/test_packaging_and_config.py::test_dockerfile_and_streamlit_hardening`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_packaging_and_config.py::test_dockerfile_and_streamlit_hardening
AssertionError: Dockerfile must exist
assert False
where False = exists()
```
- Change summary (files, why):
  - Created `Dockerfile` configuring non-root user `chronica` (UID 1000), local entrypoint bound to `127.0.0.1`, health check, and disabling telemetry.
  - Updated `.streamlit/config.toml` enforcing `gatherUsageStats=false`, `server.address="127.0.0.1"`, `server.headless=true`, and `client.showErrorDetails=false`.
  - Added test assertions in `tests/unit/test_packaging_and_config.py` confirming non-root container user and all 4 Streamlit security settings.
- New test result (real, pasted):
```text
tests/unit/test_packaging_and_config.py::test_dockerfile_and_streamlit_hardening PASSED [100%]
============================== 6 passed in 0.08s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 133 passed in 7.80s =============================
```
- Commit: a01b1b6 fix(T0-3): add Dockerfile with non-root user and harden Streamlit air-gap config
- Status: DONE
- Notes and surprises:
  Streamlit configuration hardened to loopback-only binding (`127.0.0.1`), headless operation, error detail redaction, and total telemetry suppression.

### Iteration 4 | Finding: T0-4 | Started: 2026-11-09T17:15:30+05:30
- Reproduction test: `tests/unit/test_packaging_and_config.py::test_plotly_installed_and_functional`
- Failing output (real, pasted):
```text
(In auditor sandbox without plotly: ModuleNotFoundError: No module named 'plotly')
```
- Change summary (files, why):
  - Confirmed `plotly>=5.20.0` is present in `pyproject.toml` and `requirements.txt` (installed: `plotly 7.1.0`).
  - Added unit test `test_plotly_installed_and_functional` in `tests/unit/test_packaging_and_config.py` verifying `plotly.graph_objects` import and `EntityGraphBuilder` figure generation.
- New test result (real, pasted):
```text
tests/unit/test_packaging_and_config.py::test_plotly_installed_and_functional PASSED [100%]
============================== 1 passed in 0.14s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 134 passed in 7.21s =============================
```
- Commit: d4f3ac9 fix(T0-4): verify plotly installation and add integration test
- Status: DONE
- Notes and surprises:
  Confirmed all 134 tests in the suite pass cleanly with plotly installed and verified.

### Iteration 5 | Finding: F-01 | Started: 2026-11-09T21:05:00+05:30
- Reproduction test: `tests/unit/test_auditd_real_samples.py::test_auditd_real_user_auth_failed_inside_quoted_msg`
- Failing output (real, pasted):
```text
AssertionError: Expected severity 'AUTH_FAIL' on res=failed, got 'AUTH_SUCCESS'
assert 'AUTH_SUCCESS' == 'AUTH_FAIL'
- AUTH_FAIL
+ AUTH_SUCCESS
```
- Change summary (files, why):
  - `src/parsers/auditd_parser.py`: Added `_parse_auditd_kvs` handling single-quote-aware parsing of nested `msg='...'` blocks in auditd lines and stripping surrounding quotes from keys/values.
  - `src/parsers/auditd_parser.py`: Removed fallback of `username` to SELinux `subj` context (strictly assigning `username = kv.get("acct")`).
  - `src/parsers/auditd_parser.py`: Normalized `res` and `success` strings to lower/stripped format, accurately matching `res="failed"` or `res="0"` to `AUTH_FAIL`.
  - `tests/unit/test_new_parsers_and_features.py`: Updated fixture line 32 to realistic auditd syntax with `msg='...'` wrapper.
  - `tests/unit/test_auditd_real_samples.py`: Created golden-file tests with realistic `msg='...'` records, `res=failed`, `res=success`, numeric res codes, and assertions verifying `subj` is never used as username.
- New test result (real, pasted):
```text
tests/unit/test_auditd_real_samples.py::test_auditd_real_user_auth_failed_inside_quoted_msg PASSED [ 25%]
tests/unit/test_auditd_real_samples.py::test_auditd_subj_never_used_as_username PASSED [ 50%]
tests/unit/test_auditd_real_samples.py::test_auditd_real_user_auth_success PASSED [ 75%]
tests/unit/test_auditd_real_samples.py::test_auditd_numeric_res_codes PASSED [100%]
============================== 4 passed in 0.04s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 138 passed in 6.82s =============================
```
- Commit: d550766 fix(F-01): parse nested auditd msg block quotes and exclude subj from username
- Status: DONE
- Notes and surprises:
  Resolved inversion where trailing quote on `res=failed'` prevented matching `res == "failed"`, causing failed logins to be recorded as `AUTH_SUCCESS`. SELinux subject context `subj` is now strictly excluded from actor identity.

### Iteration 6 | Finding: F-02 | Started: 2026-11-09T21:13:30+05:30
- Reproduction test: `tests/unit/test_clock_skew.py::test_auditd_serial_collision_produces_zero_anchors`
- Failing output (real, pasted):
```text
AssertionError: Colliding auditd serial numbers should produce 0 anchors, got 1
assert 1 == 0
+  where 1 = len([AnchorPair(anchor_id='anc_req_audit-1001_0', target_event_id='evt_d94f69dd53b8', target_source='host_b', target_utc_iso='2026-10-12T10:20:00.000000Z', target_utc_epoch=1791800400.0, reference_event_id='evt_57d07c88e068', reference_source='host_a', reference_utc_iso='2026-10-12T10:00:00.000000Z', reference_utc_epoch=1791799200.0, anchor_type='REQUEST_ID', anchor_key='audit-1001', raw_offset_sec=1200.0, is_confirmed=True, confidence_notes="Linked by shared Request ID 'audit-1001'.")])
```
- Change summary (files, why):
  - `src/timeline/clock_skew.py`: Added static method `is_anchor_eligible(key: str) -> bool` to `ClockSkewAnalyzer` that explicitly rejects local audit serials (`audit-*`) and numeric values (e.g. status codes, PIDs, response times) from forming cross-source synchronization anchors.
  - `src/timeline/clock_skew.py`: Filtered both `REQUEST_ID` and `SESSION_ID` anchor discovery loops using `self.is_anchor_eligible(key)`.
  - `tests/unit/test_clock_skew.py`: Added reproduction test `test_auditd_serial_collision_produces_zero_anchors` and adversarial test `test_is_anchor_eligible_adversarial`.
- New test result (real, pasted):
```text
tests/unit/test_clock_skew.py::test_auditd_serial_collision_produces_zero_anchors PASSED [ 22%]
tests/unit/test_clock_skew.py::test_is_anchor_eligible_adversarial PASSED [ 33%]
============================== 9 passed in 0.07s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 140 passed in 6.90s =============================
```
- Commit: ab19ba8 fix(F-02): enforce anchor eligibility to reject local auditd serial collisions
- Status: DONE
- Notes and surprises:
  Eliminated false anchor discovery caused by colliding host-local auditd serial numbers across independent Linux servers. Distributed request IDs (`req-*`, `trace-*`, UUIDs) remain fully eligible for clock synchronization.

### Iteration 7 | Finding: F-03 | Started: 2026-11-09T21:18:00+05:30
- Reproduction test: `tests/unit/test_heuristics_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_heuristics_remediation.py::test_web_log_4616_bytes_does_not_trigger_tamper_lead
AssertionError: Expected 0 tamper leads for 4616-byte HTTP response, got 1
FAILED tests/unit/test_heuristics_remediation.py::test_privilege_escalation_requires_same_host_or_user
AssertionError: Cross-host unlinked events must not produce privilege escalation lead, got 1
FAILED tests/unit/test_heuristics_remediation.py::test_multiple_distinct_leads_emitted_no_early_break
AssertionError: Expected 2 privilege escalation leads for 2 distinct users/hosts, got 1
```
- Change summary (files, why):
  - `src/diagnostics/heuristics.py`: Removed `1102` and `4616` from `TAMPER_KEYWORDS` free-text regex; explicitly check parsed Windows `event_id` or `EventID` integers so web log response sizes (e.g. 4616 bytes) and ports do not trigger tampering alarms.
  - `src/diagnostics/heuristics.py`: Restricted diagnostic escalation in tampering to `H_EVIDENCE_INTEGRITY_ISSUE`, excluding benign coverage gaps (`F_COVERAGE_GAP`).
  - `src/diagnostics/heuristics.py`: Added `_event_effective_epoch` prioritizing `corrected_utc_iso` over `normalized_utc_iso` across all temporal window evaluations.
  - `src/diagnostics/heuristics.py`: Scoped privilege escalation and sensitive export heuristics to require host matching or user identity linkage.
  - `src/diagnostics/heuristics.py`: Removed premature loop `break` so all distinct qualifying leads are emitted.
  - `src/diagnostics/heuristics.py`: Added `@property evidence_event_ids` on `HeuristicLead`.
  - `tests/unit/test_heuristics_remediation.py`: Added reproduction and adversarial tests for tamper precision, entity scoping, corrected time windows, and corrupted timestamp robustness.
- New test result (real, pasted):
```text
tests/unit/test_heuristics_remediation.py::test_web_log_4616_bytes_does_not_trigger_tamper_lead PASSED [ 16%]
tests/unit/test_heuristics_remediation.py::test_privilege_escalation_requires_same_host_or_user PASSED [ 33%]
tests/unit/test_heuristics_remediation.py::test_multiple_distinct_leads_emitted_no_early_break PASSED [ 50%]
tests/unit/test_heuristics_remediation.py::test_corrected_time_used_in_heuristics PASSED [ 66%]
tests/unit/test_heuristics_remediation.py::test_windows_event_id_string_and_int_detection PASSED [ 83%]
tests/unit/test_heuristics_remediation.py::test_malformed_and_missing_timestamps_do_not_crash_engine PASSED [100%]
============================== 6 passed in 0.06s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 146 passed in 6.95s =============================
```
- Commit: a4e986e fix(F-03): scope heuristics by entity, use corrected time, and refine tamper detection
- Status: DONE
- Notes and surprises:
  Resolved four distinct forensic heuristics flaws: (1) false CRITICAL tampering alerts on HTTP response sizes matching Windows Event IDs, (2) spurious cross-host attribution, (3) ignoring clock skew corrections during temporal sequence evaluation, and (4) premature early-break omitting valid investigative leads.

### Iteration 8 | Finding: F-11 | Started: 2026-11-09T21:24:00+05:30
- Reproduction test: `tests/unit/test_syslog_real_samples.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_syslog_real_samples.py::test_rsyslog_iso_timestamp_parsed_successfully
AssertionError: Expected SUCCESS, got MALFORMED: ['Line does not conform to RFC 3164 or RFC 5424 syslog patterns.']
FAILED tests/unit/test_syslog_real_samples.py::test_failed_keyboard_interactive_pam_flagged_as_auth_fail
AssertionError: Expected AUTH_FAIL, got INFO
FAILED tests/unit/test_syslog_real_samples.py::test_session_opened_strips_uid_into_separate_field
AssertionError: Expected username 'alice', got 'alice(uid=1000)'
FAILED tests/unit/test_syslog_real_samples.py::test_rfc5424_multiple_structured_data_elements_does_not_leak_into_message
AssertionError: Expected 'User logged in', got '[examplePriority@32473 class="high"] User logged in'
FAILED tests/unit/test_syslog_real_samples.py::test_sudo_auth_failure_flagged_as_auth_fail
AssertionError: Expected AUTH_FAIL, got INFO
```
- Change summary (files, why):
  - `src/parsers/syslog_parser.py`: Added `RSYSLOG_ISO_PATTERN` supporting standard rsyslog RFC 3339/ISO-8601 timestamps without misclassifying them as MALFORMED or requiring yearless inference warnings.
  - `src/parsers/syslog_parser.py`: Implemented RFC 5424 structured data parser handling multiple `[SD-ELEMENT]` blocks, escape characters within parameters, and NILVALUE (`-`), preventing structured data from leaking into the message field.
  - `src/parsers/syslog_parser.py`: Extended OpenSSH failure regex and added `PAM_AUTH_FAIL` and `SUDO_INCORRECT_PASS` regexes to capture `keyboard-interactive/pam`, PAM auth failures, and sudo incorrect password attempts as `AUTH_FAIL`.
  - `src/parsers/syslog_parser.py`: Added `_clean_user_and_uid` helper to parse and strip `(uid=N)` out of usernames into `extra_fields["uid"]`.
  - `src/parsers/syslog_parser.py`: Updated `score_confidence` to score rsyslog ISO-8601 files.
  - `tests/unit/test_syslog_real_samples.py`: Created test suite covering rsyslog ISO-8601, SSH and PAM failures, UID extraction, RFC 5424 multiple SD elements, and adversarial escaped bracket syntax.
- New test result (real, pasted):
```text
tests/unit/test_syslog_real_samples.py::test_rsyslog_iso_timestamp_parsed_successfully PASSED [ 14%]
tests/unit/test_syslog_real_samples.py::test_failed_keyboard_interactive_pam_flagged_as_auth_fail PASSED [ 28%]
tests/unit/test_syslog_real_samples.py::test_session_opened_strips_uid_into_separate_field PASSED [ 42%]
tests/unit/test_syslog_real_samples.py::test_rfc5424_multiple_structured_data_elements_does_not_leak_into_message PASSED [ 57%]
tests/unit/test_syslog_real_samples.py::test_sudo_auth_failure_flagged_as_auth_fail PASSED [ 71%]
tests/unit/test_syslog_real_samples.py::test_rfc5424_escaped_brackets_in_sd_and_nilvalue PASSED [ 85%]
tests/unit/test_syslog_real_samples.py::test_rsyslog_iso_variants_and_confidence_scoring PASSED [100%]
============================== 7 passed in 0.05s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 153 passed in 7.04s =============================
```
- Commit: afdbdfb fix(F-11): support rsyslog ISO, RFC 5424 multi-SD, PAM failures, and uid stripping
- Status: DONE
- Notes and surprises:
  Standard rsyslog ISO-8601 logs now parse cleanly as first-class syslog records. Multiple RFC 5424 structured data elements are extracted into `extra_fields["structured_data"]` without leaking into message content, and PAM / sudo authentication failures are correctly classified as `AUTH_FAIL`.

### Iteration 9 | Finding: F-12 | Started: 2026-11-09T21:30:00+05:30
- Reproduction test: `tests/unit/test_web_and_firewall_parsers.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_web_and_firewall_parsers.py::test_web_log_sqli_with_spaces_parsed_successfully
AssertionError: Expected SUCCESS, got MALFORMED: ['Line does not conform to Common or Combined web access log format.']
FAILED tests/unit/test_web_and_firewall_parsers.py::test_web_log_dash_request_line_parsed_successfully
AssertionError: Expected SUCCESS, got MALFORMED: ['Line does not conform to Common or Combined web access log format.']
FAILED tests/unit/test_web_and_firewall_parsers.py::test_web_log_lowercase_method_parsed_successfully
AssertionError: Expected SUCCESS, got MALFORMED: ['Line does not conform to Common or Combined web access log format.']
FAILED tests/unit/test_web_and_firewall_parsers.py::test_web_log_trailing_float_is_not_request_id
AssertionError: Float 0.005 was incorrectly assigned as request_id: 0.005
FAILED tests/unit/test_web_and_firewall_parsers.py::test_web_log_named_or_explicit_request_id_extracted
AssertionError: assert 'request_id' == 'trace-abc-123'
FAILED tests/unit/test_web_and_firewall_parsers.py::test_csv_firewall_header_driven_mapping_and_unknown_columns
AssertionError: Expected src_ip '10.0.0.5', got 'DENY'
```
- Change summary (files, why):
  - `src/parsers/web_access_parser.py`: Updated Combined/Common log grammar to extract the full quoted request string, allowing spaces in URIs (SQL injection), lowercase HTTP methods, and `-` timeout/disconnect lines without failing as MALFORMED.
  - `src/parsers/web_access_parser.py`: Enforced that request IDs are only extracted from named fields (`request_id=`, `req_id=`, `trace_id=`) or explicit trace token formats (`req-*`, `trace-*`, UUIDs); trailing floating-point response times (e.g. `$request_time` = 0.005) are stored in `extra["response_time"]` instead of polluting `request_id`.
  - `src/parsers/csv_firewall_parser.py`: Replaced rigid positional indexing with a comprehensive header alias dictionary mapping (`timestamp`, `src_ip`, `dst_ip`, `action`, `src_port`, `dst_port`, `proto`, `rule_id`); preserved unknown/custom CSV columns in `extra_fields`; surfaced explicit diagnostics when required columns are absent.
  - `src/pipeline.py` & `app.py`: Added user-supplied host assignment `source_host` parameter and fallback evidence-isolated source naming (`f"{filename} [{evidence_id[:8]}]"`) to prevent identical filenames across multiple servers (e.g., `access.log`) from collapsing into a single merged source.
  - `tests/unit/test_web_and_firewall_parsers.py`: Added comprehensive unit and adversarial tests covering SQLi spaces, binary probes, mixed-case headers, quoted CSV cells with commas, and multi-server source separation.
- New test result (real, pasted):
```text
tests/unit/test_web_and_firewall_parsers.py::test_web_log_sqli_with_spaces_parsed_successfully PASSED [ 10%]
tests/unit/test_web_and_firewall_parsers.py::test_web_log_dash_request_line_parsed_successfully PASSED [ 20%]
tests/unit/test_web_and_firewall_parsers.py::test_web_log_lowercase_method_parsed_successfully PASSED [ 30%]
tests/unit/test_web_and_firewall_parsers.py::test_web_log_trailing_float_is_not_request_id PASSED [ 40%]
tests/unit/test_web_and_firewall_parsers.py::test_web_log_named_or_explicit_request_id_extracted PASSED [ 50%]
tests/unit/test_web_and_firewall_parsers.py::test_csv_firewall_header_driven_mapping_and_unknown_columns PASSED [ 60%]
tests/unit/test_web_and_firewall_parsers.py::test_csv_firewall_missing_required_column_diagnostic PASSED [ 70%]
tests/unit/test_web_and_firewall_parsers.py::test_two_servers_access_logs_do_not_collapse_into_one_source PASSED [ 80%]
tests/unit/test_web_and_firewall_parsers.py::test_web_log_empty_and_binary_request_lines PASSED [ 90%]
tests/unit/test_web_and_firewall_parsers.py::test_csv_firewall_mixed_case_aliases_and_quoted_commas PASSED [100%]
============================= 10 passed in 0.14s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 163 passed in 8.03s =============================
```
- Commit: 5ce7943 fix(F-12): improve web access and CSV firewall grammar and distinguish multi-host sources
- Status: DONE
- Notes and surprises:
  Resolved web log request line rejection on attack payloads with spaces, prevented trailing request duration floats from masquerading as cross-host request IDs, enabled header-aware column mapping for firewall CSVs with arbitrary column ordering, and separated identically-named evidence files into distinct timeline sources.

### Iteration 10 | Finding: F-14 | Started: 2026-11-09T21:38:00+05:30
- Reproduction test: `tests/unit/test_normalization_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_normalization_remediation.py::test_dst_spring_forward_gap_flagged_as_nonexistent
AssertionError: assert 'AMBIGUOUS_DST' == 'NONEXISTENT_DST'
- NONEXISTENT_DST
+ AMBIGUOUS_DST
FAILED tests/unit/test_normalization_remediation.py::test_ambiguous_dd_mm_vs_mm_dd_flagged
AssertionError: assert 'NORMALIZED_EXACT' in ('AMBIGUOUS_TIMESTAMP', 'AMBIGUOUS_TIMESTAMP', 'AMBIGUOUS')
FAILED tests/unit/test_normalization_remediation.py::test_unsupported_12h_ampm_and_ctime_and_tz_abbr
AssertionError: assert 'INVALID_TIMESTAMP' != 'INVALID_TIMESTAMP'
FAILED tests/unit/test_normalization_remediation.py::test_yearless_syslog_uses_configured_base_year
AssertionError: assert '2026-10-11T14:32:01.000000Z'.startswith('2023-10-11')
```
- Change summary (files, why):
  - `src/timeline/schema.py`: Added `NONEXISTENT_DST` and `AMBIGUOUS_TIMESTAMP` (with forensic aliases `NONEXISTENT` and `AMBIGUOUS`) to `NormalizationStatus`.
  - `src/timeline/normalization.py`: Refined `_localize_and_check_dst()` by round-tripping localized naive timestamps to distinguish non-existent spring-forward DST transition gaps from repeated fall-back hours; formatted both candidate UTC times (`fold=0` and `fold=1`) into explicit warning diagnostics.
  - `src/timeline/normalization.py`: Added RFC 822 / POSIX timezone abbreviation table `TZ_ABBREVIATIONS` with exact offsets and ambiguity flags for EST, CST, IST, and BST.
  - `src/timeline/normalization.py`: Implemented POSIX `ctime` parser pattern (`CTIME_PATTERN`) handling both single and double space-padded days.
  - `src/timeline/normalization.py`: Added regex and logic detecting ambiguous `DD/MM` vs `MM/DD` date formats when both day and month are `<= 12` and unequal; flagged with `AMBIGUOUS_TIMESTAMP` while applying the investigation's `date_order_preference` ("DMY" vs "MDY").
  - `src/timeline/normalization.py`: Supported 12-hour AM/PM formats across common strptime variants and slash-formatted dates.
  - `src/timeline/normalization.py`: Added configurable `base_year` and `date_order_preference` parameters to `TimestampNormalizer` to prevent defaulting yearless syslog to analysis-time year.
  - `tests/unit/test_normalization_remediation.py`: Added reproduction and adversarial tests for DST gap vs fallback distinction, unambiguous day>12 date acceptance, Dec->Jan rollover persistence, and ctime/tz abbreviation validation.
- New test result (real, pasted):
```text
tests/unit/test_normalization_remediation.py::test_dst_spring_forward_gap_flagged_as_nonexistent PASSED [ 12%]
tests/unit/test_normalization_remediation.py::test_ambiguous_dd_mm_vs_mm_dd_flagged PASSED [ 25%]
tests/unit/test_normalization_remediation.py::test_unsupported_12h_ampm_and_ctime_and_tz_abbr PASSED [ 37%]
tests/unit/test_normalization_remediation.py::test_yearless_syslog_uses_configured_base_year PASSED [ 50%]
tests/unit/test_normalization_remediation.py::test_adversarial_dst_fallback_vs_spring_forward PASSED [ 62%]
tests/unit/test_normalization_remediation.py::test_adversarial_unambiguous_slashed_dates_do_not_flag_ambiguous PASSED [ 75%]
tests/unit/test_normalization_remediation.py::test_adversarial_syslog_new_year_rollover_sequence PASSED [ 87%]
tests/unit/test_normalization_remediation.py::test_adversarial_ctime_with_padding_spaces_and_tz_abbr_coverage PASSED [100%]
============================== 8 passed in 0.07s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 171 passed in 7.04s =============================
```
- Commit: c4546dd fix(F-14): handle DST gaps, date ambiguity, AM/PM, ctime, and timezone abbreviations
- Status: DONE
- Notes and surprises:
  Standard Python `zoneinfo` astimezone produces `dt0 != dt1` for both non-existent spring-forward hours and repeated fall-back hours. Round-tripping the localized datetime to naive local time uniquely and deterministically separates non-existent gaps from repeated hours without third-party timezone libraries.

### Iteration 11 | Finding: F-15 | Started: 2026-11-09T21:47:00+05:30
- Reproduction test: `tests/unit/test_clock_skew_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_clock_skew_remediation.py::test_two_identical_anchors_must_not_report_zero_uncertainty
AssertionError: Uncertainty must not be 0.0 with only 2 anchors, got 0.0
assert 0.0 > 0.0
FAILED tests/unit/test_clock_skew_remediation.py::test_linear_drift_applied_to_corrected_timestamps
AssertionError: Expected drift-corrected time 10:50:00, got 10:50:05 (constant median offset was incorrectly applied without drift)
assert '10:50:05' == '10:50:00'
FAILED tests/unit/test_clock_skew_remediation.py::test_default_reference_source_is_source_with_most_anchors
AssertionError: Expected default reference 'host_central', got 'host_00_isolated'
assert 'host_00_isolated' == 'host_central'
```
- Change summary (files, why):
  - `src/timeline/clock_skew.py`: Added `uncertainty_sec` to `ClockSkewEstimate` implementing a defensible uncertainty model: combines detrended residual spread with network latency bound and small-sample penalty ($k_N = \text{latency\_tolerance} / \sqrt{N}$), enforcing a resolution floor ($0.5$s) and never reporting $\pm 0.0$ when anchor count $< N$ ($N=30$, documented).
  - `src/timeline/clock_skew.py`: Implemented linear drift application in `ClockSkewAnalyzer.apply_corrections()` using the exact transformation $T_{\text{ref}} = T_{\text{target}, 0} + (T_{\text{target}} - T_{\text{target}, 0}) / (1 + m)$ when Theil-Sen drift is significant ($\ge 10.0$ ppm); states drift was ignored when insignificant ($< 10.0$ ppm).
  - `src/timeline/clock_skew.py`: Added detection of probable timezone misconfigurations (offsets within $\pm 60$s of 30-minute / 1-hour multiples) with `probable_tz_misconfiguration=True` and clear explanatory diagnostics.
  - `src/pipeline.py`: Replaced arbitrary alphabetical source selection with connectivity-based reference source discovery (choosing the source with the highest anchor count across all pairs, falling back to event count), while preserving explicit user overrides.
  - `src/pipeline.py`: Updated transitive 2-hop synchronization to compute combined uncertainty bounds ($U_1 + U_2$) and forward drift parameters.
  - `tests/unit/test_clock_skew_remediation.py`: Added comprehensive unit and adversarial tests covering uncertainty bounds covering residuals in 60-70s drift scenarios, insignificant drift suppression, timezone misconfiguration flags, and connectivity-driven reference source selection.
- New test result (real, pasted):
```text
tests/unit/test_clock_skew_remediation.py::test_two_identical_anchors_must_not_report_zero_uncertainty PASSED [ 20%]
tests/unit/test_clock_skew_remediation.py::test_linear_drift_applied_to_corrected_timestamps PASSED [ 40%]
tests/unit/test_clock_skew_remediation.py::test_default_reference_source_is_source_with_most_anchors PASSED [ 60%]
tests/unit/test_clock_skew_remediation.py::test_adversarial_uncertainty_covers_residuals_in_drifting_scenario PASSED [ 80%]
tests/unit/test_clock_skew_remediation.py::test_adversarial_insignificant_drift_ignored_and_tz_misconfiguration_flagged PASSED [100%]
============================== 5 passed in 0.15s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================ 176 passed in 10.19s =============================
```
- Commit: 1c57fd0 fix(F-15): add uncertainty bounds, apply Theil-Sen drift, and choose reference by connectivity
- Status: DONE
- Notes and surprises:
  Raw MAD of identical offsets is mathematically 0.0, which misled investigators into believing clock synchronization had ±0.000s uncertainty. Adding `uncertainty_sec` with a resolution floor of 0.5s and sample-size penalty preserves mathematical definitions while establishing a forensically defensible confidence bound.

### Iteration 12 | Finding: F-16 | Started: 2026-11-09T21:54:30+05:30
- Reproduction test: `tests/unit/test_search_cql_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_search_cql_remediation.py::test_quoted_phrase_search
assert 0 == 1
FAILED tests/unit/test_search_cql_remediation.py::test_or_operator_disjunction
assert 0 == 2
FAILED tests/unit/test_search_cql_remediation.py::test_not_field_scoped_to_field_only
AssertionError: assert 'web-01-backup' in {'db-01', 'web-01'}
FAILED tests/unit/test_search_cql_remediation.py::test_host_exact_match_vs_wildcard
AssertionError: assert 2 == 1
FAILED tests/unit/test_search_cql_remediation.py::test_before_date_inclusive_of_day
AssertionError: assert 0 == 2
FAILED tests/unit/test_search_cql_remediation.py::test_full_text_search_beyond_8192_chars
assert 0 == 1
FAILED tests/unit/test_search_cql_remediation.py::test_redos_pattern_guarded_with_timeout
assert 15.182373499999812 < 1.0
```
- Change summary (files, why):
  - `src/timeline/search.py`: Implemented a full recursive-descent CQL parser with AST nodes (`FreeTextNode`, `FieldMatchNode`, `TimeBoundNode`, `AndNode`, `OrNode`, `NotNode`), supporting quoted phrases, explicit disjunction (`OR`), conjunction (`AND`), negation (`NOT`, `-`), and parentheses groupings.
  - `src/timeline/search.py`: Enforced exact field matching by default (e.g. `host:web-01` matches strictly `web-01`), while supporting explicit wildcard syntax (`host:web*` or `fnmatch` globbing).
  - `src/timeline/search.py`: Scoped `NOT field:value` to only negate the targeted field rather than globally matching against the full text corpus.
  - `src/timeline/search.py`: Fixed date semantics to be inclusive: `before:YYYY-MM-DD` automatically bounds to `YYYY-MM-DDT23:59:59.999999Z` and `after:YYYY-MM-DD` bounds to `YYYY-MM-DDT00:00:00.000000Z`.
  - `src/timeline/search.py`: Removed the `[:8192]` character corpus limit to search complete log lines and payloads of any length.
  - `src/timeline/search.py`: Hardened regex execution against ReDoS by capping pattern length (`MAX_REGEX_LEN = 256`), detecting nested repetition quantifiers upfront (`is_suspect_redos`), and bounding regex search execution with a hard timeout (`safe_regex_search`).
  - `tests/unit/test_search_cql_remediation.py`: Added comprehensive unit and adversarial tests covering exact phrases, OR logic, scoped field negation, exact vs wildcard hosts, inclusive date boundaries, full-text corpus traversal, and ReDoS execution safety.
- New test result (real, pasted):
```text
tests/unit/test_search_cql_remediation.py::test_quoted_phrase_search PASSED [ 11%]
tests/unit/test_search_cql_remediation.py::test_or_operator_disjunction PASSED [ 22%]
tests/unit/test_search_cql_remediation.py::test_not_field_scoped_to_field_only PASSED [ 33%]
tests/unit/test_search_cql_remediation.py::test_host_exact_match_vs_wildcard PASSED [ 44%]
tests/unit/test_search_cql_remediation.py::test_before_date_inclusive_of_day PASSED [ 55%]
tests/unit/test_search_cql_remediation.py::test_full_text_search_beyond_8192_chars PASSED [ 66%]
tests/unit/test_search_cql_remediation.py::test_redos_pattern_guarded_with_timeout PASSED [ 77%]
tests/unit/test_search_cql_remediation.py::test_adversarial_nested_parentheses_and_boolean_precedence PASSED [ 88%]
tests/unit/test_search_cql_remediation.py::test_adversarial_quoted_field_with_spaces_and_special_chars PASSED [100%]
============================== 9 passed in 0.06s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 185 passed in 7.39s =============================
```
- Commit: 7125839 fix(F-16): build AST tokenizer for CQL with boolean logic, exact field matching, and ReDoS guard
- Status: DONE
- Notes and surprises:
  Quoted phrases like `"failed password"` previously fell through without unquoting because `is_structured` omitted `free_terms`, resulting in zero matches. Building an explicit AST with `FreeTextNode` and `FieldMatchNode` solved phrase matching, boolean precedence, and scoped negation cleanly.

### Iteration 13 | Finding: F-17 | Started: 2026-11-09T22:02:20+05:30
- Reproduction test: `tests/unit/test_correlation_remediation.py::test_same_ip_on_two_sources_a_week_apart_is_not_lateral_movement`
- Failing output (real, pasted):
```text
AssertionError: Expected neutral shared identity wording, got: Source IP '192.168.1.50' active across 2 distinct sources: srv1, srv2. Possible lateral movement or scanning indicator.
assert 'lateral movement' not in "source ip '...g indicator."
'lateral movement' is contained here:
   possible lateral movement or scanning indicator.
```
- Change summary (files, why):
  - `src/timeline/correlation.py`: Renamed generic multi-host activity clusters from `LATERAL_USER` / `LATERAL_IP` to `SHARED_USER` / `SHARED_IP` with neutral notes ("Shared identity across sources"), eliminating false claims of attacker lateral movement on routine multi-host service accounts, admin logins, and shared proxy IPs.
  - `src/timeline/correlation.py`: Added `lateral_movement_window_sec` parameter (default 3600.0s) and implemented `_detect_ordered_hop` algorithm: requires an ordered chronological transition between distinct sources within the time window before classifying as `LATERAL_MOVEMENT_USER` or `LATERAL_MOVEMENT_IP`.
  - `src/timeline/correlation.py`: Implemented `_effective_time` and `_effective_epoch` prioritizing clock-skew corrected timestamps (`corrected_utc_iso`) over uncorrected normalized time, ensuring clock synchronization directly improves correlation accuracy.
  - `tests/unit/test_correlation_remediation.py`: Added unit and adversarial tests verifying 7-day apart IPs remain neutral `SHARED_IP`, 15-minute ordered transitions are detected as `LATERAL_MOVEMENT_USER`, and corrected timestamps successfully resolve hops separated by clock drift.
- New test result (real, pasted):
```text
tests/unit/test_correlation_remediation.py::test_same_ip_on_two_sources_a_week_apart_is_not_lateral_movement PASSED [ 33%]
tests/unit/test_correlation_remediation.py::test_adversarial_ordered_hop_within_window_classified_as_lateral_movement PASSED [ 66%]
tests/unit/test_correlation_remediation.py::test_adversarial_corrected_time_used_for_window_evaluation PASSED [100%]
============================== 3 passed in 0.05s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 188 passed in 7.00s =============================
```
- Commit: fa48387 fix(F-17): enforce time window and neutral labeling for shared identities vs lateral movement
- Status: DONE
- Notes and surprises:
  Unconditionally labeling any account or IP on two or more sources as "lateral movement" led to false critical alarms on standard infrastructure. Requiring an ordered hop within `lateral_movement_window_sec` using corrected time grounds correlation in verified temporal sequences.

### Iteration 14 | Finding: F-18 | Started: 2026-11-09T22:05:30+05:30
- Reproduction test: `tests/unit/test_decoding_and_raw_text.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_decoding_and_raw_text.py::test_utf16le_log_decodes_cleanly_and_records_encoding
AssertionError: assert 3 == 2
FAILED tests/unit/test_decoding_and_raw_text.py::test_corrupt_byte_sequence_emits_replacement_character_warning
AssertionError: Expected corruption/replacement character warning, got: ['Line does not conform to RFC 3164 or RFC 5424 syslog patterns.', 'Record contains no timestamp string.']
FAILED tests/unit/test_decoding_and_raw_text.py::test_windows_event_parser_csv_preserves_original_raw_text
AssertionError: Expected true original line '"2026-10-12 10:00:00",4624,WIN-SRV,"Special, with quotes and spaces"', got reconstructed '2026-10-12 10:00:00,4624,WIN-SRV,Special, with quotes and spaces'
- "2026-10-12 10:00:00",4624,WIN-SRV,"Special, with quotes and spaces"
+ 2026-10-12 10:00:00,4624,WIN-SRV,Special, with quotes and spaces
```
- Change summary (files, why):
  - `src/pipeline.py`: Added `detect_and_decode_text()` supporting BOM detection (UTF-8-SIG, UTF-16-LE, UTF-16-BE, UTF-32), strict UTF-8 validation, UTF-16-LE heuristics without BOM (interleaved NUL detection), and Latin-1 fallback.
  - `src/pipeline.py`: Counted replacement characters ($U+FFFD$) when fallback decoding occurs, recording `encoding` and `replacement_char_count` into event provenance and surfacing explicit data quality warnings on corrupted byte sequences.
  - `src/parsers/windows_event_parser.py`: Replaced synthetic string reconstruction (`",".join(...)` and `json.dumps(...)`) with direct preservation of true unmutated original lines in both CSV and JSON streams.
  - `tests/unit/test_decoding_and_raw_text.py`: Added unit and adversarial tests covering UTF-16-LE with BOM, UTF-16-BE with BOM, UTF-8-SIG BOM stripping, Latin-1 non-UTF-8 characters, corruption warnings, and exact CSV raw line retention.
- New test result (real, pasted):
```text
tests/unit/test_decoding_and_raw_text.py::test_utf16le_log_decodes_cleanly_and_records_encoding PASSED [ 20%]
tests/unit/test_decoding_and_raw_text.py::test_corrupt_byte_sequence_emits_replacement_character_warning PASSED [ 40%]
tests/unit/test_decoding_and_raw_text.py::test_windows_event_parser_csv_preserves_original_raw_text PASSED [ 60%]
tests/unit/test_decoding_and_raw_text.py::test_adversarial_utf8_bom_and_utf16_be PASSED [ 80%]
tests/unit/test_decoding_and_raw_text.py::test_adversarial_latin1_high_bit_characters PASSED [100%]
============================== 5 passed in 0.12s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================ 193 passed in 10.20s =============================
```
- Commit: 0f64c9d fix(F-18): detect BOM and text encoding, warn on corrupt bytes, and preserve Windows raw text
- Status: DONE
- Notes and surprises:
  Hardcoded UTF-8 decoding previously corrupted Windows exports written in UTF-16, generating NUL bytes that failed downstream parsers. Comprehensive BOM and interleaved-NUL detection enables transparent ingestion of UTF-16 and Latin-1 evidence files.

### Iteration 15 | Finding: F-05 | Started: 2026-11-09T22:11:30+05:30
- Reproduction test: `tests/unit/test_audit_chain_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_audit_chain_remediation.py::test_tail_truncation_must_be_detected
AssertionError: Truncated chain must FAIL verification!
assert True is False
FAILED tests/unit/test_audit_chain_remediation.py::test_whole_chain_rewrite_must_be_detected
AssertionError: Rewritten chain must FAIL verification against anchored head!
assert True is False
FAILED tests/unit/test_audit_chain_remediation.py::test_corrupt_last_line_must_fail_closed_not_fork
Failed: DID NOT RAISE Exception
======================== 3 failed, 193 passed in 8.68s ========================
```
- Change summary (files, why):
  - `src/evidence/audit_chain.py`: Implemented dual anchoring for audit chain head state (latest `seq_id` and `head_hash`) across both an external sidecar file (`audit_chain.anchor`) and SQLite database table (`audit_chain_anchor`).
  - `src/evidence/audit_chain.py`: Updated `verify_chain()` to detect tail truncation (`total < anchor_seq_id`), whole-chain rewrites (`entry_hash != anchor_head_hash`), and ledger file deletion while anchors persist.
  - `src/evidence/audit_chain.py`: Defined `AuditChainIntegrityError`. Made `_get_last_entry()` fail closed with `AuditChainIntegrityError` if the last line contains corrupt JSON or unparseable bytes, preventing chain forking and sequence resets to 1.
  - `src/evidence/audit_chain.py`: Implemented cross-platform atomic filesystem lock (`_acquire_file_lock`) on `<investigation_dir>/audit_chain.lock` combined with in-process reentrant threading lock (`_LEDGER_LOCK`), ensuring serialized concurrent appends with immediate `os.fsync`.
  - `src/storage/repository.py` & `src/pipeline.py`: Removed swallowed `try ... except Exception: pass` blocks around `ledger.append(...)`, ensuring ledger write failures fail loudly per Rule 10.
  - `tests/unit/test_audit_chain_remediation.py`: Added comprehensive unit and adversarial tests covering tail truncation detection, whole-chain rewrite detection, corrupt last line fail-closed, multi-threaded concurrent appends, deleted ledger detection, mid-chain corrupt line detection, and loud pipeline failure on disk/permission error.
- New test result (real, pasted):
```text
tests\unit\test_audit_chain_remediation.py .......                       [100%]

============================== 7 passed in 0.28s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 200 passed in 7.78s =============================
```
- Commit: 3324e8a fix(F-05): anchor audit chain head, fail closed on corrupt lines, lock appends, and fail loud on write errors
- Status: DONE
- Notes and surprises:
  Without external head anchors, any hash-chained JSONL ledger is vulnerable to tail truncation because internal hash pointers remain self-consistent. Anchoring both in a sidecar file and SQLite database closes this vulnerability and provides double-entry verification.

### Iteration 16 | Finding: F-06 | Started: 2026-11-09T22:18:15+05:30
- Reproduction test: `tests/unit/test_manifest_verification_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_manifest_verification_remediation.py::test_reproduce_edit_evidence_and_manifest_together_must_fail
AssertionError: Tampering both evidence and manifest must FAIL verification!
assert True is False
FAILED tests/unit/test_manifest_verification_remediation.py::test_reproduce_manifest_load_verifies_internal_digest
Failed: DID NOT RAISE Exception
FAILED tests/unit/test_manifest_verification_remediation.py::test_reproduce_delete_investigation_writes_surviving_tombstone
AttributeError: 'InvestigationRepository' object has no attribute 'get_tombstone_ledger'
============================== 3 failed in 0.18s ==============================
```
- Change summary (files, why):
  - `src/evidence/manifest.py`: Defined `ManifestIntegrityError`. Added `manifest_sha256` to `EvidenceManifest` and updated `load_from_file` to verify the internal cryptographic digest against normalized content, raising `ManifestIntegrityError` if tampered.
  - `src/evidence/manifest.py`: Fixed recursion in `to_dict` by gating digest recomputation strictly to `include_digest=True`.
  - `src/pipeline.py` & `src/storage/repository.py`: Anchored `manifest_sha256` into the immutable audit chain ledger during both `CASE_CREATED` and `EVIDENCE_INGESTED` events.
  - `src/evidence/verification.py`: Updated `verify_evidence_integrity()` to cross-examine current manifest digest against the anchored `manifest_sha256` in the audit ledger, immediately catching coordinated tamper attacks that modify both evidence and manifest.
  - `src/evidence/collector.py` & `src/storage/repository.py`: Hardened evidence directories to `0700` and preserved evidence files to `0444` (read-only).
  - `src/storage/repository.py`: Added `get_tombstone_ledger()` and updated `delete_investigation()` to write a durable tombstone entry recording final sequence id and head hash to `<data_root>/tombstones` prior to case deletion.
  - `tests/unit/test_manifest_verification_remediation.py`: Added reproduction and adversarial tests for dual evidence/manifest tampering detection, manifest load digest validation, surviving tombstone ledger verification across multiple deletions, sequential ingest manifest tracking, and disk permissions.
- New test result (real, pasted):
```text
tests\unit\test_manifest_verification_remediation.py ......              [100%]

============================== 6 passed in 0.26s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 206 passed in 8.00s =============================
```
- Commit: 58b6935 fix(F-06): anchor manifest in ledger, verify on load, restrict permissions, and write tombstones
- Status: DONE
- Notes and surprises:
  Verifying files strictly against `manifest.json` without verifying the manifest against the ledger allowed an attacker who had write access to the filesystem to modify evidence and recalculate the manifest unnoticed. Anchoring `manifest_sha256` in the immutable hash-chained ledger seals this loophole.

### Iteration 17 | Finding: F-07 | Started: 2026-11-09T22:25:25+05:30
- Reproduction test: `tests/unit/test_tamper_lab_remediation.py`
- Failing output (real, pasted):
```text
ImportError while importing test module 'tests/unit/test_tamper_lab_remediation.py'.
ImportError: cannot import name 'simulate_isolated_tamper_check' from 'src.evidence.verification'
============================== 1 error in 0.16s ===============================
```
- Change summary (files, why):
  - `src/evidence/verification.py`: Implemented `simulate_isolated_tamper_check()` to execute tamper simulation strictly on an ephemeral throwaway copy in an isolated temporary sandbox directory, verifying baseline integrity, proving 1-byte alteration is caught by SHA-256 mismatch, and confirming the stored original file remains 100% unaltered. Added support for 0-byte edge cases.
  - `app.py`: Replaced the in-place file mutation logic in Module 4 (`Integrity & Custody Chain`) with `simulate_isolated_tamper_check()`. Removed the unsafe `.bak` writing and "Restore Clean Artifact State" button that previously mutated real evidence files and corrupted clean evidence on false restores.
  - `app.py`: Updated the UI to display side-by-side verification rows comparing the pristine on-disk evidence (`INTACT / UNTOUCHED`) against the ephemeral sandbox copy (`TAMPERING DETECTED`).
  - `tests/unit/test_tamper_lab_remediation.py`: Added unit and adversarial tests verifying stored evidence hash is byte-for-byte identical before and after simulations, zero `.bak` files are created on disk, 0-byte files detect alteration without crashing, and repeated simulations maintain pristine evidence.
- New test result (real, pasted):
```text
tests\unit\test_tamper_lab_remediation.py ...                            [100%]

============================== 3 passed in 0.18s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 209 passed in 7.87s =============================
```
- Commit: 33c6091 fix(F-07): run tamper lab strictly on ephemeral sandbox copy leaving evidence unaltered
- Status: DONE
- Notes and surprises:
  The previous tamper lab flipped bytes directly on stored forensic evidence and relied on a fragile `.bak` file or reverse bit-flip to restore clean state. If an analyst clicked "Restore" without tampering, it corrupted authentic evidence. Shifting the demonstration to an ephemeral throwaway copy strictly enforces Rule 9 ("Evidence is read-only forever").

### Iteration 18 | Finding: F-08 | Started: 2026-11-09T22:30:20+05:30
- Reproduction test: `tests/unit/test_atomic_ingest_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_atomic_ingest_remediation.py::test_reproduce_windows_event_parser_int_none_crash
TypeError: int() argument must be a string, a bytes-like object or a real number, not 'NoneType'
FAILED tests/unit/test_atomic_ingest_remediation.py::test_reproduce_atomic_ingest_rollback_on_fault_injection
AssertionError: Expected 0 evidence files, found [WindowsPath('.../evidence/ev_47fed7b4d03e_crash.log')]
FAILED tests/unit/test_atomic_ingest_remediation.py::test_reproduce_archive_preserves_original_archive_and_member_hashes
AssertionError: assert 'PARSED' == 'ARCHIVE'
========================= 3 failed, 1 passed in 0.21s =========================
```
- Change summary (files, why):
  - `src/parsers/windows_event_parser.py`: Handled null/missing event IDs safely (`int(raw_eid) if raw_eid is not None else 0`) with `(ValueError, TypeError)` exception guard, preventing unhandled `int(None)` crashes on JSON events.
  - `src/parsers/windows_event_parser.py`: Replaced broad outer `except Exception: pass` in CSV parsing with per-line try/except error handling that emits `MALFORMED` `ParsedRecord` diagnostics with line numbers while continuing to parse subsequent valid rows.
  - `src/evidence/collector.py`: Added staged evidence preservation via `.staging` directory, with atomic promotion (`commit_preserved`) and cleanup (`rollback_preserved`).
  - `src/storage/database.py`: Added `delete_evidence_events(investigation_id, evidence_id)` to purge partial events if an ingest transaction rolls back.
  - `src/pipeline.py`: Wrapped `ingest_evidence_bytes()` in an atomic transaction that stages preservation before processing, saving events and manifest entries only upon success, and rolling back files, database rows, and manifest entries upon any failure.
  - `src/pipeline.py`: Implemented `_ingest_archive_pipeline()`: preserves and hashes the pristine original `.zip`/`.tar.gz` archive with an `ARCHIVE` manifest entry documenting all `member_hashes`, extracts members, and links all member events to the parent archive.
  - `src/evidence/manifest.py`: Added optional `metadata` dictionary to `EvidenceFileEntry` (omitted from serialized dict when empty to maintain 100% hash compatibility with pre-existing manifests).
  - `tests/unit/test_atomic_ingest_remediation.py`: Added comprehensive unit and adversarial tests for `int(None)` handling, CSV per-line error diagnostics, atomic rollback on fault injection (mid-ingest crash and DB failure), and archive original preservation with member hashes.
- New test result (real, pasted):
```text
tests\unit\test_atomic_ingest_remediation.py ......                      [100%]

============================== 6 passed in 0.23s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 215 passed in 7.94s =============================
```
- Commit: ebf4eff fix(F-08): atomic ingest transaction with staging and rollback, archive preservation, and safe Windows parsing
- Status: DONE
- Notes and surprises:
  Pre-existing manifests did not have `"metadata"` in entry JSONs. Serializing `"metadata": {}` on entries altered the calculated manifest SHA-256 digest on existing cases. Conditioning the emission of `metadata` on `bool(self.metadata)` preserved complete backward-compatible cryptographic validity.

### Iteration 19 | Finding: F-09 | Started: 2026-11-09T22:38:00+05:30
- Reproduction test: `tests/unit/test_archive_bomb_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_archive_bomb_remediation.py::test_reproduce_streaming_bomb_guard_caps_peak_memory
AssertionError: Peak memory 49.44MB exceeded 5MB bound!
FAILED tests/unit/test_archive_bomb_remediation.py::test_reproduce_member_count_cap
Failed: DID NOT RAISE any of (FileSizeExceededError, IngestionError)
======================== 2 failed, 216 passed in 8.10s ========================
```
- Change summary (files, why):
  - `src/pipeline.py`: Added constants `MAX_ARCHIVE_MEMBERS = 1000`, `MAX_NESTING_DEPTH = 3`, and `STREAM_CHUNK_SIZE = 65536`.
  - `src/pipeline.py`: Updated `_decompress_if_needed` to check `MAX_ARCHIVE_MEMBERS` before unpacking zip infolist, and read member content in streaming chunks (`STREAM_CHUNK_SIZE = 65536`) with running byte total, raising `FileSizeExceededError` before full buffer allocation.
  - `src/pipeline.py`: Updated `expand_archive_bytes` to enforce `depth <= MAX_NESTING_DEPTH`, cap member count (`len(zf.infolist()) <= MAX_ARCHIVE_MEMBERS` and `len(tf.getmembers()) <= MAX_ARCHIVE_MEMBERS`), stream member decompression in chunks with running byte total, and sanitize zip-slip path traversals.
  - `src/pipeline.py`: Passed `archive_depth` through `ingest_evidence_bytes` and `_ingest_archive_pipeline` to defend against recursive archive bombs.
  - `tests/unit/test_archive_bomb_remediation.py`: Added unit and adversarial tests measuring peak RSS bounded memory on `.zip` and `.tar.gz` bombs with tracemalloc, member count caps, nesting depth limit, and zip-slip directory traversal sanitization.
- New test result (real, pasted):
```text
tests/unit/test_archive_bomb_remediation.py::test_reproduce_streaming_bomb_guard_caps_peak_memory PASSED [ 16%]
tests/unit/test_archive_bomb_remediation.py::test_reproduce_member_count_cap PASSED [ 33%]
tests/unit/test_archive_bomb_remediation.py::test_reproduce_zip_slip_path_traversal_blocked PASSED [ 50%]
tests/unit/test_archive_bomb_remediation.py::test_adversarial_tar_gz_bomb_streaming_bound PASSED [ 66%]
tests/unit/test_archive_bomb_remediation.py::test_adversarial_nesting_depth_cap PASSED [ 83%]
tests/unit/test_archive_bomb_remediation.py::test_adversarial_windows_backslash_traversal_sanitized PASSED [100%]

============================== 6 passed in 0.21s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 221 passed in 8.00s =============================
```
- Commit: 0d90d3e fix(F-09): stream archive decompression with running byte cap, member limit, and zip-slip guard
- Status: DONE
- Notes and surprises:
  `zf.read(info.filename)` and `tf.extractfile(member).read()` previously loaded entire uncompressed files into RAM before checking size limits, allowing small compressed archives to cause large memory spikes. Streaming decompression in 64KB chunks allows aborting immediately upon exceeding byte boundaries, keeping memory strictly bounded under 5MB.

### Iteration 20 | Finding: F-19 | Started: 2026-11-10T11:30:00+05:30
- Reproduction test: `tests/unit/test_backup_restore_and_cli_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_backup_restore_and_cli_remediation.py::test_reproduce_cli_exits_nonzero_on_tamper_or_chain_failure
AssertionError: Expected non-zero exit code on compromised integrity, got 0
FAILED tests/unit/test_backup_restore_and_cli_remediation.py::test_reproduce_json_backup_includes_skew_integrity_and_roundtrips
TypeError: export_investigation_json() got an unexpected keyword argument 'repo'
FAILED tests/unit/test_backup_restore_and_cli_remediation.py::test_reproduce_export_writes_audit_ledger_entry
AssertionError: Expected INVESTIGATION_EXPORTED in ledger actions, found: ['CASE_CREATED', 'EVIDENCE_INGESTED']
============================== 3 failed in 0.44s ==============================
```
- Change summary (files, why):
  - `src/reporting/json_export.py`: Enhanced `export_investigation_json` to include clock skew analysis, evidence integrity verification results, complete audit ledger chain entries, and base64-encoded evidence files with SHA-256 verification digests.
  - `src/reporting/json_export.py`: Implemented `restore_investigation_from_json(json_str_or_data, repo)` performing complete round-trip restoration of investigation metadata, evidence files with cryptographic hash verification and 0444 read-only permissions, manifest verification, timeline database events, and audit chain-of-custody anchors. Logs `INVESTIGATION_RESTORED` ledger entry.
  - `src/evidence/manifest.py`: Added `EvidenceManifest.from_dict` classmethod supporting direct dictionary parsing with integrity digest verification.
  - `scripts/chronica_cli.py`: Passed skew estimates, integrity summary, audit ledger entries, and repository into `export_investigation_json`. Appended `INVESTIGATION_EXPORTED` audit ledger entry. Enforced non-zero exit code (`return 1`) when evidence vault integrity or audit chain verification fails or when execution raises an unhandled error.
  - `app.py`: Updated forensic report export generation in Module 9 to pass skew estimates, integrity summary, audit chain, and repository to `export_investigation_json`, and recorded `INVESTIGATION_EXPORTED` in the active audit ledger.
  - `tests/unit/test_backup_restore_and_cli_remediation.py`: Added comprehensive unit and adversarial tests for CLI non-zero exit codes on vault tampering or broken audit chain, JSON export/restore round trip, audit logging of exports, payload tampering detection, and evidence-free backup restoration.
- New test result (real, pasted):
```text
tests/unit/test_backup_restore_and_cli_remediation.py::test_reproduce_cli_exits_nonzero_on_tamper_or_chain_failure PASSED [ 16%]
tests/unit/test_backup_restore_and_cli_remediation.py::test_reproduce_json_backup_includes_skew_integrity_and_roundtrips PASSED [ 33%]
tests/unit/test_backup_restore_and_cli_remediation.py::test_reproduce_export_writes_audit_ledger_entry PASSED [ 50%]
tests/unit/test_backup_restore_and_cli_remediation.py::test_adversarial_restore_detects_tampered_evidence_payload PASSED [ 66%]
tests/unit/test_backup_restore_and_cli_remediation.py::test_adversarial_cli_exits_nonzero_on_broken_audit_chain PASSED [ 83%]
tests/unit/test_backup_restore_and_cli_remediation.py::test_adversarial_restore_backup_without_evidence_files PASSED [100%]

============================== 6 passed in 0.56s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 227 passed in 9.10s =============================
```
- Commit: e2dce0f fix(F-19): full JSON backup round-trip, audit-logged exports, and non-zero CLI failure exit
- Status: DONE
- Notes and surprises:
  The CLI previously always printed "[SUCCESS]" and returned exit code 0 even when it detected a hash mismatch ("FAILED (Integrity Mismatch)") or a severed chain of custody. Now it fails closed with exit code 1 whenever either check fails or whenever an unexpected error occurs during execution. In addition, the JSON export previously omitted evidence files and had no restore path; it is now a complete, restorable forensic backup bundle.

### Iteration 21 | Finding: F-23 | Started: 2026-11-10T12:35:00+05:30
- Reproduction test: `tests/unit/test_report_injection_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_report_injection_remediation.py::test_reproduce_markdown_export_escapes_images_and_html
AssertionError: Active markdown image syntax '![' must be neutralized/escaped
assert '![' not in '# Digital F.../iframe> |\n'
FAILED tests/unit/test_report_injection_remediation.py::test_reproduce_csv_formula_injection_defense
AssertionError: Expected '=..., got =1+1
assert False
where False = '=1+1'.startswith('\'=')
============================== 2 failed in 0.28s ==============================
```
- Change summary (files, why):
  - `src/reporting/csv_export.py`: Added `CSV_FORMULA_TRIGGERS` and `sanitize_csv_cell()` to prepend a single quote `'` to any cell beginning with formula triggers (`=`, `+`, `-`, `@`, `\t`, `\r`) or leading whitespace preceding a trigger, preventing DDE/formula execution when opened in Excel/LibreOffice. Preserved numeric types and normal text without quotes.
  - `src/reporting/markdown_export.py`: Added `_sanitize_md_text()` to escape raw HTML tags (`<` to `&lt;`, `>` to `&gt;`), escape markdown image markers (`!` to `\!`), and escape brackets (`[` to `\[`, `]` to `\]`). Integrated `_sanitize_md_text()` into `_md_cell()` and all case metadata, filtering criteria, and investigator notes fields.
  - `app.py`: Updated Live Report Preview in Module 9 to render markdown via `st.code(..., language="markdown")` rather than unescaped `st.markdown`, eliminating browser execution of HTML tags and image fetching in preview tabs.
  - `tests/unit/test_report_injection_remediation.py`: Created unit tests reproducing both vulnerabilities, plus adversarial tests covering nested markdown images in links, SVG/onload payloads, base64 data URIs, leading-whitespace formula triggers, and CSV column round trips.
- New test result (real, pasted):
```text
tests\unit\test_report_injection_remediation.py ....                     [100%]

============================== 4 passed in 0.20s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================= 231 passed in 9.90s =============================
```
- Commit: c744651 fix(F-23): escape markdown image/HTML tags and sanitize CSV formula triggers
- Status: DONE
- Notes and surprises:
  Raw markdown tables previously passed through unsanitized strings for description, notes, and tags, permitting `![beacon](http://...)` outbound SSRF/tracking image requests and phishing links. By neutralizing image and link brackets, HTML-escaping angle brackets, escaping CSV formula triggers, and rendering report previews using Streamlit's `st.code`, export and UI report inspection are protected against client-side execution.

### Iteration 22 | Finding: F-10 | Started: 2026-11-10T12:42:00+05:30
- Reproduction test: `tests/unit/test_passphrase_gate_and_security_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_passphrase_gate_and_security_remediation.py
ModuleNotFoundError: No module named 'src.security'
============================== 1 error in 0.37s ===============================
```
- Change summary (files, why):
  - Created `src/security/passphrase_gate.py`: Implemented local passphrase gate using salted PBKDF2-HMAC-SHA256 (100,000 iterations, 16-byte cryptographically secure random salt) and constant-time verification (`hmac.compare_digest`). Provided `check_destructive_action_authorized()`, `set_passphrase()`, `verify_passphrase()`, and `clear_passphrase()`.
  - `src/storage/repository.py`: Integrated `auth_file` and authorization check into `InvestigationRepository.delete_investigation()`, raising `PermissionError` when destructive deletion is attempted without valid passphrase.
  - `src/reporting/json_export.py`: Gated `export_investigation_json()` and `restore_investigation_from_json()` through `check_destructive_action_authorized()`.
  - `app.py`: Integrated passphrase gate prompt into Module 11 ("Manage Existing Workspaces") for case deletion and added a "Local Passphrase Security Gate" management panel allowing analysts to activate, verify, or disable the security gate.
  - `SECURITY.md`: Authored comprehensive project threat model documenting 127.0.0.1 default binding, STRIDE analysis, offline air-gap controls, salted KDF passphrase gate, and vulnerability reporting guidelines.
  - `tests/unit/test_passphrase_gate_and_security_remediation.py`: Created reproduction and adversarial tests for salted KDF verification, destructive action gating (delete, export, restore), empty passphrase rejection, secure clearing, and corrupted auth file fail-closed behavior.
- New test result (real, pasted):
```text
tests\unit\test_passphrase_gate_and_security_remediation.py .....        [100%]

============================== 5 passed in 0.72s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================ 236 passed in 14.91s =============================
```
- Commit: b40bb21 fix(F-10): salted KDF passphrase gate for destructive actions, loopback binding, and SECURITY.md threat model
- Status: DONE
- Notes and surprises:
  The application previously had no gate for destructive actions, allowing immediate deletion or export. The new `src/security/passphrase_gate.py` enforces salted PBKDF2-HMAC-SHA256 authorization when configured, while remaining completely optional and frictionless for single-user triage when unconfigured.

### Iteration 23 | Finding: F-04 | Started: 2026-11-10T12:48:00+05:30
- Reproduction test: `tests/unit/test_performance_heuristics_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_performance_heuristics_remediation.py::test_reproduce_event_cached_epoch_parsing
AssertionError: Event must provide effective_epoch property
FAILED tests/unit/test_performance_heuristics_remediation.py::test_reproduce_heuristics_sliding_window_scaling
AssertionError: Expected 6000 events to analyze in under 0.35s, took 6.230s
FAILED tests/unit/test_performance_heuristics_remediation.py::test_reproduce_bench_script_exists
AssertionError: scripts/bench.py must exist
============================== 3 failed in 6.42s ==============================
```
- Change summary (files, why):
  - `src/timeline/schema.py`: Added cached properties `normalized_epoch`, `corrected_epoch`, and `effective_epoch` to `Event`, caching parsed Unix timestamp floats and eliminating repeated `datetime.fromisoformat()` parsing across timeline analysis.
  - `src/diagnostics/heuristics.py`: Refactored `_detect_privilege_escalation` and `_detect_sensitive_data_export` to pre-filter candidate events in O(N) single-pass regex evaluation and use binary search (`bisect.bisect_right`) to slice temporal windows in O(log N + k), replacing the previous quadratic O(A * N) nested scans.
  - `src/diagnostics/heuristics.py`: Optimized `_detect_brute_force` to use `bisect.bisect_left` over precomputed group epochs.
  - `scripts/bench.py`: Created automated performance benchmark script generating synthetic workloads across 2k, 4k, 8k, 20k, and 100k events, printing performance and throughput metrics.
  - `tests/unit/test_performance_heuristics_remediation.py`: Added unit and adversarial tests covering cached epoch evaluation, sub-0.35s 6k event analysis, script existence, missing/corrupted timestamp robustness, and zero-auth early exit.
- New test result (real, pasted):
```text
tests\unit\test_performance_heuristics_remediation.py .....              [100%]

============================== 5 passed in 0.24s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================ 241 passed in 14.61s =============================
```
- Benchmark results (real, measured table from `scripts/bench.py`):
```text
================================================================================
CHRONICA FORENSIC HEURISTIC ENGINE BENCHMARK (F-04)
================================================================================
    Events |   Analysis Time |         Throughput |    Leads |     Status
--------------------------------------------------------------------------------
     2,000 |         0.036s |         55,945 ev/s |       40 | PASS (<60s)
     4,000 |         0.075s |         53,454 ev/s |       80 | PASS (<60s)
     8,000 |         0.154s |         51,994 ev/s |      160 | PASS (<60s)
    20,000 |         0.498s |         40,193 ev/s |      400 | PASS (<60s)
   100,000 |         8.990s |         11,123 ev/s |     2000 | PASS (<60s)
================================================================================
```
- Commit: c773cb9 fix(F-04): cached event epochs, sliding-window heuristics, and bench script for 100k events in <9s
- Status: DONE
- Notes and surprises:
  The quadratic bottleneck in `_detect_sensitive_data_export` and `_detect_privilege_escalation` was caused by running full regex searches across all N events for every authentication event (A * N regex invocations) while repeatedly re-parsing the same ISO timestamp strings. Pre-filtering matching candidates in O(N) once and using `bisect` for the temporal window reduced 100k event analysis time down to 8.99s, far exceeding the 60s benchmark requirement.

### Iteration 24 | Finding: F-20 | Started: 2026-11-10T12:55:00+05:30
- Reproduction test: `tests/unit/test_database_and_diagnostics_aggregation_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_database_and_diagnostics_aggregation_remediation.py::test_reproduce_diagnostics_aggregation_when_repetitive
AssertionError: Expected repetitive diagnostics to be aggregated (< 100 entries), got 5000
FAILED tests/unit/test_database_and_diagnostics_aggregation_remediation.py::test_reproduce_database_foreign_keys_and_connection_closing
AssertionError: Foreign keys must be ON: PRAGMA foreign_keys returned 0
FAILED tests/unit/test_database_and_diagnostics_aggregation_remediation.py::test_reproduce_database_schema_version_and_migrations
sqlite3.OperationalError: no such table: schema_version
FAILED tests/unit/test_database_and_diagnostics_aggregation_remediation.py::test_reproduce_investigations_and_evidence_files_tables_used
AssertionError: Expected investigations table to contain records
============================== 4 failed in 0.35s ==============================
```
- Change summary (files, why):
  - `src/diagnostics/gap_analysis.py`: Aggregated repetitive Category D timestamp ambiguity and non-standard format diagnostics by grouping on `(file, status, tz, yr)`. If a file encounters >3 repetitive diagnostics of the same type, an aggregated diagnostic record is generated showing total occurrences and the first 3 line examples (`L1, L2, L3...`), preventing thousands of redundant diagnostic alerts.
  - `src/storage/database.py`: Enforced `PRAGMA foreign_keys = ON;` on every SQLite connection. Implemented context-manager `@contextmanager def connection()` yielding `sqlite3.Connection` and guaranteeing `conn.close()` upon exit to prevent leaked file handles.
  - `src/storage/database.py`: Created `schema_version` table and implemented forward-only migrations (`_migrate_v1`, setting version to 1). Added `get_schema_version()`.
  - `src/storage/database.py` & `src/storage/repository.py`: Populated and maintained `investigations` and `evidence_files` tables during `create_investigation`, `update_investigation`, `save_manifest`, and `save_events`. Enforced cascading foreign key integrity.
  - `src/reporting/json_export.py`: Upserted parent investigation record prior to saving manifest child evidence files during JSON backup restoration.
  - `tests/unit/test_database_and_diagnostics_aggregation_remediation.py`: Added comprehensive unit and adversarial tests covering diagnostic aggregation limits, foreign key enforcement, connection auto-closing, schema migration idempotency, and cascading integrity.
- New test result (real, pasted):
```text
tests\unit\test_database_and_diagnostics_aggregation_remediation.py .... [ 57%]
...                                                                      [100%]

============================== 7 passed in 0.26s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================ 248 passed in 12.01s =============================
```
- Commit: de31adc fix(F-20): aggregate repetitive diagnostics, enable foreign keys, connection closing, and schema versioning
- Status: DONE
- Notes and surprises:
  In Python's standard `sqlite3`, using `with conn:` only manages a transaction, not the connection lifecycle itself, so connections remained open until garbage collection. Implementing `@contextmanager def connection()` with a `finally: conn.close()` block prevents file lock retention on Windows. When enabling `PRAGMA foreign_keys = ON`, `restore_investigation_from_json` needed to ensure the parent investigation record existed before child evidence files were inserted.

### Iteration 25 | Finding: F-21 | Started: 2026-11-10T13:12:00+05:30
- Reproduction test: `tests/unit/test_readme_and_synthetic_jitter_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_readme_and_synthetic_jitter_remediation.py::test_reproduce_readme_test_counts_inconsistency
AssertionError: README.md contains stale '104 passed' summary
FAILED tests/unit/test_readme_and_synthetic_jitter_remediation.py::test_reproduce_synthetic_generator_supports_jitter_drift_loss_duplicates
AssertionError: ScenarioGenerator must provide methods to inject jitter, drift, packet loss, duplicates, and out-of-order records
FAILED tests/unit/test_readme_and_synthetic_jitter_remediation.py::test_reproduce_skew_metrics_reports_error_distribution
AssertionError: Must report median error
FAILED tests/unit/test_readme_and_synthetic_jitter_remediation.py::test_skew_metrics_calculates_percentiles_correctly
AttributeError: 'SkewEvaluationMetric' object has no attribute 'post_correction_median_abs_error_sec'. Did you mean: 'post_correction_mean_abs_error_sec'?
============================== 4 failed in 0.19s ==============================
```
- Change summary (files, why):
  - `src/evaluation/metrics.py`: Extended `SkewEvaluationMetric` with error distribution metrics: `pre_correction_median_abs_error_sec`, `pre_correction_p95_abs_error_sec`, `pre_correction_max_abs_error_sec`, `post_correction_median_abs_error_sec`, `post_correction_p95_abs_error_sec`, and `post_correction_max_abs_error_sec`. Updated `BenchmarkEvaluator.evaluate_clock_skew` to compute full error distribution percentiles on timing residuals.
  - `src/evaluation/runner.py`: Updated benchmark CLI reporting to output comprehensive error distribution statistics (mean, median, p95, max) for both pre- and post-correction residuals.
  - `synthetic_data/generator.py`: Implemented `inject_evidence_noise()` supporting Gaussian timing jitter (`jitter_std_sec`), linear drift (`drift_ppm`), packet loss rate (`packet_loss_rate`), duplicates (`duplicate_rate`), and out-of-order log transpositions (`out_of_order_prob`). Added `generate_noisy_scenario()` and parameterized `generate_scenario_2()`.
  - `scripts/sync_test_metrics.py`: Created automated script to introspect pytest test collection and update `README.md` badge (`pytest-254 passed`), Section 6 test summary table, `docs/limitations.md`, and `docs/testing.md` dynamically from real test runs.
  - `tests/unit/test_readme_and_synthetic_jitter_remediation.py`: Added comprehensive unit and adversarial tests covering README synchronization, noise injection edge cases (100% loss, non-timestamped lines, 100% duplicate rate), and percentile computations on empty/degraded sets.
- New test result (real, pasted):
```text
tests\unit\test_readme_and_synthetic_jitter_remediation.py ......        [100%]

============================== 6 passed in 0.13s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================ 254 passed in 12.18s =============================
```
- Commit: 4343ba5 fix(F-21): add realistic noise to synthetic generator, report error distribution, and synchronize README test counts
- Status: DONE
- Notes and surprises:
  The synthetic benchmark previously tested a single deterministic offset without noise, yielding an artificial 0.0s error that demonstrated code execution rather than algorithmic resilience. By adding `inject_evidence_noise()` and percentile error distributions (`median`, `p95`, `max`) into `BenchmarkEvaluator` and `scripts/sync_test_metrics.py` to keep documentation metrics synchronized with the full suite, claims of test counts and timing accuracy are verified against reality.

### Iteration 26 | Finding: F-22 | Started: 2026-11-10T13:55:00+05:30
- Reproduction test: `tests/unit/test_devsecops_remediation.py`
- Failing output (real, pasted):
```text
FAILED tests/unit/test_devsecops_remediation.py::test_reproduce_devsecops_files_exist
AssertionError: Missing required DevSecOps files: ['.github\\dependabot.yml', '.pre-commit-config.yaml', 'CONTRIBUTING.md']
FAILED tests/unit/test_devsecops_remediation.py::test_reproduce_ci_runs_pip_audit
AssertionError: CI workflow must execute pip-audit
FAILED tests/unit/test_devsecops_remediation.py::test_reproduce_dependabot_config_valid
AssertionError: .github/dependabot.yml must exist
FAILED tests/unit/test_devsecops_remediation.py::test_reproduce_pre_commit_config_valid
AssertionError: .pre-commit-config.yaml must exist
FAILED tests/unit/test_devsecops_remediation.py::test_reproduce_license_and_contributing_clarity
AssertionError: CONTRIBUTING.md must exist
============================== 5 failed in 0.10s ==============================
```
- Change summary (files, why):
  - `.github/dependabot.yml`: Added automated weekly dependency vulnerability and version monitoring for both `pip` and `github-actions` ecosystems.
  - `.pre-commit-config.yaml`: Configured pre-commit hooks for whitespace cleanup (`trailing-whitespace`), newline termination (`end-of-file-fixer`), YAML syntax validation (`check-yaml`), large file blocking (`check-added-large-files`), and `ruff` linting.
  - `.github/workflows/ci.yml`: Added an automated `pip-audit` step to the CI test matrix to detect CVEs in third-party dependencies on pull requests and pushes.
  - `pyproject.toml`: Added `pip-audit>=2.7.0` to the `dev` dependencies.
  - `CONTRIBUTING.md`: Authored comprehensive contribution guidelines detailing development setup, forensic invariants, air-gap principles, verification commands (`pytest`, `ruff`, `pip-audit`), and conventional commit formats.
  - `tests/unit/test_devsecops_remediation.py`: Added unit and adversarial tests verifying all DevSecOps files, CI pip-audit invocation, YAML tab/formatting hygiene, and dependency version bounds.
- New test result (real, pasted):
```text
tests\unit\test_devsecops_remediation.py .......                         [100%]

============================== 7 passed in 0.06s ==============================
```
- Full suite result (real, pasted, with counts):
```text
============================ 261 passed in 12.31s =============================
```
- Commit: 739f4ce fix(F-22): add dependabot, pre-commit config, pip-audit in CI, and CONTRIBUTING.md
- Status: DONE
- Notes and surprises:
  Dependency audits and automated PR dependency management were previously absent from the project lifecycle. Introducing `pip-audit` in CI and `.github/dependabot.yml` ensures forensic supply-chain vulnerabilities are detected before code enters production.

## Open questions for the human
(only things the agent genuinely cannot decide)

## Decisions made
(any ambiguity resolved, with reasoning, so it can be reviewed)
