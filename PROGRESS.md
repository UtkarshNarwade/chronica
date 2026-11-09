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

## Open questions for the human
(only things the agent genuinely cannot decide)

## Decisions made
(any ambiguity resolved, with reasoning, so it can be reviewed)
