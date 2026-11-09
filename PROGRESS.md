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

## Open questions for the human
(only things the agent genuinely cannot decide)

## Decisions made
(any ambiguity resolved, with reasoning, so it can be reviewed)
