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
- Commit: pending
- Status: DONE
- Notes and surprises:
  `pip install -e .[dev]` successfully built and installed editable chronica wheel. Mypy on Windows has an AppLocker/Application Control block for its C-extension DLL locally, but ruff runs cleanly and mypy config is established in pyproject.toml for CI.

## Open questions for the human
(only things the agent genuinely cannot decide)

## Decisions made
(any ambiguity resolved, with reasoning, so it can be reviewed)
