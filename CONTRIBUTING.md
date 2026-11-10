# Contributing to Chronica

Thank you for contributing to Chronica! As a digital forensics timeline and evidence analysis workbench, our core mission is **forensic correctness, chain-of-custody integrity, and reproducible evidence handling**.

Forensic accuracy always beats new features and speed.

---

## 1. Development Setup

Chronica requires Python 3.11 or newer. We recommend using a clean virtual environment:

```bash
# Clone the repository
git clone https://github.com/UtkarshNarwade/chronica.git
cd chronica

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install editable package with development dependencies
pip install -e .[dev]

# Install pre-commit hooks
pre-commit install
```

---

## 2. Invariants & Code Standards

Every contribution must strictly adhere to the following forensic invariants:

1. **Evidence is Read-Only Forever:** No code path may modify, rename, or delete evidence files after ingestion (`chmod 0444`). All operations run on in-memory buffers or isolated sandbox copies.
2. **Audit Ledger Logging:** Every state-changing action (`ingest`, `delete`, `export`, `analyze`, `restore`) must append an immutable entry to the SHA-256 audit ledger with anchored chain heads. If ledger writing fails, the action must fail loudly.
3. **No Silent Error Swallowing:** Never use bare `except Exception: pass`. Parsing anomalies must produce visible `DiagnosticEntry` records with explicit root causes.
4. **Honest Timestamps:** Record original string, normalized UTC, corrected UTC, confidence, and method used. Never guess timestamps silently.
5. **Air-Gapped Operation:** Zero remote telemetry, zero CDN assets, zero external network calls at runtime. Local loopback binding (`127.0.0.1`) only.

---

## 3. Running Verification & Quality Checks

Before submitting a Pull Request, ensure that all automated checks pass locally:

### Run Test Suite
```bash
python -m pytest
```

### Run Linter
```bash
ruff check src tests scripts
```

### Run Dependency Vulnerability Scan
```bash
pip-audit
```

### Pre-commit Formatting
```bash
pre-commit run --all-files
```

---

## 4. Submitting Pull Requests

1. **One Finding/Feature Per PR:** Keep changes focused and minimal.
2. **Test First:** Write a failing reproduction test for any bug fix before implementing code changes.
3. **Commit Messages:** Follow conventional commits:
   - `fix(F-XX): <short summary>`
   - `feat(U-XX): <short summary>`
   - `chore: <short summary>`
4. **Documentation:** Update README metrics using `python scripts/sync_test_metrics.py` when test suites expand.

