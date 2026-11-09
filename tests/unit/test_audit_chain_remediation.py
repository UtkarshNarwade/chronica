"""Tests reproducing and verifying F-05:
- Tail truncation must be detected via SQLite / sidecar anchor.
- Whole-chain rewrite must be detected via anchored head hash.
- Corrupt last line must fail closed, never fork the chain.
- Ledger write failures must raise loudly, never be swallowed.
- File locking must prevent race conditions on concurrent appends.
"""

import shutil
import tempfile
from pathlib import Path
import pytest
from src.evidence.audit_chain import AuditChainLedger


def test_tail_truncation_must_be_detected():
    """Reproduce F-05 defect 1: Truncating the last entry passes verification because verify_chain has no anchor."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_audit_trunc_"))
    try:
        ledger = AuditChainLedger(temp_dir)
        ledger.append("CASE_CREATED", "Case created")
        ledger.append("EVIDENCE_INGESTED", "File 1 ingested")
        ledger.append("EVIDENCE_INGESTED", "File 2 ingested")

        # Truncate the last line from audit_chain.jsonl
        lines = ledger.ledger_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 3
        # Remove the 3rd line
        ledger.ledger_path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")

        # Verification MUST fail because seq=2 < anchored seq=3
        is_valid, count, err = ledger.verify_chain()
        assert is_valid is False, "Truncated chain must FAIL verification!"
        assert err is not None
        assert "truncat" in err.lower() or "seq" in err.lower()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_whole_chain_rewrite_must_be_detected():
    """Reproduce F-05 defect 2: Rewriting the entire chain with new valid hashes passes verification without anchor."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_audit_rewrite_"))
    try:
        ledger = AuditChainLedger(temp_dir)
        ledger.append("CASE_CREATED", "Case created")
        ledger.append("EVIDENCE_INGESTED", "Original evidence ingested")

        # An attacker rewrites the chain with 2 completely different entries with self-consistent hashes
        fake_ledger_dir = Path(tempfile.mkdtemp(prefix="chronica_fake_"))
        try:
            fake_ledger = AuditChainLedger(fake_ledger_dir)
            fake_ledger.append("CASE_CREATED", "Forged case")
            fake_ledger.append("EVIDENCE_INGESTED", "Forged evidence")
            # Copy forged chain over real chain
            ledger.ledger_path.write_text(fake_ledger.ledger_path.read_text(encoding="utf-8"), encoding="utf-8")
        finally:
            shutil.rmtree(fake_ledger_dir, ignore_errors=True)

        is_valid, count, err = ledger.verify_chain()
        assert is_valid is False, "Rewritten chain must FAIL verification against anchored head!"
        assert err is not None
        assert "rewrite" in err.lower() or "anchor" in err.lower() or "mismatch" in err.lower()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_corrupt_last_line_must_fail_closed_not_fork():
    """Reproduce F-05 defect 3: Corrupt last line causes append to restart at seq_id=1 and GENESIS_HASH."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_audit_fork_"))
    try:
        ledger = AuditChainLedger(temp_dir)
        ledger.append("CASE_CREATED", "Case created")

        # Corrupt the last line in the ledger file
        with open(ledger.ledger_path, "a", encoding="utf-8") as f:
            f.write("{corrupt json\n")

        # Appending should NOT silently restart from seq_id=1, prev_hash=GENESIS (forking the chain)
        with pytest.raises(Exception):
            ledger.append("EVIDENCE_INGESTED", "Next evidence")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_adversarial_concurrent_appends_preserve_chain_integrity():
    """Adversarial check 1: Concurrent appends from multiple threads must serialize without race conditions."""
    from concurrent.futures import ThreadPoolExecutor

    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_audit_concurrent_"))
    try:
        ledger = AuditChainLedger(temp_dir)
        num_threads = 10

        def do_append(idx: int):
            return ledger.append("EVENT_ANNOTATED", f"Thread {idx} event", {"thread_idx": idx})

        with ThreadPoolExecutor(max_workers=5) as executor:
            entries = list(executor.map(do_append, range(num_threads)))

        assert len(entries) == num_threads
        seq_ids = [e.seq_id for e in sorted(entries, key=lambda x: x.seq_id)]
        assert seq_ids == list(range(1, num_threads + 1)), f"Expected sequential 1..10, got {seq_ids}"

        # Entire chain must verify cleanly
        is_valid, total, err = ledger.verify_chain()
        assert is_valid is True, f"Concurrent chain verification failed: {err}"
        assert total == num_threads
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_adversarial_deleted_ledger_file_detected_by_anchors():
    """Adversarial check 2: Deleting audit_chain.jsonl while anchor exists must fail verification."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_audit_deleted_"))
    try:
        ledger = AuditChainLedger(temp_dir)
        ledger.append("CASE_CREATED", "Case created")
        ledger.append("EVIDENCE_INGESTED", "File ingested")

        # Delete audit_chain.jsonl
        ledger.ledger_path.unlink()

        is_valid, total, err = ledger.verify_chain()
        assert is_valid is False
        assert err is not None
        assert "deleted" in err.lower() or "missing" in err.lower()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_adversarial_corrupt_intermediate_line_fails_verification():
    """Adversarial check 3: Corrupt line in middle of chain must fail verification at that exact line."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_audit_midcorrupt_"))
    try:
        ledger = AuditChainLedger(temp_dir)
        ledger.append("CASE_CREATED", "Entry 1")
        ledger.append("EVIDENCE_INGESTED", "Entry 2")
        ledger.append("EVIDENCE_INGESTED", "Entry 3")

        lines = ledger.ledger_path.read_text(encoding="utf-8").strip().splitlines()
        # Corrupt line 2 (1-indexed)
        lines[1] = "NOT_VALID_JSON{{"
        ledger.ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        is_valid, count, err = ledger.verify_chain()
        assert is_valid is False
        assert err is not None
        assert "line 2" in err
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_adversarial_pipeline_fails_loudly_on_ledger_write_failure():
    """Adversarial check 4: Pipeline ingest must fail loudly (raise) if audit ledger write fails."""
    from unittest.mock import patch
    from src.pipeline import ForensicPipeline
    from src.storage.repository import InvestigationRepository

    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_audit_pipe_"))
    try:
        repo = InvestigationRepository(data_root=temp_dir)
        meta = repo.create_investigation("pipe_audit_test", "Pipe Audit Test", "analyst")
        pipeline = ForensicPipeline(repo)

        raw_log = b"Oct 12 10:00:00 srv1 sshd[123]: Accepted password for alice from 10.0.0.1 port 22\n"

        with patch.object(AuditChainLedger, "append", side_effect=OSError("Disk full / permission denied")):
            with pytest.raises(OSError, match="Disk full"):
                pipeline.ingest_evidence_bytes(
                    investigation_id=meta.investigation_id,
                    filename="auth.log",
                    data=raw_log,
                )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

