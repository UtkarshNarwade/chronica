"""Tests reproducing and verifying F-07:
- Tamper lab must operate only on a throwaway COPY in a temp dir, never on stored evidence.
- Real evidence file hash must be 100% unchanged before and after simulation.
- Unsafe restore is removed.
- No .bak files created in evidence or case directories.
"""

import shutil
import tempfile
from pathlib import Path

from src.evidence.verification import simulate_isolated_tamper_check, IntegrityStatus
from src.pipeline import ForensicPipeline
from src.storage.repository import InvestigationRepository


def test_isolated_tamper_simulation_leaves_original_evidence_unchanged():
    """Reproduce F-07: Tamper lab must never mutate stored evidence files."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_f07_test_"))
    try:
        repo = InvestigationRepository(data_root=temp_dir)
        meta = repo.create_investigation("case_tamper_lab", "Tamper Lab Case", "analyst")
        pipeline = ForensicPipeline(repo)

        raw_bytes = b"Oct 12 10:00:00 srv1 sshd[123]: Accepted password for alice from 10.0.0.1 port 22\n"
        preserved, _ = pipeline.ingest_evidence_bytes(
            investigation_id=meta.investigation_id,
            filename="auth.log",
            data=raw_bytes,
        )

        stored_path = preserved.stored_path
        original_hash_before = preserved.sha256_digest
        assert stored_path.read_bytes() == raw_bytes

        # Run isolated tamper simulation
        sim_res = simulate_isolated_tamper_check(
            stored_path=stored_path,
            recorded_sha256=preserved.sha256_digest,
            evidence_id=preserved.evidence_id,
            original_filename=preserved.original_filename,
        )

        # Baseline was verified
        assert sim_res["baseline"].status == IntegrityStatus.VERIFIED
        # Tampered copy was caught as MISMATCH
        assert sim_res["tampered_copy"].status == IntegrityStatus.MISMATCH
        assert sim_res["tampered_copy"].calculated_sha256 != original_hash_before

        # Stored evidence file was NOT mutated:
        assert sim_res["original_unaltered"] is True
        assert sim_res["original_post_check"].status == IntegrityStatus.VERIFIED
        assert stored_path.read_bytes() == raw_bytes

        # No .bak files were created in evidence dir or investigation dir
        ev_dir = repo.get_evidence_dir(meta.investigation_id)
        inv_dir = repo._get_inv_dir(meta.investigation_id)
        assert len(list(ev_dir.glob("*.bak"))) == 0
        assert len(list(inv_dir.glob("*.bak"))) == 0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_adversarial_empty_evidence_file_tamper_simulation():
    """Adversarial check 1: Simulating tampering on a 0-byte file must detect alteration and not crash."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_f07_empty_"))
    try:
        repo = InvestigationRepository(data_root=temp_dir)
        meta = repo.create_investigation("case_empty", "Empty Case", "analyst")
        pipeline = ForensicPipeline(repo)

        preserved, _ = pipeline.ingest_evidence_bytes(
            investigation_id=meta.investigation_id,
            filename="empty.log",
            data=b"",
        )

        sim_res = simulate_isolated_tamper_check(
            stored_path=preserved.stored_path,
            recorded_sha256=preserved.sha256_digest,
            evidence_id=preserved.evidence_id,
            original_filename=preserved.original_filename,
        )

        assert sim_res["baseline"].status == IntegrityStatus.VERIFIED
        assert sim_res["tampered_copy"].status == IntegrityStatus.MISMATCH
        assert sim_res["original_unaltered"] is True
        assert preserved.stored_path.stat().st_size == 0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_adversarial_repeated_tamper_simulations_keep_evidence_pristine():
    """Adversarial check 2: Running repeated tamper simulations across multiple files never alters evidence."""
    import hashlib

    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_f07_repeat_"))
    try:
        repo = InvestigationRepository(data_root=temp_dir)
        meta = repo.create_investigation("repeat_test_case", "Repeat Test Case", "analyst")
        pipeline = ForensicPipeline(repo)

        raw = b"Oct 12 10:00:00 srv1 sshd[123]: Test auth line\n"
        preserved, _ = pipeline.ingest_evidence_bytes(
            investigation_id=meta.investigation_id,
            filename="app_auth.log",
            data=raw,
        )

        hash_before = hashlib.sha256(preserved.stored_path.read_bytes()).hexdigest()

        # Run tamper simulation 5 times consecutively
        for i in range(5):
            res = simulate_isolated_tamper_check(
                stored_path=preserved.stored_path,
                recorded_sha256=preserved.sha256_digest,
                evidence_id=preserved.evidence_id,
                original_filename=preserved.original_filename,
            )
            assert res["baseline"].status == IntegrityStatus.VERIFIED
            assert res["tampered_copy"].status == IntegrityStatus.MISMATCH
            assert res["original_unaltered"] is True

        # Verify hash on disk after 5 runs is strictly identical
        hash_after = hashlib.sha256(preserved.stored_path.read_bytes()).hexdigest()
        assert hash_before == hash_after
        assert len(list(repo.get_evidence_dir(meta.investigation_id).glob("*.bak"))) == 0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

