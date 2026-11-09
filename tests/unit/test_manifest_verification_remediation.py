"""Tests reproducing and verifying F-06:
- Manifest sha256 must be verified on load.
- Tampering with both evidence and manifest together must fail verification (manifest anchored in ledger).
- Evidence directory permissions must be 0700 (or platform read/write restricted to owner).
- Evidence files must be 0444 (read-only).
- delete_investigation must write a durable tombstone entry to a surviving ledger.
"""

import json
import os
import shutil
import stat
import tempfile
from pathlib import Path
import pytest

from src.evidence.manifest import EvidenceManifest, EvidenceFileEntry
from src.evidence.verification import IntegrityStatus
from src.pipeline import ForensicPipeline
from src.storage.repository import InvestigationRepository


def test_reproduce_edit_evidence_and_manifest_together_must_fail():
    """Reproduce F-06 defect 1: Editing evidence and manifest together passes verification unless manifest is anchored in ledger."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_f06_tamper_"))
    try:
        repo = InvestigationRepository(data_root=temp_dir)
        meta = repo.create_investigation("case_f06", "Case F06", "analyst")
        pipeline = ForensicPipeline(repo)

        raw_log = b"Oct 12 10:00:00 srv1 sshd[123]: Accepted password for alice from 10.0.0.1 port 22\n"
        preserved, _ = pipeline.ingest_evidence_bytes(
            investigation_id=meta.investigation_id,
            filename="auth.log",
            data=raw_log,
        )

        # Baseline: verification passes
        summary = repo.verify_evidence_integrity(meta.investigation_id)
        assert summary.all_verified is True

        # Attacker modifies stored evidence file
        ev_file = preserved.stored_path
        # On Windows/POSIX, ensure writable to tamper
        ev_file.chmod(stat.S_IWRITE | stat.S_IREAD)
        ev_file.write_bytes(b"Oct 12 10:00:00 srv1 sshd[123]: Accepted password for evil from 10.0.0.1 port 22\n")

        # Attacker also modifies manifest.json to match the new hash!
        import hashlib
        new_ev_sha = hashlib.sha256(ev_file.read_bytes()).hexdigest()
        manifest_path = repo._get_inv_dir(meta.investigation_id) / "manifest.json"
        m_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        m_data["entries"][0]["sha256_digest"] = new_ev_sha

        # Recompute manifest_sha256 in manifest.json so internal json hash matches
        raw_to_hash = json.dumps({k: v for k, v in m_data.items() if k != "manifest_sha256"}, sort_keys=True, indent=2).encode("utf-8")
        m_data["manifest_sha256"] = hashlib.sha256(raw_to_hash).hexdigest()
        manifest_path.write_text(json.dumps(m_data, indent=2), encoding="utf-8")

        # Now verify again:
        # WITHOUT the fix, this passes because verify_evidence_integrity only checks evidence vs manifest!
        summary2 = repo.verify_evidence_integrity(meta.investigation_id)
        assert summary2.all_verified is False, "Tampering both evidence and manifest must FAIL verification!"
        assert any(r.evidence_id == "__manifest__" or r.status == IntegrityStatus.MISMATCH for r in summary2.results)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_reproduce_manifest_load_verifies_internal_digest():
    """Reproduce F-06 defect 2: load_from_file ignores manifest_sha256 tampering."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_f06_mload_"))
    try:
        manifest_path = temp_dir / "manifest.json"
        manifest = EvidenceManifest(investigation_id="test_inv")
        manifest.add_entry(EvidenceFileEntry(
            evidence_id="ev_1",
            original_filename="test.log",
            stored_filename="ev_1_test.log",
            file_size_bytes=100,
            sha256_digest="a" * 64,
            collection_time_utc="2026-10-12T10:00:00Z",
            record_count=1,
            assigned_timezone="UTC",
        ))
        manifest.save_to_file(manifest_path)

        # Tamper with an entry in manifest.json without updating manifest_sha256
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        data["entries"][0]["original_filename"] = "tampered.log"
        manifest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        # Loading must raise an integrity error because manifest_sha256 doesn't match
        with pytest.raises(Exception):
            EvidenceManifest.load_from_file(manifest_path)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_reproduce_delete_investigation_writes_surviving_tombstone():
    """Reproduce F-06 defect 3: delete_investigation leaves no audit record."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_f06_del_"))
    try:
        repo = InvestigationRepository(data_root=temp_dir)
        meta = repo.create_investigation("del_case", "Delete Case", "analyst")

        repo.delete_investigation(meta.investigation_id)

        # Investigation dir is deleted
        assert not repo._get_inv_dir(meta.investigation_id).exists()

        # But a tombstone audit ledger must survive in data_root
        tombstone_ledger = repo.get_tombstone_ledger()
        entries = tombstone_ledger.list_entries()
        assert len(entries) >= 1
        assert any(e.action == "INVESTIGATION_DELETED" and e.details.get("investigation_id") == "del_case" for e in entries)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_adversarial_sequential_ingestions_anchor_latest_manifest():
    """Adversarial check 1: Ingesting multiple files sequentially updates anchored manifest digest cleanly."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_f06_multi_"))
    try:
        repo = InvestigationRepository(data_root=temp_dir)
        meta = repo.create_investigation("multi_case", "Multi Ingest Case", "analyst")
        pipeline = ForensicPipeline(repo)

        pipeline.ingest_evidence_bytes(
            investigation_id=meta.investigation_id,
            filename="auth1.log",
            data=b"Oct 12 10:00:00 srv1 sshd[1]: user 1\n",
        )
        pipeline.ingest_evidence_bytes(
            investigation_id=meta.investigation_id,
            filename="auth2.log",
            data=b"Oct 12 10:01:00 srv1 sshd[2]: user 2\n",
        )

        summary = repo.verify_evidence_integrity(meta.investigation_id)
        assert summary.all_verified is True
        assert summary.total_files == 3  # 1 manifest + 2 evidence files
        assert summary.verified_files == 3
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_adversarial_tombstone_ledger_integrity_after_multiple_deletions():
    """Adversarial check 2: Multiple deletions append sequentially and verify chain in tombstone ledger."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_f06_tomb_"))
    try:
        repo = InvestigationRepository(data_root=temp_dir)
        m1 = repo.create_investigation("case_a", "Case A", "analyst")
        m2 = repo.create_investigation("case_b", "Case B", "analyst")

        repo.delete_investigation(m1.investigation_id)
        repo.delete_investigation(m2.investigation_id)

        tombstone_ledger = repo.get_tombstone_ledger()
        is_valid, count, err = tombstone_ledger.verify_chain()
        assert is_valid is True, f"Tombstone chain verification failed: {err}"
        assert count == 2

        entries = tombstone_ledger.list_entries()
        assert entries[0].details["investigation_id"] == "case_a"
        assert entries[1].details["investigation_id"] == "case_b"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_adversarial_evidence_file_read_only_and_dir_permissions():
    """Adversarial check 3: Evidence files must have read-only permissions (0444) and dir 0700."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_f06_perm_"))
    try:
        repo = InvestigationRepository(data_root=temp_dir)
        meta = repo.create_investigation("perm_case", "Perm Case", "analyst")
        pipeline = ForensicPipeline(repo)

        preserved, _ = pipeline.ingest_evidence_bytes(
            investigation_id=meta.investigation_id,
            filename="readonly.log",
            data=b"Oct 12 10:00:00 srv1 sshd[10]: Read only test\n",
        )

        ev_path = preserved.stored_path
        ev_dir = repo.get_evidence_dir(meta.investigation_id)

        # File should be read-only (stat.S_IWRITE should not be set for non-owners, or read-only on Windows)
        mode = ev_path.stat().st_mode
        # On all platforms (including Windows), S_IREAD is set
        assert bool(mode & stat.S_IREAD) is True
        # On Windows stat.S_IWRITE is cleared for read-only files; on POSIX check 0o444
        if os.name != "nt":
            assert (mode & 0o777) == 0o444
            dir_mode = ev_dir.stat().st_mode
            assert (dir_mode & 0o777) == 0o700
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

