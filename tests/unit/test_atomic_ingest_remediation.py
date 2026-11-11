"""Tests reproducing and verifying F-08:
- WindowsEventParser int(None) crash handling.
- Windows CSV per-line error handling (no broad except swallow).
- Atomic ingest: fault injection mid-ingest leaves zero orphan files, rows, or manifest entries.
- Archive preservation: original archive is stored, hashed, and recorded in manifest along with member hashes.
"""

import io
import shutil
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch
import pytest

from src.parsers.windows_event_parser import WindowsEventParser
from src.pipeline import ForensicPipeline
from src.storage.repository import InvestigationRepository


def test_reproduce_windows_event_parser_int_none_crash():
    """Reproduce F-08 defect 1: WindowsEventParser crashes on EventID: null."""
    parser = WindowsEventParser()
    json_log = '[{"EventID": null, "TimeCreated": "2026-10-12T10:00:00Z", "Computer": "WIN-SRV"}]'

    # Without fix, int(None) raises TypeError
    records = list(parser.parse_stream(iter(json_log.splitlines())))
    assert len(records) == 1
    assert records[0].extra_fields.get("event_id") == 0


def test_reproduce_windows_csv_error_does_not_abort_subsequent_rows():
    """Reproduce F-08 defect 2: Broad except in CSV parser swallows subsequent rows without warning."""
    parser = WindowsEventParser()
    # 3 lines of CSV: line 1 valid, line 2 malformed/bad, line 3 valid
    csv_lines = [
        "TimeCreated,EventID,Computer,Message",
        "2026-10-12 10:00:00,4624,WIN-SRV,Valid login",
        "2026-10-12 10:01:00,,WIN-SRV,Valid event missing ID",
        "2026-10-12 10:02:00,4634,WIN-SRV,Valid logoff",
    ]

    records = list(parser.parse_stream(iter(csv_lines)))
    # Must parse all 3 data rows (2, 3, 4)
    assert len(records) == 3
    assert records[0].parse_status == "SUCCESS"
    assert records[1].parse_status in ("SUCCESS", "PARTIAL", "MALFORMED")
    assert records[2].parse_status == "SUCCESS"


def test_reproduce_atomic_ingest_rollback_on_fault_injection():
    """Reproduce F-08 defect 3: Mid-ingest failure leaves orphan evidence file on disk."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_f08_atomic_"))
    try:
        repo = InvestigationRepository(data_root=temp_dir)
        meta = repo.create_investigation("atomic_case", "Atomic Case", "analyst")
        pipeline = ForensicPipeline(repo)

        ev_dir = repo.get_evidence_dir(meta.investigation_id)

        # Fault injection: normalizer raises an unexpected exception mid-ingest
        with patch.object(pipeline.normalizer, "normalize", side_effect=RuntimeError("Simulated mid-ingest crash")):
            with pytest.raises(RuntimeError, match="Simulated mid-ingest crash"):
                pipeline.ingest_evidence_bytes(
                    investigation_id=meta.investigation_id,
                    filename="crash.log",
                    data=b"Oct 12 10:00:00 srv1 sshd[1]: Crash test line\n",
                )

        # ZERO orphan files in evidence directory
        assert len(list(ev_dir.iterdir())) == 0, f"Expected 0 evidence files, found {list(ev_dir.iterdir())}"
        # ZERO manifest entries
        manifest = repo.get_manifest(meta.investigation_id)
        assert len(manifest.entries) == 0
        # ZERO SQLite events
        events = repo.load_events(meta.investigation_id)
        assert len(events) == 0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_reproduce_archive_preserves_original_archive_and_member_hashes():
    """Reproduce F-08 defect 4: Ingesting an archive must preserve the original archive file and member hashes."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_f08_arch_"))
    try:
        repo = InvestigationRepository(data_root=temp_dir)
        meta = repo.create_investigation("arch_case", "Archive Case", "analyst")
        pipeline = ForensicPipeline(repo)

        # Create zip in memory with 2 files
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("syslog1.log", b"Oct 12 10:00:00 srv1 sshd[1]: user 1\n")
            zf.writestr("syslog2.log", b"Oct 12 10:01:00 srv2 sshd[2]: user 2\n")
        zip_bytes = buf.getvalue()

        pipeline.ingest_evidence_bytes(
            investigation_id=meta.investigation_id,
            filename="bundle.zip",
            data=zip_bytes,
        )

        manifest = repo.get_manifest(meta.investigation_id)
        ev_dir = repo.get_evidence_dir(meta.investigation_id)

        # Original bundle.zip must be preserved on disk in evidence directory
        zip_entries = [e for e in manifest.entries if e.original_filename == "bundle.zip"]
        assert len(zip_entries) == 1, "Original archive must have a manifest entry!"
        archive_entry = zip_entries[0]
        assert archive_entry.ingestion_status == "ARCHIVE"
        assert (ev_dir / archive_entry.stored_filename).is_file()

        # Archive metadata must record member hashes
        assert "member_hashes" in archive_entry.metadata or "members" in archive_entry.metadata

        # Extracted members must also have manifest entries and events
        member_entries = [e for e in manifest.entries if e.original_filename != "bundle.zip"]
        assert len(member_entries) == 2
        events = repo.load_events(meta.investigation_id)
        assert len(events) == 2
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_adversarial_db_save_failure_rolls_back_evidence():
    """Adversarial check 1: Failure during SQLite save_events rolls back preserved evidence file."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_f08_dberr_"))
    try:
        repo = InvestigationRepository(data_root=temp_dir)
        meta = repo.create_investigation("db_err_case", "DB Err Case", "analyst")
        pipeline = ForensicPipeline(repo)

        ev_dir = repo.get_evidence_dir(meta.investigation_id)

        with patch.object(repo, "save_events", side_effect=OSError("Simulated database write error")):
            with pytest.raises(OSError, match="database write error"):
                pipeline.ingest_evidence_bytes(
                    investigation_id=meta.investigation_id,
                    filename="dberr.log",
                    data=b"Oct 12 10:00:00 srv1 sshd[1]: DB error test\n",
                )

        assert len(list(ev_dir.iterdir())) == 0, "Evidence file must be rolled back on DB save error!"
        assert len(repo.get_manifest(meta.investigation_id).entries) == 0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_adversarial_corrupt_archive_member_rolls_back_archive_and_members():
    """Adversarial check 2: Failure while processing archive member rolls back archive file and events."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_f08_archfail_"))
    try:
        repo = InvestigationRepository(data_root=temp_dir)
        meta = repo.create_investigation("arch_fail_case", "Archive Fail Case", "analyst")
        pipeline = ForensicPipeline(repo)

        ev_dir = repo.get_evidence_dir(meta.investigation_id)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("ok.log", b"Oct 12 10:00:00 srv1 sshd[1]: ok\n")
            zf.writestr("fail.log", b"Oct 12 10:01:00 srv2 sshd[2]: fail\n")
        zip_bytes = buf.getvalue()

        # Mock second file ingest to fail
        original_ingest = pipeline.ingest_evidence_bytes

        def failing_ingest(*args, **kwargs):
            if kwargs.get("filename") == "fail.log" or (len(args) > 1 and args[1] == "fail.log"):
                raise ValueError("Simulated member failure")
            return original_ingest(*args, **kwargs)

        with patch.object(pipeline, "ingest_evidence_bytes", side_effect=failing_ingest):
            with pytest.raises(ValueError, match="Simulated member failure"):
                pipeline.ingest_evidence_bytes(
                    investigation_id=meta.investigation_id,
                    filename="bad_bundle.zip",
                    data=zip_bytes,
                )

        # Original archive file must NOT remain as an orphan
        assert not (ev_dir / "bad_bundle.zip").exists()
        assert not any(f.name.endswith("bad_bundle.zip") for f in ev_dir.iterdir())
        # Member 'ok.log' processed before failure must also be cleanly rolled back
        assert not any("ok.log" in f.name for f in ev_dir.iterdir())
        manifest = repo.get_manifest(meta.investigation_id)
        assert len(manifest.entries) == 0, f"Expected 0 manifest entries, got {len(manifest.entries)}"
        assert len(repo.load_events(meta.investigation_id)) == 0, "Expected 0 events in database after rollback"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

