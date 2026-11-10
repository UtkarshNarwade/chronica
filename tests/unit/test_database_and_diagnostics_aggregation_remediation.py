"""Unit tests for F-20: Diagnostic aggregation, foreign keys, connection closing, schema versioning, and table utilization."""

import sqlite3
from pathlib import Path
import pytest

from src.diagnostics.gap_analysis import DiagnosticCategory, EvidenceGapAnalyzer
from src.evidence.manifest import EvidenceFileEntry, EvidenceManifest
from src.storage.database import DatabaseManager
from src.storage.repository import InvestigationMetadata, InvestigationRepository
from src.timeline.schema import Event, NormalizationStatus


def test_reproduce_category_d_diagnostics_aggregation():
    """Repetitive Category D diagnostics must be aggregated rather than producing thousands of identical entries."""
    events = []
    for i in range(100):
        ev = Event.create(
            investigation_id="diag_test",
            evidence_id="ev_001",
            original_filename="syslog.log",
            line_number=i + 1,
            raw_text=f"Oct 12 10:00:{i%60:02d} host sshd: log message {i}",
            original_timestamp_str=f"Oct 12 10:00:{i%60:02d}",
            normalized_utc_iso=f"2026-10-12T10:00:{i%60:02d}.000000Z",
            normalization_status=NormalizationStatus.NORMALIZED_ASSUMED_TZ.value,
            timezone_assumed="UTC",
            year_inferred=True,
            severity="INFO",
        )
        events.append(ev)

    analyzer = EvidenceGapAnalyzer()
    diagnostics = analyzer.analyze(events)

    cat_d_items = [d for d in diagnostics if d.category == DiagnosticCategory.D_TIMESTAMP_AMBIGUITY]
    # In unaggregated code, this produces 100 separate diagnostics
    assert len(cat_d_items) < 10, f"Expected aggregated Category D diagnostics, got {len(cat_d_items)}"
    agg_d = cat_d_items[0]
    assert "100" in agg_d.explanation or "100" in agg_d.affected_target
    assert "L1" in agg_d.affected_target or "L1" in agg_d.supporting_details


def test_reproduce_foreign_keys_enabled_and_enforced(tmp_path):
    """PRAGMA foreign_keys=ON must be enabled, rejecting orphaned events without an investigation."""
    db_path = tmp_path / "test_fk.db"
    db = DatabaseManager(db_path)

    # Verify foreign_keys pragma is enabled on connections
    with db.connection() as conn:
        fk_status = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
        assert fk_status == 1, "PRAGMA foreign_keys must be enabled (1)"

    # Attempting to save event for non-existent investigation must raise IntegrityError
    orphan_event = Event.create(
        investigation_id="non_existent_case",
        evidence_id="ev_001",
        original_filename="test.log",
        line_number=1,
        raw_text="Test",
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00.000000Z",
    )
    with pytest.raises(sqlite3.IntegrityError):
        db.save_events("non_existent_case", [orphan_event])


def test_reproduce_schema_version_and_migrations(tmp_path):
    """Database must maintain a schema_version table with forward migrations."""
    db_path = tmp_path / "test_mig.db"
    db = DatabaseManager(db_path)

    with db.connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'")
        assert cur.fetchone() is not None, "schema_version table must exist"

        cur.execute("SELECT MAX(version) FROM schema_version")
        ver = cur.fetchone()[0]
        assert ver is not None and ver >= 1, f"Schema version must be >= 1, got {ver}"

    assert db.get_schema_version() >= 1


def test_reproduce_investigations_and_evidence_tables_populated(tmp_path):
    """investigations and evidence_files tables must be populated and utilized by InvestigationRepository."""
    repo = InvestigationRepository(data_root=tmp_path / "cases")
    meta = repo.create_investigation("case_tbl_01", "Table Utilization Test", description="Testing DB records")

    # Verify investigation record exists in SQLite
    with repo.db.connection() as conn:
        row = conn.execute("SELECT * FROM investigations WHERE investigation_id = ?", ("case_tbl_01",)).fetchone()
        assert row is not None, "investigations table must contain created case"
        assert row["title"] == "Table Utilization Test"

    # Save evidence in manifest
    manifest = repo.get_manifest("case_tbl_01")
    manifest.add_entry(EvidenceFileEntry(
        evidence_id="ev_tbl_01",
        original_filename="auth.log",
        stored_filename="ev_tbl_01_auth.log",
        file_size_bytes=2048,
        sha256_digest="abcdef123456",
        collection_time_utc="2026-10-12T10:00:00Z",
        detected_format="syslog",
    ))
    repo.save_manifest("case_tbl_01", manifest)

    # Verify evidence record exists in SQLite
    with repo.db.connection() as conn:
        ev_row = conn.execute("SELECT * FROM evidence_files WHERE evidence_id = ?", ("ev_tbl_01",)).fetchone()
        assert ev_row is not None, "evidence_files table must contain manifest entry"
        assert ev_row["original_filename"] == "auth.log"


def test_adversarial_connection_closed_on_exit(tmp_path):
    """Adversarial check: connection context manager closes the sqlite3 connection."""
    db_path = tmp_path / "test_close.db"
    db = DatabaseManager(db_path)

    captured_conn = None
    with db.connection() as conn:
        captured_conn = conn
        assert conn.execute("SELECT 1").fetchone()[0] == 1

    # After exiting with block, attempting a query on the captured connection must fail
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        captured_conn.execute("SELECT 1")


def test_adversarial_cascading_foreign_key_deletion(tmp_path):
    """Adversarial check: deleting parent investigation cascades to evidence_files and events."""
    repo = InvestigationRepository(data_root=tmp_path / "cases_cascade")
    repo.create_investigation("case_cascade_01", "Cascade Test")

    manifest = repo.get_manifest("case_cascade_01")
    manifest.add_entry(EvidenceFileEntry(
        evidence_id="ev_c1",
        original_filename="cascade.log",
        stored_filename="ev_c1.log",
        file_size_bytes=100,
        sha256_digest="123456",
        collection_time_utc="2026-10-12T10:00:00Z",
        detected_format="syslog",
    ))
    repo.save_manifest("case_cascade_01", manifest)

    event = Event.create(
        investigation_id="case_cascade_01",
        evidence_id="ev_c1",
        original_filename="cascade.log",
        line_number=1,
        raw_text="Cascade event",
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00.000000Z",
    )
    repo.save_events("case_cascade_01", [event])

    # Verify rows exist
    with repo.db.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM investigations WHERE investigation_id = 'case_cascade_01'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM evidence_files WHERE investigation_id = 'case_cascade_01'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM events WHERE investigation_id = 'case_cascade_01'").fetchone()[0] == 1

    # Delete investigation
    repo.delete_investigation("case_cascade_01")

    # Verify cascading delete cleared evidence_files and events
    with repo.db.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM investigations WHERE investigation_id = 'case_cascade_01'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM evidence_files WHERE investigation_id = 'case_cascade_01'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM events WHERE investigation_id = 'case_cascade_01'").fetchone()[0] == 0


def test_adversarial_small_category_d_remains_granular():
    """Adversarial check: <= 3 Category D occurrences remain individual diagnostics."""
    events = [
        Event.create(
            investigation_id="small_diag",
            evidence_id="ev_1",
            original_filename="auth.log",
            line_number=i + 1,
            raw_text=f"Auth log {i}",
            original_timestamp_str="Oct 12 10:00:00",
            normalized_utc_iso="2026-10-12T10:00:00.000000Z",
            normalization_status=NormalizationStatus.NORMALIZED_ASSUMED_TZ.value,
            timezone_assumed="UTC",
            year_inferred=True,
            severity="INFO",
        )
        for i in range(2)
    ]
    analyzer = EvidenceGapAnalyzer()
    diagnostics = analyzer.analyze(events)
    cat_d = [d for d in diagnostics if d.category == DiagnosticCategory.D_TIMESTAMP_AMBIGUITY]
    # For 2 events, each line is reported individually
    assert len(cat_d) == 2
    assert "auth.log:L1" in [d.affected_target for d in cat_d]
    assert "auth.log:L2" in [d.affected_target for d in cat_d]
