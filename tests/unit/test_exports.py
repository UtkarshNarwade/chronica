"""Unit tests for forensic report generators (JSON, CSV, Markdown, PDF)."""

import csv
import io
import json
import pytest

from src.diagnostics.gap_analysis import ParsingCoverageStats
from src.evidence.manifest import EvidenceFileEntry, EvidenceManifest
from src.reporting.csv_export import export_timeline_csv
from src.reporting.json_export import export_investigation_json
from src.reporting.markdown_export import export_markdown_report
from src.reporting.pdf_export import export_pdf_report
from src.storage.repository import InvestigationMetadata
from src.timeline.schema import Event


@pytest.fixture
def mock_export_data():
    meta = InvestigationMetadata(
        investigation_id="test_case_001",
        title="Unauthorized Data Access Investigation",
        description="Investigation into abnormal database exports.",
        created_at_utc="2026-10-12T10:00:00Z",
        last_updated_utc="2026-10-12T10:30:00Z",
        notes="Preliminary triage completed.",
    )
    manifest = EvidenceManifest(investigation_id=meta.investigation_id)
    manifest.add_entry(EvidenceFileEntry(
        evidence_id="ev_001",
        original_filename="audit.log",
        stored_filename="ev_001_audit.log",
        file_size_bytes=1024,
        sha256_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        collection_time_utc="2026-10-12T10:00:00Z",
        detected_format="syslog",
    ))
    events = [
        Event.create(
            investigation_id=meta.investigation_id,
            evidence_id="ev_001",
            original_filename="audit.log",
            line_number=1,
            raw_text="Accepted publickey for alice",
            original_timestamp_str="2026-10-12T10:00:00Z",
            normalized_utc_iso="2026-10-12T10:00:00Z",
            source_host="srv-app",
            severity="AUTH_SUCCESS",
            category="AUTHENTICATION",
            username="alice",
            src_ip="192.168.1.10",
        )
    ]
    coverage = ParsingCoverageStats(1, 1, 0, 1, 0, 0)
    return meta, manifest, events, coverage


def test_json_export_validity(mock_export_data):
    meta, manifest, events, coverage = mock_export_data
    json_str = export_investigation_json(
        metadata=meta,
        manifest=manifest,
        events=events,
        diagnostics=[],
        coverage_stats=coverage,
    )

    data = json.loads(json_str)
    assert data["investigation"]["investigation_id"] == "test_case_001"
    assert data["evidence_manifest"]["total_files"] == 1
    assert data["timeline_events_count"] == 1
    assert "forensic_disclaimer" in data


def test_csv_export_validity(mock_export_data):
    _, _, events, _ = mock_export_data
    csv_str = export_timeline_csv(events)

    reader = csv.reader(io.StringIO(csv_str))
    rows = list(reader)
    assert len(rows) == 2  # Header + 1 event
    assert rows[0][0] == "event_id"
    assert rows[1][8] == "alice"  # username


def test_markdown_export_has_all_17_sections(mock_export_data):
    meta, manifest, events, coverage = mock_export_data
    md_str = export_markdown_report(
        metadata=meta,
        manifest=manifest,
        events=events,
        diagnostics=[],
        coverage_stats=coverage,
    )

    # Check for presence of all numbered section headers 1 through 17
    for i in range(1, 18):
        assert f"## {i}." in md_str, f"Missing section {i} in Markdown report"


def test_pdf_export_generates_valid_pdf(mock_export_data):
    meta, manifest, events, coverage = mock_export_data
    pdf_bytes = export_pdf_report(
        metadata=meta,
        manifest=manifest,
        events=events,
        diagnostics=[],
        coverage_stats=coverage,
    )

    assert len(pdf_bytes) > 500
    # Standard PDF header check
    assert pdf_bytes.startswith(b"%PDF-")
