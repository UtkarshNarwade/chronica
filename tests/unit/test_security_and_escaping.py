"""Security, path traversal, and escaping tests.

Tests:
- InvestigationRepository.sanitize_investigation_id rejects dangerous inputs
- PDF export handles malicious XML/SSRF content without crash
- Markdown export handles pipe characters and newlines in table cells
"""

import pytest

from src.diagnostics.gap_analysis import ParsingCoverageStats
from src.evidence.manifest import EvidenceFileEntry, EvidenceManifest
from src.reporting.markdown_export import _md_cell, export_markdown_report
from src.reporting.pdf_export import _esc, export_pdf_report
from src.storage.repository import InvestigationMetadata, InvestigationRepository
from src.timeline.schema import Event


# ── sanitize_investigation_id ────────────────────────────────────────────────

class TestSanitizeInvestigationId:
    """Tests for InvestigationRepository.sanitize_investigation_id."""

    def test_valid_ids_pass(self):
        valid = ["case_001", "INV-2026", "test123", "a", "A" * 128]
        for v in valid:
            result = InvestigationRepository.sanitize_investigation_id(v)
            assert result == v.strip()

    def test_path_traversal_rejected(self):
        with pytest.raises(ValueError, match="Invalid investigation_id"):
            InvestigationRepository.sanitize_investigation_id("../../etc/passwd")

    def test_slash_rejected(self):
        with pytest.raises(ValueError, match="Invalid investigation_id"):
            InvestigationRepository.sanitize_investigation_id("case/1")

    def test_empty_string_rejected(self):
        with pytest.raises(ValueError):
            InvestigationRepository.sanitize_investigation_id("")

    def test_whitespace_only_rejected(self):
        with pytest.raises(ValueError):
            InvestigationRepository.sanitize_investigation_id("   ")

    def test_too_long_rejected(self):
        with pytest.raises(ValueError, match="128"):
            InvestigationRepository.sanitize_investigation_id("A" * 129)

    def test_special_chars_rejected(self):
        bad_inputs = ["case.1", "case 1", "case@1", "case!1", "../secret"]
        for bad in bad_inputs:
            with pytest.raises(ValueError, match="Invalid investigation_id"):
                InvestigationRepository.sanitize_investigation_id(bad)

    def test_strips_whitespace(self):
        result = InvestigationRepository.sanitize_investigation_id("  case_001  ")
        assert result == "case_001"


# ── _esc (XML escape for PDF) ────────────────────────────────────────────────

class TestXmlEscape:
    """Tests for _esc() PDF XML escaping."""

    def test_ampersand_escaped(self):
        assert _esc("GET /login?a=1&b=2") == "GET /login?a=1&amp;b=2"

    def test_less_than_escaped(self):
        assert _esc("<script>alert('xss')</script>") == "&lt;script&gt;alert('xss')&lt;/script&gt;"

    def test_greater_than_escaped(self):
        assert _esc("a > b") == "a &gt; b"

    def test_none_becomes_empty_string(self):
        assert _esc(None) == ""

    def test_int_converted(self):
        assert _esc(42) == "42"

    def test_img_ssrf_escaped(self):
        val = '<img src="http://127.0.0.1"/>'
        escaped = _esc(val)
        assert "<img" not in escaped
        assert "&lt;img" in escaped


# ── PDF export with dangerous content ────────────────────────────────────────

@pytest.fixture
def dangerous_events():
    """Events containing content that could crash ReportLab or inject SSRF."""
    events = [
        Event.create(
            investigation_id="sec_test",
            evidence_id="ev_001",
            original_filename="access.log",
            line_number=1,
            raw_text='GET /api?user=alice&role=admin HTTP/1.1 200',
            original_timestamp_str="2026-10-12T10:00:00Z",
            normalized_utc_iso="2026-10-12T10:00:00.000000Z",
            source_host="web-srv",
            severity="INFO",
            description='GET /api?user=alice&role=admin HTTP/1.1',
        ),
        Event.create(
            investigation_id="sec_test",
            evidence_id="ev_001",
            original_filename="audit.log",
            line_number=2,
            raw_text='<script>alert("xss")</script>',
            original_timestamp_str="2026-10-12T10:01:00Z",
            normalized_utc_iso="2026-10-12T10:01:00.000000Z",
            source_host="web-srv",
            severity="WARNING",
            description='<script>alert("xss")</script>',
        ),
        Event.create(
            investigation_id="sec_test",
            evidence_id="ev_001",
            original_filename="system.log",
            line_number=3,
            raw_text='<img src="http://127.0.0.1/steal"/>',
            original_timestamp_str="2026-10-12T10:02:00Z",
            normalized_utc_iso="2026-10-12T10:02:00.000000Z",
            source_host="app-srv",
            severity="CRITICAL",
            description='<img src="http://127.0.0.1/steal"/>',
        ),
        Event.create(
            investigation_id="sec_test",
            evidence_id="ev_001",
            original_filename="auth.log",
            line_number=4,
            raw_text="cat /etc/passwd | grep root",
            original_timestamp_str="2026-10-12T10:03:00Z",
            normalized_utc_iso="2026-10-12T10:03:00.000000Z",
            source_host="app-srv",
            severity="AUTH_FAIL",
            description="cat /etc/passwd | grep root",
        ),
    ]
    return events


@pytest.fixture
def basic_meta():
    return InvestigationMetadata(
        investigation_id="sec_test_001",
        title="Security & Escaping Test Investigation",
        description="Tests PDF and Markdown with dangerous content including & < > | newlines.",
        created_at_utc="2026-10-12T10:00:00Z",
        last_updated_utc="2026-10-12T10:30:00Z",
        notes="Notes with <dangerous> content & special chars.",
    )


@pytest.fixture
def basic_manifest(basic_meta):
    manifest = EvidenceManifest(investigation_id=basic_meta.investigation_id)
    manifest.add_entry(EvidenceFileEntry(
        evidence_id="ev_001",
        original_filename="access.log",
        stored_filename="ev_001_access.log",
        file_size_bytes=1024,
        sha256_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        collection_time_utc="2026-10-12T10:00:00Z",
        detected_format="web_access",
    ))
    return manifest


def test_pdf_export_with_xml_dangerous_content(basic_meta, basic_manifest, dangerous_events):
    """PDF export must succeed without crash when events contain &, <, >, SSRF payloads."""
    coverage = ParsingCoverageStats(4, 4, 0, 4, 0, 0)
    pdf_bytes = export_pdf_report(
        metadata=basic_meta,
        manifest=basic_manifest,
        events=dangerous_events,
        diagnostics=[],
        coverage_stats=coverage,
    )
    assert pdf_bytes.startswith(b"%PDF-"), "Output must be valid PDF"
    assert len(pdf_bytes) > 500


def test_pdf_export_with_pipe_and_newline_in_notes(basic_manifest, dangerous_events):
    """PDF export must not crash when metadata.notes contains & and < chars."""
    meta = InvestigationMetadata(
        investigation_id="sec_test_002",
        title="Case with <Special> Notes & Flags",
        description="Test <description> with &ampersands.",
        created_at_utc="2026-10-12T10:00:00Z",
        last_updated_utc="2026-10-12T10:30:00Z",
        notes="Note line 1 with & ampersand\nNote line 2 with <tags>\nURL: http://example.com?a=1&b=2",
    )
    coverage = ParsingCoverageStats(1, 1, 0, 1, 0, 0)
    pdf_bytes = export_pdf_report(
        metadata=meta,
        manifest=basic_manifest,
        events=dangerous_events[:1],
        diagnostics=[],
        coverage_stats=coverage,
    )
    assert pdf_bytes.startswith(b"%PDF-")


# ── Markdown escaping ─────────────────────────────────────────────────────────

class TestMarkdownCellEscape:
    """Tests for _md_cell() Markdown table cell escaping."""

    def test_pipe_escaped(self):
        result = _md_cell("value | with | pipes")
        assert "|" not in result.replace(r"\|", "")
        assert r"\|" in result

    def test_newline_collapsed(self):
        result = _md_cell("line1\nline2\r\nline3")
        assert "\n" not in result
        assert "\r" not in result

    def test_none_becomes_empty(self):
        assert _md_cell(None) == ""

    def test_int_converted(self):
        assert _md_cell(42) == "42"


def test_markdown_export_survives_pipe_in_description(basic_meta, basic_manifest, dangerous_events):
    """Markdown export must not break table rows when events contain | in description."""
    coverage = ParsingCoverageStats(4, 4, 0, 4, 0, 0)
    md_str = export_markdown_report(
        metadata=basic_meta,
        manifest=basic_manifest,
        events=dangerous_events,
        diagnostics=[],
        coverage_stats=coverage,
    )
    # Sections 1-17 must all be present
    for i in range(1, 18):
        assert f"## {i}." in md_str, f"Missing section {i}"
    # Raw pipe from "cat /etc/passwd | grep root" should be escaped in table rows
    # The | character in description should appear escaped as \| in table context


def test_markdown_export_section_18_present_with_bookmarks(basic_meta, basic_manifest, dangerous_events):
    """Section 18 appears in report when bookmarked events are present."""
    # Add bookmark to first event
    dangerous_events[0].extra_fields["bookmarked"] = True
    dangerous_events[0].extra_fields["tags"] = ["Key Evidence"]
    dangerous_events[0].extra_fields["analyst_note"] = "This is the primary suspicious request."

    coverage = ParsingCoverageStats(4, 4, 0, 4, 0, 0)
    md_str = export_markdown_report(
        metadata=basic_meta,
        manifest=basic_manifest,
        events=dangerous_events,
        diagnostics=[],
        coverage_stats=coverage,
    )
    assert "## 18." in md_str, "Section 18 should appear when bookmarked events are present"
    assert "Chain-of-Custody" in md_str
