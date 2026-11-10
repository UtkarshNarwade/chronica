"""Unit tests for F-23: Report injection defenses (Markdown and CSV formula injection)."""

import csv
import io
import pytest

from src.diagnostics.gap_analysis import ParsingCoverageStats
from src.evidence.manifest import EvidenceFileEntry, EvidenceManifest
from src.reporting.csv_export import export_timeline_csv
from src.reporting.markdown_export import _md_cell, export_markdown_report
from src.storage.repository import InvestigationMetadata
from src.timeline.schema import Event


def test_reproduce_markdown_export_escapes_images_and_html():
    """Markdown export must sanitize/neutralize ![img](...), [link](...), and raw HTML tags."""
    meta = InvestigationMetadata(
        investigation_id="inv_inj_001",
        title="Test Case <script>alert('title')</script>",
        description="Case description with ![banner](http://attacker.example/banner.png)",
        created_at_utc="2026-10-12T10:00:00Z",
        last_updated_utc="2026-10-12T10:00:00Z",
        notes="Notes with <img src='http://attacker.example/pixel.gif'/> and [phish](http://evil.com)",
    )
    manifest = EvidenceManifest(investigation_id="inv_inj_001")
    manifest.add_entry(EvidenceFileEntry(
        evidence_id="ev_001",
        original_filename="bad_file_<script>.log",
        stored_filename="ev_001_bad.log",
        file_size_bytes=100,
        sha256_digest="abc",
        collection_time_utc="2026-10-12T10:00:00Z",
        detected_format="web_access",
    ))
    event = Event.create(
        investigation_id="inv_inj_001",
        evidence_id="ev_001",
        original_filename="bad_file.log",
        line_number=1,
        raw_text='GET /login HTTP/1.1 ![beacon](http://attacker.example/p.png) <img src="http://evil.com/x">',
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00.000000Z",
        source_host="host1",
        severity="INFO",
        description='User logged in ![beacon](http://attacker.example/p.png) <img src="http://evil.com/x"> [Click here](http://malicious.example)',
        extra_fields={
            "bookmarked": True,
            "tags": ["![tag_img](http://attacker/tag.png)"],
            "analyst_note": "Look at <iframe src='http://evil.com'></iframe>",
        },
    )

    coverage = ParsingCoverageStats(1, 1, 0, 1, 0, 0)
    report = export_markdown_report(
        metadata=meta,
        manifest=manifest,
        events=[event],
        diagnostics=[],
        coverage_stats=coverage,
    )

    # 1. No unescaped markdown image syntax ![...](...)
    assert "![" not in report, "Active markdown image syntax '![' must be neutralized/escaped"
    # 2. No raw dangerous HTML tags (<script>, <img, <iframe)
    assert "<script" not in report.lower(), "Raw <script> tags must be sanitized/escaped"
    assert "<img" not in report.lower(), "Raw <img> tags must be sanitized/escaped"
    assert "<iframe" not in report.lower(), "Raw <iframe> tags must be sanitized/escaped"


def test_reproduce_csv_formula_injection_defense():
    """CSV export must prefix formula trigger characters (=, +, -, @, \\t, \\r) with a single quote."""
    dangerous_events = [
        Event.create(
            investigation_id="inv_csv_001",
            evidence_id="ev_001",
            original_filename="audit.log",
            line_number=1,
            raw_text="=cmd|' /C calc'!A0",
            original_timestamp_str="2026-10-12T10:00:00Z",
            normalized_utc_iso="2026-10-12T10:00:00.000000Z",
            source_host="+evil-host",
            source_app="-evil-app",
            severity="WARNING",
            username="@admin_user",
            description="=1+1",
        ),
        Event.create(
            investigation_id="inv_csv_001",
            evidence_id="ev_001",
            original_filename="audit.log",
            line_number=2,
            raw_text="\t=cmd|' /C calc'!A0",
            original_timestamp_str="2026-10-12T10:01:00Z",
            normalized_utc_iso="2026-10-12T10:01:00.000000Z",
            source_host="normal-host",
            source_app="normal-app",
            severity="INFO",
            username="normal_user",
            description="\r-dangerous_formula",
        ),
    ]

    csv_text = export_timeline_csv(dangerous_events)
    reader = list(csv.reader(io.StringIO(csv_text)))
    headers = reader[0]
    row1 = dict(zip(headers, reader[1]))
    row2 = dict(zip(headers, reader[2]))

    # Cells with trigger characters must be prefixed with a single quote '
    assert row1["description"].startswith("'="), f"Expected '=..., got {row1['description']}"
    assert row1["raw_text"].startswith("'="), f"Expected '=..., got {row1['raw_text']}"
    assert row1["host"].startswith("'+"), f"Expected '+..., got {row1['host']}"
    assert row1["app"].startswith("'-"), f"Expected '-..., got {row1['app']}"
    assert row1["username"].startswith("'@"), f"Expected '@..., got {row1['username']}"

    # Tab and carriage return triggers
    assert row2["raw_text"].startswith("'\t") or row2["raw_text"].startswith("'="), f"Tab trigger not escaped: {row2['raw_text']}"
    assert row2["description"].startswith("'\r") or row2["description"].startswith("'-"), f"CR trigger not escaped: {row2['description']}"

    # Benign cells must NOT be prefixed with single quote
    assert not row2["host"].startswith("'"), f"Benign host should not be escaped: {row2['host']}"
    assert not row2["username"].startswith("'"), f"Benign username should not be escaped: {row2['username']}"


def test_adversarial_nested_and_svg_markdown_injection():
    """Adversarial check: nested markdown image-in-link, SVG onload, and data URI payloads."""
    meta = InvestigationMetadata(
        investigation_id="inv_adv_001",
        title="Adversarial Payload Test",
        description="Testing nested injections",
        created_at_utc="2026-10-12T10:00:00Z",
        last_updated_utc="2026-10-12T10:00:00Z",
        notes="[![nested](http://attacker.example/beacon.png)](http://evil.com) <svg onload=alert(document.cookie)>",
    )
    manifest = EvidenceManifest(investigation_id="inv_adv_001")
    event = Event.create(
        investigation_id="inv_adv_001",
        evidence_id="ev_adv",
        original_filename="syslog.log",
        line_number=1,
        raw_text='sshd: <SVG/ONLOAD=alert(1)> ![data](data:image/svg+xml;base64,PHN2Zz4=)',
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00.000000Z",
        source_host="linux-01",
        severity="CRITICAL",
        description='Nested beacon: [![nested_img](http://tracker.example/pixel.gif)](http://tracker.example) <IMG SRC="javascript:alert(1)">',
    )
    coverage = ParsingCoverageStats(1, 1, 0, 1, 0, 0)
    report = export_markdown_report(
        metadata=meta,
        manifest=manifest,
        events=[event],
        diagnostics=[],
        coverage_stats=coverage,
    )

    # Must neutralize all image triggers and HTML tags
    assert "![" not in report, "Active image syntax must not appear in report"
    assert "<svg" not in report.lower(), "Raw SVG tags must not appear in report"
    assert "<img" not in report.lower(), "Raw IMG tags must not appear in report"
    assert "onload" in report.lower() or "&lt;svg" in report.lower()  # Escaped content is retained safely as text


def test_adversarial_csv_formula_whitespace_and_numbers():
    """Adversarial check: leading spaces before formulas, numeric safety, and clean RFC 4180 parsing."""
    events = [
        Event.create(
            investigation_id="inv_adv_csv",
            evidence_id="ev_1",
            original_filename="clean.log",
            line_number=42,  # Numeric int
            raw_text="   =HYPERLINK('http://attacker.example', 'Click')",
            original_timestamp_str="2026-10-12T12:00:00Z",
            normalized_utc_iso="2026-10-12T12:00:00.000000Z",
            source_host="web-01",
            source_app="nginx",
            severity="INFO",
            username="alice",
            description=" \t@SUM(1,2)",
        ),
        Event.create(
            investigation_id="inv_adv_csv",
            evidence_id="ev_2",
            original_filename="clean.log",
            line_number=43,
            raw_text="Normal syslog line without formulas",
            original_timestamp_str="2026-10-12T12:01:00Z",
            normalized_utc_iso="2026-10-12T12:01:00.000000Z",
            source_host="db-01",
            source_app="postgres",
            severity="ERROR",
            username="postgres",
            description="-5.4 offset note",  # Starts with hyphen, must be neutralized
        ),
    ]

    csv_text = export_timeline_csv(events)
    reader = list(csv.reader(io.StringIO(csv_text)))
    headers = reader[0]
    row1 = dict(zip(headers, reader[1]))
    row2 = dict(zip(headers, reader[2]))

    # Formula with leading spaces
    assert row1["raw_text"].startswith("'"), f"Leading-space formula must be escaped: {row1['raw_text']}"
    assert row1["description"].startswith("'"), f"Leading-tab @SUM formula must be escaped: {row1['description']}"

    # Hyphen prefix neutralized
    assert row2["description"].startswith("'-"), f"Leading hyphen must be escaped: {row2['description']}"

    # Integer line_number must not have quotes prepended
    assert row1["line_number"] == "42"
    assert row2["line_number"] == "43"

    # Standard timestamps must remain untouched
    assert row1["normalized_utc"] == "2026-10-12T12:00:00.000000Z"
    assert row2["normalized_utc"] == "2026-10-12T12:01:00.000000Z"
