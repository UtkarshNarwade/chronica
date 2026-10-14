"""Unit tests for diagnostic taxonomy and parsing coverage statistics."""

import pytest

from src.diagnostics.gap_analysis import (
    DiagnosticCategory,
    DiagnosticSeverity,
    EvidenceGapAnalyzer,
    ParsingCoverageStats,
)
from src.evidence.manifest import EvidenceFileEntry, EvidenceManifest
from src.evidence.verification import (
    IntegrityStatus,
    InvestigationIntegritySummary,
    VerificationResult,
)
from src.timeline.clock_skew import ClockSkewEstimate
from src.timeline.schema import Event, NormalizationStatus


def test_coverage_statistics_calculation():
    events = [
        Event.create("inv1", "ev1", "f1", 1, "raw1", "2026-10-12T10:00:00Z", normalized_utc_iso="2026-10-12T10:00:00Z", parsing_status="SUCCESS"),
        Event.create("inv1", "ev1", "f1", 2, "raw2", "2026-10-12T10:01:00Z", normalized_utc_iso="2026-10-12T10:01:00Z", parsing_status="SUCCESS", year_inferred=True),
        Event.create("inv1", "ev1", "f1", 3, "raw3", None, normalization_status=NormalizationStatus.INVALID_TIMESTAMP.value, parsing_status="MALFORMED"),
    ]
    analyzer = EvidenceGapAnalyzer()
    stats = analyzer.compute_coverage_stats(events)

    assert stats.total_records_encountered == 3
    assert stats.successfully_parsed_records == 2
    assert stats.failed_records == 1
    assert stats.parsing_success_rate == 66.67
    assert stats.records_with_usable_timestamps == 2
    assert stats.records_requiring_assumptions == 1
    assert stats.assumption_rate == 50.0


def test_diagnostic_taxonomy_detection():
    analyzer = EvidenceGapAnalyzer(coverage_gap_threshold_sec=600.0)  # 10 min threshold

    events = [
        # Normal event 1 at 10:00:00
        Event.create("inv1", "ev1", "f1", 1, "raw text 1", "2026-10-12T10:00:00Z", normalized_utc_iso="2026-10-12T10:00:00Z", parsing_status="SUCCESS", source_host="srv1"),
        # Duplicate of event 1
        Event.create("inv1", "ev1", "f1", 2, "raw text 1", "2026-10-12T10:00:00Z", normalized_utc_iso="2026-10-12T10:00:00Z", parsing_status="SUCCESS", source_host="srv1"),
        # Malformed record (Category A)
        Event.create("inv1", "ev1", "f1", 3, "malformed {json", None, parsing_status="MALFORMED", source_host="srv1"),
        # Missing timestamp (Category C)
        Event.create("inv1", "ev1", "f1", 4, "no ts log line", None, normalization_status=NormalizationStatus.MISSING_TIMESTAMP.value, source_host="srv1"),
        # Auth event lacking user & IP (Category E)
        Event.create("inv1", "ev1", "f1", 5, "auth fail", "2026-10-12T10:02:00Z", normalized_utc_iso="2026-10-12T10:02:00Z", category="AUTHENTICATION", source_host="srv1"),
        # Coverage gap: event at 10:30:00 (28 mins after 10:02:00 > 10 min threshold -> Category F)
        Event.create("inv1", "ev1", "f1", 6, "resumed after quiet", "2026-10-12T10:30:00Z", normalized_utc_iso="2026-10-12T10:30:00Z", source_host="srv1"),
    ]

    integrity_summary = InvestigationIntegritySummary(
        investigation_id="inv1",
        verification_time_utc="2026-10-12T11:00:00Z",
        total_files=1,
        verified_files=0,
        mismatched_files=1,
        unavailable_files=0,
        results=[
            VerificationResult(
                evidence_id="ev1",
                original_filename="f1",
                stored_path="/path/f1",
                status=IntegrityStatus.MISMATCH,
                recorded_sha256="expected_hash",
                calculated_sha256="altered_hash",
                verification_time_utc="2026-10-12T11:00:00Z",
                details="Hash mismatch detected.",
            )
        ],
    )

    skew_estimates = {
        "srv2": ClockSkewEstimate(
            target_source="srv2",
            reference_source="srv1",
            anchor_count=1,
            estimated_offset_sec=None,
            status="INCONCLUSIVE_INSUFFICIENT_ANCHORS",
            explanation="Only 1 anchor found.",
        )
    }

    diagnostics = analyzer.analyze(
        events=events,
        integrity_summary=integrity_summary,
        skew_estimates=skew_estimates,
    )

    categories = {d.category for d in diagnostics}
    assert DiagnosticCategory.A_PARSE_FAILURE in categories
    assert DiagnosticCategory.C_TIMESTAMP_FAILURE in categories
    assert DiagnosticCategory.E_MISSING_FIELD_WARNING in categories
    assert DiagnosticCategory.F_COVERAGE_GAP in categories
    assert DiagnosticCategory.G_UNRESOLVED_CLOCK_SKEW in categories
    assert DiagnosticCategory.H_EVIDENCE_INTEGRITY_ISSUE in categories
    assert DiagnosticCategory.I_DUPLICATE_CANDIDATE in categories
