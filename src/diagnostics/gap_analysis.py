"""Forensic diagnostics and evidence-gap taxonomy engine.

Identifies parsing failures, timestamp ambiguities, quiet-period gaps,
clock skew limitations, and integrity violations according to an explainable taxonomy.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from src.evidence.manifest import EvidenceManifest
from src.evidence.verification import IntegrityStatus, InvestigationIntegritySummary
from src.timeline.clock_skew import ClockSkewEstimate
from src.timeline.schema import Event, NormalizationStatus


class DiagnosticCategory(str, Enum):
    A_PARSE_FAILURE = "A_PARSE_FAILURE"
    B_UNSUPPORTED_RECORD = "B_UNSUPPORTED_RECORD"
    C_TIMESTAMP_FAILURE = "C_TIMESTAMP_FAILURE"
    D_TIMESTAMP_AMBIGUITY = "D_TIMESTAMP_AMBIGUITY"
    E_MISSING_FIELD_WARNING = "E_MISSING_FIELD_WARNING"
    F_COVERAGE_GAP = "F_COVERAGE_GAP"
    G_UNRESOLVED_CLOCK_SKEW = "G_UNRESOLVED_CLOCK_SKEW"
    H_EVIDENCE_INTEGRITY_ISSUE = "H_EVIDENCE_INTEGRITY_ISSUE"
    I_DUPLICATE_CANDIDATE = "I_DUPLICATE_CANDIDATE"


class DiagnosticSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class DiagnosticItem:
    """A structured finding representing a data-quality, integrity, or timing limitation."""
    diag_id: str
    category: DiagnosticCategory
    severity: DiagnosticSeverity
    affected_target: str  # File name, host, or event ID
    explanation: str
    supporting_details: str
    suggested_action: str
    timestamp_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d


@dataclass
class ParsingCoverageStats:
    """Quantitative coverage metrics with explicit denominators."""
    total_records_encountered: int
    successfully_parsed_records: int
    failed_records: int
    records_with_usable_timestamps: int
    records_requiring_assumptions: int
    unresolved_records: int

    @property
    def parsing_success_rate(self) -> float:
        """Percentage of total records successfully parsed."""
        if self.total_records_encountered == 0:
            return 100.0
        return round((self.successfully_parsed_records / self.total_records_encountered) * 100.0, 2)

    @property
    def parsing_failure_rate(self) -> float:
        """Percentage of total records that failed parsing."""
        if self.total_records_encountered == 0:
            return 0.0
        return round((self.failed_records / self.total_records_encountered) * 100.0, 2)

    @property
    def timestamp_usability_rate(self) -> float:
        """Percentage of successfully parsed records that have usable timestamps."""
        if self.successfully_parsed_records == 0:
            return 100.0
        return round((self.records_with_usable_timestamps / self.successfully_parsed_records) * 100.0, 2)

    @property
    def assumption_rate(self) -> float:
        """Percentage of usable timestamps that required timezone or year assumptions."""
        if self.records_with_usable_timestamps == 0:
            return 0.0
        return round((self.records_requiring_assumptions / self.records_with_usable_timestamps) * 100.0, 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_records_encountered": self.total_records_encountered,
            "successfully_parsed_records": self.successfully_parsed_records,
            "failed_records": self.failed_records,
            "records_with_usable_timestamps": self.records_with_usable_timestamps,
            "records_requiring_assumptions": self.records_requiring_assumptions,
            "unresolved_records": self.unresolved_records,
            "parsing_success_rate_percent": self.parsing_success_rate,
            "parsing_failure_rate_percent": self.parsing_failure_rate,
            "timestamp_usability_rate_percent": self.timestamp_usability_rate,
            "assumption_rate_percent": self.assumption_rate,
            "denominators": {
                "parsing_denominator": "total_records_encountered",
                "timestamp_denominator": "successfully_parsed_records",
                "assumption_denominator": "records_with_usable_timestamps",
            },
        }


class EvidenceGapAnalyzer:
    """Evaluates evidence files, events, integrity audits, and clock skew for data-quality gaps."""

    def __init__(self, coverage_gap_threshold_sec: float = 1800.0) -> None:
        """
        Args:
            coverage_gap_threshold_sec: Minimum quiet period in seconds to trigger
                                        a coverage gap warning (default: 30 minutes).
        """
        self.coverage_gap_threshold_sec = coverage_gap_threshold_sec

    def compute_coverage_stats(self, events: List[Event]) -> ParsingCoverageStats:
        """Calculate coverage statistics with explicit denominators."""
        total = len(events)
        parsed = sum(1 for e in events if e.parsing_status in ("SUCCESS", "PARTIAL"))
        failed = sum(1 for e in events if e.parsing_status in ("MALFORMED", "UNSUPPORTED"))

        usable_ts = sum(
            1 for e in events
            if e.normalized_utc_iso is not None and e.normalization_status not in (
                NormalizationStatus.INVALID_TIMESTAMP.value,
                NormalizationStatus.MISSING_TIMESTAMP.value,
            )
        )

        assumptions = sum(
            1 for e in events
            if e.normalization_status in (
                NormalizationStatus.NORMALIZED_ASSUMED_TZ.value,
                NormalizationStatus.NORMALIZED_CONFIGURED_TZ.value,
            ) or e.year_inferred
        )

        unresolved = sum(
            1 for e in events
            if e.normalization_status in (
                NormalizationStatus.INVALID_TIMESTAMP.value,
                NormalizationStatus.MISSING_TIMESTAMP.value,
            ) or e.parsing_status == "MALFORMED"
        )

        return ParsingCoverageStats(
            total_records_encountered=total,
            successfully_parsed_records=parsed,
            failed_records=failed,
            records_with_usable_timestamps=usable_ts,
            records_requiring_assumptions=assumptions,
            unresolved_records=unresolved,
        )

    def analyze(
        self,
        events: List[Event],
        manifest: Optional[EvidenceManifest] = None,
        integrity_summary: Optional[InvestigationIntegritySummary] = None,
        skew_estimates: Optional[Dict[str, ClockSkewEstimate]] = None,
    ) -> List[DiagnosticItem]:
        """Generate structured diagnostic findings across all nine categories."""
        diagnostics: List[DiagnosticItem] = []
        diag_idx = 1

        # H: Evidence Integrity Issues
        if integrity_summary:
            for res in integrity_summary.results:
                if res.status == IntegrityStatus.MISMATCH:
                    diagnostics.append(
                        DiagnosticItem(
                            diag_id=f"DIAG-H-{diag_idx:03d}",
                            category=DiagnosticCategory.H_EVIDENCE_INTEGRITY_ISSUE,
                            severity=DiagnosticSeverity.CRITICAL,
                            affected_target=res.original_filename,
                            explanation=f"SHA-256 integrity mismatch: {res.details}",
                            supporting_details=f"Recorded: {res.recorded_sha256} | Computed: {res.calculated_sha256}",
                            suggested_action="Isolate evidence immediately. Investigate potential tampering or storage corruption.",
                        )
                    )
                    diag_idx += 1
                elif res.status == IntegrityStatus.UNAVAILABLE:
                    diagnostics.append(
                        DiagnosticItem(
                            diag_id=f"DIAG-H-{diag_idx:03d}",
                            category=DiagnosticCategory.H_EVIDENCE_INTEGRITY_ISSUE,
                            severity=DiagnosticSeverity.CRITICAL,
                            affected_target=res.original_filename,
                            explanation=f"Preserved evidence file missing or unreadable: {res.details}",
                            supporting_details=f"Path: {res.stored_path}",
                            suggested_action="Restore preserved evidence file from offline backup.",
                        )
                    )
                    diag_idx += 1

        # G: Unresolved Clock Skew
        if skew_estimates:
            for host, est in skew_estimates.items():
                if est.status == "INCONCLUSIVE_INSUFFICIENT_ANCHORS":
                    diagnostics.append(
                        DiagnosticItem(
                            diag_id=f"DIAG-G-{diag_idx:03d}",
                            category=DiagnosticCategory.G_UNRESOLVED_CLOCK_SKEW,
                            severity=DiagnosticSeverity.WARNING,
                            affected_target=host,
                            explanation=est.explanation,
                            supporting_details=f"Target: {est.target_source}, Ref: {est.reference_source}, Anchors: {est.anchor_count}",
                            suggested_action="Review raw logs to identify shared session tokens or confirm anchor pairs manually.",
                        )
                    )
                    diag_idx += 1
                elif est.status == "INCONCLUSIVE_CONFLICTING_ANCHORS":
                    diagnostics.append(
                        DiagnosticItem(
                            diag_id=f"DIAG-G-{diag_idx:03d}",
                            category=DiagnosticCategory.G_UNRESOLVED_CLOCK_SKEW,
                            severity=DiagnosticSeverity.WARNING,
                            affected_target=host,
                            explanation=est.explanation,
                            supporting_details=f"MAD: ±{est.spread_mad_sec}s, Range: [{est.min_offset_sec}s, {est.max_offset_sec}s]",
                            suggested_action="Inspect individual anchors for network latency or buffering delays before applying corrections.",
                        )
                    )
                    diag_idx += 1

        # Event-Level Diagnostics: A, B, C, D, E, I
        seen_texts: Dict[str, str] = {}

        for ev in events:
            # A: Parse failure
            if ev.parsing_status == "MALFORMED":
                diagnostics.append(
                    DiagnosticItem(
                        diag_id=f"DIAG-A-{diag_idx:03d}",
                        category=DiagnosticCategory.A_PARSE_FAILURE,
                        severity=DiagnosticSeverity.WARNING,
                        affected_target=f"{ev.original_filename}:L{ev.line_number}",
                        explanation=f"Parser could not interpret record syntax: {ev.data_quality_warnings}",
                        supporting_details=f"Raw text preview: {ev.raw_text[:120]}",
                        suggested_action="Examine raw log format. Verify if custom delimiter or truncation occurred.",
                    )
                )
                diag_idx += 1

            # B: Unsupported record
            elif ev.parsing_status == "UNSUPPORTED":
                diagnostics.append(
                    DiagnosticItem(
                        diag_id=f"DIAG-B-{diag_idx:03d}",
                        category=DiagnosticCategory.B_UNSUPPORTED_RECORD,
                        severity=DiagnosticSeverity.INFO,
                        affected_target=f"{ev.original_filename}:L{ev.line_number}",
                        explanation="Record structure does not conform to known sub-schemas.",
                        supporting_details=ev.raw_text[:120],
                        suggested_action="Verify parser configuration or add custom pattern matcher.",
                    )
                )
                diag_idx += 1

            # C: Timestamp failure
            if ev.normalization_status in (
                NormalizationStatus.INVALID_TIMESTAMP.value,
                NormalizationStatus.MISSING_TIMESTAMP.value,
            ):
                diagnostics.append(
                    DiagnosticItem(
                        diag_id=f"DIAG-C-{diag_idx:03d}",
                        category=DiagnosticCategory.C_TIMESTAMP_FAILURE,
                        severity=DiagnosticSeverity.WARNING,
                        affected_target=f"{ev.original_filename}:L{ev.line_number}",
                        explanation="Timestamp is missing, truncated, or invalid.",
                        supporting_details=f"Original ts: '{ev.original_timestamp_str}' | Warnings: {ev.data_quality_warnings}",
                        suggested_action="Investigate whether upstream logging agent failed to write timestamp.",
                    )
                )
                diag_idx += 1

            # D: Timestamp ambiguity
            if ev.normalization_status in (
                NormalizationStatus.NORMALIZED_ASSUMED_TZ.value,
                NormalizationStatus.NORMALIZED_CONFIGURED_TZ.value,
                NormalizationStatus.AMBIGUOUS_DST.value,
            ) or ev.year_inferred:
                diagnostics.append(
                    DiagnosticItem(
                        diag_id=f"DIAG-D-{diag_idx:03d}",
                        category=DiagnosticCategory.D_TIMESTAMP_AMBIGUITY,
                        severity=DiagnosticSeverity.INFO,
                        affected_target=f"{ev.original_filename}:L{ev.line_number}",
                        explanation="Timestamp interpretation required inference (timezone assumption, inferred year, or DST boundary).",
                        supporting_details=f"Original: '{ev.original_timestamp_str}' | Assumed TZ: '{ev.timezone_assumed}' | Year inferred: {ev.year_inferred}",
                        suggested_action="Confirm source system local timezone in investigation settings.",
                    )
                )
                diag_idx += 1

            # E: Missing-field warning
            if ev.parsing_status in ("SUCCESS", "PARTIAL"):
                if not ev.username and not ev.src_ip and ev.category in ("AUTHENTICATION", "WEB_REQUEST"):
                    diagnostics.append(
                        DiagnosticItem(
                            diag_id=f"DIAG-E-{diag_idx:03d}",
                            category=DiagnosticCategory.E_MISSING_FIELD_WARNING,
                            severity=DiagnosticSeverity.INFO,
                            affected_target=f"{ev.original_filename}:L{ev.line_number}",
                            explanation=f"Record of category '{ev.category}' lacks both username and source IP identifier.",
                            supporting_details=ev.description[:120],
                            suggested_action="Correlate with adjacent session records to infer client identity.",
                        )
                    )
                    diag_idx += 1

            # I: Duplicate candidate
            if ev.raw_text in seen_texts:
                prev_ref = seen_texts[ev.raw_text]
                diagnostics.append(
                    DiagnosticItem(
                        diag_id=f"DIAG-I-{diag_idx:03d}",
                        category=DiagnosticCategory.I_DUPLICATE_CANDIDATE,
                        severity=DiagnosticSeverity.INFO,
                        affected_target=f"{ev.original_filename}:L{ev.line_number}",
                        explanation="Exact duplicate log line detected across evidence entries.",
                        supporting_details=f"Matches earlier record at {prev_ref}",
                        suggested_action="Verify whether evidence files were collected from overlapping log rotations.",
                    )
                )
                diag_idx += 1
            else:
                seen_texts[ev.raw_text] = f"{ev.original_filename}:L{ev.line_number}"

        # F: Potential Coverage Gaps (analyzed per source host)
        hosts = {ev.source_host or ev.original_filename for ev in events}
        for h in hosts:
            h_events = [
                e for e in events
                if (e.source_host or e.original_filename) == h and e.normalized_utc_iso
            ]
            # Sort by normalized time
            h_sorted = sorted(h_events, key=lambda e: e.normalized_utc_iso or "")

            for i in range(len(h_sorted) - 1):
                t1 = datetime.fromisoformat(h_sorted[i].normalized_utc_iso.replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(h_sorted[i+1].normalized_utc_iso.replace("Z", "+00:00"))
                diff_sec = (t2 - t1).total_seconds()

                if diff_sec >= self.coverage_gap_threshold_sec:
                    diff_mins = round(diff_sec / 60.0, 1)
                    diagnostics.append(
                        DiagnosticItem(
                            diag_id=f"DIAG-F-{diag_idx:03d}",
                            category=DiagnosticCategory.F_COVERAGE_GAP,
                            severity=DiagnosticSeverity.WARNING,
                            affected_target=h,
                            explanation=(
                                f"Inactivity or logging quiet period of {diff_mins} minutes detected "
                                f"between {t1.isoformat()} and {t2.isoformat()}."
                            ),
                            supporting_details=(
                                "Forensic Note: Inactivity does not prove malicious log clearing or tampering; "
                                "it may represent normal system quiescence, scheduled maintenance, or log rotation."
                            ),
                            suggested_action="Correlate with system uptime or service availability logs during this interval.",
                        )
                    )
                    diag_idx += 1

        return diagnostics
