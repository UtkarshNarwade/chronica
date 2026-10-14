"""Forensic processing pipeline and service orchestrator.

Coordinates evidence ingestion, SHA-256 preservation, format detection, parsing,
UTC timestamp normalization, cross-source clock-skew analysis, and diagnostic gap analysis.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from src.diagnostics.gap_analysis import (
    DiagnosticItem,
    EvidenceGapAnalyzer,
    ParsingCoverageStats,
)
from src.evidence.collector import EvidenceCollector, PreservedEvidence
from src.evidence.manifest import EvidenceFileEntry, EvidenceManifest
from src.evidence.verification import (
    InvestigationIntegritySummary,
    verify_evidence_integrity,
)
from src.parsers.detector import ParserRegistry
from src.storage.repository import InvestigationMetadata, InvestigationRepository
from src.timeline.assembler import TimelineAssembler
from src.timeline.clock_skew import (
    AnchorPair,
    ClockSkewAnalyzer,
    ClockSkewEstimate,
)
from src.timeline.normalization import TimestampNormalizer
from src.timeline.schema import Event


class ForensicPipeline:
    """High-level service interface for managing and executing forensic investigations."""

    def __init__(self, repository: InvestigationRepository) -> None:
        self.repo = repository
        self.parser_registry = ParserRegistry()
        self.normalizer = TimestampNormalizer()
        self.skew_analyzer = ClockSkewAnalyzer()
        self.gap_analyzer = EvidenceGapAnalyzer()

    def ingest_evidence_bytes(
        self,
        investigation_id: str,
        filename: str,
        data: bytes,
        explicit_format: Optional[str] = None,
        assigned_timezone: Optional[str] = None,
    ) -> Tuple[PreservedEvidence, List[Event]]:
        """Collect, preserve, hash, parse, and normalize an evidence file provided as bytes."""
        collector = self.repo.get_evidence_collector(investigation_id)
        meta = self.repo.get_investigation(investigation_id)
        tz_to_use = assigned_timezone or (meta.assigned_timezone if meta else "UTC")

        # 1. Cryptographically hash and preserve original bytes
        preserved = collector.collect_from_bytes(data, original_filename=filename)

        # 2. Format detection or selection
        raw_text = data.decode("utf-8", errors="replace")
        sample_lines = raw_text.splitlines()[:25]

        detected_format = explicit_format
        if not detected_format or detected_format == "autodetect":
            det_res = self.parser_registry.detect_format(sample_lines)
            detected_format = det_res.detected_format or "syslog"  # Fallback if inconclusive

        parser = self.parser_registry.get_parser(detected_format)
        if not parser:
            parser = self.parser_registry.get_parser("syslog")
            detected_format = "syslog"

        # 3. Parse records preserving line numbers
        parsed_records = list(parser.parse_stream(iter(sample_lines + raw_text.splitlines()[25:])))

        # 4. Normalize timestamps to UTC
        events: List[Event] = []
        for prec in parsed_records:
            norm_res = self.normalizer.normalize(
                raw_ts=prec.original_timestamp_str,
                configured_timezone=tz_to_use,
            )

            # Combine warnings
            all_warnings = prec.warnings + norm_res.warnings

            ev = Event.create(
                investigation_id=investigation_id,
                evidence_id=preserved.evidence_id,
                original_filename=preserved.original_filename,
                line_number=prec.line_number,
                raw_text=prec.raw_text,
                original_timestamp_str=prec.original_timestamp_str,
                parsed_dt_iso=norm_res.normalized_utc_iso,
                normalized_utc_iso=norm_res.normalized_utc_iso,
                corrected_utc_iso=norm_res.normalized_utc_iso,  # Initial state prior to clock skew analysis
                normalization_status=norm_res.status.value,
                timezone_assumed=norm_res.timezone_used,
                year_inferred=norm_res.year_inferred,
                source_host=prec.source_host,
                source_app=prec.source_app,
                severity=prec.severity,
                category=prec.category,
                username=prec.username,
                src_ip=prec.src_ip,
                dst_ip=prec.dst_ip,
                description=prec.message or prec.raw_text[:80],
                request_id=prec.request_id,
                session_id=prec.session_id,
                parsing_status=prec.parse_status,
                data_quality_warnings=all_warnings,
                provenance={
                    "evidence_id": preserved.evidence_id,
                    "sha256": preserved.sha256_digest,
                    "file_name": preserved.original_filename,
                    "line_number": prec.line_number,
                    "parser": parser.format_name,
                },
                extra_fields=prec.extra_fields,
            )
            events.append(ev)

        # 5. Update Manifest
        manifest = self.repo.get_manifest(investigation_id)
        entry = EvidenceFileEntry(
            evidence_id=preserved.evidence_id,
            original_filename=preserved.original_filename,
            stored_filename=preserved.stored_filename,
            file_size_bytes=preserved.file_size_bytes,
            sha256_digest=preserved.sha256_digest,
            collection_time_utc=preserved.collection_time_utc,
            hash_algorithm="sha256",
            detected_format=detected_format,
            selected_parser=parser.format_name,
            ingestion_status="PARSED" if events else "EMPTY",
            record_count=len(events),
            assigned_timezone=tz_to_use,
        )
        manifest.add_entry(entry)
        self.repo.save_manifest(investigation_id, manifest)

        # 6. Save events to database
        self.repo.save_events(investigation_id, events)

        return preserved, events

    def analyze_investigation(
        self,
        investigation_id: str,
        reference_source: Optional[str] = None,
        clock_skew_enabled: bool = True,
    ) -> Dict[str, Any]:
        """Run complete timeline assembly, clock-skew analysis, and diagnostic gap analysis."""
        meta = self.repo.get_investigation(investigation_id)
        manifest = self.repo.get_manifest(investigation_id)
        evidence_dir = self.repo.get_evidence_dir(investigation_id)

        # 1. Verify evidence integrity
        integrity_summary = verify_evidence_integrity(evidence_dir, manifest)

        # 2. Load all raw events from DB
        raw_events = self.repo.load_events(investigation_id)

        if not raw_events:
            empty_stats = ParsingCoverageStats(0, 0, 0, 0, 0, 0)
            return {
                "events": [],
                "unresolved_events": [],
                "anchors": [],
                "skew_estimates": {},
                "diagnostics": [],
                "coverage_stats": empty_stats,
                "integrity_summary": integrity_summary,
            }

        # 3. Identify reference source
        available_sources = list({e.source_host or e.original_filename for e in raw_events})
        ref_src = reference_source or (meta.reference_source if meta else None) or (available_sources[0] if available_sources else "")

        # 4. Clock Skew Analysis
        anchors: List[AnchorPair] = []
        skew_estimates: Dict[str, ClockSkewEstimate] = {}

        for src in available_sources:
            if src == ref_src:
                continue
            src_anchors = self.skew_analyzer.discover_anchors(raw_events, reference_source=ref_src, target_source=src)
            anchors.extend(src_anchors)
            estimate = self.skew_analyzer.estimate_skew(src_anchors, target_source=src, reference_source=ref_src)
            skew_estimates[src] = estimate

        # 5. Apply corrections to events
        corrected_events = self.skew_analyzer.apply_corrections(
            raw_events, estimates=skew_estimates, enabled=clock_skew_enabled
        )

        # Update events in database with clock-skew calculations
        self.repo.save_events(investigation_id, corrected_events)

        # 6. Sort Timeline
        valid_timeline, unresolved_events = TimelineAssembler.sort_timeline(
            corrected_events,
            sort_by="corrected_utc" if clock_skew_enabled else "normalized_utc",
        )

        # 7. Diagnostic Gap Analysis
        coverage_stats = self.gap_analyzer.compute_coverage_stats(corrected_events)
        diagnostics = self.gap_analyzer.analyze(
            events=corrected_events,
            manifest=manifest,
            integrity_summary=integrity_summary,
            skew_estimates=skew_estimates,
        )

        return {
            "events": valid_timeline,
            "unresolved_events": unresolved_events,
            "anchors": anchors,
            "skew_estimates": skew_estimates,
            "diagnostics": diagnostics,
            "coverage_stats": coverage_stats,
            "integrity_summary": integrity_summary,
            "reference_source": ref_src,
        }
