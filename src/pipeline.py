"""Forensic processing pipeline and service orchestrator.

Coordinates evidence ingestion, SHA-256 preservation, format detection, parsing,
UTC timestamp normalization, cross-source clock-skew analysis, and diagnostic gap analysis.

Phase 1.3 improvements:
- Strict \r?\n line splitting (no split on \v, \f)
- CSV HEADER record filtering
- Duplicate evidence guard (by SHA-256)
- Dominant host inheritance for MALFORMED lines
- Transparent .gz and .zip decompression with bomb guard

Phase 2.3 improvements:
- Deterministic sorted reference source selection
- Filename-to-host mapping for benchmark resolution
"""

from __future__ import annotations

import gzip
import io
import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from src.diagnostics.gap_analysis import (
    DiagnosticItem,
    EvidenceGapAnalyzer,
    ParsingCoverageStats,
)
from src.evidence.collector import EvidenceCollector, FileSizeExceededError, PreservedEvidence
from src.evidence.manifest import EvidenceFileEntry, EvidenceManifest
from src.evidence.hashing import calculate_sha256_bytes
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

    def _decompress_if_needed(
        self,
        data: bytes,
        filename: str,
        max_bytes: int,
    ) -> Tuple[bytes, str]:
        """Transparently decompress .gz or .zip files with a bomb guard.

        Returns:
            (decompressed_bytes, effective_filename)

        Raises:
            FileSizeExceededError: If decompressed size exceeds max_bytes.
        """
        fname_lower = filename.lower()

        if fname_lower.endswith(".gz"):
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                    chunks = []
                    total = 0
                    while True:
                        chunk = gz.read(65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_bytes:
                            raise FileSizeExceededError(
                                f"Decompressed content of '{filename}' exceeds "
                                f"maximum limit of {max_bytes} bytes (bomb guard)."
                            )
                        chunks.append(chunk)
                    decompressed = b"".join(chunks)
                # Strip .gz extension for downstream parser selection
                inner_name = filename[:-3] if len(filename) > 3 else filename
                return decompressed, inner_name
            except FileSizeExceededError:
                raise
            except Exception as exc:
                # If decompression fails, treat as plain text
                pass

        if fname_lower.endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                    names = zf.namelist()
                    if not names:
                        return data, filename
                    # Process the first non-directory file in the archive
                    for name in names:
                        info = zf.getinfo(name)
                        if info.is_dir():
                            continue
                        if info.file_size > max_bytes:
                            raise FileSizeExceededError(
                                f"Decompressed content of '{name}' in '{filename}' exceeds "
                                f"maximum limit of {max_bytes} bytes (bomb guard)."
                            )
                        decompressed = zf.read(name)
                        if len(decompressed) > max_bytes:
                            raise FileSizeExceededError(
                                f"Decompressed content of '{name}' in '{filename}' exceeds "
                                f"maximum limit of {max_bytes} bytes (bomb guard)."
                            )
                        return decompressed, name
            except FileSizeExceededError:
                raise
            except Exception:
                pass

        return data, filename

    def ingest_evidence_bytes(
        self,
        investigation_id: str,
        filename: str,
        data: bytes,
        explicit_format: Optional[str] = None,
        assigned_timezone: Optional[str] = None,
        allow_duplicate: bool = False,
    ) -> Tuple[PreservedEvidence, List[Event]]:
        """Collect, preserve, hash, parse, and normalize an evidence file provided as bytes."""
        collector = self.repo.get_evidence_collector(investigation_id)
        meta = self.repo.get_investigation(investigation_id)
        tz_to_use = assigned_timezone or (meta.assigned_timezone if meta else "UTC")

        # 1. Compute SHA-256 of raw bytes first
        raw_sha256 = calculate_sha256_bytes(data)

        # 1b. Duplicate evidence guard
        if not allow_duplicate:
            manifest_check = self.repo.get_manifest(investigation_id)
            for existing_entry in manifest_check.entries:
                if existing_entry.sha256_digest == raw_sha256:
                    existing_events = [
                        ev for ev in self.repo.load_events(investigation_id)
                        if ev.evidence_id == existing_entry.evidence_id
                    ]
                    from src.evidence.collector import PreservedEvidence
                    stored_rel = getattr(existing_entry, "stored_filename", None) or getattr(existing_entry, "stored_relpath", None) or existing_entry.original_filename
                    existing_path = self.repo.get_evidence_dir(investigation_id) / stored_rel
                    existing_preserved = PreservedEvidence(
                        evidence_id=existing_entry.evidence_id,
                        original_filename=existing_entry.original_filename,
                        stored_filename=stored_rel,
                        stored_path=existing_path,
                        file_size_bytes=existing_entry.file_size_bytes,
                        sha256_digest=existing_entry.sha256_digest,
                        collection_time_utc=getattr(existing_entry, "collection_time_utc", getattr(existing_entry, "collection_timestamp_utc", "")),
                    )
                    return existing_preserved, []

        # 1c. Cryptographically hash and preserve original bytes
        preserved = collector.collect_from_bytes(data, original_filename=filename)

        # 2. Transparent decompression (.gz / .zip) with bomb guard
        text_data, effective_filename = self._decompress_if_needed(
            data, filename, collector.max_file_size_bytes
        )

        # 3. Format detection or selection
        raw_text = text_data.decode("utf-8", errors="replace")

        # Strict \r?\n line splitting (no split on \v, \f)
        if raw_text.endswith("\n"):
            raw_text_for_split = raw_text[:-1]
        elif raw_text.endswith("\r\n"):
            raw_text_for_split = raw_text[:-2]
        else:
            raw_text_for_split = raw_text
        all_lines = re.split(r"\r?\n", raw_text_for_split)
        sample_lines = all_lines[:25]

        detected_format = explicit_format
        if not detected_format or detected_format == "autodetect":
            det_res = self.parser_registry.detect_format(sample_lines)
            detected_format = det_res.detected_format or "syslog"  # Fallback if inconclusive

        parser = self.parser_registry.get_parser(detected_format)
        if not parser:
            parser = self.parser_registry.get_parser("syslog")
            detected_format = "syslog"

        # 4. Parse records preserving line numbers (strict line iterator)
        parsed_records = list(parser.parse_stream(iter(all_lines)))

        # 5. Filter out HEADER records (CSV header pollution prevention)
        parsed_records = [pr for pr in parsed_records if pr.parse_status != "HEADER"]

        # 6. Dominant host inference for MALFORMED lines
        host_counts: Counter = Counter(
            pr.source_host for pr in parsed_records
            if pr.source_host is not None
        )
        dominant_host: Optional[str] = None
        if host_counts:
            dominant_host = host_counts.most_common(1)[0][0]

        # 7. BSD Syslog year rollover tracking
        last_syslog_month: Optional[int] = None
        current_year = self.normalizer.base_year

        # 8. Normalize timestamps to UTC
        events: List[Event] = []
        for prec in parsed_records:
            # Host inference for MALFORMED/None source_host records
            effective_host = prec.source_host
            host_inferred = False
            if effective_host is None and dominant_host is not None:
                effective_host = dominant_host
                host_inferred = True

            # BSD Syslog year rollover detection
            override_year = None
            if prec.original_timestamp_str:
                from src.timeline.normalization import SYSLOG_BSD_PATTERN, MONTH_MAP
                m_syslog = SYSLOG_BSD_PATTERN.match(prec.original_timestamp_str.strip())
                if m_syslog:
                    month_str = m_syslog.group(1)
                    current_month = MONTH_MAP.get(month_str.capitalize())
                    if current_month is not None:
                        if last_syslog_month is not None and last_syslog_month == 12 and current_month == 1:
                            current_year += 1
                            if not prec.warnings:
                                prec.warnings = []
                            prec.warnings.append(
                                "New Year rollover (Dec -> Jan) detected in stream; year incremented."
                            )
                        last_syslog_month = current_month
                        override_year = current_year

            norm_res = self.normalizer.normalize(
                raw_ts=prec.original_timestamp_str,
                configured_timezone=tz_to_use,
                override_year=override_year,
            )

            # Combine warnings
            all_warnings = prec.warnings + norm_res.warnings

            # Build provenance
            provenance: Dict[str, Any] = {
                "evidence_id": preserved.evidence_id,
                "sha256": preserved.sha256_digest,
                "file_name": preserved.original_filename,
                "line_number": prec.line_number,
                "parser": parser.format_name,
            }

            extra_fields = dict(prec.extra_fields)
            if host_inferred:
                extra_fields["host_inferred_from_file"] = True
                provenance["host_inferred_from_file"] = True

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
                source_host=effective_host,
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
                provenance=provenance,
                extra_fields=extra_fields,
            )
            events.append(ev)

        # 9. Update Manifest
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

        # 10. Save events to database
        self.repo.save_events(investigation_id, events)

        # 11. Log EVIDENCE_INGESTED audit entry
        try:
            ledger = self.repo.get_audit_ledger(investigation_id)
            ledger.append(
                action="EVIDENCE_INGESTED",
                summary=f"Evidence file '{preserved.original_filename}' ingested ({len(events)} events).",
                details={
                    "evidence_id": preserved.evidence_id,
                    "sha256": preserved.sha256_digest,
                    "parser": parser.format_name,
                    "record_count": len(events),
                },
            )
        except Exception:
            pass

        return preserved, events

    def analyze_investigation(
        self,
        investigation_id: str,
        reference_source: Optional[str] = None,
        clock_skew_enabled: bool = True,
        latency_tolerance_sec: float = 2.0,
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
                "reference_source": "",
                "available_sources": [],
                "filename_to_host": {},
                "correlation_clusters": [],
                "heuristic_leads": [],
            }

        # 3. Build deterministic sorted source list and filename→host mapping
        available_sources = sorted(list({e.source_host or e.original_filename for e in raw_events}))

        # Build filename→host mapping (dominant source_host for each original_filename)
        filename_to_host: Dict[str, str] = {}
        for ev in raw_events:
            if ev.original_filename and ev.source_host:
                fname = ev.original_filename
                if fname not in filename_to_host:
                    filename_to_host[fname] = ev.source_host

        # 4. Identify reference source with filename-to-host resolution
        ref_src = (
            reference_source
            or (meta.reference_source if meta else None)
            or (available_sources[0] if available_sources else "")
        )
        # Resolve filename-to-host alias if needed
        if ref_src and ref_src not in available_sources and ref_src in filename_to_host:
            ref_src = filename_to_host[ref_src]

        # 5. Get manual anchors from investigation metadata
        manual_anchors_raw: List[Dict[str, Any]] = (meta.manual_anchors if meta and meta.manual_anchors else [])
        manual_anchor_pairs: List[AnchorPair] = []
        for ma_dict in manual_anchors_raw:
            try:
                manual_anchor_pairs.append(AnchorPair(**ma_dict))
            except Exception:
                pass

        # 6. Clock Skew Analysis with configurable latency tolerance
        skew_analyzer = ClockSkewAnalyzer(latency_tolerance_sec=latency_tolerance_sec)
        anchors: List[AnchorPair] = []
        skew_estimates: Dict[str, ClockSkewEstimate] = {}

        for src in available_sources:
            if src == ref_src:
                continue
            src_anchors = skew_analyzer.discover_anchors(
                raw_events,
                reference_source=ref_src,
                target_source=src,
                manual_anchors=[ma for ma in manual_anchor_pairs if ma.target_source == src],
            )
            anchors.extend(src_anchors)
            estimate = skew_analyzer.estimate_skew(src_anchors, target_source=src, reference_source=ref_src)
            skew_estimates[src] = estimate

        # 7. Apply corrections to events
        corrected_events = skew_analyzer.apply_corrections(
            raw_events, estimates=skew_estimates, enabled=clock_skew_enabled
        )

        # Only save if corrections changed anything
        timestamps_changed = any(
            ce.corrected_utc_iso != re.corrected_utc_iso or ce.correction_status != re.correction_status
            for ce, re in zip(corrected_events, raw_events)
        )
        if timestamps_changed:
            self.repo.save_events(investigation_id, corrected_events)

        # 8. Sort Timeline
        valid_timeline, unresolved_events = TimelineAssembler.sort_timeline(
            corrected_events,
            sort_by="corrected_utc" if clock_skew_enabled else "normalized_utc",
        )

        # 9. Diagnostic Gap Analysis
        coverage_stats = self.gap_analyzer.compute_coverage_stats(corrected_events)
        diagnostics = self.gap_analyzer.analyze(
            events=corrected_events,
            manifest=manifest,
            integrity_summary=integrity_summary,
            skew_estimates=skew_estimates,
        )

        # 10. Correlation clusters and heuristic leads
        correlation_clusters = []
        heuristic_leads = []
        try:
            from src.timeline.correlation import EventCorrelator
            correlator = EventCorrelator()
            correlation_clusters = correlator.correlate(corrected_events)
        except Exception:
            pass

        try:
            from src.diagnostics.heuristics import ForensicHeuristicEngine
            engine = ForensicHeuristicEngine()
            heuristic_leads = engine.analyze(corrected_events)
        except Exception:
            pass

        return {
            "events": valid_timeline,
            "unresolved_events": unresolved_events,
            "anchors": anchors,
            "skew_estimates": skew_estimates,
            "diagnostics": diagnostics,
            "coverage_stats": coverage_stats,
            "integrity_summary": integrity_summary,
            "reference_source": ref_src,
            "available_sources": available_sources,
            "filename_to_host": filename_to_host,
            "correlation_clusters": correlation_clusters,
            "heuristic_leads": heuristic_leads,
        }
