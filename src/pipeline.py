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
import tarfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.diagnostics.gap_analysis import (
    EvidenceGapAnalyzer,
    ParsingCoverageStats,
)
from src.evidence.collector import FileSizeExceededError, PreservedEvidence
from src.evidence.manifest import EvidenceFileEntry
from src.evidence.hashing import calculate_sha256_bytes
from src.evidence.verification import (
    verify_evidence_integrity,
)
from src.parsers.detector import ParserRegistry
from src.storage.repository import InvestigationRepository
from src.timeline.assembler import TimelineAssembler
from src.timeline.clock_skew import (
    AnchorPair,
    ClockSkewAnalyzer,
    ClockSkewEstimate,
)
from src.timeline.normalization import TimestampNormalizer
from src.timeline.schema import Event


def detect_and_decode_text(raw_bytes: bytes) -> Tuple[str, str, int]:
    """Detect encoding (BOM or content heuristics), decode, and count replacement characters (F-18).

    Supports:
    - UTF-8 with BOM (\\xef\\xbb\\xbf) -> 'utf-8-sig'
    - UTF-16-LE with BOM (\\xff\\xfe) -> 'utf-16'
    - UTF-16-BE with BOM (\\xfe\\xff) -> 'utf-16'
    - UTF-8 (strict validation without BOM) -> 'utf-8'
    - UTF-16-LE heuristics without BOM (common in Windows powershell exports without BOM)
    - Latin-1 fallback (preserves all byte values 0x00-0xFF)

    Returns:
        (decoded_text, encoding_name, replacement_char_count)
    """
    if not raw_bytes:
        return "", "utf-8", 0

    # 1. BOM checks
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        try:
            return raw_bytes.decode("utf-8-sig"), "utf-8-sig", 0
        except UnicodeDecodeError:
            pass
    elif raw_bytes.startswith(b"\xff\xfe") or raw_bytes.startswith(b"\xfe\xff"):
        try:
            return raw_bytes.decode("utf-16"), "utf-16", 0
        except UnicodeDecodeError:
            pass

    # 2. Try strict UTF-8
    try:
        return raw_bytes.decode("utf-8"), "utf-8", 0
    except UnicodeDecodeError:
        pass

    # 3. Check for UTF-16-LE without BOM (ASCII characters interleaved with NUL bytes)
    if len(raw_bytes) >= 4 and (raw_bytes[1::2].count(0) > len(raw_bytes) // 4):
        try:
            return raw_bytes.decode("utf-16-le"), "utf-16-le", 0
        except UnicodeDecodeError:
            pass

    # 4. Fallback to UTF-8 with errors='replace', count U+FFFD replacement characters
    decoded = raw_bytes.decode("utf-8", errors="replace")
    rep_count = decoded.count("\ufffd")
    if rep_count > 0:
        return decoded, "utf-8", rep_count

    # 5. Latin-1 fallback
    return raw_bytes.decode("latin-1"), "latin-1", 0


# Maximum limits for archive expansion (archive bomb defense)
MAX_ARCHIVE_MEMBERS: int = 1000
MAX_NESTING_DEPTH: int = 3
STREAM_CHUNK_SIZE: int = 65536


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
            except Exception:
                # If decompression fails, treat as plain text
                pass

        if fname_lower.endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                    infolist = zf.infolist()
                    if not infolist:
                        return data, filename
                    if len(infolist) > MAX_ARCHIVE_MEMBERS:
                        raise FileSizeExceededError(
                            f"Archive '{filename}' contains {len(infolist)} members, exceeding "
                            f"maximum limit of {MAX_ARCHIVE_MEMBERS} (archive bomb guard)."
                        )
                    # Process the first non-directory file in the archive
                    for info in infolist:
                        if info.is_dir():
                            continue
                        chunks = []
                        total = 0
                        with zf.open(info) as zf_file:
                            while True:
                                chunk = zf_file.read(STREAM_CHUNK_SIZE)
                                if not chunk:
                                    break
                                total += len(chunk)
                                if total > max_bytes:
                                    raise FileSizeExceededError(
                                        f"Decompressed content of '{info.filename}' in '{filename}' exceeds "
                                        f"maximum limit of {max_bytes} bytes (bomb guard)."
                                    )
                                chunks.append(chunk)
                        decompressed = b"".join(chunks)
                        clean_name = Path(info.filename.replace("\\", "/")).name
                        return decompressed, clean_name or info.filename
            except FileSizeExceededError:
                raise
            except Exception:
                pass

        return data, filename

    def expand_archive_bytes(
        self,
        filename: str,
        data: bytes,
        max_bytes: Optional[int] = None,
        depth: int = 1,
    ) -> List[Tuple[str, bytes]]:
        """Expand .zip, .tar.gz, or .tgz archive files into individual members.

        Enforces a cumulative decompression limit (bomb guard), streaming chunk reads,
        member count limit, nesting depth cap, and zip-slip path traversal prevention.
        Ignores directory entries, macOS metadata (__MACOSX/), and hidden files (starting with .).
        """
        if depth > MAX_NESTING_DEPTH:
            raise FileSizeExceededError(
                f"Archive '{filename}' exceeds maximum nesting depth of {MAX_NESTING_DEPTH} (archive bomb guard)."
            )

        limit = max_bytes or (100 * 1024 * 1024)
        fname_lower = filename.lower()
        extracted: List[Tuple[str, bytes]] = []

        if fname_lower.endswith(".zip"):
            cumulative_size = 0
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                infolist = zf.infolist()
                if len(infolist) > MAX_ARCHIVE_MEMBERS:
                    raise FileSizeExceededError(
                        f"Archive '{filename}' contains {len(infolist)} members, exceeding "
                        f"maximum limit of {MAX_ARCHIVE_MEMBERS} (archive bomb guard)."
                    )
                for info in infolist:
                    if info.is_dir():
                        continue
                    # Zip-slip guard: sanitize member path and reject directory traversal
                    raw_name = info.filename.replace("\\", "/")
                    clean_name = Path(raw_name).name
                    if not clean_name or clean_name.startswith(".") or "__MACOSX" in raw_name:
                        continue
                    if clean_name in [n for n, _ in extracted]:
                        parent_prefix = Path(raw_name).parent.name
                        clean_name = f"{parent_prefix}_{clean_name}" if parent_prefix else clean_name

                    # Stream member decompression in chunks to abort before memory allocation
                    chunks = []
                    member_size = 0
                    with zf.open(info) as zf_member:
                        while True:
                            chunk = zf_member.read(STREAM_CHUNK_SIZE)
                            if not chunk:
                                break
                            cumulative_size += len(chunk)
                            member_size += len(chunk)
                            if cumulative_size > limit:
                                raise FileSizeExceededError(
                                    f"Cumulative extracted size of archive '{filename}' exceeds {limit} bytes (bomb guard)."
                                )
                            chunks.append(chunk)
                    member_bytes = b"".join(chunks)
                    extracted.append((clean_name, member_bytes))
            return extracted if extracted else [(filename, data)]

        if fname_lower.endswith((".tar.gz", ".tgz")):
            cumulative_size = 0
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
                members = tf.getmembers()
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    raise FileSizeExceededError(
                        f"Archive '{filename}' contains {len(members)} members, exceeding "
                        f"maximum limit of {MAX_ARCHIVE_MEMBERS} (archive bomb guard)."
                    )
                for member in members:
                    if not member.isfile():
                        continue
                    # Zip-slip guard: sanitize member path and reject directory traversal
                    raw_name = member.name.replace("\\", "/")
                    clean_name = Path(raw_name).name
                    if not clean_name or clean_name.startswith(".") or "__MACOSX" in raw_name:
                        continue
                    if clean_name in [n for n, _ in extracted]:
                        parent_prefix = Path(raw_name).parent.name
                        clean_name = f"{parent_prefix}_{clean_name}" if parent_prefix else clean_name
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    # Stream member decompression in chunks
                    chunks = []
                    member_size = 0
                    with f:
                        while True:
                            chunk = f.read(STREAM_CHUNK_SIZE)
                            if not chunk:
                                break
                            cumulative_size += len(chunk)
                            member_size += len(chunk)
                            if cumulative_size > limit:
                                raise FileSizeExceededError(
                                    f"Cumulative extracted size of archive '{filename}' exceeds {limit} bytes (bomb guard)."
                                )
                            chunks.append(chunk)
                    member_bytes = b"".join(chunks)
                    extracted.append((clean_name, member_bytes))
            return extracted if extracted else [(filename, data)]

        return [(filename, data)]

    def ingest_evidence_bytes(
        self,
        investigation_id: str,
        filename: str,
        data: bytes,
        explicit_format: Optional[str] = None,
        assigned_timezone: Optional[str] = None,
        allow_duplicate: bool = False,
        custom_regex: Optional[str] = None,
        source_host: Optional[str] = None,
        archive_depth: int = 0,
    ) -> Tuple[PreservedEvidence, List[Event]]:
        """Collect, preserve, hash, parse, and normalize an evidence file provided as bytes."""
        if archive_depth > MAX_NESTING_DEPTH:
            raise FileSizeExceededError(
                f"Archive nesting depth {archive_depth} exceeds maximum limit of {MAX_NESTING_DEPTH} (archive bomb guard)."
            )

        # Reset stateful syslog year tracker per file
        self.normalizer.last_syslog_month = None
        self.normalizer.current_syslog_year = self.normalizer.base_year

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

        fname_lower = filename.lower()
        if fname_lower.endswith((".zip", ".tar.gz", ".tgz")):
            return self._ingest_archive_pipeline(
                investigation_id=investigation_id,
                filename=filename,
                data=data,
                assigned_timezone=tz_to_use,
                allow_duplicate=allow_duplicate,
                source_host=source_host,
                explicit_format=explicit_format,
                archive_depth=archive_depth,
            )

        # 1c. Cryptographically hash and preserve original bytes in staging
        preserved = collector.collect_from_bytes(data, original_filename=filename, staging=True)

        try:
            # 2. Transparent decompression (.gz) with bomb guard
            text_data, effective_filename = self._decompress_if_needed(
                data, filename, collector.max_file_size_bytes
            )

            # 3. Format detection and encoding resolution (F-18)
            raw_text, encoding_used, rep_char_count = detect_and_decode_text(text_data)

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

            if detected_format == "custom_regex":
                from src.parsers.custom_regex_parser import CustomRegexParser
                if custom_regex:
                    parser = CustomRegexParser(pattern=custom_regex)
                else:
                    parser = self.parser_registry.get_parser("custom_regex")
            else:
                parser = self.parser_registry.get_parser(detected_format)
                if not parser:
                    parser = self.parser_registry.get_parser("syslog")
                    detected_format = "syslog"

            # 4. Parse records preserving line numbers (strict line iterator)
            ingest_context = {
                "source_host": source_host,
                "evidence_id": preserved.evidence_id,
                "filename": filename,
            }
            parsed_records = list(parser.parse_stream(iter(all_lines), context=ingest_context))

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
                effective_host = prec.source_host or source_host
                host_inferred = False
                if effective_host is None and dominant_host is not None:
                    effective_host = dominant_host
                    host_inferred = True
                elif effective_host is None:
                    effective_host = f"{filename} [{preserved.evidence_id[:8]}]"
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
                all_warnings = list(prec.warnings) + list(norm_res.warnings)
                if rep_char_count > 0:
                    all_warnings.append(
                        f"File decoded with {encoding_used}; contains {rep_char_count} invalid byte sequence(s) "
                        f"replaced by U+FFFD (possible data corruption)."
                    )

                # Build provenance
                provenance: Dict[str, Any] = {
                    "evidence_id": preserved.evidence_id,
                    "sha256": preserved.sha256_digest,
                    "file_name": preserved.original_filename,
                    "line_number": prec.line_number,
                    "parser": parser.format_name,
                    "encoding": encoding_used,
                    "replacement_char_count": rep_char_count,
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

            # 9. Save events to database first
            self.repo.save_events(investigation_id, events)

            # 10. Atomic commit: promote staged evidence file to evidence directory
            preserved = collector.commit_preserved(preserved)

            # 11. Update and save Manifest
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

            # 12. Log EVIDENCE_INGESTED audit entry
            ledger = self.repo.get_audit_ledger(investigation_id)
            ledger.append(
                action="EVIDENCE_INGESTED",
                summary=f"Evidence file '{preserved.original_filename}' ingested ({len(events)} events).",
                details={
                    "evidence_id": preserved.evidence_id,
                    "sha256": preserved.sha256_digest,
                    "manifest_sha256": manifest.calculate_manifest_digest(),
                    "parser": parser.format_name,
                    "record_count": len(events),
                },
            )

            return preserved, events
        except Exception:
            # Atomic rollback: clean up staged files, manifest entries, and partial database state
            collector.rollback_preserved(preserved)
            self.repo.db.delete_evidence_events(investigation_id, preserved.evidence_id)
            try:
                m_rb = self.repo.get_manifest(investigation_id)
                m_rb.entries = [e for e in m_rb.entries if e.evidence_id != preserved.evidence_id]
                self.repo.save_manifest(investigation_id, m_rb)
            except Exception:
                pass
            raise

    def _ingest_archive_pipeline(
        self,
        investigation_id: str,
        filename: str,
        data: bytes,
        assigned_timezone: Optional[str] = None,
        allow_duplicate: bool = False,
        source_host: Optional[str] = None,
        explicit_format: Optional[str] = None,
        archive_depth: int = 0,
    ) -> Tuple[PreservedEvidence, List[Event]]:
        """Preserve original archive and ingest all extracted archive members atomically."""
        if archive_depth > MAX_NESTING_DEPTH:
            raise FileSizeExceededError(
                f"Archive nesting depth {archive_depth} exceeds maximum limit of {MAX_NESTING_DEPTH} (archive bomb guard)."
            )

        collector = self.repo.get_evidence_collector(investigation_id)
        archive_preserved = collector.collect_from_bytes(data, original_filename=filename, staging=True)

        try:
            members = self.expand_archive_bytes(
                filename, data, collector.max_file_size_bytes, depth=archive_depth + 1
            )
            member_hashes: Dict[str, str] = {}
            all_extracted_events: List[Event] = []

            for m_name, m_bytes in members:
                m_sha = calculate_sha256_bytes(m_bytes)
                member_hashes[m_name] = m_sha
                _, m_events = self.ingest_evidence_bytes(
                    investigation_id=investigation_id,
                    filename=m_name,
                    data=m_bytes,
                    explicit_format=explicit_format,
                    assigned_timezone=assigned_timezone,
                    allow_duplicate=allow_duplicate,
                    source_host=source_host,
                    archive_depth=archive_depth + 1,
                )
                all_extracted_events.extend(m_events)

            # Promote original archive file
            archive_preserved = collector.commit_preserved(archive_preserved)

            # Update manifest with original archive entry
            manifest = self.repo.get_manifest(investigation_id)
            archive_entry = EvidenceFileEntry(
                evidence_id=archive_preserved.evidence_id,
                original_filename=filename,
                stored_filename=archive_preserved.stored_filename,
                file_size_bytes=archive_preserved.file_size_bytes,
                sha256_digest=archive_preserved.sha256_digest,
                collection_time_utc=archive_preserved.collection_time_utc,
                hash_algorithm="sha256",
                detected_format="archive",
                selected_parser="archive_extractor",
                ingestion_status="ARCHIVE",
                record_count=len(all_extracted_events),
                assigned_timezone=assigned_timezone,
            )
            archive_entry.metadata = {"member_hashes": member_hashes}
            manifest.add_entry(archive_entry)
            self.repo.save_manifest(investigation_id, manifest)

            # Audit ledger entry
            ledger = self.repo.get_audit_ledger(investigation_id)
            ledger.append(
                action="ARCHIVE_INGESTED",
                summary=f"Archive '{filename}' ingested ({len(members)} member files, {len(all_extracted_events)} events).",
                details={
                    "evidence_id": archive_preserved.evidence_id,
                    "sha256": archive_preserved.sha256_digest,
                    "manifest_sha256": manifest.calculate_manifest_digest(),
                    "member_count": len(members),
                    "member_hashes": member_hashes,
                    "record_count": len(all_extracted_events),
                },
            )

            return archive_preserved, all_extracted_events
        except Exception:
            collector.rollback_preserved(archive_preserved)
            self.repo.db.delete_evidence_events(investigation_id, archive_preserved.evidence_id)
            try:
                m_rb = self.repo.get_manifest(investigation_id)
                m_rb.entries = [e for e in m_rb.entries if e.evidence_id != archive_preserved.evidence_id]
                self.repo.save_manifest(investigation_id, m_rb)
            except Exception:
                pass
            raise

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
        available_sources = sorted(list({e.source_host or (f"{e.original_filename} [{e.evidence_id[:8]}]" if e.original_filename else "unknown") for e in raw_events}))

        # Build filename→host mapping (dominant source_host for each original_filename)
        filename_to_host: Dict[str, str] = {}
        for ev in raw_events:
            if ev.original_filename and ev.source_host:
                fname = ev.original_filename
                if fname not in filename_to_host:
                    filename_to_host[fname] = ev.source_host

        # 4. Identify reference source with filename-to-host resolution
        if not reference_source and (not meta or not meta.reference_source):
            # Select default reference source with the highest anchor connectivity (F-15)
            skew_analyzer_temp = ClockSkewAnalyzer(latency_tolerance_sec=latency_tolerance_sec)
            anchor_counts: Dict[str, int] = {s: 0 for s in available_sources}
            for i in range(len(available_sources)):
                for j in range(i + 1, len(available_sources)):
                    s1 = available_sources[i]
                    s2 = available_sources[j]
                    pair_anchors = skew_analyzer_temp.discover_anchors(
                        raw_events, reference_source=s1, target_source=s2
                    )
                    c = len(pair_anchors)
                    anchor_counts[s1] += c
                    anchor_counts[s2] += c
            best_src = max(
                available_sources,
                key=lambda s: (anchor_counts.get(s, 0), sum(1 for e in raw_events if (e.source_host or e.original_filename) == s)),
            ) if available_sources else ""
            ref_src = best_src
        else:
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

        # Transitive 2-hop clock-skew synchronization (A <-> B <-> C)
        resolved_sources = [
            s for s, est in skew_estimates.items()
            if est.status == "ESTIMATED" and est.estimated_offset_sec is not None
        ]
        unresolved_sources = [
            s for s, est in skew_estimates.items()
            if est.status == "INCONCLUSIVE_INSUFFICIENT_ANCHORS"
        ]

        for unres_src in unresolved_sources:
            for inter_src in sorted(resolved_sources):
                hop_anchors = skew_analyzer.discover_anchors(
                    raw_events,
                    reference_source=inter_src,
                    target_source=unres_src,
                    manual_anchors=[
                        ma for ma in manual_anchor_pairs
                        if (ma.target_source == unres_src and ma.reference_source == inter_src)
                        or (ma.target_source == inter_src and ma.reference_source == unres_src)
                    ],
                )
                hop_est = skew_analyzer.estimate_skew(
                    hop_anchors, target_source=unres_src, reference_source=inter_src
                )
                if hop_est.status == "ESTIMATED" and hop_est.estimated_offset_sec is not None:
                    inter_est = skew_estimates[inter_src]
                    total_offset = round((inter_est.estimated_offset_sec or 0.0) + hop_est.estimated_offset_sec, 3)
                    import math
                    total_mad = round(math.hypot(inter_est.spread_mad_sec or 0.0, hop_est.spread_mad_sec or 0.0), 3)
                    total_unc = round((inter_est.uncertainty_sec or inter_est.spread_mad_sec or 0.0) + (hop_est.uncertainty_sec or hop_est.spread_mad_sec or 0.0), 3)
                    within_tol = bool(latency_tolerance_sec > 0 and abs(total_offset) <= latency_tolerance_sec)
                    min_off = (
                        round((inter_est.min_offset_sec or 0.0) + (hop_est.min_offset_sec or 0.0), 3)
                        if inter_est.min_offset_sec is not None and hop_est.min_offset_sec is not None
                        else None
                    )
                    max_off = (
                        round((inter_est.max_offset_sec or 0.0) + (hop_est.max_offset_sec or 0.0), 3)
                        if inter_est.max_offset_sec is not None and hop_est.max_offset_sec is not None
                        else None
                    )

                    skew_estimates[unres_src] = ClockSkewEstimate(
                        target_source=unres_src,
                        reference_source=ref_src,
                        anchor_count=hop_est.anchor_count,
                        estimated_offset_sec=total_offset,
                        spread_mad_sec=total_mad,
                        uncertainty_sec=total_unc,
                        min_offset_sec=min_off,
                        max_offset_sec=max_off,
                        drift_rate_ppm=hop_est.drift_rate_ppm,
                        drift_applied=hop_est.drift_applied,
                        drift_base_epoch=hop_est.drift_base_epoch,
                        estimation_method=f"Transitive 2-hop median via '{inter_src}'",
                        status="ESTIMATED",
                        within_latency_tolerance=within_tol,
                        explanation=(
                            f"Transitive 2-hop clock offset ({total_offset:+.3f}s) resolved via intermediate "
                            f"host '{inter_src}' ({inter_est.estimated_offset_sec:+.3f}s) + '{unres_src}<->{inter_src}' "
                            f"({hop_est.estimated_offset_sec:+.3f}s), combined MAD ±{total_mad:.3f}s."
                        ),
                    )
                    anchors.extend(hop_anchors)
                    break

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
            heuristic_leads = engine.analyze(corrected_events, diagnostics=diagnostics)
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
