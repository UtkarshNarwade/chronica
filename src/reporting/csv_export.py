"""CSV timeline export with standardized digital forensics schema."""

from __future__ import annotations

import csv
import io
from typing import List

from src.timeline.schema import Event

CSV_HEADERS = [
    "event_id",
    "normalized_utc",
    "corrected_utc",
    "original_timestamp",
    "host",
    "app",
    "severity",
    "category",
    "username",
    "src_ip",
    "dst_ip",
    "request_id",
    "session_id",
    "description",
    "normalization_status",
    "correction_status",
    "evidence_file",
    "line_number",
    "parsing_status",
    "warnings",
    "raw_text",
]


def export_timeline_csv(events: List[Event]) -> str:
    """Generate an RFC 4180 compliant CSV string containing the timeline events."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_HEADERS)

    for ev in events:
        writer.writerow([
            ev.event_id,
            ev.normalized_utc_iso or "",
            ev.corrected_utc_iso or "",
            ev.original_timestamp_str or "",
            ev.source_host or "",
            ev.source_app or "",
            ev.severity,
            ev.category,
            ev.username or "",
            ev.src_ip or "",
            ev.dst_ip or "",
            ev.request_id or "",
            ev.session_id or "",
            ev.description,
            ev.normalization_status,
            ev.correction_status,
            ev.original_filename,
            ev.line_number,
            ev.parsing_status,
            "; ".join(ev.data_quality_warnings),
            ev.raw_text,
        ])

    return output.getvalue()
