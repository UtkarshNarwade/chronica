"""CSV timeline export with standardized digital forensics schema."""

from __future__ import annotations

import csv
import io
from typing import Any, List

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

CSV_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(val: Any) -> Any:
    """Sanitize CSV cell against formula injection (CSV injection).

    If the string begins with =, +, -, @, \\t, or \\r (or starts with whitespace
    followed by one of these formula triggers), prepend a single quote (')
    so spreadsheet software (Excel, Calc, Sheets) treats it strictly as text.
    Numeric types (int, float) are preserved as-is.
    """
    if val is None:
        return ""
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        return val
    s = str(val)
    if not s:
        return ""
    if s[0] in CSV_FORMULA_TRIGGERS:
        return "'" + s
    lstripped = s.lstrip(" \t\r\n")
    if lstripped and lstripped[0] in CSV_FORMULA_TRIGGERS:
        return "'" + s
    return s


def export_timeline_csv(events: List[Event]) -> str:
    """Generate an RFC 4180 compliant CSV string containing the timeline events."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_HEADERS)

    for ev in events:
        writer.writerow([
            sanitize_csv_cell(ev.event_id),
            sanitize_csv_cell(ev.normalized_utc_iso or ""),
            sanitize_csv_cell(ev.corrected_utc_iso or ""),
            sanitize_csv_cell(ev.original_timestamp_str or ""),
            sanitize_csv_cell(ev.source_host or ""),
            sanitize_csv_cell(ev.source_app or ""),
            sanitize_csv_cell(ev.severity),
            sanitize_csv_cell(ev.category),
            sanitize_csv_cell(ev.username or ""),
            sanitize_csv_cell(ev.src_ip or ""),
            sanitize_csv_cell(ev.dst_ip or ""),
            sanitize_csv_cell(ev.request_id or ""),
            sanitize_csv_cell(ev.session_id or ""),
            sanitize_csv_cell(ev.description),
            sanitize_csv_cell(ev.normalization_status),
            sanitize_csv_cell(ev.correction_status),
            sanitize_csv_cell(ev.original_filename),
            sanitize_csv_cell(ev.line_number),
            sanitize_csv_cell(ev.parsing_status),
            sanitize_csv_cell("; ".join(ev.data_quality_warnings)),
            sanitize_csv_cell(ev.raw_text),
        ])

    return output.getvalue()
