"""Windows Security & System Event Log parser (CSV or JSON export format).

Supports Windows Event Log exports containing EventID-based records:
- 4624: Logon Success -> AUTH_SUCCESS
- 4625: Failed Logon -> AUTH_FAIL
- 4672: Special Privileges -> WARNING
- 4688: Process Creation -> INFO/WARNING
- 1102: Audit Log Cleared -> CRITICAL
- 4616: System Time Changed -> WARNING
- 7045: Service Installed -> WARNING

Parses both CSV exports (with header row) and JSON-structured event arrays.
"""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any, Dict, Iterator, List, Optional

from src.parsers.base import BaseParser, ParsedRecord

# Windows Event Log specific EventID mappings
WINDOWS_EVENT_SEVERITY_MAP = {
    4624: "AUTH_SUCCESS",
    4625: "AUTH_FAIL",
    4672: "WARNING",
    4688: "INFO",
    1102: "CRITICAL",
    4616: "WARNING",
    7045: "WARNING",
    4634: "INFO",     # Logoff
    4648: "WARNING",  # Logon with explicit credentials
    4768: "INFO",     # Kerberos TGT request
    4769: "INFO",     # Kerberos service ticket request
    4776: "INFO",     # NTLM authentication
}

WINDOWS_EVENT_CATEGORY_MAP = {
    4624: "AUTHENTICATION",
    4625: "AUTHENTICATION",
    4672: "AUTHENTICATION",
    4688: "SYSTEM",
    1102: "SYSTEM",
    4616: "SYSTEM",
    7045: "SYSTEM",
}

WINDOWS_EVENT_DESCRIPTION_MAP = {
    4624: "Logon Success",
    4625: "Failed Logon Attempt",
    4672: "Special Privileges Assigned to New Logon",
    4688: "A new process has been created",
    1102: "The audit log was cleared",
    4616: "The system time was changed",
    7045: "A service was installed in the system",
    4634: "An account was logged off",
    4648: "A logon was attempted using explicit credentials",
}

# CSV header columns to detect Windows Event format
WINDOWS_CSV_INDICATORS = {
    "eventid", "timecreated", "computer", "targetusername",
    "machinename", "logontype", "ipaddress",
}

# JSON field indicators
WINDOWS_JSON_INDICATORS = {
    "EventID", "TimeCreated", "Computer", "TargetUserName",
    "MachineName", "LogonType",
}


class WindowsEventParser(BaseParser):
    """Parser for Windows Security & System Event Logs (CSV or JSON export format)."""

    @property
    def format_name(self) -> str:
        return "windows_event"

    @property
    def description(self) -> str:
        return "Windows Security & System Event Logs (CSV / Structured Export)"

    def _normalize_key(self, key: str) -> str:
        """Normalize a header key to lowercase for flexible matching."""
        return key.strip().lower()

    def _parse_csv_stream(self, lines: Iterator[str]) -> List[ParsedRecord]:
        """Parse a Windows Event Log CSV export."""
        records: List[ParsedRecord] = []
        all_lines = list(lines)
        if not all_lines:
            return records

        # First line is header
        header_line = all_lines[0].strip()
        if not header_line:
            return records

        try:
            reader = csv.DictReader(io.StringIO("\n".join(all_lines)))

            for line_num, row in enumerate(reader, start=2):
                orig_raw = (
                    all_lines[line_num - 1].rstrip("\r\n")
                    if (line_num - 1) < len(all_lines)
                    else (",".join(str(v) for v in row.values()) if row else "")
                )
                try:
                    # Normalize row keys
                    norm_row: Dict[str, str] = {self._normalize_key(k): (v or "") for k, v in row.items()}

                    # Extract EventID
                    event_id_str = (
                        norm_row.get("eventid")
                        or norm_row.get("id")
                        or norm_row.get("event_id")
                        or ""
                    )
                    try:
                        event_id = int(re.search(r"\d+", event_id_str).group()) if re.search(r"\d+", event_id_str) else 0
                    except Exception:
                        event_id = 0

                    # Extract timestamp
                    timestamp = (
                        norm_row.get("timecreated")
                        or norm_row.get("timestamp")
                        or norm_row.get("time")
                        or norm_row.get("date")
                        or None
                    )

                    # Extract host
                    source_host = (
                        norm_row.get("computer")
                        or norm_row.get("machinename")
                        or norm_row.get("computername")
                        or None
                    )

                    # Extract username
                    username = (
                        norm_row.get("targetusername")
                        or norm_row.get("subjectusername")
                        or norm_row.get("username")
                        or None
                    )
                    if username in ("-", "N/A", ""):
                        username = None

                    # Extract IP
                    src_ip = norm_row.get("ipaddress") or norm_row.get("sourceipaddress") or None
                    if src_ip in ("-", "N/A", "::1", "::"):
                        src_ip = None

                    # Extract session/correlation IDs
                    session_id = norm_row.get("logonid") or norm_row.get("subjectlogonid") or None
                    request_id = norm_row.get("correlationid") or norm_row.get("activityid") or None

                    severity = WINDOWS_EVENT_SEVERITY_MAP.get(event_id, "INFO")
                    category = WINDOWS_EVENT_CATEGORY_MAP.get(event_id, "SYSTEM")
                    description = WINDOWS_EVENT_DESCRIPTION_MAP.get(event_id, f"Windows Event ID {event_id}")

                    extra_fields: Dict[str, Any] = {"event_id": event_id}
                    for k in ("logontype", "processname", "processid", "parentprocessid", "servicename"):
                        if k in norm_row and norm_row[k] not in ("-", "N/A", ""):
                            extra_fields[k] = norm_row[k]

                    records.append(ParsedRecord(
                        line_number=line_num,
                        raw_text=orig_raw,
                        original_timestamp_str=timestamp,
                        source_host=source_host,
                        severity=severity,
                        category=category,
                        username=username,
                        src_ip=src_ip,
                        message=description,
                        session_id=session_id,
                        request_id=request_id,
                        extra_fields=extra_fields,
                        parse_status="SUCCESS",
                    ))
                except Exception as row_err:
                    records.append(ParsedRecord(
                        line_number=line_num,
                        raw_text=orig_raw,
                        original_timestamp_str=None,
                        parse_status="MALFORMED",
                        warnings=[f"WindowsEventParser CSV row error at line {line_num}: {row_err}"],
                    ))
        except csv.Error as csv_err:
            records.append(ParsedRecord(
                line_number=2,
                raw_text="",
                original_timestamp_str=None,
                parse_status="MALFORMED",
                warnings=[f"WindowsEventParser CSV stream error: {csv_err}"],
            ))

        return records

    def parse_line(self, line: str, line_number: int, context: Optional[Dict[str, Any]] = None) -> ParsedRecord:
        """Parse a single line (used for plain-text/line-by-line mode)."""
        # For CSV, parse_stream is preferred; this is a fallback
        return ParsedRecord(
            line_number=line_number,
            raw_text=line,
            original_timestamp_str=None,
            parse_status="PARTIAL",
            warnings=["WindowsEventParser: use parse_stream for CSV exports."],
        )

    def parse_stream(
        self,
        lines: Iterator[str],
        context: Optional[Dict[str, Any]] = None,
    ) -> Iterator[ParsedRecord]:
        """Parse a Windows Event Log CSV or JSON export stream."""
        all_lines = list(lines)
        if not all_lines:
            return

        # Try JSON first
        joined = "\n".join(all_lines).strip()
        if joined.startswith("[") or joined.startswith("{"):
            try:
                data = json.loads(joined)
                if isinstance(data, dict):
                    data = [data]
                if isinstance(data, list):
                    for line_num, item in enumerate(data, start=1):
                        if not isinstance(item, dict):
                            continue
                        raw_eid = item.get("EventID") if item.get("EventID") is not None else item.get("event_id")
                        try:
                            event_id = int(raw_eid) if raw_eid is not None else 0
                        except (ValueError, TypeError):
                            event_id = 0
                        timestamp = (
                            item.get("TimeCreated")
                            or item.get("Timestamp")
                            or item.get("time")
                            or None
                        )
                        source_host = item.get("Computer") or item.get("MachineName") or None
                        username = item.get("TargetUserName") or item.get("SubjectUserName") or None
                        if username in ("-", "N/A", ""):
                            username = None
                        src_ip = item.get("IpAddress") or None
                        if src_ip in ("-", "N/A", "::1"):
                            src_ip = None
                        session_id = item.get("LogonId") or item.get("SubjectLogonId") or None
                        request_id = item.get("CorrelationId") or item.get("ActivityId") or None
                        severity = WINDOWS_EVENT_SEVERITY_MAP.get(event_id, "INFO")
                        category = WINDOWS_EVENT_CATEGORY_MAP.get(event_id, "SYSTEM")
                        description = WINDOWS_EVENT_DESCRIPTION_MAP.get(event_id, f"Windows Event ID {event_id}")
                        extra_fields: Dict[str, Any] = {"event_id": event_id}
                        for k in ("LogonType", "ProcessName", "ProcessId", "ServiceName"):
                            if k in item:
                                extra_fields[k.lower()] = item[k]
                        orig_raw = (
                            all_lines[line_num - 1].rstrip("\r\n")
                            if (line_num - 1) < len(all_lines) and all_lines[line_num - 1].strip().startswith("{")
                            else json.dumps(item)
                        )
                        yield ParsedRecord(
                            line_number=line_num,
                            raw_text=orig_raw,
                            original_timestamp_str=timestamp,
                            source_host=source_host,
                            severity=severity,
                            category=category,
                            username=username,
                            src_ip=src_ip,
                            message=description,
                            session_id=session_id,
                            request_id=request_id,
                            extra_fields=extra_fields,
                            parse_status="SUCCESS",
                        )
                    return
            except (json.JSONDecodeError, ValueError, TypeError):
                pass

        # Try CSV
        # Check if first non-empty line looks like a Windows Event CSV header
        first_non_empty = next((l.strip() for l in all_lines if l.strip()), "")
        if first_non_empty:
            cols = {c.strip().lower() for c in first_non_empty.split(",")}
            if cols.intersection(WINDOWS_CSV_INDICATORS):
                records = self._parse_csv_stream(iter(all_lines))
                for r in records:
                    yield r
                return

        # Fallback: yield MALFORMED for each line
        for idx, line in enumerate(all_lines, start=1):
            stripped = line.rstrip("\r\n")
            if not stripped:
                continue
            yield ParsedRecord(
                line_number=idx,
                raw_text=stripped,
                original_timestamp_str=None,
                parse_status="MALFORMED",
                warnings=[f"Line {idx}: unrecognized Windows Event format."],
            )

    def score_confidence(self, sample_lines: List[str]) -> tuple[float, str]:
        """Evaluate confidence that sample lines are Windows Event Log format."""
        if not sample_lines:
            return 0.0, "No sample lines."

        # Check JSON format
        joined = "\n".join(sample_lines[:10]).strip()
        if joined.startswith("[") or joined.startswith("{"):
            try:
                data = json.loads(joined)
                if isinstance(data, list):
                    data = data[:3]
                elif isinstance(data, dict):
                    data = [data]
                if any(
                    any(k in item for k in WINDOWS_JSON_INDICATORS)
                    for item in data if isinstance(item, dict)
                ):
                    return 0.88, "JSON structure contains Windows Event Log fields (EventID, TimeCreated, Computer)."
            except Exception:
                pass

        # Check CSV header
        first_non_empty = next((l.strip() for l in sample_lines if l.strip()), "")
        if first_non_empty:
            cols = {c.strip().lower() for c in first_non_empty.split(",")}
            overlap = cols.intersection(WINDOWS_CSV_INDICATORS)
            if len(overlap) >= 3:
                return 0.85, f"CSV header contains {len(overlap)} Windows Event Log columns: {overlap}"
            if len(overlap) >= 2:
                return 0.60, f"CSV header contains {len(overlap)} Windows Event Log columns: {overlap}"

        return 0.0, "No Windows Event Log format indicators detected."
