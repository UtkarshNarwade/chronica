"""CSV Firewall and network packet filter log parser.

Parses comma-separated network logs with columns such as
timestamp, src_ip, src_port, dst_ip, dst_port, proto, action, rule_id.
"""

from __future__ import annotations

import csv
import io
from typing import Any, Dict, Iterator, List, Optional

from src.parsers.base import BaseParser, ParsedRecord


REQUIRED_COLUMNS = ["timestamp", "src_ip", "dst_ip", "action"]

COLUMN_ALIASES: Dict[str, List[str]] = {
    "timestamp": ["timestamp", "time", "datetime", "date_time", "@timestamp", "event_time", "logdate"],
    "src_ip": ["src_ip", "source_ip", "srcip", "source", "src", "client_ip", "src_addr", "source_address"],
    "dst_ip": ["dst_ip", "destination_ip", "dest_ip", "dstip", "destination", "dst", "dst_addr", "destination_address", "target_ip"],
    "src_port": ["src_port", "source_port", "srcport", "sport", "s_port"],
    "dst_port": ["dst_port", "destination_port", "dest_port", "dstport", "dport", "d_port"],
    "action": ["action", "act", "verdict", "decision", "status", "disposition"],
    "proto": ["proto", "protocol", "transport", "ip_proto"],
    "rule_id": ["rule_id", "rule", "rule_name", "policy_id", "ruleid", "policy"],
}


class CsvFirewallParser(BaseParser):
    """Parser for CSV-formatted firewall / packet filter logs."""

    def __init__(self) -> None:
        super().__init__()
        self.raw_header_cols: Optional[List[str]] = None
        self.header_cols: Optional[List[str]] = None
        self.canonical_map: Dict[str, int] = {}
        self.header_error: Optional[str] = None

    def reset(self) -> None:
        """Reset stream state before parsing a new log stream."""
        self.raw_header_cols = None
        self.header_cols = None
        self.canonical_map = {}
        self.header_error = None

    def parse_stream(
        self,
        lines: Iterator[str],
        context: Optional[Dict[str, Any]] = None,
    ) -> Iterator[ParsedRecord]:
        self.reset()
        for idx, line in enumerate(lines, start=1):
            stripped = line.rstrip("\r\n")
            if not stripped:
                continue
            yield self.parse_line(stripped, line_number=idx, context=context)

    @property
    def format_name(self) -> str:
        return "csv_firewall"

    @property
    def description(self) -> str:
        return "CSV Firewall & Network Access Logs (timestamp, src_ip, dst_ip, action, proto)"

    EXPECTED_COLUMNS = {"timestamp", "src_ip", "dst_ip", "action"}

    def _is_header_row(self, row: List[str]) -> bool:
        normalized = [c.strip().lower().replace('"', '') for c in row]
        matches = 0
        for canonical, aliases in COLUMN_ALIASES.items():
            if any(col in aliases for col in normalized):
                matches += 1
        return matches >= 2 or any("timestamp" in col for col in normalized)

    def parse_line(
        self,
        line: str,
        line_number: int,
        context: Optional[Dict[str, Any]] = None,
    ) -> ParsedRecord:
        reader = csv.reader(io.StringIO(line))
        try:
            row = next(reader)
        except Exception as err:
            return ParsedRecord(
                line_number=line_number,
                raw_text=line,
                original_timestamp_str=None,
                parse_status="MALFORMED",
                message=line,
                warnings=[f"CSV parsing error: {err}"],
            )

        # Check if this is the header line
        if self._is_header_row(row):
            self.raw_header_cols = [c.strip().replace('"', '') for c in row]
            self.header_cols = [c.lower() for c in self.raw_header_cols]
            self.canonical_map = {}
            for idx, col_name in enumerate(self.header_cols):
                for canonical, aliases in COLUMN_ALIASES.items():
                    if col_name in aliases and canonical not in self.canonical_map:
                        self.canonical_map[canonical] = idx
                        break

            missing = [req for req in REQUIRED_COLUMNS if req not in self.canonical_map]
            if missing:
                self.header_error = f"Missing required column(s) in CSV firewall header: {', '.join(missing)}"
                return ParsedRecord(
                    line_number=line_number,
                    raw_text=line,
                    original_timestamp_str=None,
                    message=f"CSV Header missing required columns: {', '.join(missing)}",
                    parse_status="HEADER",
                    warnings=[self.header_error],
                )
            self.header_error = None
            return ParsedRecord(
                line_number=line_number,
                raw_text=line,
                original_timestamp_str=None,
                message="CSV Header Row",
                parse_status="HEADER",
                warnings=["Header row skipped during event timeline indexing."],
            )

        if self.header_error:
            return ParsedRecord(
                line_number=line_number,
                raw_text=line,
                original_timestamp_str=None,
                parse_status="MALFORMED",
                message=line,
                warnings=[self.header_error],
            )

        warnings: List[str] = []
        extra: Dict[str, Any] = {}

        if self.canonical_map:
            def _get_val(canonical: str) -> Optional[str]:
                if canonical in self.canonical_map:
                    idx = self.canonical_map[canonical]
                    if idx < len(row):
                        v = row[idx].strip()
                        return v if v else None
                return None

            ts_str = _get_val("timestamp")
            src_ip = _get_val("src_ip")
            dst_ip = _get_val("dst_ip")
            action_raw = _get_val("action") or "UNKNOWN"
            action = action_raw.upper()
            src_port = _get_val("src_port") or ""
            dst_port = _get_val("dst_port") or ""
            proto = (_get_val("proto") or "TCP").upper()
            rule_id = _get_val("rule_id")

            # Keep unknown/extra columns in extra_fields
            mapped_indices = set(self.canonical_map.values())
            for idx, val in enumerate(row):
                if idx not in mapped_indices:
                    col_name = (
                        self.raw_header_cols[idx]
                        if self.raw_header_cols and idx < len(self.raw_header_cols)
                        else (
                            self.header_cols[idx]
                            if self.header_cols and idx < len(self.header_cols)
                            else f"col_{idx}"
                        )
                    )
                    extra[col_name] = val.strip()
        else:
            if len(row) < 4:
                return ParsedRecord(
                    line_number=line_number,
                    raw_text=line,
                    original_timestamp_str=None,
                    parse_status="MALFORMED",
                    message=line,
                    warnings=[f"Row has {len(row)} columns; expected at least 4."],
                )
            ts_str = row[0].strip()
            src_ip = row[1].strip() if len(row) > 1 else None
            src_port = row[2].strip() if len(row) > 2 else ""
            dst_ip = row[3].strip() if len(row) > 3 else None
            dst_port = row[4].strip() if len(row) > 4 else ""
            proto = row[5].strip().upper() if len(row) > 5 else "TCP"
            action = row[6].strip().upper() if len(row) > 6 else "UNKNOWN"
            rule_id = row[7].strip() if len(row) > 7 else None
            for idx in range(8, len(row)):
                extra[f"col_{idx}"] = row[idx].strip()
            warnings.append("No CSV header detected; falling back to default positional column mapping.")

        severity = "INFO"
        if action in ("DENY", "DROP", "BLOCK", "REJECT"):
            severity = "WARNING"

        msg = f"FIREWALL {action} {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        if rule_id:
            msg += f" (Rule: {rule_id})"

        extra["proto"] = proto
        extra["action"] = action
        extra["src_port"] = src_port
        extra["dst_port"] = dst_port
        if rule_id:
            extra["rule_id"] = rule_id

        source_host = None
        if context:
            source_host = context.get("source_host") or context.get("host")

        return ParsedRecord(
            line_number=line_number,
            raw_text=line,
            original_timestamp_str=ts_str,
            source_host=source_host,
            source_app="firewall",
            severity=severity,
            category="NETWORK",
            username=None,
            src_ip=src_ip,
            dst_ip=dst_ip,
            message=msg,
            extra_fields=extra,
            parse_status="SUCCESS",
            warnings=warnings,
        )

    def score_confidence(self, sample_lines: List[str]) -> tuple[float, str]:
        if not sample_lines:
            return 0.0, "Empty sample"

        header_found = False
        valid_rows = 0
        total = 0

        for idx, line in enumerate(sample_lines[:15]):
            stripped = line.strip().lower()
            if not stripped:
                continue
            total += 1
            if idx == 0 and ("timestamp" in stripped and "src_ip" in stripped):
                header_found = True
                continue

            parts = [p.strip() for p in stripped.split(",")]
            if len(parts) >= 4 and any(act in stripped for act in ["allow", "deny", "drop", "block", "accept"]):
                valid_rows += 1

        if total == 0:
            return 0.0, "No non-empty lines in sample"

        if header_found and valid_rows > 0:
            return 0.95, f"CSV Firewall detector: Header row detected and {valid_rows} rows match firewall schema."
        elif valid_rows >= 2:
            return 0.70, f"CSV Firewall detector: {valid_rows}/{total} rows conform to CSV network log format."

        return 0.0, "Lines do not match CSV firewall format."
