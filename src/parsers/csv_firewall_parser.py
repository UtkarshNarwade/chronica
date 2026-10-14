"""CSV Firewall and network packet filter log parser.

Parses comma-separated network logs with columns such as
timestamp, src_ip, src_port, dst_ip, dst_port, proto, action, rule_id.
"""

from __future__ import annotations

import csv
import io
from typing import Any, Dict, List, Optional

from src.parsers.base import BaseParser, ParsedRecord


class CsvFirewallParser(BaseParser):
    """Parser for CSV-formatted firewall / packet filter logs."""

    @property
    def format_name(self) -> str:
        return "csv_firewall"

    @property
    def description(self) -> str:
        return "CSV Firewall & Network Access Logs (timestamp, src_ip, dst_ip, action, proto)"

    EXPECTED_COLUMNS = {"timestamp", "src_ip", "dst_ip", "action"}

    def parse_line(
        self,
        line: str,
        line_number: int,
        context: Optional[Dict[str, Any]] = None,
    ) -> ParsedRecord:
        # Check if this is the header line
        stripped = line.strip().lower()
        if "timestamp" in stripped and ("src_ip" in stripped or "action" in stripped):
            return ParsedRecord(
                line_number=line_number,
                raw_text=line,
                original_timestamp_str=None,
                message="CSV Header Row",
                parse_status="HEADER",
                warnings=["Header row skipped during event timeline indexing."],
            )

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

        if len(row) < 4:
            return ParsedRecord(
                line_number=line_number,
                raw_text=line,
                original_timestamp_str=None,
                parse_status="MALFORMED",
                message=line,
                warnings=[f"Row has {len(row)} columns; expected at least 4."],
            )

        # Standard column mapping:
        # 0: timestamp, 1: src_ip, 2: src_port, 3: dst_ip, 4: dst_port, 5: proto, 6: action, 7: rule_id
        ts_str = row[0].strip()
        src_ip = row[1].strip() if len(row) > 1 else None
        src_port = row[2].strip() if len(row) > 2 else ""
        dst_ip = row[3].strip() if len(row) > 3 else None
        dst_port = row[4].strip() if len(row) > 4 else ""
        proto = row[5].strip().upper() if len(row) > 5 else "TCP"
        action = row[6].strip().upper() if len(row) > 6 else "UNKNOWN"
        rule_id = row[7].strip() if len(row) > 7 else None

        severity = "INFO"
        if action in ("DENY", "DROP", "BLOCK", "REJECT"):
            severity = "WARNING"

        msg = f"FIREWALL {action} {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        if rule_id:
            msg += f" (Rule: {rule_id})"

        extra = {
            "proto": proto,
            "action": action,
            "src_port": src_port,
            "dst_port": dst_port,
        }
        if rule_id:
            extra["rule_id"] = rule_id

        return ParsedRecord(
            line_number=line_number,
            raw_text=line,
            original_timestamp_str=ts_str,
            source_host=None,
            source_app="firewall",
            severity=severity,
            category="NETWORK",
            username=None,
            src_ip=src_ip,
            dst_ip=dst_ip,
            message=msg,
            extra_fields=extra,
            parse_status="SUCCESS",
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
