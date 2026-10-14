"""JSON Lines (JSONL) application log parser.

Parses structured application logs with one JSON document per line,
mapping common fields (timestamp, host, service, severity, request_id, user, IP)
while preserving unmapped attributes in extra_fields.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from src.parsers.base import BaseParser, ParsedRecord


class JsonlParser(BaseParser):
    """Parser for newline-delimited JSON (JSON Lines / NDJSON) log files."""

    @property
    def format_name(self) -> str:
        return "jsonl"

    @property
    def description(self) -> str:
        return "JSON Lines (JSONL/NDJSON) structured application logs"

    # Known key variations across common logging frameworks
    TIMESTAMP_KEYS = ["timestamp", "@timestamp", "time", "ts", "datetime", "date"]
    LEVEL_KEYS = ["level", "severity", "log_level", "loglevel", "type"]
    HOST_KEYS = ["host", "hostname", "server", "node"]
    APP_KEYS = ["app", "service", "application", "logger", "source", "module"]
    USER_KEYS = ["user", "username", "account", "user_id", "actor", "principal"]
    SRC_IP_KEYS = ["src_ip", "source_ip", "client_ip", "ip", "remote_addr", "remote_ip"]
    DST_IP_KEYS = ["dst_ip", "dest_ip", "destination_ip", "server_ip"]
    REQUEST_ID_KEYS = ["request_id", "req_id", "trace_id", "correlation_id", "span_id"]
    SESSION_ID_KEYS = ["session_id", "sid", "session"]
    MESSAGE_KEYS = ["message", "msg", "event", "action", "description", "details"]

    def _find_field(self, data: Dict[str, Any], candidate_keys: List[str]) -> Optional[Any]:
        for k in candidate_keys:
            if k in data and data[k] is not None:
                return data[k]
        return None

    def parse_line(
        self,
        line: str,
        line_number: int,
        context: Optional[Dict[str, Any]] = None,
    ) -> ParsedRecord:
        warnings: List[str] = []

        try:
            doc = json.loads(line)
        except json.JSONDecodeError as err:
            return ParsedRecord(
                line_number=line_number,
                raw_text=line,
                original_timestamp_str=None,
                severity="ERROR",
                category="APPLICATION",
                message=line,
                parse_status="MALFORMED",
                warnings=[f"JSON syntax error at line {line_number}: {err}"],
            )

        if not isinstance(doc, dict):
            return ParsedRecord(
                line_number=line_number,
                raw_text=line,
                original_timestamp_str=None,
                severity="ERROR",
                category="APPLICATION",
                message=str(doc),
                parse_status="MALFORMED",
                warnings=[f"Line {line_number} is valid JSON but not an object/dictionary."],
            )

        # Extract normalized fields
        ts_val = self._find_field(doc, self.TIMESTAMP_KEYS)
        ts_str = str(ts_val) if ts_val is not None else None
        if not ts_str:
            warnings.append("Record does not specify a timestamp field.")

        level_val = self._find_field(doc, self.LEVEL_KEYS)
        level_str = str(level_val).upper() if level_val is not None else "INFO"

        host_val = self._find_field(doc, self.HOST_KEYS)
        app_val = self._find_field(doc, self.APP_KEYS)
        user_val = self._find_field(doc, self.USER_KEYS)
        src_ip_val = self._find_field(doc, self.SRC_IP_KEYS)
        dst_ip_val = self._find_field(doc, self.DST_IP_KEYS)
        req_id_val = self._find_field(doc, self.REQUEST_ID_KEYS)
        sess_id_val = self._find_field(doc, self.SESSION_ID_KEYS)
        msg_val = self._find_field(doc, self.MESSAGE_KEYS)
        msg_str = str(msg_val) if msg_val is not None else json.dumps(doc)

        # Categorize
        category = "APPLICATION"
        event_lower = (str(doc.get("event", "")) + " " + msg_str).lower()
        if any(term in event_lower for term in ["login", "auth", "password", "token", "session"]):
            category = "AUTHENTICATION"
        elif any(term in event_lower for term in ["http", "request", "api", "endpoint", "url"]):
            category = "WEB_REQUEST"
        elif any(term in event_lower for term in ["network", "packet", "connect", "disconnect"]):
            category = "NETWORK"

        # Separate unmapped fields
        mapped_keys = set(
            self.TIMESTAMP_KEYS
            + self.LEVEL_KEYS
            + self.HOST_KEYS
            + self.APP_KEYS
            + self.USER_KEYS
            + self.SRC_IP_KEYS
            + self.DST_IP_KEYS
            + self.REQUEST_ID_KEYS
            + self.SESSION_ID_KEYS
            + self.MESSAGE_KEYS
        )
        extra = {k: v for k, v in doc.items() if k not in mapped_keys}

        return ParsedRecord(
            line_number=line_number,
            raw_text=line,
            original_timestamp_str=ts_str,
            source_host=str(host_val) if host_val is not None else None,
            source_app=str(app_val) if app_val is not None else "app",
            severity=level_str,
            category=category,
            username=str(user_val) if user_val is not None else None,
            src_ip=str(src_ip_val) if src_ip_val is not None else None,
            dst_ip=str(dst_ip_val) if dst_ip_val is not None else None,
            message=msg_str,
            request_id=str(req_id_val) if req_id_val is not None else None,
            session_id=str(sess_id_val) if sess_id_val is not None else None,
            extra_fields=extra,
            parse_status="SUCCESS",
            warnings=warnings,
        )

    def score_confidence(self, sample_lines: List[str]) -> tuple[float, str]:
        if not sample_lines:
            return 0.0, "Empty sample"

        valid_json_count = 0
        has_ts_count = 0
        total = 0

        for line in sample_lines[:20]:
            stripped = line.strip()
            if not stripped:
                continue
            total += 1
            if stripped.startswith("{") and stripped.endswith("}"):
                try:
                    obj = json.loads(stripped)
                    if isinstance(obj, dict):
                        valid_json_count += 1
                        if any(k in obj for k in self.TIMESTAMP_KEYS):
                            has_ts_count += 1
                except Exception:
                    pass

        if total == 0:
            return 0.0, "No non-empty lines in sample"

        if valid_json_count == 0:
            return 0.0, "Lines do not match JSON object syntax"

        score = (valid_json_count / total) * 0.7 + (has_ts_count / total) * 0.3
        explanation = (
            f"JSON Lines detector: {valid_json_count}/{total} valid JSON objects, "
            f"{has_ts_count}/{total} include timestamp keys."
        )
        return score, explanation
