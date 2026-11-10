"""Investigator-defined custom named-group regular expression parser.

Allows forensic investigators to define custom regex patterns with named capture groups
to parse unique or proprietary log formats that don't match any built-in parser.

Named groups supported:
- (?P<timestamp>...) - Required: raw timestamp string
- (?P<host>...)       - Optional: source hostname
- (?P<user>...)       - Optional: username/actor
- (?P<src_ip>...)     - Optional: source IP address
- (?P<severity>...)   - Optional: severity level string
- (?P<request_id>...) - Optional: request/correlation ID
- (?P<message>...)    - Optional: main log message/description

score_confidence() always returns 0.0 so this parser is never auto-selected;
it must be explicitly chosen by the investigator.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Union

from src.parsers.base import BaseParser, ParsedRecord

# Map common severity string variants to canonical values
SEVERITY_MAP = {
    "info": "INFO",
    "information": "INFO",
    "warning": "WARNING",
    "warn": "WARNING",
    "error": "ERROR",
    "err": "ERROR",
    "critical": "CRITICAL",
    "crit": "CRITICAL",
    "debug": "INFO",
    "notice": "INFO",
    "auth": "AUTH_SUCCESS",
    "auth_success": "AUTH_SUCCESS",
    "auth_fail": "AUTH_FAIL",
    "failure": "AUTH_FAIL",
}


class CustomRegexParser(BaseParser):
    """Investigator-defined custom named-group regular expression parser.

    Only usable when explicitly selected; never auto-detected.
    """

    def __init__(self, pattern: Optional[str] = None) -> None:
        """Initialize with an optional regex pattern string.

        Args:
            pattern: A Python regex string with named capture groups.
                     If None, all lines will be yielded as MALFORMED.
        """
        self._pattern_str = pattern
        self._compiled: Optional[re.Pattern] = None
        if pattern:
            try:
                self._compiled = re.compile(pattern, re.IGNORECASE)
            except re.error as err:
                raise ValueError(f"Invalid custom regex pattern: {err}")

    @property
    def format_name(self) -> str:
        return "custom_regex"

    @property
    def description(self) -> str:
        return "Investigator-defined custom named-group regular expression parser"

    def set_pattern(self, pattern: str) -> None:
        """Update the regex pattern at runtime."""
        self._pattern_str = pattern
        self._compiled = re.compile(pattern, re.IGNORECASE)

    def parse_line(self, line: str, line_number: int, context: Optional[Dict[str, Any]] = None) -> ParsedRecord:
        """Parse a single line using the custom regex pattern."""
        if not self._compiled:
            return ParsedRecord(
                line_number=line_number,
                raw_text=line,
                original_timestamp_str=None,
                parse_status="MALFORMED",
                warnings=["CustomRegexParser: no pattern configured. Set a named-group regex pattern."],
            )

        m = self._compiled.match(line[:8192].strip())
        if not m:
            return ParsedRecord(
                line_number=line_number,
                raw_text=line,
                original_timestamp_str=None,
                parse_status="MALFORMED",
                warnings=[f"Line {line_number}: does not match custom regex pattern."],
            )

        groups = m.groupdict()

        # Extract known named groups
        timestamp = groups.get("timestamp") or groups.get("ts") or groups.get("time")
        host = groups.get("host") or groups.get("hostname") or groups.get("source")
        user = groups.get("user") or groups.get("username") or groups.get("actor")
        src_ip = groups.get("src_ip") or groups.get("ip") or groups.get("source_ip")
        raw_severity = groups.get("severity") or groups.get("level") or groups.get("loglevel")
        request_id = groups.get("request_id") or groups.get("req_id") or groups.get("correlation_id")
        message = groups.get("message") or groups.get("msg") or groups.get("description")

        # Normalize severity
        severity = "INFO"
        if raw_severity:
            severity = SEVERITY_MAP.get(raw_severity.lower().strip(), raw_severity.upper()[:20])

        # Collect all named groups as extra_fields (excluding the standard ones)
        standard_keys = {
            "timestamp", "ts", "time", "host", "hostname", "source",
            "user", "username", "actor", "src_ip", "ip", "source_ip",
            "severity", "level", "loglevel", "request_id", "req_id",
            "correlation_id", "message", "msg", "description",
        }
        extra_fields: Dict[str, Any] = {
            k: v for k, v in groups.items()
            if k not in standard_keys and v is not None
        }

        return ParsedRecord(
            line_number=line_number,
            raw_text=line,
            original_timestamp_str=timestamp,
            source_host=host,
            username=user,
            src_ip=src_ip,
            severity=severity,
            message=message or line[:120],
            request_id=request_id,
            extra_fields=extra_fields,
            parse_status="SUCCESS",
        )

    def score_confidence(self, sample_lines: List[str]) -> tuple[float, str]:
        """Always returns 0.0 — custom_regex is never auto-detected.

        Investigators must explicitly select this parser.
        """
        return 0.0, "CustomRegexParser is never auto-detected; must be explicitly selected."

    def test_pattern(self, sample_lines: Union[List[str], str]) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
        """Test the current pattern against sample lines for live preview.

        Returns a list of match results, or a single result dict if a single string was passed.
        """
        is_single = isinstance(sample_lines, str)
        lines = [sample_lines] if is_single else sample_lines

        results = []
        for line in lines:
            if not self._compiled:
                results.append({
                    "line": line,
                    "matched": False,
                    "groups": {},
                    "captured_groups": {},
                    "error": "Pattern not compiled",
                })
            else:
                m = self._compiled.match(line[:8192].strip())
                results.append({
                    "line": line,
                    "matched": m is not None,
                    "groups": m.groupdict() if m else {},
                    "captured_groups": m.groupdict() if m else {},
                    "error": None if m else "No match for pattern",
                })

        return results[0] if is_single else results
