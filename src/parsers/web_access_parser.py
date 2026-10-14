"""Web server access log parser.

Supports Common Log Format (CLF) and Combined Log Format (Apache / Nginx),
with support for optional trailing fields such as request_id, upstream response time,
and custom headers.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from src.parsers.base import BaseParser, ParsedRecord

# Standard Combined Log Format regex with optional trailing request ID / session ID
COMBINED_LOG_REGEX = re.compile(
    r'^([^\s]+)\s+'                   # 1: Client IP
    r'([^\s]+)\s+'                   # 2: Remote logname (identd)
    r'([^\s]+)\s+'                   # 3: Auth user
    r'\[([^\]]+)\]\s+'               # 4: Timestamp [10/Oct/2026:13:55:36 -0700]
    r'"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP/(\d\.\d))?"\s+'  # 5: Method, 6: URI, 7: HTTP ver
    r'(\d{3})\s+'                    # 8: HTTP status code
    r'([^\s]+)'                      # 9: Response bytes or '-'
    r'(?:\s+"([^"]*)"'               # 10: Referer (optional)
    r'\s+"([^"]*)")?'                # 11: User-Agent (optional)
    r'(?:\s+"?([a-zA-Z0-9_\-\.]+)"?)?'  # 12: Optional trailing Request ID / Trace ID
    r'.*$'
)

# Loose fallback for basic Common Log Format (CLF) without referer/agent
COMMON_LOG_REGEX = re.compile(
    r'^([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP/(\d\.\d))?"\s+(\d{3})\s+([^\s]+).*$'
)


class WebAccessParser(BaseParser):
    """Parser for Apache and Nginx web server access logs."""

    @property
    def format_name(self) -> str:
        return "web_access"

    @property
    def description(self) -> str:
        return "Nginx / Apache web server access logs (Common & Combined Log Format)"

    def parse_line(
        self,
        line: str,
        line_number: int,
        context: Optional[Dict[str, Any]] = None,
    ) -> ParsedRecord:
        warnings: List[str] = []
        extra: Dict[str, Any] = {}

        m = COMBINED_LOG_REGEX.match(line)
        if not m:
            m = COMMON_LOG_REGEX.match(line)

        if not m:
            return ParsedRecord(
                line_number=line_number,
                raw_text=line,
                original_timestamp_str=None,
                severity="ERROR",
                category="WEB_REQUEST",
                message=line,
                parse_status="MALFORMED",
                warnings=["Line does not conform to Common or Combined web access log format."],
            )

        groups = m.groups()
        client_ip = groups[0]
        ident = groups[1]
        authuser = groups[2] if groups[2] != "-" else None
        ts_str = groups[3]
        method = groups[4]
        uri = groups[5]
        http_ver = groups[6] if len(groups) > 6 else None
        status_code_str = groups[7] if len(groups) > 7 else "200"
        bytes_str = groups[8] if len(groups) > 8 else "0"

        referer = groups[9] if len(groups) > 9 and groups[9] is not None and groups[9] != "-" else None
        user_agent = groups[10] if len(groups) > 10 and groups[10] is not None and groups[10] != "-" else None
        request_id = groups[11] if len(groups) > 11 and groups[11] is not None and groups[11] != "-" else None

        # Check for request ID embedded in query string if not in trailing column
        if not request_id and "req_id=" in uri:
            m_req = re.search(r"req_id=([a-zA-Z0-9_\-]+)", uri)
            if m_req:
                request_id = m_req.group(1)

        try:
            status_code = int(status_code_str)
        except ValueError:
            status_code = 0
            warnings.append(f"Invalid HTTP status code: '{status_code_str}'")

        try:
            resp_bytes = int(bytes_str) if bytes_str != "-" else 0
        except ValueError:
            resp_bytes = 0

        # Assess severity and category
        category = "WEB_REQUEST"
        severity = "INFO"
        if 400 <= status_code < 500:
            if status_code in (401, 403):
                severity = "AUTH_FAIL"
                category = "AUTHENTICATION"
            else:
                severity = "WARNING"
        elif status_code >= 500:
            severity = "ERROR"

        extra["method"] = method
        extra["uri"] = uri
        extra["status_code"] = status_code
        extra["response_bytes"] = resp_bytes
        if http_ver:
            extra["http_version"] = http_ver
        if referer:
            extra["referer"] = referer
        if user_agent:
            extra["user_agent"] = user_agent

        description = f"{method} {uri} -> {status_code} ({resp_bytes} bytes)"

        return ParsedRecord(
            line_number=line_number,
            raw_text=line,
            original_timestamp_str=ts_str,
            source_host=None,
            source_app="web_server",
            severity=severity,
            category=category,
            username=authuser,
            src_ip=client_ip,
            dst_ip=None,
            message=description,
            request_id=request_id,
            session_id=None,
            extra_fields=extra,
            parse_status="SUCCESS",
            warnings=warnings,
        )

    def score_confidence(self, sample_lines: List[str]) -> tuple[float, str]:
        if not sample_lines:
            return 0.0, "Empty sample"

        matches = 0
        total = 0

        for line in sample_lines[:20]:
            stripped = line.strip()
            if not stripped:
                continue
            total += 1
            if COMBINED_LOG_REGEX.match(stripped) or COMMON_LOG_REGEX.match(stripped):
                matches += 1

        if total == 0:
            return 0.0, "No non-empty lines in sample"

        score = matches / total
        explanation = (
            f"Web access detector: {matches}/{total} lines matched "
            f"Apache/Nginx Common or Combined Access Log syntax."
        )
        return score, explanation
