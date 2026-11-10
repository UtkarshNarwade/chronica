"""Web server access log parser.

Supports Common Log Format (CLF) and Combined Log Format (Apache / Nginx),
with support for optional trailing fields such as request_id, upstream response time,
and custom headers.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from src.parsers.base import BaseParser, ParsedRecord

# Standard Combined Log Format regex with quoted request string and optional trailing fields
COMBINED_LOG_REGEX = re.compile(
    r'^([^\s]+)\s+'                   # 1: Client IP
    r'([^\s]+)\s+'                   # 2: Remote logname (identd)
    r'([^\s]+)\s+'                   # 3: Auth user
    r'\[([^\]]+)\]\s+'               # 4: Timestamp [10/Oct/2026:13:55:36 -0700]
    r'"([^"]*)"\s+'                  # 5: Full quoted request string
    r'(\d{3})\s+'                    # 6: HTTP status code
    r'([^\s]+)'                      # 7: Response bytes or '-'
    r'(?:\s+"([^"]*)"'               # 8: Referer (optional)
    r'\s+"([^"]*)")?'                # 9: User-Agent (optional)
    r'(?:\s+(.*))?$'                 # 10: Trailing fields / tokens (optional)
)

# Loose fallback for basic Common Log Format (CLF) without referer/agent
COMMON_LOG_REGEX = re.compile(
    r'^([^\s]+)\s+'
    r'([^\s]+)\s+'
    r'([^\s]+)\s+'
    r'\[([^\]]+)\]\s+'
    r'"([^"]*)"\s+'
    r'(\d{3})\s+'
    r'([^\s]+)'
    r'(?:\s+(.*))?$'
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

        is_combined = True
        m = COMBINED_LOG_REGEX.match(line)
        if not m:
            is_combined = False
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
        req_raw = groups[4].strip()
        status_code_str = groups[5]
        bytes_str = groups[6]

        if ident != "-":
            extra["ident"] = ident

        if is_combined:
            referer = groups[7] if len(groups) > 7 and groups[7] is not None and groups[7] != "-" else None
            user_agent = groups[8] if len(groups) > 8 and groups[8] is not None and groups[8] != "-" else None
            trailing = groups[9] if len(groups) > 9 and groups[9] is not None else None
        else:
            referer = None
            user_agent = None
            trailing = groups[7] if len(groups) > 7 and groups[7] is not None else None

        # Parse request string into method, uri, http_version
        method = "-"
        uri = "-"
        http_ver = None
        if req_raw and req_raw != "-":
            parts = req_raw.split()
            if len(parts) == 1:
                method = parts[0].upper()
                uri = "-"
            elif len(parts) >= 2:
                method = parts[0].upper()
                if parts[-1].upper().startswith("HTTP/"):
                    http_ver = parts[-1][5:]
                    uri = " ".join(parts[1:-1])
                else:
                    uri = " ".join(parts[1:])

        # Extract request ID: only from named field or explicit req/trace ID token
        request_id = None
        if trailing:
            trailing_clean = trailing.strip()
            # 1. Named request ID field (e.g. request_id=..., req_id=..., trace_id=...)
            m_named = re.search(
                r'(?:request_id|req_id|x_request_id|trace_id)=["\']?([a-zA-Z0-9_\-\.]+)["\']?',
                trailing_clean,
                re.IGNORECASE,
            )
            if m_named:
                request_id = m_named.group(1)
            else:
                # 2. Explicit request ID token format (req-..., trace-..., or UUID)
                m_explicit = re.search(
                    r'(?:^|\s)["\']?(req[-_][a-zA-Z0-9_\-\.]+|trace[-_][a-zA-Z0-9_\-\.]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']?(?:\s|$)',
                    trailing_clean,
                    re.IGNORECASE,
                )
                if m_explicit:
                    request_id = m_explicit.group(1)
                else:
                    # 3. Numeric response time / duration ($request_time or $upstream_response_time)
                    clean_token = trailing_clean.strip('"\'; ')
                    try:
                        extra["response_time"] = float(clean_token)
                    except ValueError:
                        extra["trailing_extra"] = trailing_clean

        # Check for request ID embedded in query string if not in trailing column
        if not request_id and uri and uri != "-":
            m_req = re.search(r'(?:req_id|request_id|trace_id)=([a-zA-Z0-9_\-]+)', uri, re.IGNORECASE)
            if m_req:
                request_id = m_req.group(1)

        source_host = None
        if context:
            source_host = context.get("source_host") or context.get("host")

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
            source_host=source_host,
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
