"""Linux syslog, auth.log, and secure log parser.

Parses RFC 3164 BSD syslog, RFC 5424 IETF syslog, SSH daemon (sshd) auth events,
sudo privilege escalations, and system service messages.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from src.parsers.base import BaseParser, ParsedRecord

# RFC 3164: "Oct 11 14:32:01 server-01 sshd[1234]: message" or "Oct  5 09:12:00 host app: msg"
RFC3164_PATTERN = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([^\s:]+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s*(.*)$"
)

# RFC 5424: "<34>1 2026-10-11T14:32:01.000Z host sshd 1234 MSGID - message"
RFC5424_PATTERN = re.compile(
    r"^<(\d+)>(\d+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+(?:\[[^\]]*\]|-)\s*(.*)$"
)

# SSH event extractors
SSH_ACCEPTED = re.compile(
    r"Accepted\s+(password|publickey|keyboard-interactive)\s+for\s+(?:invalid\s+user\s+)?([^\s]+)\s+from\s+([^\s]+)\s+port\s+(\d+)",
    re.IGNORECASE,
)
SSH_FAILED = re.compile(
    r"Failed\s+(password|publickey)\s+for\s+(?:invalid\s+user\s+)?([^\s]+)\s+from\s+([^\s]+)\s+port\s+(\d+)",
    re.IGNORECASE,
)
SSH_INVALID_USER = re.compile(
    r"Invalid\s+user\s+([^\s]+)\s+from\s+([^\s]+)",
    re.IGNORECASE,
)
SSH_SESSION_OPEN = re.compile(
    r"session\s+opened\s+for\s+user\s+([^\s]+)",
    re.IGNORECASE,
)
SSH_SESSION_CLOSE = re.compile(
    r"session\s+closed\s+for\s+user\s+([^\s]+)",
    re.IGNORECASE,
)

# Sudo event extractors
SUDO_CMD = re.compile(
    r"([^\s:]+)\s*:\s*TTY=[^;]*;\s*PWD=[^;]*;\s*USER=([^\s;]+)\s*;\s*COMMAND=(.*)",
    re.IGNORECASE,
)


class SyslogParser(BaseParser):
    """Parser for Linux syslog / auth.log formats."""

    @property
    def format_name(self) -> str:
        return "syslog"

    @property
    def description(self) -> str:
        return "Linux syslog (RFC 3164 / RFC 5424) and authentication logs (sshd, sudo, systemd)"

    def parse_line(
        self,
        line: str,
        line_number: int,
        context: Optional[Dict[str, Any]] = None,
    ) -> ParsedRecord:
        warnings: List[str] = []
        extra: Dict[str, Any] = {}

        # 1. Try RFC 3164
        m3164 = RFC3164_PATTERN.match(line)
        if m3164:
            ts_str, host, app, pid, msg = m3164.groups()
            if pid:
                extra["pid"] = int(pid)
            warnings.append("Yearless syslog timestamp: year must be inferred during normalization.")
            return self._enrich_event(
                line_number=line_number,
                raw_text=line,
                timestamp_str=ts_str,
                host=host,
                app=app,
                msg=msg,
                extra=extra,
                warnings=warnings,
            )

        # 2. Try RFC 5424
        m5424 = RFC5424_PATTERN.match(line)
        if m5424:
            pri, ver, ts_str, host, app, procid, msgid, msg = m5424.groups()
            extra["priority"] = pri
            extra["version"] = ver
            if procid != "-":
                extra["pid"] = procid
            if msgid != "-":
                extra["msgid"] = msgid
            return self._enrich_event(
                line_number=line_number,
                raw_text=line,
                timestamp_str=ts_str if ts_str != "-" else None,
                host=host if host != "-" else None,
                app=app if app != "-" else None,
                msg=msg,
                extra=extra,
                warnings=warnings,
            )

        # 3. Fallback: Loose syslog style (e.g. Month day time without standard separator)
        loose_match = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(.*)$", line)
        if loose_match:
            ts_str, rest = loose_match.groups()
            warnings.append("Non-standard syslog structure: host and application could not be separated.")
            warnings.append("Yearless syslog timestamp: year must be inferred during normalization.")
            return ParsedRecord(
                line_number=line_number,
                raw_text=line,
                original_timestamp_str=ts_str,
                source_host=None,
                source_app="syslog",
                severity="INFO",
                category="SYSTEM",
                message=rest,
                parse_status="PARTIAL",
                warnings=warnings,
            )

        # Malformed record
        return ParsedRecord(
            line_number=line_number,
            raw_text=line,
            original_timestamp_str=None,
            source_host=None,
            source_app="syslog",
            severity="ERROR",
            category="SYSTEM",
            message=line,
            parse_status="MALFORMED",
            warnings=["Line does not conform to RFC 3164 or RFC 5424 syslog patterns."],
        )

    def _enrich_event(
        self,
        line_number: int,
        raw_text: str,
        timestamp_str: Optional[str],
        host: Optional[str],
        app: Optional[str],
        msg: str,
        extra: Dict[str, Any],
        warnings: List[str],
    ) -> ParsedRecord:
        severity = "INFO"
        category = "SYSTEM"
        username: Optional[str] = None
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None

        # SSH Accepted Login
        if m := SSH_ACCEPTED.search(msg):
            auth_type, user, ip, port = m.groups()
            severity = "AUTH_SUCCESS"
            category = "AUTHENTICATION"
            username = user
            src_ip = ip
            extra["auth_type"] = auth_type
            extra["src_port"] = int(port)

        # SSH Failed Login
        elif m := SSH_FAILED.search(msg):
            auth_type, user, ip, port = m.groups()
            severity = "AUTH_FAIL"
            category = "AUTHENTICATION"
            username = user
            src_ip = ip
            extra["auth_type"] = auth_type
            extra["src_port"] = int(port)

        # SSH Invalid User
        elif m := SSH_INVALID_USER.search(msg):
            user, ip = m.groups()
            severity = "AUTH_FAIL"
            category = "AUTHENTICATION"
            username = user
            src_ip = ip

        # SSH Session Opened
        elif m := SSH_SESSION_OPEN.search(msg):
            user = m.group(1)
            severity = "INFO"
            category = "AUTHENTICATION"
            username = user

        # SSH Session Closed
        elif m := SSH_SESSION_CLOSE.search(msg):
            user = m.group(1)
            severity = "INFO"
            category = "AUTHENTICATION"
            username = user

        # Sudo Command
        elif m := SUDO_CMD.search(msg):
            sudo_user, target_user, cmd = m.groups()
            severity = "WARNING"
            category = "SYSTEM"
            username = sudo_user
            extra["target_user"] = target_user
            extra["command"] = cmd

        # Generic App Categorization
        elif app and ("sshd" in app or "login" in app or "auth" in app):
            category = "AUTHENTICATION"

        return ParsedRecord(
            line_number=line_number,
            raw_text=raw_text,
            original_timestamp_str=timestamp_str,
            source_host=host,
            source_app=app,
            severity=severity,
            category=category,
            username=username,
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

        matches = 0
        total = 0
        reasons = []

        for line in sample_lines[:20]:
            stripped = line.strip()
            if not stripped:
                continue
            total += 1
            if RFC3164_PATTERN.match(stripped):
                matches += 1
                if "RFC 3164 BSD syslog format" not in reasons:
                    reasons.append("RFC 3164 BSD syslog format (Month Day Time Host App[PID])")
            elif RFC5424_PATTERN.match(stripped):
                matches += 1
                if "RFC 5424 IETF syslog format" not in reasons:
                    reasons.append("RFC 5424 IETF syslog format (<PRI>VER Timestamp Host...)")

        if total == 0:
            return 0.0, "No non-empty lines in sample"

        score = matches / total
        explanation = (
            f"Syslog detector: {matches}/{total} lines matched syslog signatures. "
            f"Detected patterns: {', '.join(reasons) if reasons else 'none'}."
        )
        return score, explanation
