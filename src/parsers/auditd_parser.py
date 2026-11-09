"""Linux Audit Daemon (auditd) log parser.

Parses audit.log records in the standard auditd format:
  type=SYSCALL msg=audit(1728123456.789:12345): uid=0 auid=1000 exe="/bin/cat" ...

Features:
- Extracts epoch timestamp from msg=audit(epoch.ms:serial) 
- Sets request_id = "audit-{serial}" for multi-line record correlation
- Decodes hex-encoded proctitle values (e.g. proctitle=636174202F6574632F736861646F77)
- Extracts acct/uid/auid -> username, addr/hostname -> source_host/src_ip
- Sets severity=AUTH_FAIL for failed USER_AUTH/USER_LOGIN, WARNING for SYSCALL/EXECVE
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from src.parsers.base import BaseParser, ParsedRecord

# Main auditd line pattern
AUDITD_PATTERN = re.compile(
    r"type=([A-Z0-9_]+)\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s*(.*)$"
)

# Key-value extraction regex: handles key="val", key='val', key=val
KV_PATTERN = re.compile(r"""(\w+)=(?:"([^"]*)"|'([^']*)'|(\S+))""")

# Confidence detection patterns
AUDITD_CONFIDENCE_PATTERNS = [
    re.compile(r"type=[A-Z0-9_]+\s+msg=audit\(\d+"),
]


def _parse_auditd_kvs(kv_section: str) -> Dict[str, str]:
    """Parse auditd key-value pairs, properly handling single-quoted msg='...' blocks.

    In standard Linux auditd logs (e.g. USER_AUTH), messages have the form:
      type=USER_AUTH ... msg='op=PAM:authentication acct="alice" ... res=failed'
    This extracts outer key-values as well as the inner key-values defined within
    the msg='...' block, stripping surrounding quotes so values like res='failed'
    evaluate correctly.
    """
    kv: Dict[str, str] = {}

    # 1. Parse outer key-values
    for m in KV_PATTERN.finditer(kv_section):
        k = m.group(1)
        # Skip raw msg here if it's the nested sub-block; we parse it in step 2
        if k == "msg" and m.group(3) is not None:
            continue
        v = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
        if v is not None:
            kv[k] = v.strip("'\"")

    # 2. Extract and parse nested msg='...' block
    msg_block_match = re.search(r"\bmsg='([^']*)'", kv_section)
    if msg_block_match:
        inner_content = msg_block_match.group(1)
        for m in KV_PATTERN.finditer(inner_content):
            k = m.group(1)
            v = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
            if v is not None:
                kv[k] = v.strip("'\"")

    return kv


def _decode_hex_proctitle(hex_str: str) -> str:
    """Decode a hex-encoded proctitle into a human-readable string.

    Replaces null bytes with spaces for display.
    Returns the original string if decoding fails.
    """
    try:
        # Only decode if it looks like all-hex
        cleaned = hex_str.strip()
        if re.match(r"^[0-9A-Fa-f]+$", cleaned) and len(cleaned) % 2 == 0:
            raw = bytes.fromhex(cleaned)
            return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except Exception:
        pass
    return hex_str


class AuditdParser(BaseParser):
    """Parser for Linux Audit Daemon (auditd / audit.log) syscall & security records."""

    @property
    def format_name(self) -> str:
        return "auditd"

    @property
    def description(self) -> str:
        return "Linux Audit Daemon (auditd / audit.log) syscall & security records"

    def parse_line(self, line: str, line_number: int, context: Optional[Dict[str, Any]] = None) -> ParsedRecord:
        """Parse a single auditd log line."""
        m = AUDITD_PATTERN.match(line.strip())
        if not m:
            return ParsedRecord(
                line_number=line_number,
                raw_text=line,
                original_timestamp_str=None,
                parse_status="MALFORMED",
                warnings=[f"Line {line_number}: does not match auditd format."],
            )

        record_type = m.group(1)
        epoch_str = m.group(2)
        serial_id = m.group(3)
        kv_section = m.group(4)

        # Parse epoch timestamp (seconds.milliseconds)
        original_timestamp_str = epoch_str

        # Extract key-value pairs (single-quote aware)
        kv = _parse_auditd_kvs(kv_section)

        # Extract username strictly from acct (never from SELinux subj context)
        username = kv.get("acct")
        if username and username in ("4294967295", "-1", "?", "(none)", ""):
            username = None

        # Extract host/IP
        source_host = kv.get("hostname") or kv.get("node")
        src_ip = kv.get("addr")
        if src_ip in ("?", "(none)", ""):
            src_ip = None
        if source_host in ("?", "(none)", ""):
            source_host = None

        # Decode proctitle if present
        extra_fields: Dict[str, Any] = {}
        proctitle_raw = kv.get("proctitle", "")
        if proctitle_raw:
            decoded = _decode_hex_proctitle(proctitle_raw)
            extra_fields["decoded_proctitle"] = decoded
            kv["proctitle"] = decoded

        # Store interesting fields
        for k in ("exe", "comm", "syscall", "key", "exit", "a0", "a1", "pid", "ppid"):
            if k in kv:
                extra_fields[k] = kv[k]

        # Determine severity
        severity = "INFO"
        res = kv.get("res", "").lower().strip("'\"")
        success = kv.get("success", "").lower().strip("'\"")
        if record_type in ("USER_AUTH", "USER_LOGIN", "USER_CMD"):
            if res in ("failed", "0") or success in ("no", "0"):
                severity = "AUTH_FAIL"
            else:
                severity = "AUTH_SUCCESS"
        elif record_type in ("SYSCALL", "EXECVE"):
            severity = "WARNING"
        elif record_type in ("SERVICE_START", "SERVICE_STOP"):
            severity = "INFO"

        # Category
        category = "SYSTEM"
        if record_type.startswith("USER_"):
            category = "AUTHENTICATION"
        elif record_type in ("SYSCALL", "EXECVE", "CWD", "PATH"):
            category = "SYSTEM"

        # Build message
        decoded_pt = extra_fields.get("decoded_proctitle", "")
        exe = kv.get("exe", "")
        if decoded_pt:
            message = f"[{record_type}] {decoded_pt}"
        elif exe:
            message = f"[{record_type}] exe={exe}"
        else:
            message = f"[{record_type}] {kv_section[:120]}"

        return ParsedRecord(
            line_number=line_number,
            raw_text=line,
            original_timestamp_str=original_timestamp_str,
            source_host=source_host,
            severity=severity,
            category=category,
            username=username,
            src_ip=src_ip,
            message=message,
            request_id=f"audit-{serial_id}",  # Correlates multi-line auditd records
            extra_fields=extra_fields,
            parse_status="SUCCESS",
        )

    def score_confidence(self, sample_lines: List[str]) -> tuple[float, str]:
        """Return confidence score for auditd format detection."""
        if not sample_lines:
            return 0.0, "No sample lines provided."

        matches = 0
        for line in sample_lines[:15]:
            if AUDITD_PATTERN.match(line.strip()):
                matches += 1

        if matches == 0:
            return 0.0, "No auditd-format lines (type=... msg=audit(...)) detected."

        ratio = matches / min(len(sample_lines), 15)
        score = min(0.95, 0.6 + ratio * 0.35)
        return round(score, 3), f"{matches}/{min(len(sample_lines), 15)} lines match auditd format (type=... msg=audit(...))."
