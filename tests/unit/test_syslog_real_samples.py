"""Tests reproducing and verifying F-11: syslog parser ISO-8601, auth variants, uid stripping, and RFC5424 SD.

Formats cited:
- RFC 3164: The BSD syslog Protocol
- RFC 5424: The Syslog Protocol (Structured Data section 6.3)
- rsyslog RSYSLOG_FileFormat default ISO-8601 template: "%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag%%msg%\n"
- OpenSSH sshd auth log samples & Linux PAM audit samples
"""

from src.parsers.syslog_parser import SyslogParser


def test_rsyslog_iso_timestamp_parsed_successfully():
    """Reproduce F-11 defect 1: default rsyslog ISO-8601 lines must not be rejected as MALFORMED."""
    parser = SyslogParser()
    line = "2026-10-11T14:32:01.123456+00:00 web01 sshd[812]: Accepted publickey for alice from 192.168.1.100 port 55123 ssh2"
    record = parser.parse_line(line, 1)

    assert record.parse_status == "SUCCESS", f"Expected SUCCESS, got {record.parse_status}: {record.warnings}"
    assert record.source_host == "web01"
    assert record.source_app == "sshd"
    assert record.original_timestamp_str == "2026-10-11T14:32:01.123456+00:00"
    assert record.severity == "AUTH_SUCCESS"
    assert record.username == "alice"
    assert record.src_ip == "192.168.1.100"


def test_failed_keyboard_interactive_pam_flagged_as_auth_fail():
    """Reproduce F-11 defect 2: Failed keyboard-interactive/pam must be flagged as AUTH_FAIL with user and IP."""
    parser = SyslogParser()
    line = "Oct 11 14:32:01 web01 sshd[812]: Failed keyboard-interactive/pam for root from 192.168.1.50 port 44322 ssh2"
    record = parser.parse_line(line, 1)

    assert record.parse_status == "SUCCESS"
    assert record.severity == "AUTH_FAIL", f"Expected AUTH_FAIL, got {record.severity}"
    assert record.username == "root"
    assert record.src_ip == "192.168.1.50"


def test_session_opened_strips_uid_into_separate_field():
    """Reproduce F-11 defect 3: session opened for alice(uid=1000) must strip uid and set username to alice."""
    parser = SyslogParser()
    line = "Oct 11 14:32:01 web01 systemd-logind[500]: session opened for user alice(uid=1000) by (uid=0)"
    record = parser.parse_line(line, 1)

    assert record.parse_status == "SUCCESS"
    assert record.username == "alice", f"Expected username 'alice', got '{record.username}'"
    assert record.extra_fields.get("uid") == 1000 or record.extra_fields.get("uid") == "1000"


def test_rfc5424_multiple_structured_data_elements_does_not_leak_into_message():
    """Reproduce F-11 defect 4: multiple RFC 5424 structured data elements must be parsed without leaking into msg."""
    parser = SyslogParser()
    line = '<34>1 2026-10-11T14:32:01.000Z myhost myapp 1234 MSG01 [exampleSDID@32473 iut="3" eventSource="Application"][examplePriority@32473 class="high"] User logged in'
    record = parser.parse_line(line, 1)

    assert record.parse_status == "SUCCESS"
    assert record.message.strip() == "User logged in", f"Expected 'User logged in', got '{record.message}'"
    assert "structured_data" in record.extra_fields
    assert len(record.extra_fields["structured_data"]) == 2


def test_sudo_auth_failure_flagged_as_auth_fail():
    """Reproduce F-11 defect 5: sudo authentication failure must be flagged as AUTH_FAIL with user."""
    parser = SyslogParser()
    line1 = "Oct 11 14:35:00 web01 sudo: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost= user=alice"
    record1 = parser.parse_line(line1, 1)

    assert record1.severity == "AUTH_FAIL", f"Expected AUTH_FAIL, got {record1.severity}"
    assert record1.category == "AUTHENTICATION"
    assert record1.username == "alice"

    line2 = "Oct 11 14:35:05 web01 sudo:   alice : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    record2 = parser.parse_line(line2, 2)
    assert record2.severity == "AUTH_FAIL", f"Expected AUTH_FAIL on incorrect password attempt, got {record2.severity}"
    assert record2.username == "alice"


def test_rfc5424_escaped_brackets_in_sd_and_nilvalue():
    """Adversarial check 1: RFC 5424 with escaped bracket in param and NILVALUE structured data."""
    parser = SyslogParser()
    # 1. Escaped bracket in SD-PARAM value
    line_escaped = '<34>1 2026-10-11T14:32:01.000Z myhost myapp 1234 MSG01 [exampleSDID@32473 tag="val\\]ue"] App started'
    rec1 = parser.parse_line(line_escaped, 1)
    assert rec1.parse_status == "SUCCESS"
    assert rec1.message == "App started"
    assert len(rec1.extra_fields.get("structured_data", [])) == 1

    # 2. NILVALUE structured data "-" with empty msg and with non-empty msg
    line_nil = "<34>1 2026-10-11T14:32:01.000Z myhost myapp 1234 MSG02 - System reboot initiated"
    rec2 = parser.parse_line(line_nil, 2)
    assert rec2.parse_status == "SUCCESS"
    assert rec2.message == "System reboot initiated"
    assert "structured_data" not in rec2.extra_fields


def test_rsyslog_iso_variants_and_confidence_scoring():
    """Adversarial check 2: Rsyslog ISO without fraction, without PID brackets, and detector scoring."""
    parser = SyslogParser()
    line_no_frac = "2026-10-11T14:32:01Z web-srv02 kernel: eth0: link up"
    rec = parser.parse_line(line_no_frac, 1)
    assert rec.parse_status == "SUCCESS"
    assert rec.source_host == "web-srv02"
    assert rec.source_app == "kernel"
    assert rec.message == "eth0: link up"

    # Verify score_confidence scores rsyslog ISO lines with high confidence
    score, reason = parser.score_confidence([
        "2026-10-11T14:32:01.123456+00:00 web01 sshd[812]: Accepted publickey for alice",
        "2026-10-11T14:32:02.123456+00:00 web01 sshd[812]: session opened for user alice",
    ])
    assert score == 1.0
    assert "rsyslog ISO-8601 format" in reason

