"""Unit tests for log parsers and explainable format detection."""

import pytest

from src.parsers.base import ParsedRecord
from src.parsers.csv_firewall_parser import CsvFirewallParser
from src.parsers.detector import ParserRegistry
from src.parsers.jsonl_parser import JsonlParser
from src.parsers.syslog_parser import SyslogParser
from src.parsers.web_access_parser import WebAccessParser


def test_syslog_rfc3164_ssh_login():
    parser = SyslogParser()
    line = "Oct 12 14:32:01 server-01 sshd[1234]: Accepted publickey for alice from 192.168.1.50 port 54321 ssh2"
    rec = parser.parse_line(line, line_number=1)

    assert rec.parse_status == "SUCCESS"
    assert rec.source_host == "server-01"
    assert rec.source_app == "sshd"
    assert rec.severity == "AUTH_SUCCESS"
    assert rec.category == "AUTHENTICATION"
    assert rec.username == "alice"
    assert rec.src_ip == "192.168.1.50"
    assert rec.extra_fields.get("src_port") == 54321
    assert rec.extra_fields.get("pid") == 1234
    assert any("Yearless syslog timestamp" in w for w in rec.warnings)


def test_syslog_sudo_command():
    parser = SyslogParser()
    line = "Oct 12 14:35:10 host-02 sudo[981]:    bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    rec = parser.parse_line(line, line_number=2)

    assert rec.parse_status == "SUCCESS"
    assert rec.username == "bob"
    assert rec.extra_fields.get("target_user") == "root"
    assert "/etc/shadow" in rec.extra_fields.get("command", "")
    assert rec.severity == "WARNING"


def test_syslog_malformed_line():
    parser = SyslogParser()
    line = "Random garbage text without timestamp or syslog header"
    rec = parser.parse_line(line, line_number=3)

    assert rec.parse_status == "MALFORMED"
    assert rec.severity == "ERROR"
    assert len(rec.warnings) > 0


def test_jsonl_parser_valid():
    parser = JsonlParser()
    line = '{"timestamp": "2026-10-12T14:30:00Z", "level": "INFO", "user": "alice", "src_ip": "10.0.0.1", "event": "user_logout", "request_id": "req-99"}'
    rec = parser.parse_line(line, line_number=1)

    assert rec.parse_status == "SUCCESS"
    assert rec.original_timestamp_str == "2026-10-12T14:30:00Z"
    assert rec.username == "alice"
    assert rec.src_ip == "10.0.0.1"
    assert rec.request_id == "req-99"
    assert rec.severity == "INFO"


def test_jsonl_parser_malformed_syntax():
    parser = JsonlParser()
    line = '{"timestamp": "2026-10-12T14:30:00Z", "level": "INFO", INVALID_JSON'
    rec = parser.parse_line(line, line_number=2)

    assert rec.parse_status == "MALFORMED"
    assert rec.severity == "ERROR"
    assert any("JSON syntax error" in w for w in rec.warnings)


def test_web_access_combined_format():
    parser = WebAccessParser()
    line = '192.168.1.100 - frank [12/Oct/2026:14:32:00 +0000] "GET /api/v1/users HTTP/1.1" 200 1420 "https://example.com" "Mozilla/5.0" "req-alpha-123"'
    rec = parser.parse_line(line, line_number=1)

    assert rec.parse_status == "SUCCESS"
    assert rec.src_ip == "192.168.1.100"
    assert rec.username == "frank"
    assert rec.original_timestamp_str == "12/Oct/2026:14:32:00 +0000"
    assert rec.request_id == "req-alpha-123"
    assert rec.extra_fields.get("status_code") == 200
    assert rec.severity == "INFO"


def test_web_access_auth_failure():
    parser = WebAccessParser()
    line = '192.168.1.100 - admin [12/Oct/2026:14:33:00 +0000] "POST /login HTTP/1.1" 401 230 "-" "curl/7.68"'
    rec = parser.parse_line(line, line_number=2)

    assert rec.severity == "AUTH_FAIL"
    assert rec.category == "AUTHENTICATION"


def test_csv_firewall_parser():
    parser = CsvFirewallParser()
    header = "timestamp,src_ip,src_port,dst_ip,dst_port,proto,action,rule_id"
    row = "2026-10-12T14:35:00Z,192.168.1.50,44321,10.0.0.1,22,TCP,DENY,RULE_BLOCK_SSH"

    h_rec = parser.parse_line(header, line_number=1)
    assert h_rec.parse_status == "HEADER"

    r_rec = parser.parse_line(row, line_number=2)
    assert r_rec.parse_status == "SUCCESS"
    assert r_rec.src_ip == "192.168.1.50"
    assert r_rec.dst_ip == "10.0.0.1"
    assert r_rec.severity == "WARNING"  # DENY action


def test_parser_registry_autodetection():
    registry = ParserRegistry()

    syslog_samples = [
        "Oct 12 10:00:01 host-1 sshd[10]: Accepted publickey for user1",
        "Oct 12 10:00:05 host-1 sudo[12]: user1 : TTY=pts/0 ; COMMAND=/bin/ls",
    ]
    res_sys = registry.detect_format(syslog_samples)
    assert res_sys.is_confident is True
    assert res_sys.detected_format == "syslog"

    jsonl_samples = [
        '{"timestamp": "2026-10-12T10:00:00Z", "event": "start", "user": "u1"}',
        '{"timestamp": "2026-10-12T10:00:01Z", "event": "stop", "user": "u1"}',
    ]
    res_json = registry.detect_format(jsonl_samples)
    assert res_json.is_confident is True
    assert res_json.detected_format == "jsonl"

    unsupported_samples = [
        "THIS_IS_SOME_TOTALLY_RANDOM_UNSTRUCTURED_DATA_12345",
        "FOO BAR BAZ NO DELIMITERS OR TIMESTAMPS AT ALL",
    ]
    res_unknown = registry.detect_format(unsupported_samples)
    assert res_unknown.is_confident is False
    assert res_unknown.detected_format is None
