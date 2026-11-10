"""Tests reproducing and verifying F-12:
- Web access parser SQLi spaces, '-' request lines, lowercase methods, response time vs request_id.
- CSV firewall header-driven alias mapping, unknown column retention, and missing column diagnostics.
- Source identity separation for identical filenames across hosts.
"""

from src.parsers.web_access_parser import WebAccessParser
from src.parsers.csv_firewall_parser import CsvFirewallParser


def test_web_log_sqli_with_spaces_parsed_successfully():
    """Reproduce F-12 defect 1: URI containing SQLi spaces must parse, not become MALFORMED."""
    parser = WebAccessParser()
    line = '192.168.1.50 - - [12/Oct/2026:10:00:00 +0000] "GET /search?q=1 UNION SELECT 1,2 -- HTTP/1.1" 200 4616'
    rec = parser.parse_line(line, 1)

    assert rec.parse_status == "SUCCESS", f"Expected SUCCESS, got {rec.parse_status}: {rec.warnings}"
    assert rec.extra_fields["method"] == "GET"
    assert "UNION SELECT" in rec.extra_fields["uri"]
    assert rec.extra_fields["status_code"] == 200


def test_web_log_dash_request_line_parsed_successfully():
    """Reproduce F-12 defect 2: '-' request line (timeout/disconnect) must not become MALFORMED."""
    parser = WebAccessParser()
    line = '192.168.1.50 - - [12/Oct/2026:10:00:00 +0000] "-" 408 0'
    rec = parser.parse_line(line, 1)

    assert rec.parse_status == "SUCCESS", f"Expected SUCCESS, got {rec.parse_status}: {rec.warnings}"
    assert rec.extra_fields["status_code"] == 408


def test_web_log_lowercase_method_parsed_successfully():
    """Reproduce F-12 defect 3: lowercase HTTP method must parse successfully."""
    parser = WebAccessParser()
    line = '192.168.1.50 - - [12/Oct/2026:10:00:00 +0000] "get /index.html HTTP/1.1" 200 1234'
    rec = parser.parse_line(line, 1)

    assert rec.parse_status == "SUCCESS", f"Expected SUCCESS, got {rec.parse_status}: {rec.warnings}"
    assert rec.extra_fields["method"].upper() == "GET"
    assert rec.extra_fields["status_code"] == 200


def test_web_log_trailing_float_is_not_request_id():
    """Reproduce F-12 defect 4: trailing float ($request_time like 0.005) must not become request_id."""
    parser = WebAccessParser()
    line = '192.168.1.50 - - [12/Oct/2026:10:00:00 +0000] "GET /api/data HTTP/1.1" 200 500 "https://example.com" "Mozilla/5.0" 0.005'
    rec = parser.parse_line(line, 1)

    assert rec.parse_status == "SUCCESS"
    assert rec.request_id != "0.005", f"Float 0.005 was incorrectly assigned as request_id: {rec.request_id}"
    assert rec.request_id is None


def test_web_log_named_or_explicit_request_id_extracted():
    """Verify request_id is extracted when it is an explicit request ID or named field."""
    parser = WebAccessParser()
    # Explicit req-* token
    line1 = '192.168.1.50 - - [12/Oct/2026:10:00:00 +0000] "GET /api/data HTTP/1.1" 200 500 "https://example.com" "Mozilla/5.0" "req-987654"'
    rec1 = parser.parse_line(line1, 1)
    assert rec1.request_id == "req-987654"

    # Named key=value in trailing field
    line2 = '192.168.1.50 - - [12/Oct/2026:10:00:00 +0000] "GET /api/data HTTP/1.1" 200 500 "https://example.com" "Mozilla/5.0" "request_id=trace-abc-123"'
    rec2 = parser.parse_line(line2, 2)
    assert rec2.request_id == "trace-abc-123"


def test_csv_firewall_header_driven_mapping_and_unknown_columns():
    """Reproduce F-12 defect 5: CSV firewall parser must map columns by header name and keep extra columns."""
    parser = CsvFirewallParser()
    lines = [
        "timestamp,action,src_ip,src_port,dst_ip,dst_port,proto,interface",
        "2026-10-12T10:00:00Z,DENY,10.0.0.5,44321,192.168.1.1,80,TCP,eth0",
    ]
    records = list(parser.parse_stream(iter(lines)))
    # The data row is record 0 (after filtering header) or record 1
    data_records = [r for r in records if r.parse_status != "HEADER"]
    assert len(data_records) == 1
    rec = data_records[0]

    assert rec.parse_status == "SUCCESS"
    assert rec.src_ip == "10.0.0.5", f"Expected src_ip '10.0.0.5', got '{rec.src_ip}'"
    assert rec.dst_ip == "192.168.1.1", f"Expected dst_ip '192.168.1.1', got '{rec.dst_ip}'"
    assert rec.extra_fields.get("action") == "DENY"
    assert rec.extra_fields.get("interface") == "eth0", f"Expected extra field 'interface', got {rec.extra_fields}"


def test_csv_firewall_missing_required_column_diagnostic():
    """Reproduce F-12 defect 6: CSV firewall missing required columns must produce clear diagnostic."""
    parser = CsvFirewallParser()
    lines = [
        "timestamp,rule_id,info",
        "2026-10-12T10:00:00Z,101,blocked",
    ]
    records = list(parser.parse_stream(iter(lines)))
    data_records = [r for r in records if r.parse_status != "HEADER"]
    assert len(data_records) == 1
    rec = data_records[0]
    assert rec.parse_status == "MALFORMED" or any("Missing required column" in w for w in rec.warnings)


def test_two_servers_access_logs_do_not_collapse_into_one_source(tmp_path):
    """Reproduce and verify F-12 defect 7: two servers with access.log must produce distinct source identities."""
    from src.storage.repository import InvestigationRepository
    from src.pipeline import ForensicPipeline

    repo = InvestigationRepository(tmp_path / "chronica_db")
    inv = repo.create_investigation("multi_srv_test", "Multi-Server Web Log Test")
    pipeline = ForensicPipeline(repo)

    log_srv1 = (
        '192.168.1.50 - - [12/Oct/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1200\n'
    ).encode("utf-8")
    log_srv2 = (
        '192.168.1.51 - - [12/Oct/2026:10:00:05 +0000] "GET /app.html HTTP/1.1" 200 1350\n'
    ).encode("utf-8")

    # Ingest log 1 with explicit user-supplied host "web-srv-01"
    pe1, evs1 = pipeline.ingest_evidence_bytes(
        inv.investigation_id,
        "access.log",
        log_srv1,
        source_host="web-srv-01",
        allow_duplicate=True,
    )
    # Ingest log 2 with explicit user-supplied host "web-srv-02"
    pe2, evs2 = pipeline.ingest_evidence_bytes(
        inv.investigation_id,
        "access.log",
        log_srv2,
        source_host="web-srv-02",
        allow_duplicate=True,
    )

    assert evs1[0].source_host == "web-srv-01"
    assert evs2[0].source_host == "web-srv-02"

    analysis = pipeline.analyze_investigation(inv.investigation_id)
    sources = analysis["available_sources"]
    assert "web-srv-01" in sources
    assert "web-srv-02" in sources
    assert len(sources) == 2, f"Expected 2 distinct sources, got {sources}"


def test_web_log_empty_and_binary_request_lines():
    """Adversarial check 1: Empty request line and raw binary SSL probe must not crash parser."""
    parser = WebAccessParser()
    # 1. Empty request line ""
    line_empty = '192.168.1.50 - - [12/Oct/2026:10:00:00 +0000] "" 400 0'
    rec1 = parser.parse_line(line_empty, 1)
    assert rec1.parse_status == "SUCCESS"
    assert rec1.extra_fields["method"] == "-"
    assert rec1.extra_fields["status_code"] == 400

    # 2. SSL handshake probe sent to HTTP port
    line_ssl = r'192.168.1.50 - - [12/Oct/2026:10:00:00 +0000] "\x16\x03\x01\x00\xa5\x01" 400 157'
    rec2 = parser.parse_line(line_ssl, 2)
    assert rec2.parse_status == "SUCCESS"
    assert rec2.extra_fields["status_code"] == 400


def test_csv_firewall_mixed_case_aliases_and_quoted_commas():
    """Adversarial check 2: Mixed-case header aliases and quoted cells containing commas."""
    parser = CsvFirewallParser()
    lines = [
        'TIMESTAMP,ACTION,Source_Address,Destination_Address,SPORT,DPORT,PROTOCOL,Notes',
        '2026-10-12T10:00:00Z,"DROP, ALERT",10.10.10.5,172.16.0.1,53210,443,TCP,"Suspicious probe, flagged"',
    ]
    records = list(parser.parse_stream(iter(lines)))
    data_records = [r for r in records if r.parse_status != "HEADER"]
    assert len(data_records) == 1
    rec = data_records[0]
    assert rec.parse_status == "SUCCESS"
    assert rec.src_ip == "10.10.10.5"
    assert rec.dst_ip == "172.16.0.1"
    assert rec.extra_fields["action"] == "DROP, ALERT"
    assert rec.extra_fields["Notes"] == "Suspicious probe, flagged"


