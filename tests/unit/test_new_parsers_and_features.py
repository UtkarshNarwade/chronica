"""Tests for new parsers, audit chain, search enhancements, and compressed ingestion.

Covers:
- AuditdParser: epoch timestamps, request_id correlation, hex proctitle decoding
- WindowsEventParser: EventID 4624/4625/1102 parsing
- .gz compressed log ingestion via ForensicPipeline
- AuditChainLedger: hash chain construction and tamper detection
- TimelineSearchEngine: use_regex, exclude_keyword, ip_subnet_cidr, bookmarked_only
"""

from __future__ import annotations

import gzip
import json
import tempfile
from pathlib import Path
from typing import List

import pytest

from src.evidence.audit_chain import AuditChainLedger, AuditEntry
from src.parsers.auditd_parser import AuditdParser, _decode_hex_proctitle
from src.parsers.windows_event_parser import WindowsEventParser
from src.timeline.schema import Event
from src.timeline.search import FilterCriteria, TimelineSearchEngine


# ── AuditdParser Tests ────────────────────────────────────────────────────────

SAMPLE_AUDITD_LINES = [
    'type=SYSCALL msg=audit(1728123456.789:12345): arch=c000003e syscall=59 success=yes exit=0 uid=1000 auid=1000 exe="/bin/cat" comm="cat"',
    'type=USER_AUTH msg=audit(1728123457.000:12346): pid=1234 uid=0 auid=1000 ses=1 msg=\'op=PAM:authentication acct="root" exe="/usr/sbin/sshd" hostname=attacker.local addr=192.168.1.50 terminal=ssh res=failed\'',
    'type=EXECVE msg=audit(1728123458.100:12347): argc=2 a0="/usr/bin/cat" a1="/etc/shadow" proctitle=636174202f6574632f736861646f77',
    'type=USER_LOGIN msg=audit(1728123459.200:12348): pid=5678 uid=0 auid=0 res=success acct="admin" hostname=srv-01 addr=10.0.0.1',
]


class TestAuditdParser:
    def setup_method(self):
        self.parser = AuditdParser()

    def test_format_name(self):
        assert self.parser.format_name == "auditd"

    def test_parses_syscall_line(self):
        rec = self.parser.parse_line(SAMPLE_AUDITD_LINES[0], 1)
        assert rec.parse_status == "SUCCESS"
        assert rec.original_timestamp_str == "1728123456.789"
        assert rec.request_id == "audit-12345"

    def test_extracts_auth_fail_severity(self):
        rec = self.parser.parse_line(SAMPLE_AUDITD_LINES[1], 2)
        assert rec.parse_status == "SUCCESS"
        assert rec.severity == "AUTH_FAIL"
        assert rec.src_ip == "192.168.1.50"
        assert rec.source_host == "attacker.local"

    def test_decodes_hex_proctitle(self):
        rec = self.parser.parse_line(SAMPLE_AUDITD_LINES[2], 3)
        assert rec.parse_status == "SUCCESS"
        decoded = rec.extra_fields.get("decoded_proctitle", "")
        # "636174202f6574632f736861646f77" = "cat /etc/shadow"
        assert "cat" in decoded.lower() or "shadow" in decoded.lower()

    def test_request_id_correlates_serial(self):
        """All records with the same audit serial share a request_id."""
        lines = [
            'type=SYSCALL msg=audit(1728123460.000:99999): uid=0',
            'type=EXECVE msg=audit(1728123460.001:99999): argc=1 a0="id"',
        ]
        records = list(self.parser.parse_stream(iter(lines)))
        req_ids = [r.request_id for r in records if r.request_id]
        assert len(req_ids) == 2
        assert req_ids[0] == req_ids[1] == "audit-99999"

    def test_auth_success_severity(self):
        rec = self.parser.parse_line(SAMPLE_AUDITD_LINES[3], 4)
        assert rec.severity == "AUTH_SUCCESS"

    def test_confidence_score_high_on_auditd_lines(self):
        score, expl = self.parser.score_confidence(SAMPLE_AUDITD_LINES)
        assert score >= 0.60
        assert "auditd" in expl.lower() or "audit(" in expl.lower()

    def test_confidence_score_zero_on_non_auditd(self):
        non_auditd = ["GET /index.html HTTP/1.1 200 1234", "Oct 11 12:00:00 syslog msg"]
        score, _ = self.parser.score_confidence(non_auditd)
        assert score == 0.0

    def test_hex_decode_helper_direct(self):
        assert "cat /etc/shadow" in _decode_hex_proctitle("636174202f6574632f736861646f77")

    def test_malformed_line_returns_malformed_status(self):
        rec = self.parser.parse_line("this is not an auditd line at all", 99)
        assert rec.parse_status == "MALFORMED"


# ── WindowsEventParser Tests ───────────────────────────────────────────────────

WINDOWS_CSV_CONTENT = """EventID,TimeCreated,Computer,TargetUserName,IpAddress,LogonType
4624,2026-10-12T10:00:00Z,WIN-SRV01,alice,192.168.1.100,3
4625,2026-10-12T10:01:00Z,WIN-SRV01,bob,192.168.1.200,3
1102,2026-10-12T10:02:00Z,WIN-SRV01,-,-,0"""

WINDOWS_JSON_CONTENT = json.dumps([
    {"EventID": 4624, "TimeCreated": "2026-10-12T10:00:00Z", "Computer": "WIN-SRV01",
     "TargetUserName": "alice", "IpAddress": "192.168.1.100"},
    {"EventID": 4625, "TimeCreated": "2026-10-12T10:01:00Z", "Computer": "WIN-SRV01",
     "TargetUserName": "bob", "IpAddress": "192.168.1.200"},
    {"EventID": 1102, "TimeCreated": "2026-10-12T10:02:00Z", "Computer": "WIN-SRV01"},
])


class TestWindowsEventParser:
    def setup_method(self):
        self.parser = WindowsEventParser()

    def test_format_name(self):
        assert self.parser.format_name == "windows_event"

    def test_parses_csv_logon_success(self):
        lines = WINDOWS_CSV_CONTENT.strip().split("\n")
        records = list(self.parser.parse_stream(iter(lines)))
        assert len(records) >= 1
        logon_records = [r for r in records if "AUTH_SUCCESS" == r.severity or "4624" in r.raw_text]
        assert len(logon_records) >= 1

    def test_csv_auth_fail_event_4625(self):
        lines = WINDOWS_CSV_CONTENT.strip().split("\n")
        records = list(self.parser.parse_stream(iter(lines)))
        fail_records = [r for r in records if r.severity == "AUTH_FAIL"]
        assert len(fail_records) >= 1

    def test_csv_log_cleared_event_1102(self):
        lines = WINDOWS_CSV_CONTENT.strip().split("\n")
        records = list(self.parser.parse_stream(iter(lines)))
        critical = [r for r in records if r.severity == "CRITICAL"]
        assert len(critical) >= 1

    def test_parses_json_format(self):
        lines = WINDOWS_JSON_CONTENT.split("\n")
        records = list(self.parser.parse_stream(iter(lines)))
        assert len(records) == 3
        assert records[0].severity == "AUTH_SUCCESS"
        assert records[1].severity == "AUTH_FAIL"
        assert records[2].severity == "CRITICAL"

    def test_confidence_on_csv_headers(self):
        sample = WINDOWS_CSV_CONTENT.strip().split("\n")[:5]
        score, expl = self.parser.score_confidence(sample)
        assert score >= 0.50

    def test_confidence_zero_on_syslog(self):
        syslog_lines = ["Oct 11 12:00:00 srv sshd: Accepted publickey for alice"]
        score, _ = self.parser.score_confidence(syslog_lines)
        assert score < 0.50


# ── .gz Compressed Log Ingestion ─────────────────────────────────────────────

class TestGzCompressedIngestion:
    def test_ingest_gz_compressed_log(self, tmp_path):
        """ForensicPipeline.ingest_evidence_bytes should transparently decompress .gz files."""
        from src.pipeline import ForensicPipeline
        from src.storage.repository import InvestigationRepository

        data_dir = tmp_path / "data"
        repo = InvestigationRepository(data_dir)
        repo.create_investigation("gz_test", "GZ Test Investigation")
        pipeline = ForensicPipeline(repo)

        # Create sample log content
        sample_log = b'{"timestamp": "2026-10-12T10:00:00Z", "host": "test-host", "message": "test gz event", "request_id": "req-gz-001"}\n'

        # Compress it
        buf = __import__("io").BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(sample_log)
        gz_data = buf.getvalue()

        preserved, events = pipeline.ingest_evidence_bytes(
            "gz_test", "test_log.jsonl.gz", gz_data
        )

        assert preserved is not None
        assert len(events) > 0
        # Events should come from decompressed content
        assert any("test gz event" in (ev.raw_text or ev.description) for ev in events)


# ── AuditChainLedger Tests ────────────────────────────────────────────────────

class TestAuditChainLedger:
    def test_creates_valid_chain(self, tmp_path):
        ledger = AuditChainLedger(tmp_path)

        e1 = ledger.append("CASE_CREATED", "Case opened.", {"id": "test"})
        e2 = ledger.append("EVIDENCE_INGESTED", "Evidence added.", {"file": "a.log"})
        e3 = ledger.append("INTEGRITY_VERIFIED", "All files verified.")

        assert e1.seq_id == 1
        assert e2.seq_id == 2
        assert e3.seq_id == 3
        assert e1.prev_hash == "0" * 64
        assert e2.prev_hash == e1.entry_hash
        assert e3.prev_hash == e2.entry_hash

    def test_chain_verification_passes(self, tmp_path):
        ledger = AuditChainLedger(tmp_path)
        for i in range(5):
            ledger.append(f"ACTION_{i}", f"Summary {i}")

        is_valid, total, error = ledger.verify_chain()
        assert is_valid is True
        assert total == 5
        assert error is None

    def test_tamper_detection(self, tmp_path):
        """Modifying a line in audit_chain.jsonl should cause verify_chain() to fail."""
        ledger = AuditChainLedger(tmp_path)
        ledger.append("CASE_CREATED", "Original summary.")
        ledger.append("EVIDENCE_INGESTED", "Evidence added.")

        # Tamper with the first entry
        ledger_path = tmp_path / "audit_chain.jsonl"
        lines = ledger_path.read_text(encoding="utf-8").splitlines()
        data = json.loads(lines[0])
        data["summary"] = "TAMPERED SUMMARY"
        lines[0] = json.dumps(data)
        ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        is_valid, total, error = ledger.verify_chain()
        assert is_valid is False
        assert error is not None
        assert "tamper" in error.lower() or "mismatch" in error.lower()

    def test_empty_ledger_is_valid(self, tmp_path):
        ledger = AuditChainLedger(tmp_path)
        is_valid, total, error = ledger.verify_chain()
        assert is_valid is True
        assert total == 0

    def test_list_entries_correct_order(self, tmp_path):
        ledger = AuditChainLedger(tmp_path)
        ledger.append("ACTION_A", "First")
        ledger.append("ACTION_B", "Second")
        ledger.append("ACTION_C", "Third")

        entries = ledger.list_entries()
        assert len(entries) == 3
        assert entries[0].action == "ACTION_A"
        assert entries[2].action == "ACTION_C"


# ── TimelineSearchEngine Enhancement Tests ────────────────────────────────────

def make_test_events() -> List[Event]:
    """Create a set of test events for search engine testing."""
    events = []

    e1 = Event.create(
        investigation_id="srch_test",
        evidence_id="ev_001",
        original_filename="access.log",
        line_number=1,
        raw_text="GET /admin/export HTTP/1.1 200 15000",
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00.000000Z",
        source_host="web-srv",
        severity="INFO",
        src_ip="192.168.1.10",
        username="alice",
        description="admin export request",
    )
    e1.extra_fields["bookmarked"] = True
    e1.extra_fields["tags"] = ["Key Evidence", "Exfiltration"]
    events.append(e1)

    e2 = Event.create(
        investigation_id="srch_test",
        evidence_id="ev_002",
        original_filename="auth.log",
        line_number=5,
        raw_text="Failed password for root from 10.0.0.5",
        original_timestamp_str="2026-10-12T10:01:00Z",
        normalized_utc_iso="2026-10-12T10:01:00.000000Z",
        source_host="db-srv",
        severity="AUTH_FAIL",
        src_ip="10.0.0.5",
        username="root",
        description="Failed SSH login",
    )
    events.append(e2)

    e3 = Event.create(
        investigation_id="srch_test",
        evidence_id="ev_003",
        original_filename="syslog",
        line_number=10,
        raw_text="normal system log event at 2026-10-12",
        original_timestamp_str="2026-10-12T10:02:00Z",
        normalized_utc_iso="2026-10-12T10:02:00.000000Z",
        source_host="app-srv",
        severity="INFO",
        src_ip="172.16.0.1",
        description="normal system event",
    )
    events.append(e3)

    return events


class TestTimelineSearchEngineEnhancements:
    def setup_method(self):
        self.events = make_test_events()

    def test_use_regex_true_matches(self):
        criteria = FilterCriteria(keyword=r"GET /admin/\w+", use_regex=True)
        result = TimelineSearchEngine.filter_events(self.events, criteria)
        assert result.filtered_events == 1
        assert "export" in result.events[0].raw_text

    def test_use_regex_false_literal(self):
        # With regex=False, the pattern is treated as literal text
        criteria = FilterCriteria(keyword="Failed password", use_regex=False)
        result = TimelineSearchEngine.filter_events(self.events, criteria)
        assert result.filtered_events == 1

    def test_exclude_keyword(self):
        criteria = FilterCriteria(exclude_keyword="admin")
        result = TimelineSearchEngine.filter_events(self.events, criteria)
        assert all("admin" not in ev.raw_text.lower() for ev in result.events)

    def test_ip_subnet_cidr_192_168(self):
        criteria = FilterCriteria(ip_subnet_cidr="192.168.1.0/24")
        result = TimelineSearchEngine.filter_events(self.events, criteria)
        assert result.filtered_events == 1
        assert result.events[0].src_ip == "192.168.1.10"

    def test_ip_subnet_cidr_10_0(self):
        criteria = FilterCriteria(ip_subnet_cidr="10.0.0.0/8")
        result = TimelineSearchEngine.filter_events(self.events, criteria)
        assert result.filtered_events == 1
        assert result.events[0].src_ip == "10.0.0.5"

    def test_bookmarked_only_true(self):
        criteria = FilterCriteria(bookmarked_only=True)
        result = TimelineSearchEngine.filter_events(self.events, criteria)
        assert result.filtered_events == 1
        assert result.events[0].extra_fields.get("bookmarked") is True

    def test_bookmarked_only_false_returns_all(self):
        criteria = FilterCriteria(bookmarked_only=False)
        result = TimelineSearchEngine.filter_events(self.events, criteria)
        assert result.filtered_events == len(self.events)

    def test_tag_filter_match(self):
        criteria = FilterCriteria(tag_filter="Exfiltration")
        result = TimelineSearchEngine.filter_events(self.events, criteria)
        assert result.filtered_events == 1
        assert "Exfiltration" in result.events[0].extra_fields.get("tags", [])

    def test_tag_filter_no_match(self):
        criteria = FilterCriteria(tag_filter="NonExistentTag")
        result = TimelineSearchEngine.filter_events(self.events, criteria)
        assert result.filtered_events == 0

    def test_existing_filters_still_work(self):
        """Ensure backward-compatible filters (keyword, severity, host) still function."""
        criteria = FilterCriteria(severity="AUTH_FAIL")
        result = TimelineSearchEngine.filter_events(self.events, criteria)
        assert result.filtered_events == 1
        assert result.events[0].severity == "AUTH_FAIL"


# ── CustomRegexParser Tests ──────────────────────────────────────────────────

class TestCustomRegexParser:
    def test_format_name(self):
        from src.parsers.custom_regex_parser import CustomRegexParser
        parser = CustomRegexParser()
        assert parser.format_name == "custom_regex"

    def test_score_confidence_zero(self):
        from src.parsers.custom_regex_parser import CustomRegexParser
        parser = CustomRegexParser()
        score, _ = parser.score_confidence(["2026-10-12 10:00:00 [INFO] host: message"])
        assert score == 0.0

    def test_parses_named_groups(self):
        from src.parsers.custom_regex_parser import CustomRegexParser
        pattern = r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+\[(?P<severity>\w+)\]\s+(?P<host>[^\s:]+):\s+(?P<message>.*)$"
        parser = CustomRegexParser(pattern=pattern)
        rec = parser.parse_line("2026-10-12 14:00:00 [ERROR] web-server-01: DB timeout", 1)
        assert rec.parse_status == "SUCCESS"
        assert rec.original_timestamp_str == "2026-10-12 14:00:00"
        assert rec.severity == "ERROR"
        assert rec.source_host == "web-server-01"
        assert rec.message == "DB timeout"

    def test_test_pattern_method(self):
        from src.parsers.custom_regex_parser import CustomRegexParser
        pattern = r"^(?P<timestamp>\d+)\s+(?P<message>.*)$"
        parser = CustomRegexParser(pattern=pattern)
        match_res = parser.test_pattern("12345 Hello World")
        assert match_res["matched"] is True
        assert match_res["captured_groups"]["timestamp"] == "12345"


# ── ForensicPayloadBaker Tests ──────────────────────────────────────────────

class TestForensicPayloadBaker:
    def test_shannon_entropy(self):
        from src.forensic_tools import ForensicPayloadBaker
        assert ForensicPayloadBaker.shannon_entropy("") == 0.0
        assert ForensicPayloadBaker.shannon_entropy("AAAAAAA") == 0.0
        # High entropy for diverse base64 string
        high_ent = ForensicPayloadBaker.shannon_entropy("8f7a9c2b1e4d6f8a0b3c5e7d9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a")
        assert high_ent > 3.5

    def test_extract_iocs(self):
        from src.forensic_tools import ForensicPayloadBaker
        sample = "Conn from 192.168.1.100 and 8.8.8.8 via /etc/shadow at http://evil.com/x?a=1 with sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        iocs = ForensicPayloadBaker.extract_iocs(sample)
        assert "192.168.1.100" in iocs["ipv4_private"]
        assert "8.8.8.8" in iocs["ipv4_public"]
        assert "/etc/shadow" in iocs["file_paths"]
        assert any("evil.com" in u for u in iocs["urls_uris"])
        assert "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" in iocs["sha256_hashes"]

    def test_auto_bake_and_recipes(self):
        from src.forensic_tools import ForensicPayloadBaker
        # Hex decode
        res_hex = ForensicPayloadBaker.apply_recipe("636174", "Hex Decode")
        assert res_hex == "cat"

        # Base64 decode
        res_b64 = ForensicPayloadBaker.apply_recipe("Y2F0", "Base64 Decode")
        assert res_b64 == "cat"

        # Defang and Refang
        defanged = ForensicPayloadBaker.apply_recipe("http://1.1.1.1/test", "Defang IOCs")
        assert "hxxp://" in defanged and "1[.]1[.]1[.]1" in defanged
        refanged = ForensicPayloadBaker.apply_recipe(defanged, "Refang IOCs")
        assert "http://" in refanged and "1.1.1.1" in refanged


# ── EntityGraphBuilder Tests ────────────────────────────────────────────────

class TestEntityGraphBuilder:
    def test_build_plotly_graph_with_events(self):
        from src.forensic_tools import EntityGraphBuilder
        events = make_test_events()
        fig = EntityGraphBuilder.build_plotly_graph(events)
        assert fig is not None
        assert len(fig.data) >= 1

    def test_build_plotly_graph_empty(self):
        from src.forensic_tools import EntityGraphBuilder
        fig = EntityGraphBuilder.build_plotly_graph([])
        assert fig is not None


# ── ForensicHeuristicEngine Tests ───────────────────────────────────────────

class TestForensicHeuristicEngine:
    def test_brute_force_then_success(self):
        from src.diagnostics.heuristics import ForensicHeuristicEngine
        events = []
        for i in range(4):
            e = Event.create(
                investigation_id="h_test",
                evidence_id="ev_01",
                original_filename="auth.log",
                line_number=i + 1,
                raw_text=f"Failed auth attempt {i}",
                original_timestamp_str=f"2026-10-12T10:0{i}:00Z",
                normalized_utc_iso=f"2026-10-12T10:0{i}:00.000000Z",
                source_host="srv-app",
                severity="AUTH_FAIL",
                username="root",
            )
            events.append(e)

        e_succ = Event.create(
            investigation_id="h_test",
            evidence_id="ev_01",
            original_filename="auth.log",
            line_number=5,
            raw_text="Accepted password for root",
            original_timestamp_str="2026-10-12T10:05:00Z",
            normalized_utc_iso="2026-10-12T10:05:00.000000Z",
            source_host="srv-app",
            severity="AUTH_SUCCESS",
            username="root",
        )
        events.append(e_succ)

        engine = ForensicHeuristicEngine()
        leads = engine.analyze(events)
        assert any(l.rule_name == "BRUTE_FORCE_THEN_SUCCESS" for l in leads)


# ── Pipeline Deduplication & Header Skipping Tests ──────────────────────────

class TestPipelineDeduplicationAndHeaderSkipping:
    def test_duplicate_sha256_skipped(self, tmp_path):
        from src.pipeline import ForensicPipeline
        from src.storage.repository import InvestigationRepository

        repo = InvestigationRepository(tmp_path / "data")
        repo.create_investigation("dedup_test", "Dedup Test")
        pipeline = ForensicPipeline(repo)

        log_data = b'{"timestamp": "2026-10-12T10:00:00Z", "host": "h1", "message": "msg 1"}\n'
        p1, ev1 = pipeline.ingest_evidence_bytes("dedup_test", "file1.jsonl", log_data)
        assert len(ev1) == 1

        # Ingesting exact same bytes with different name should deduplicate
        p2, ev2 = pipeline.ingest_evidence_bytes("dedup_test", "file2.jsonl", log_data)
        assert p2.evidence_id == p1.evidence_id
        assert len(ev2) == 0

        # With allow_duplicate=True, it should ingest
        p3, ev3 = pipeline.ingest_evidence_bytes("dedup_test", "file3.jsonl", log_data, allow_duplicate=True)
        assert p3.evidence_id != p1.evidence_id
        assert len(ev3) == 1


# ── Structured CQL Query Parser Tests ─────────────────────────────────────────

class TestStructuredCQLQueryParser:
    def test_parse_cql_query_tokens(self):
        from src.timeline.search import parse_cql_query
        q = 'host:srv-01 user:admin ip:192.168.1.1 severity:CRITICAL req:req-99 session:sess-1 status:CORRECTED NOT failure keyword'
        preds = parse_cql_query(q)
        assert any("srv-01" in grp for grp in preds.hosts)
        assert any("admin" in grp for grp in preds.users)
        assert any("192.168.1.1" in grp for grp in preds.ips)
        assert any("CRITICAL" in grp for grp in preds.severities)
        assert any("req-99" in grp for grp in preds.request_ids)
        assert any("sess-1" in grp for grp in preds.session_ids)
        assert any("CORRECTED" in grp for grp in preds.statuses)
        assert "failure" in preds.not_terms
        assert "keyword" in preds.free_terms

    def test_cql_filtering_in_search_engine(self):
        from src.timeline.search import FilterCriteria, TimelineSearchEngine
        ev1 = Event.create(
            investigation_id="inv1",
            evidence_id="ev01",
            original_filename="auth.log",
            line_number=1,
            raw_text="Admin logon success",
            original_timestamp_str="2026-10-12T10:00:00Z",
            source_host="web-01",
            username="admin",
            src_ip="10.0.0.5",
            severity="AUTH_SUCCESS",
            category="AUTH",
            request_id="req-100",
        )
        ev2 = Event.create(
            investigation_id="inv1",
            evidence_id="ev02",
            original_filename="syslog.log",
            line_number=2,
            raw_text="Service stopped failure",
            original_timestamp_str="2026-10-12T10:01:00Z",
            source_host="db-01",
            username="service_acc",
            src_ip="10.0.0.8",
            severity="ERROR",
            category="SYSTEM",
            request_id="req-200",
        )

        events = [ev1, ev2]

        # Filter by host
        res1 = TimelineSearchEngine.filter_events(events, FilterCriteria(keyword="host:web-01"))
        assert res1.filtered_events == 1
        assert res1.events[0].source_host == "web-01"

        # Filter by NOT
        res2 = TimelineSearchEngine.filter_events(events, FilterCriteria(keyword="NOT failure"))
        assert res2.filtered_events == 1
        assert res2.events[0].source_host == "web-01"

        # Filter by severity and user
        res3 = TimelineSearchEngine.filter_events(events, FilterCriteria(keyword="user:admin severity:AUTH_SUCCESS"))
        assert res3.filtered_events == 1
        assert res3.events[0].event_id == ev1.event_id


# ── Repository File Path Resolution Tests ─────────────────────────────────────

class TestEvidenceFilePathResolution:
    def test_get_evidence_file_path_various_naming_schemes(self, tmp_path):
        from src.storage.repository import InvestigationRepository
        repo = InvestigationRepository(tmp_path / "data")
        inv = repo.create_investigation("res_test", "Resolution Test")
        ev_dir = repo.get_evidence_dir("res_test")

        # Create dummy evidence file
        dummy_file = ev_dir / "ev_test_123_sample.log"
        dummy_file.write_text("sample content")

        found_path = repo.get_evidence_file_path("res_test", "ev_test_123")
        assert found_path is not None
        assert found_path.name == "ev_test_123_sample.log"


# ── Pipeline Custom Regex Ingestion Tests ─────────────────────────────────────

class TestPipelineCustomRegexIngestion:
    def test_custom_regex_ingestion(self, tmp_path):
        from src.pipeline import ForensicPipeline
        from src.storage.repository import InvestigationRepository

        repo = InvestigationRepository(tmp_path / "data")
        repo.create_investigation("regex_inv", "Regex Ingestion Test")
        pipeline = ForensicPipeline(repo)

        custom_rx = r"^(?P<timestamp>\S+)\s+\[(?P<host>\S+)\]\s+(?P<user>\S+)\s+(?P<message>.*)$"
        raw_log = b"2026-10-12T12:00:00Z [app-server] alice User logged in\n2026-10-12T12:01:00Z [app-server] bob Action performed\n"

        pe, parsed_events = pipeline.ingest_evidence_bytes(
            investigation_id="regex_inv",
            filename="custom.log",
            data=raw_log,
            explicit_format="custom_regex",
            custom_regex=custom_rx,
        )

        manifest = repo.get_manifest("regex_inv")
        entry = manifest.get_entry(pe.evidence_id)
        assert entry is not None
        assert entry.detected_format == "custom_regex"
        assert len(parsed_events) == 2
        assert parsed_events[0].source_host == "app-server"
        assert parsed_events[0].actor == "alice"


# ── Heuristics Diagnostics Tests ──────────────────────────────────────────────

class TestHeuristicsDiagnostics:
    def test_heuristics_with_integrity_and_gap_diagnostics(self):
        from src.diagnostics.gap_analysis import DiagnosticCategory, DiagnosticItem, DiagnosticSeverity
        from src.diagnostics.heuristics import ForensicHeuristicEngine

        engine = ForensicHeuristicEngine()
        diag = DiagnosticItem(
            diag_id="diag_01",
            category=DiagnosticCategory.H_EVIDENCE_INTEGRITY_ISSUE,
            severity=DiagnosticSeverity.CRITICAL,
            affected_target="auth.log",
            explanation="Hash mismatch detected",
            supporting_details="SHA-256 baseline changed",
            suggested_action="Review integrity",
        )

        leads = engine.analyze([], diagnostics=[diag])
        assert any(l.rule_name == "CLOCK_OR_LOG_TAMPERING_INDICATOR" for l in leads)
        tamper_lead = next(l for l in leads if l.rule_name == "CLOCK_OR_LOG_TAMPERING_INDICATOR")
        assert "auth.log" in tamper_lead.hosts


# ── v2.1 Audit Remediation Tests ──────────────────────────────────────────────

class TestJsonExportDefaultCoverage:
    def test_json_export_default_coverage_stats_no_crash(self):
        from src.reporting.json_export import export_investigation_json
        from src.storage.repository import InvestigationMetadata
        from src.evidence.manifest import EvidenceManifest

        meta = InvestigationMetadata(
            investigation_id="test_exp",
            title="Test",
            description="",
            created_at_utc="2026-10-12T00:00:00Z",
            last_updated_utc="2026-10-12T00:00:00Z",
        )
        manifest = EvidenceManifest(investigation_id="test_exp")
        out = export_investigation_json(
            metadata=meta,
            manifest=manifest,
            events=[],
            diagnostics=[],
            coverage_stats=None,
        )
        assert "Chronica Forensic Investigation Export" in out


class TestMultiFileArchiveExpansion:
    def test_multi_file_zip_expansion(self, tmp_path):
        import zipfile
        import io
        from src.pipeline import ForensicPipeline
        from src.storage.repository import InvestigationRepository

        repo = InvestigationRepository(tmp_path / "data")
        pipeline = ForensicPipeline(repo)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.log", "2026-10-12T10:00:00Z line 1\n")
            zf.writestr("b.jsonl", '{"timestamp": "2026-10-12T10:01:00Z", "msg": "test"}\n')
            zf.writestr("__MACOSX/._a.log", "metadata")

        extracted = pipeline.expand_archive_bytes("bundle.zip", buf.getvalue())
        assert len(extracted) == 2
        names = [name for name, _ in extracted]
        assert "a.log" in names
        assert "b.jsonl" in names


class TestTransitiveTwoHopClockSkew:
    def test_transitive_two_hop_clock_skew(self, tmp_path):
        from src.pipeline import ForensicPipeline
        from src.storage.repository import InvestigationRepository

        repo = InvestigationRepository(tmp_path / "data")
        repo.create_investigation("two_hop", "Two Hop Skew", reference_source="host-a")
        pipeline = ForensicPipeline(repo)

        raw_a = (
            b'{"timestamp": "2026-10-12T10:00:00Z", "host": "host-a", "request_id": "req-1", "message": "msg 1"}\n'
            b'{"timestamp": "2026-10-12T10:05:00Z", "host": "host-a", "request_id": "req-2", "message": "msg 2"}\n'
        )
        raw_b = (
            b'{"timestamp": "2026-10-12T10:01:00Z", "host": "host-b", "request_id": "req-1", "message": "msg 1b"}\n'
            b'{"timestamp": "2026-10-12T10:06:00Z", "host": "host-b", "request_id": "req-2", "message": "msg 2b"}\n'
            b'{"timestamp": "2026-10-12T10:10:00Z", "host": "host-b", "session_id": "sess-1", "message": "sess 1b"}\n'
            b'{"timestamp": "2026-10-12T10:15:00Z", "host": "host-b", "session_id": "sess-2", "message": "sess 2b"}\n'
        )
        raw_c = (
            b'{"timestamp": "2026-10-12T10:12:00Z", "host": "host-c", "session_id": "sess-1", "message": "sess 1c"}\n'
            b'{"timestamp": "2026-10-12T10:17:00Z", "host": "host-c", "session_id": "sess-2", "message": "sess 2c"}\n'
        )

        pipeline.ingest_evidence_bytes("two_hop", "a.jsonl", raw_a, explicit_format="jsonl")
        pipeline.ingest_evidence_bytes("two_hop", "b.jsonl", raw_b, explicit_format="jsonl")
        pipeline.ingest_evidence_bytes("two_hop", "c.jsonl", raw_c, explicit_format="jsonl")

        analysis = pipeline.analyze_investigation("two_hop", reference_source="host-a")
        skews = analysis["skew_estimates"]
        assert "host-b" in skews
        assert skews["host-b"].estimated_offset_sec == 60.0
        assert "host-c" in skews
        assert skews["host-c"].status == "ESTIMATED"
        assert skews["host-c"].estimated_offset_sec == 180.0
        assert "Transitive 2-hop" in skews["host-c"].estimation_method


class TestCQLCommaOrAndTimeBounds:
    def test_cql_comma_or_and_time_bounds(self):
        from src.timeline.search import FilterCriteria, TimelineSearchEngine

        ev1 = Event.create(
            investigation_id="cql_test",
            evidence_id="ev_01",
            original_filename="test.log",
            line_number=1,
            raw_text="critical failure",
            original_timestamp_str="2026-10-12T10:01:00Z",
            normalized_utc_iso="2026-10-12T10:01:00.000000Z",
            source_host="web-01",
            severity="CRITICAL",
        )
        ev2 = Event.create(
            investigation_id="cql_test",
            evidence_id="ev_02",
            original_filename="test.log",
            line_number=2,
            raw_text="auth fail",
            original_timestamp_str="2026-10-12T10:05:00Z",
            normalized_utc_iso="2026-10-12T10:05:00.000000Z",
            source_host="db-01",
            severity="AUTH_FAIL",
        )
        ev3 = Event.create(
            investigation_id="cql_test",
            evidence_id="ev_03",
            original_filename="test.log",
            line_number=3,
            raw_text="normal info",
            original_timestamp_str="2026-10-12T10:10:00Z",
            normalized_utc_iso="2026-10-12T10:10:00.000000Z",
            source_host="web-01",
            severity="INFO",
        )

        events = [ev1, ev2, ev3]

        # Comma OR matching
        res_or = TimelineSearchEngine.filter_events(events, FilterCriteria(keyword="severity:CRITICAL,AUTH_FAIL"))
        assert res_or.filtered_events == 2

        # Comma OR with after: bound
        res_time = TimelineSearchEngine.filter_events(
            events, FilterCriteria(keyword="severity:CRITICAL,AUTH_FAIL after:2026-10-12T10:02:00Z")
        )
        assert res_time.filtered_events == 1
        assert res_time.events[0].event_id == ev2.event_id


class TestO1GetEventById:
    def test_o1_get_event_by_id(self, tmp_path):
        from src.storage.repository import InvestigationRepository

        repo = InvestigationRepository(tmp_path / "data")
        repo.create_investigation("o1_inv", "O1 Test")

        ev = Event.create(
            investigation_id="o1_inv",
            evidence_id="ev_01",
            original_filename="test.log",
            line_number=1,
            raw_text="line 1",
            original_timestamp_str="2026-10-12T10:00:00Z",
            source_host="srv-01",
        )
        repo.save_events("o1_inv", [ev])

        found = repo.db.get_event_by_id("o1_inv", ev.event_id)
        assert found is not None
        assert found.event_id == ev.event_id
        assert found.source_host == "srv-01"

        missing = repo.db.get_event_by_id("o1_inv", "non_existent_id")
        assert missing is None


