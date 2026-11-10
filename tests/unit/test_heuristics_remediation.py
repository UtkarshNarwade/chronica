"""Tests reproducing and verifying F-03: heuristic scoping, timestamp selection, and tamper precision."""

from src.diagnostics.heuristics import ForensicHeuristicEngine
from src.timeline.schema import Event


def test_web_log_4616_bytes_does_not_trigger_tamper_lead():
    """Reproduce F-03 defect 1: 4616 bytes in web log must not trigger CRITICAL tamper lead."""
    engine = ForensicHeuristicEngine()
    ev = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="access.log",
        line_number=1,
        raw_text='192.168.1.50 - - [12/Oct/2026:10:00:00 +0000] "GET /manual.pdf HTTP/1.1" 200 4616',
        original_timestamp_str="12/Oct/2026:10:00:00 +0000",
        normalized_utc_iso="2026-10-12T10:00:00.000000Z",
        source_host="web-01",
        severity="INFO",
        description="HTTP GET /manual.pdf status=200 bytes=4616",
    )
    leads = engine.analyze([ev])
    tamper_leads = [l for l in leads if l.rule_name == "CLOCK_OR_LOG_TAMPERING_INDICATOR"]
    assert len(tamper_leads) == 0, f"Expected 0 tamper leads for 4616-byte HTTP response, got {len(tamper_leads)}"


def test_privilege_escalation_requires_same_host_or_user():
    """Reproduce F-03 defect 2: sudo on host Z must not be attributed to alice on host A."""
    engine = ForensicHeuristicEngine()
    ev_auth = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="auth.log",
        line_number=1,
        raw_text="Accepted publickey for alice from 192.168.1.100 port 55123 ssh2",
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00.000000Z",
        source_host="host-a",
        username="alice",
        severity="AUTH_SUCCESS",
    )
    ev_sudo = Event.create(
        investigation_id="inv1",
        evidence_id="ev2",
        original_filename="host_z.log",
        line_number=1,
        raw_text="bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        original_timestamp_str="2026-10-12T10:03:00Z",
        normalized_utc_iso="2026-10-12T10:03:00.000000Z",
        source_host="host-z",
        username="bob",
        severity="NOTICE",
        description="sudo COMMAND=/bin/cat /etc/shadow",
    )
    leads = engine.analyze([ev_auth, ev_sudo])
    priv_leads = [l for l in leads if l.rule_name == "PRIVILEGE_ESCALATION"]
    assert len(priv_leads) == 0, f"Cross-host unlinked events must not produce privilege escalation lead, got {len(priv_leads)}"


def test_multiple_distinct_leads_emitted_no_early_break():
    """Reproduce F-03 defect 4: multiple distinct privilege escalations across users must all be emitted."""
    engine = ForensicHeuristicEngine()
    ev1 = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="h1.log",
        line_number=1,
        raw_text="Accepted password for user1",
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00.000000Z",
        source_host="host1",
        username="user1",
        severity="AUTH_SUCCESS",
    )
    ev2 = Event.create(
        investigation_id="inv1",
        evidence_id="ev2",
        original_filename="h1.log",
        line_number=2,
        raw_text="user1 : COMMAND=/usr/bin/sudo /bin/bash",
        original_timestamp_str="2026-10-12T10:02:00Z",
        normalized_utc_iso="2026-10-12T10:02:00.000000Z",
        source_host="host1",
        username="user1",
        severity="NOTICE",
        description="sudo /bin/bash",
    )
    ev3 = Event.create(
        investigation_id="inv1",
        evidence_id="ev3",
        original_filename="h2.log",
        line_number=1,
        raw_text="Accepted password for user2",
        original_timestamp_str="2026-10-12T10:05:00Z",
        normalized_utc_iso="2026-10-12T10:05:00.000000Z",
        source_host="host2",
        username="user2",
        severity="AUTH_SUCCESS",
    )
    ev4 = Event.create(
        investigation_id="inv1",
        evidence_id="ev4",
        original_filename="h2.log",
        line_number=2,
        raw_text="user2 : COMMAND=/usr/bin/sudo /bin/systemctl restart secret",
        original_timestamp_str="2026-10-12T10:07:00Z",
        normalized_utc_iso="2026-10-12T10:07:00.000000Z",
        source_host="host2",
        username="user2",
        severity="NOTICE",
        description="sudo systemctl restart secret",
    )
    leads = engine.analyze([ev1, ev2, ev3, ev4])
    priv_leads = [l for l in leads if l.rule_name == "PRIVILEGE_ESCALATION"]
    assert len(priv_leads) == 2, f"Expected 2 privilege escalation leads for 2 distinct users/hosts, got {len(priv_leads)}"
    for pl in priv_leads:
        assert len(pl.evidence_event_ids) >= 2, "Lead must contain evidence event IDs"


def test_corrected_time_used_in_heuristics():
    """Reproduce F-03 defect 3: heuristics must use corrected_utc_iso rather than uncorrected normalized_utc_iso."""
    engine = ForensicHeuristicEngine()
    # In normalized time, sudo appears 1800s (30m) later -> outside 900s window.
    # In corrected time (host clock was 1000s fast), it occurred within 800s -> inside window.
    ev_auth = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="auth.log",
        line_number=1,
        raw_text="Accepted password for admin",
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00.000000Z",
        corrected_utc_iso="2026-10-12T10:00:00.000000Z",
        source_host="host1",
        username="admin",
        severity="AUTH_SUCCESS",
    )
    ev_sudo = Event.create(
        investigation_id="inv1",
        evidence_id="ev2",
        original_filename="host1.log",
        line_number=2,
        raw_text="admin : COMMAND=/usr/bin/sudo /bin/sh",
        original_timestamp_str="2026-10-12T10:30:00Z",
        normalized_utc_iso="2026-10-12T10:30:00.000000Z",  # 1800s later in normalized time
        corrected_utc_iso="2026-10-12T10:10:00.000000Z",   # 600s later in corrected time (within 900s)
        source_host="host1",
        username="admin",
        severity="NOTICE",
        description="sudo /bin/sh",
    )
    leads = engine.analyze([ev_auth, ev_sudo])
    priv_leads = [l for l in leads if l.rule_name == "PRIVILEGE_ESCALATION"]
    assert len(priv_leads) == 1, "Expected privilege escalation detected using corrected timeline"
    assert "ev1" in priv_leads[0].evidence_event_ids or any(
        e.event_id in priv_leads[0].evidence_event_ids for e in [ev_auth, ev_sudo]
    )


def test_windows_event_id_string_and_int_detection():
    """Adversarial check 1: Windows EventID as int, str, and in EventID key must detect tampering without crash."""
    engine = ForensicHeuristicEngine()
    ev_str = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="security.evtx",
        line_number=1,
        raw_text="The audit log was cleared",
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00.000000Z",
        source_host="win-dc",
        severity="CRITICAL",
        extra_fields={"EventID": "1102"},
    )
    ev_int = Event.create(
        investigation_id="inv1",
        evidence_id="ev2",
        original_filename="security.evtx",
        line_number=2,
        raw_text="The system time was changed",
        original_timestamp_str="2026-10-12T10:01:00Z",
        normalized_utc_iso="2026-10-12T10:01:00.000000Z",
        source_host="win-dc",
        severity="WARNING",
        extra_fields={"event_id": 4616},
    )
    ev_corrupt = Event.create(
        investigation_id="inv1",
        evidence_id="ev3",
        original_filename="security.evtx",
        line_number=3,
        raw_text="Random app event",
        original_timestamp_str="2026-10-12T10:02:00Z",
        normalized_utc_iso="2026-10-12T10:02:00.000000Z",
        source_host="win-dc",
        severity="INFO",
        extra_fields={"event_id": "not-a-number"},
    )
    leads = engine.analyze([ev_str, ev_int, ev_corrupt])
    tamper_leads = [l for l in leads if l.rule_name == "CLOCK_OR_LOG_TAMPERING_INDICATOR"]
    assert len(tamper_leads) == 1, "Expected tampering lead for genuine 1102 and 4616 events"
    assert ev_str.event_id in tamper_leads[0].involved_event_ids
    assert ev_int.event_id in tamper_leads[0].involved_event_ids
    assert ev_corrupt.event_id not in tamper_leads[0].involved_event_ids


def test_malformed_and_missing_timestamps_do_not_crash_engine():
    """Adversarial check 2: events with None, empty, or corrupt timestamps must not crash heuristic engine."""
    engine = ForensicHeuristicEngine()
    ev1 = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="corrupt.log",
        line_number=1,
        raw_text="Corrupt timestamp event",
        original_timestamp_str="INVALID",
        normalized_utc_iso="",
        corrected_utc_iso=None,
        source_host="host1",
        username="admin",
        severity="AUTH_SUCCESS",
    )
    ev2 = Event.create(
        investigation_id="inv1",
        evidence_id="ev2",
        original_filename="corrupt.log",
        line_number=2,
        raw_text="admin : COMMAND=/usr/bin/sudo /bin/id",
        original_timestamp_str="INVALID",
        normalized_utc_iso=None,
        corrected_utc_iso="",
        source_host="host1",
        username="admin",
        severity="NOTICE",
        description="sudo /bin/id",
    )
    leads = engine.analyze([ev1, ev2])
    assert isinstance(leads, list)


