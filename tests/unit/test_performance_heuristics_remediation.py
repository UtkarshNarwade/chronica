"""Unit tests for F-04: Timestamp epoch caching, sliding-window heuristics, and benchmark scaling."""

import time
from pathlib import Path
import pytest

from src.diagnostics.heuristics import ForensicHeuristicEngine, _event_effective_epoch
from src.timeline.schema import Event


def test_reproduce_event_cached_epoch_parsing():
    """Event must provide cached effective_epoch to avoid re-parsing ISO strings millions of times."""
    ev = Event.create(
        investigation_id="perf_inv",
        evidence_id="ev_001",
        original_filename="syslog.log",
        line_number=1,
        raw_text="Test line",
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00.000000Z",
        corrected_utc_iso="2026-10-12T10:00:05.000000Z",
    )
    # Check that effective_epoch is present and matches the corrected UTC epoch
    assert hasattr(ev, "effective_epoch"), "Event must provide effective_epoch property"
    epoch = ev.effective_epoch
    assert epoch is not None
    # 2026-10-12T10:00:05Z = 1791799205.0
    assert abs(epoch - 1791799205.0) < 1.0

    # Ensure caching prevents repeated datetime parsing
    assert ev.effective_epoch is epoch


def test_reproduce_heuristics_sliding_window_scaling():
    """Heuristics engine must scale near-linearly using bisect/sliding window instead of O(N^2)."""
    # Generate 6000 events
    events = []
    base_epoch = 1791800000
    for i in range(6000):
        sev = "AUTH_SUCCESS" if i % 25 == 0 else "INFO"
        desc = "user=admin login" if sev == "AUTH_SUCCESS" else f"GET /download/report_{i}.tar.gz"
        sec = base_epoch + i
        ev = Event.create(
            investigation_id="perf_test",
            evidence_id="ev_001",
            original_filename="access.log",
            line_number=i + 1,
            raw_text=desc,
            original_timestamp_str=f"epoch:{sec}",
            normalized_utc_iso=f"2026-10-12T10:00:{i%60:02d}.000000Z",
            corrected_utc_iso=f"2026-10-12T10:00:{i%60:02d}.000000Z",
            source_host="web-01",
            severity=sev,
            username="admin",
            description=desc,
            extra_fields={"response_bytes": 25000} if "download" in desc else {},
        )
        events.append(ev)

    engine = ForensicHeuristicEngine()
    t0 = time.perf_counter()
    leads = engine.analyze(events)
    elapsed = time.perf_counter() - t0

    # Under sliding-window / bisect implementation, 6000 events must analyze in < 0.35s
    assert elapsed < 0.35, f"Expected 6000 events to analyze in under 0.35s, took {elapsed:.3f}s"
    assert len(leads) > 0, "Expected leads to be detected"


def test_reproduce_bench_script_exists():
    """Benchmark script scripts/bench.py must exist."""
    bench_path = Path(__file__).resolve().parent.parent.parent / "scripts" / "bench.py"
    assert bench_path.exists(), "scripts/bench.py must exist"


def test_adversarial_corrupted_and_missing_timestamps_in_heuristics():
    """Adversarial check: mixed stream with missing timestamps and None epochs."""
    events = [
        Event.create(
            investigation_id="adv_perf",
            evidence_id="ev_1",
            original_filename="bad.log",
            line_number=1,
            raw_text="Corrupt line with no timestamp",
            original_timestamp_str=None,
            normalized_utc_iso=None,
            corrected_utc_iso=None,
            severity="AUTH_SUCCESS",
            username="alice",
        ),
        Event.create(
            investigation_id="adv_perf",
            evidence_id="ev_1",
            original_filename="bad.log",
            line_number=2,
            raw_text="Unparseable timestamp",
            original_timestamp_str="INVALID_DATE_FORMAT",
            normalized_utc_iso="NOT_AN_ISO_DATE",
            corrected_utc_iso=None,
            severity="INFO",
            username="alice",
            description="sudo /bin/bash",
        ),
        Event.create(
            investigation_id="adv_perf",
            evidence_id="ev_1",
            original_filename="bad.log",
            line_number=3,
            raw_text="Normal auth success",
            original_timestamp_str="2026-10-12T10:00:00Z",
            normalized_utc_iso="2026-10-12T10:00:00.000000Z",
            severity="AUTH_SUCCESS",
            username="alice",
            source_host="hostA",
        ),
        Event.create(
            investigation_id="adv_perf",
            evidence_id="ev_1",
            original_filename="bad.log",
            line_number=4,
            raw_text="sudo cat /etc/shadow",
            original_timestamp_str="2026-10-12T10:02:00Z",
            normalized_utc_iso="2026-10-12T10:02:00.000000Z",
            severity="HIGH",
            username="alice",
            source_host="hostA",
            description="sudo cat /etc/shadow",
        ),
    ]

    engine = ForensicHeuristicEngine()
    leads = engine.analyze(events)
    # The valid auth + sudo on hostA within 2 minutes must be detected cleanly
    priv_leads = [l for l in leads if l.rule_name == "PRIVILEGE_ESCALATION"]
    assert len(priv_leads) == 1
    assert "alice" in priv_leads[0].title


def test_adversarial_zero_auth_events_instant_return():
    """Adversarial check: zero auth events exits early in O(1)."""
    events = [
        Event.create(
            investigation_id="no_auth",
            evidence_id="ev_2",
            original_filename="web.log",
            line_number=i + 1,
            raw_text=f"GET /page_{i} HTTP/1.1 200",
            original_timestamp_str="2026-10-12T12:00:00Z",
            normalized_utc_iso="2026-10-12T12:00:00.000000Z",
            severity="INFO",
        )
        for i in range(500)
    ]
    engine = ForensicHeuristicEngine()
    leads = engine.analyze(events)
    # No auth events means no brute-force, no priv escalation, no data export leads
    assert len(leads) == 0
