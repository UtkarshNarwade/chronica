"""Unit tests for timeline search, facet filtering, and query conjunction."""

import pytest

from src.timeline.schema import Event
from src.timeline.search import FilterCriteria, TimelineSearchEngine


@pytest.fixture
def sample_events():
    return [
        Event.create(
            investigation_id="inv1",
            evidence_id="ev1",
            original_filename="auth.log",
            line_number=1,
            raw_text="Accepted publickey for alice",
            original_timestamp_str="2026-10-12T10:00:00Z",
            normalized_utc_iso="2026-10-12T10:00:00Z",
            source_host="srv-app",
            severity="AUTH_SUCCESS",
            category="AUTHENTICATION",
            username="alice",
            src_ip="192.168.1.10",
        ),
        Event.create(
            investigation_id="inv1",
            evidence_id="ev1",
            original_filename="auth.log",
            line_number=2,
            raw_text="Failed password for root",
            original_timestamp_str="2026-10-12T10:05:00Z",
            normalized_utc_iso="2026-10-12T10:05:00Z",
            source_host="srv-app",
            severity="AUTH_FAIL",
            category="AUTHENTICATION",
            username="root",
            src_ip="192.168.1.99",
        ),
        Event.create(
            investigation_id="inv1",
            evidence_id="ev2",
            original_filename="web.log",
            line_number=1,
            raw_text="GET /api/v1/data 200",
            original_timestamp_str="2026-10-12T10:10:00Z",
            normalized_utc_iso="2026-10-12T10:10:00Z",
            source_host="gateway",
            severity="INFO",
            category="WEB_REQUEST",
            username="alice",
            src_ip="192.168.1.10",
        ),
    ]


def test_empty_criteria_returns_all(sample_events):
    engine = TimelineSearchEngine()
    criteria = FilterCriteria()
    res = engine.filter_events(sample_events, criteria)

    assert res.total_events == 3
    assert res.filtered_events == 3
    assert len(res.events) == 3


def test_keyword_search(sample_events):
    engine = TimelineSearchEngine()
    criteria = FilterCriteria(keyword="root")
    res = engine.filter_events(sample_events, criteria)

    assert res.filtered_events == 1
    assert res.events[0].username == "root"


def test_username_filter(sample_events):
    engine = TimelineSearchEngine()
    criteria = FilterCriteria(username="alice")
    res = engine.filter_events(sample_events, criteria)

    assert res.filtered_events == 2


def test_combined_filters(sample_events):
    engine = TimelineSearchEngine()
    # Filter for alice AND category WEB_REQUEST
    criteria = FilterCriteria(username="alice", category="WEB_REQUEST")
    res = engine.filter_events(sample_events, criteria)

    assert res.filtered_events == 1
    assert res.events[0].original_filename == "web.log"


def test_time_range_filter(sample_events):
    engine = TimelineSearchEngine()
    criteria = FilterCriteria(
        start_time_iso="2026-10-12T10:04:00Z",
        end_time_iso="2026-10-12T10:08:00Z",
    )
    res = engine.filter_events(sample_events, criteria)

    assert res.filtered_events == 1
    assert res.events[0].line_number == 2  # The 10:05:00 event
