"""Tests reproducing and verifying F-16:
- Quoted phrase searches must match exact multi-word phrases.
- OR operator must provide disjunction, not be treated as a required literal word.
- NOT field:value must only exclude based on the specific field, not the entire text corpus.
- Host matching must be exact unless wildcard (*) is explicit.
- before:YYYY-MM-DD must be inclusive of the full date.
- Search must evaluate full text, not truncate at 8192 chars.
- Regex search must guard against ReDoS with timeout and pattern limits.
"""

import time
import pytest
from src.timeline.schema import Event
from src.timeline.search import FilterCriteria, TimelineSearchEngine


@pytest.fixture
def cql_test_events():
    ev1 = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="auth.log",
        line_number=1,
        raw_text="Failed password for root from 10.0.0.1",
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00Z",
        source_host="web-01",
        severity="AUTH_FAIL",
        category="AUTH",
        username="root",
    )
    ev2 = Event.create(
        investigation_id="inv1",
        evidence_id="ev2",
        original_filename="auth.log",
        line_number=2,
        raw_text="Accepted publickey for alice from 10.0.0.2",
        original_timestamp_str="2026-10-12T14:30:00Z",
        normalized_utc_iso="2026-10-12T14:30:00Z",
        source_host="web-01-backup",
        severity="AUTH_SUCCESS",
        category="AUTH",
        username="alice",
        description="Mentioning db-01 in maintenance notes",
    )
    ev3 = Event.create(
        investigation_id="inv1",
        evidence_id="ev3",
        original_filename="app.log",
        line_number=3,
        raw_text="A" * 9000 + " TARGET_PAYLOAD_AT_10K " + "B" * 500,
        original_timestamp_str="2026-10-13T09:00:00Z",
        normalized_utc_iso="2026-10-13T09:00:00Z",
        source_host="db-01",
        severity="INFO",
        category="SYSTEM",
        username="bob",
    )
    return [ev1, ev2, ev3]


def test_quoted_phrase_search(cql_test_events):
    """Reproduce F-16 defect 1: Quoted phrase 'failed password' returns nothing."""
    res = TimelineSearchEngine.filter_events(
        cql_test_events, FilterCriteria(keyword='"failed password"')
    )
    assert res.filtered_events == 1
    assert res.events[0].username == "root"


def test_or_operator_disjunction(cql_test_events):
    """Reproduce F-16 defect 2: OR is treated as a required term."""
    # 'alice OR root' should return both ev1 and ev2 (neither contains literal word 'or')
    res = TimelineSearchEngine.filter_events(
        cql_test_events, FilterCriteria(keyword="alice OR root")
    )
    assert res.filtered_events == 2


def test_not_field_scoped_to_field_only(cql_test_events):
    """Reproduce F-16 defect 3: NOT host:db-01 ignores field and excludes ev2 because db-01 is in description."""
    # ev2 has source_host='web-01-backup' but mentions 'db-01' in description.
    # NOT host:db-01 must NOT exclude ev2!
    res = TimelineSearchEngine.filter_events(
        cql_test_events, FilterCriteria(keyword="NOT host:db-01")
    )
    # ev1 (web-01) and ev2 (web-01-backup) must match; ev3 (db-01) must be excluded.
    assert res.filtered_events == 2
    matched_hosts = {e.source_host for e in res.events}
    assert "web-01" in matched_hosts
    assert "web-01-backup" in matched_hosts
    assert "db-01" not in matched_hosts


def test_host_exact_match_vs_wildcard(cql_test_events):
    """Reproduce F-16 defect 4: host:web-01 must not match web-01-backup unless wildcard is explicit."""
    res_exact = TimelineSearchEngine.filter_events(
        cql_test_events, FilterCriteria(keyword="host:web-01")
    )
    assert res_exact.filtered_events == 1
    assert res_exact.events[0].source_host == "web-01"

    res_wildcard = TimelineSearchEngine.filter_events(
        cql_test_events, FilterCriteria(keyword="host:web-01*")
    )
    assert res_wildcard.filtered_events == 2


def test_before_date_inclusive_of_day(cql_test_events):
    """Reproduce F-16 defect 5: before:2026-10-12 drops events on that day."""
    # ev1 (10:00) and ev2 (14:30) are on 2026-10-12. before:2026-10-12 must include the whole day!
    res = TimelineSearchEngine.filter_events(
        cql_test_events, FilterCriteria(keyword="before:2026-10-12")
    )
    assert res.filtered_events == 2
    assert all("2026-10-12" in e.normalized_utc_iso for e in res.events)


def test_full_text_search_beyond_8192_chars(cql_test_events):
    """Reproduce F-16 defect 6: only first 8192 chars searched, missing payload at 9000."""
    res = TimelineSearchEngine.filter_events(
        cql_test_events, FilterCriteria(keyword="TARGET_PAYLOAD_AT_10K")
    )
    assert res.filtered_events == 1
    assert res.events[0].source_host == "db-01"


def test_redos_pattern_guarded_with_timeout():
    """Reproduce F-16 defect 7: ReDoS pattern (a+)+$ hangs or takes seconds."""
    ev = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="redos.log",
        line_number=1,
        raw_text="aaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00Z",
        source_host="srv",
    )
    start = time.perf_counter()
    _ = TimelineSearchEngine.filter_events(
        [ev], FilterCriteria(keyword="(a+)+$", use_regex=True)
    )
    elapsed = time.perf_counter() - start
    # Must fail safely / time out in under 1.0 second, not hang
    assert elapsed < 1.0


def test_adversarial_nested_parentheses_and_boolean_precedence(cql_test_events):
    """Adversarial check 1: Nested boolean logic with parentheses (user:root OR user:alice) AND NOT host:db*."""
    # (user:root OR user:alice) matches ev1 (root, web-01) and ev2 (alice, web-01-backup).
    # AND NOT host:web-01-backup excludes ev2.
    # Result must be exactly ev1.
    res = TimelineSearchEngine.filter_events(
        cql_test_events, FilterCriteria(keyword="(user:root OR user:alice) NOT host:web-01-backup")
    )
    assert res.filtered_events == 1
    assert res.events[0].username == "root"
    assert res.events[0].source_host == "web-01"


def test_adversarial_quoted_field_with_spaces_and_special_chars():
    """Adversarial check 2: Field with quoted spaces e.g. user:"service account" and escaped quotes."""
    ev = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="audit.log",
        line_number=1,
        raw_text='SQL query executed: SELECT "id" FROM users',
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00Z",
        source_host="db-cluster-01",
        username="service account",
    )
    # Search with user:"service account"
    res1 = TimelineSearchEngine.filter_events(
        [ev], FilterCriteria(keyword='user:"service account"')
    )
    assert res1.filtered_events == 1

    # Search with quoted phrase containing SQL
    res2 = TimelineSearchEngine.filter_events(
        [ev], FilterCriteria(keyword='"SELECT \\"id\\" FROM users"')
    )
    assert res2.filtered_events == 1


