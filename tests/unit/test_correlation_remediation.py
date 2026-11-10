"""Tests reproducing and verifying F-17:
- Neutral wording: 'shared identity across sources' unless an ordered, time-windowed hop pattern is satisfied.
- Window parameter: same IP or user on two sources outside the window (e.g. a week apart) must NOT be labelled lateral movement.
- Corrected time must be used instead of uncorrected normalized time.
"""

from src.timeline.correlation import EventCorrelator
from src.timeline.schema import Event


def test_same_ip_on_two_sources_a_week_apart_is_not_lateral_movement():
    """Reproduce F-17 defect: Any IP on >=2 sources is unconditionally labelled 'LATERAL_IP' and 'lateral movement'."""
    ev1 = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="srv1.log",
        line_number=1,
        raw_text="Login from 192.168.1.50 on srv1",
        original_timestamp_str="2026-10-01T10:00:00Z",
        normalized_utc_iso="2026-10-01T10:00:00Z",
        source_host="srv1",
        src_ip="192.168.1.50",
    )
    # Event 2 is 7 days later on srv2
    ev2 = Event.create(
        investigation_id="inv1",
        evidence_id="ev2",
        original_filename="srv2.log",
        line_number=1,
        raw_text="Login from 192.168.1.50 on srv2",
        original_timestamp_str="2026-10-08T10:00:00Z",
        normalized_utc_iso="2026-10-08T10:00:00Z",
        source_host="srv2",
        src_ip="192.168.1.50",
    )

    correlator = EventCorrelator()
    clusters = correlator.correlate([ev1, ev2])

    ip_clusters = [c for c in clusters if c.common_value == "192.168.1.50"]
    assert len(ip_clusters) == 1
    cluster = ip_clusters[0]

    # Must NOT claim lateral movement for events 7 days apart!
    assert "lateral movement" not in cluster.notes.lower(), (
        f"Expected neutral shared identity wording, got: {cluster.notes}"
    )
    assert cluster.cluster_type != "LATERAL_IP", (
        f"Cluster type should be SHARED_IP or neutral, got {cluster.cluster_type}"
    )
    assert "shared" in cluster.notes.lower()


def test_adversarial_ordered_hop_within_window_classified_as_lateral_movement():
    """Adversarial check 1: Ordered hop between distinct sources within 1 hour is classified as lateral movement."""
    ev1 = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="ws1.log",
        line_number=1,
        raw_text="User admin logon on ws1",
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00Z",
        source_host="workstation-01",
        username="admin",
    )
    # 15 minutes later, admin logs onto domain-controller
    ev2 = Event.create(
        investigation_id="inv1",
        evidence_id="ev2",
        original_filename="dc.log",
        line_number=1,
        raw_text="User admin logon on dc",
        original_timestamp_str="2026-10-12T10:15:00Z",
        normalized_utc_iso="2026-10-12T10:15:00Z",
        source_host="domain-controller",
        username="admin",
    )

    correlator = EventCorrelator(lateral_movement_window_sec=3600.0)
    clusters = correlator.correlate([ev1, ev2])

    user_clusters = [c for c in clusters if c.common_value == "admin"]
    assert len(user_clusters) == 1
    cluster = user_clusters[0]

    assert cluster.cluster_type == "LATERAL_MOVEMENT_USER"
    assert "lateral movement" in cluster.notes.lower()
    assert "workstation-01 -> domain-controller" in cluster.notes


def test_adversarial_corrected_time_used_for_window_evaluation():
    """Adversarial check 2: Corrected time brings skewed events into window (proving clock skew impact)."""
    # Without skew correction, normalized times are 2 hours apart (outside 1-hour window)
    # With skew correction, corrected times are 5 minutes apart (inside 1-hour window)
    ev1 = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="srv1.log",
        line_number=1,
        raw_text="Login bob on srv1",
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00Z",
        corrected_utc_iso="2026-10-12T10:00:00Z",
        source_host="srv1",
        username="bob",
    )
    ev2 = Event.create(
        investigation_id="inv1",
        evidence_id="ev2",
        original_filename="srv2.log",
        line_number=1,
        raw_text="Login bob on srv2",
        original_timestamp_str="2026-10-12T12:05:00Z",
        normalized_utc_iso="2026-10-12T12:05:00Z",  # 2 hours 5 min later uncorrected
        corrected_utc_iso="2026-10-12T10:05:00Z",   # 5 min later after -7200s skew correction
        source_host="srv2",
        username="bob",
    )

    correlator = EventCorrelator(lateral_movement_window_sec=3600.0)
    clusters = correlator.correlate([ev1, ev2])

    user_clusters = [c for c in clusters if c.common_value == "bob"]
    assert len(user_clusters) == 1
    cluster = user_clusters[0]

    # Because corrected time was prioritized, the 5-minute delta is within the 1-hour window
    assert cluster.cluster_type == "LATERAL_MOVEMENT_USER"
    assert "srv1 -> srv2" in cluster.notes

