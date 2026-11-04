"""Unit tests for anchor correlation, clock skew estimation, and timeline correction."""

import pytest

from src.timeline.clock_skew import AnchorPair, ClockSkewAnalyzer, ClockSkewEstimate
from src.timeline.schema import CorrectionStatus, Event


def test_anchor_discovery():
    analyzer = ClockSkewAnalyzer()
    ev1 = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="gateway.log",
        line_number=1,
        raw_text="GET /api",
        original_timestamp_str="2026-10-12T10:00:00Z",
        normalized_utc_iso="2026-10-12T10:00:00.000000Z",
        source_host="gateway",
        request_id="req-alpha",
    )
    ev2 = Event.create(
        investigation_id="inv1",
        evidence_id="ev2",
        original_filename="db.log",
        line_number=1,
        raw_text="SQL query",
        original_timestamp_str="2026-10-12T10:03:00Z",
        normalized_utc_iso="2026-10-12T10:03:00.000000Z",
        source_host="database",
        request_id="req-alpha",
    )

    anchors = analyzer.discover_anchors([ev1, ev2], reference_source="gateway", target_source="database")
    assert len(anchors) == 1
    assert anchors[0].anchor_key == "req-alpha"
    # Target (10:03:00) - Reference (10:00:00) = +180s
    assert anchors[0].raw_offset_sec == 180.0


def test_robust_median_offset_estimation():
    analyzer = ClockSkewAnalyzer(min_anchors_required=3)
    anchors = [
        AnchorPair("a1", "t1", "db", "ts1", 1000.0, "r1", "gw", "rs1", 820.0, "REQ", "k1", 180.0),
        AnchorPair("a2", "t2", "db", "ts2", 1060.0, "r2", "gw", "rs2", 880.0, "REQ", "k2", 180.0),
        AnchorPair("a3", "t3", "db", "ts3", 1120.0, "r3", "gw", "rs3", 940.0, "REQ", "k3", 180.0),
    ]

    est = analyzer.estimate_skew(anchors, target_source="db", reference_source="gw")
    assert est.status == "ESTIMATED"
    assert est.estimated_offset_sec == 180.0
    assert est.spread_mad_sec == 0.0


def test_insufficient_anchors_inconclusive():
    analyzer = ClockSkewAnalyzer(min_anchors_required=2)
    # Only 1 anchor available
    anchors = [
        AnchorPair("a1", "t1", "sensor", "ts1", 1000.0, "r1", "gw", "rs1", 950.0, "REQ", "k1", 50.0),
    ]

    est = analyzer.estimate_skew(anchors, target_source="sensor", reference_source="gw")
    assert est.status == "INCONCLUSIVE_INSUFFICIENT_ANCHORS"
    assert est.estimated_offset_sec is None


def test_conflicting_anchors_inconclusive():
    analyzer = ClockSkewAnalyzer(min_anchors_required=2, max_conflict_spread_sec=10.0)
    # Offsets conflict by 60s (> 10s threshold)
    anchors = [
        AnchorPair("a1", "t1", "db", "ts1", 1000.0, "r1", "gw", "rs1", 950.0, "REQ", "k1", 50.0),
        AnchorPair("a2", "t2", "db", "ts2", 1110.0, "r2", "gw", "rs2", 1000.0, "REQ", "k2", 110.0),
    ]

    est = analyzer.estimate_skew(anchors, target_source="db", reference_source="gw")
    assert est.status == "INCONCLUSIVE_CONFLICTING_ANCHORS"
    assert est.estimated_offset_sec is None


def test_clock_correction_application_preserves_originals():
    analyzer = ClockSkewAnalyzer()
    ev = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="db.log",
        line_number=1,
        raw_text="SQL query",
        original_timestamp_str="2026-10-12T10:03:00Z",
        normalized_utc_iso="2026-10-12T10:03:00.000000Z",
        source_host="db",
    )
    est = ClockSkewEstimate(
        target_source="db",
        reference_source="gw",
        anchor_count=3,
        estimated_offset_sec=180.0,
        spread_mad_sec=0.1,
        status="ESTIMATED",
    )

    corrected = analyzer.apply_corrections([ev], estimates={"db": est}, enabled=True)
    assert len(corrected) == 1
    c_ev = corrected[0]

    # Original & normalized timestamps must remain intact!
    assert c_ev.original_timestamp_str == "2026-10-12T10:03:00Z"
    assert c_ev.normalized_utc_iso == "2026-10-12T10:03:00.000000Z"
    # Corrected timestamp has 180s subtracted -> 10:00:00
    assert c_ev.corrected_utc_iso.startswith("2026-10-12T10:00:00")
    assert c_ev.correction_status == CorrectionStatus.CORRECTED.value
    assert c_ev.estimated_clock_offset_sec == 180.0


def test_disabled_correction_toggle():
    analyzer = ClockSkewAnalyzer()
    ev = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="db.log",
        line_number=1,
        raw_text="SQL query",
        original_timestamp_str="2026-10-12T10:03:00Z",
        normalized_utc_iso="2026-10-12T10:03:00.000000Z",
        source_host="db",
    )
    est = ClockSkewEstimate(
        target_source="db",
        reference_source="gw",
        anchor_count=3,
        estimated_offset_sec=180.0,
        status="ESTIMATED",
    )

    corrected = analyzer.apply_corrections([ev], estimates={"db": est}, enabled=False)
    assert corrected[0].correction_status == CorrectionStatus.CORRECTION_DISABLED.value
    assert corrected[0].corrected_utc_iso == ev.normalized_utc_iso


def test_latency_guard_sub_two_seconds():
    # Latency guard (default 2.0s) should prevent false shift on 1.12s latency
    analyzer = ClockSkewAnalyzer(min_anchors_required=2, latency_tolerance_sec=2.0)
    anchors = [
        AnchorPair("a1", "t1", "srv", "ts1", 1001.12, "r1", "gw", "rs1", 1000.0, "REQ", "k1", 1.12),
        AnchorPair("a2", "t2", "srv", "ts2", 1061.12, "r2", "gw", "rs2", 1060.0, "REQ", "k2", 1.12),
    ]

    est = analyzer.estimate_skew(anchors, target_source="srv", reference_source="gw")
    assert est.status == "ESTIMATED"
    assert est.within_latency_tolerance is True
    assert est.estimated_offset_sec == 1.12

    ev = Event.create(
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="srv.log",
        line_number=1,
        raw_text="srv event",
        original_timestamp_str="2026-10-12T10:00:01.120Z",
        normalized_utc_iso="2026-10-12T10:00:01.120000Z",
        source_host="srv",
    )
    corrected = analyzer.apply_corrections([ev], estimates={"srv": est}, enabled=True)
    # Causal guard keeps event uncorrected
    assert corrected[0].correction_status == CorrectionStatus.UNCORRECTED.value
    assert corrected[0].corrected_utc_iso == ev.normalized_utc_iso
    assert corrected[0].estimated_clock_offset_sec == 0.0

    # But 180.0s skew is well beyond 2.0s and MUST be corrected
    anchors_skewed = [
        AnchorPair("a1", "t1", "db", "ts1", 1180.0, "r1", "gw", "rs1", 1000.0, "REQ", "k1", 180.0),
        AnchorPair("a2", "t2", "db", "ts2", 1240.0, "r2", "gw", "rs2", 1060.0, "REQ", "k2", 180.0),
    ]
    est_skewed = analyzer.estimate_skew(anchors_skewed, target_source="db", reference_source="gw")
    assert est_skewed.status == "ESTIMATED"
    assert est_skewed.within_latency_tolerance is False
    assert est_skewed.estimated_offset_sec == 180.0

    ev_skewed = Event.create(
        investigation_id="inv1",
        evidence_id="ev2",
        original_filename="db.log",
        line_number=1,
        raw_text="db event",
        original_timestamp_str="2026-10-12T10:03:00Z",
        normalized_utc_iso="2026-10-12T10:03:00.000000Z",
        source_host="db",
    )
    corrected_skewed = analyzer.apply_corrections([ev_skewed], estimates={"db": est_skewed}, enabled=True)
    assert corrected_skewed[0].correction_status == CorrectionStatus.CORRECTED.value
    assert corrected_skewed[0].corrected_utc_iso.startswith("2026-10-12T10:00:00")
    assert corrected_skewed[0].estimated_clock_offset_sec == 180.0

