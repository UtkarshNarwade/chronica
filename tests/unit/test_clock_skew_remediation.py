"""Tests reproducing and verifying F-15:
- Uncertainty must include network latency bound and sample-size penalty; never report ±0.
- Linear drift (Theil-Sen) must be applied to corrected timestamps when significant.
- Default reference source must be the source with the most anchors, not alphabetical first.
- Reported uncertainty must cover actual residuals in drifting scenarios (60 to 70s).
"""

from datetime import datetime
from src.timeline.clock_skew import AnchorPair, ClockSkewAnalyzer
from src.timeline.schema import Event


def test_two_identical_anchors_must_not_report_zero_uncertainty():
    """Reproduce F-15 defect 1: Two identical anchors produce MAD=0.0 (±0.0s uncertainty).
    
    A forensically defensible estimate must have a resolution floor / sample size penalty.
    """
    analyzer = ClockSkewAnalyzer(min_anchors_required=2)
    anchors = [
        AnchorPair(
            anchor_id="anc_1",
            target_event_id="tar_1",
            target_source="host_b",
            target_utc_iso="2026-10-12T10:00:05.000000Z",
            target_utc_epoch=1791799205.0,
            reference_event_id="ref_1",
            reference_source="host_a",
            reference_utc_iso="2026-10-12T10:00:00.000000Z",
            reference_utc_epoch=1791799200.0,
            anchor_type="REQUEST_ID",
            anchor_key="req-1",
            raw_offset_sec=5.0,
        ),
        AnchorPair(
            anchor_id="anc_2",
            target_event_id="tar_2",
            target_source="host_b",
            target_utc_iso="2026-10-12T10:05:05.000000Z",
            target_utc_epoch=1791799505.0,
            reference_event_id="ref_2",
            reference_source="host_a",
            reference_utc_iso="2026-10-12T10:05:00.000000Z",
            reference_utc_epoch=1791799500.0,
            anchor_type="REQUEST_ID",
            anchor_key="req-2",
            raw_offset_sec=5.0,
        ),
    ]

    estimate = analyzer.estimate_skew(anchors, target_source="host_b", reference_source="host_a")
    assert estimate.status == "ESTIMATED"
    # Raw MAD is 0.0, but defensible uncertainty must NOT be 0.0! Must have non-zero resolution/sample floor
    assert estimate.spread_mad_sec == 0.0
    assert estimate.uncertainty_sec is not None
    assert estimate.uncertainty_sec > 0.0, f"Uncertainty must not be 0.0 with only 2 anchors, got {estimate.uncertainty_sec}"


def test_linear_drift_applied_to_corrected_timestamps():
    """Reproduce F-15 defect 2: Theil-Sen drift is calculated but never applied in apply_corrections.
    
    Offsets drifting from 60s to 70s over 3000 seconds (50 min).
    """
    analyzer = ClockSkewAnalyzer(min_anchors_required=3)
    t0_ref = 1791799200.0  # 2026-10-12 10:00:00
    # Drift: +60s at t=0, +65s at t=1500s, +70s at t=3000s
    anchors = [
        AnchorPair(
            anchor_id="anc_1",
            target_event_id="t1",
            target_source="host_b",
            target_utc_iso="2026-10-12T10:01:00.000000Z",
            target_utc_epoch=t0_ref + 60.0,
            reference_event_id="r1",
            reference_source="host_a",
            reference_utc_iso="2026-10-12T10:00:00.000000Z",
            reference_utc_epoch=t0_ref,
            anchor_type="REQUEST_ID",
            anchor_key="req-1",
            raw_offset_sec=60.0,
        ),
        AnchorPair(
            anchor_id="anc_2",
            target_event_id="t2",
            target_source="host_b",
            target_utc_iso="2026-10-12T10:26:05.000000Z",
            target_utc_epoch=t0_ref + 1500.0 + 65.0,
            reference_event_id="r2",
            reference_source="host_a",
            reference_utc_iso="2026-10-12T10:25:00.000000Z",
            reference_utc_epoch=t0_ref + 1500.0,
            anchor_type="REQUEST_ID",
            anchor_key="req-2",
            raw_offset_sec=65.0,
        ),
        AnchorPair(
            anchor_id="anc_3",
            target_event_id="t3",
            target_source="host_b",
            target_utc_iso="2026-10-12T10:51:10.000000Z",
            target_utc_epoch=t0_ref + 3000.0 + 70.0,
            reference_event_id="r3",
            reference_source="host_a",
            reference_utc_iso="2026-10-12T10:50:00.000000Z",
            reference_utc_epoch=t0_ref + 3000.0,
            anchor_type="REQUEST_ID",
            anchor_key="req-3",
            raw_offset_sec=70.0,
        ),
    ]

    estimate = analyzer.estimate_skew(anchors, target_source="host_b", reference_source="host_a")
    assert estimate.status == "ESTIMATED"
    assert estimate.drift_rate_ppm is not None and abs(estimate.drift_rate_ppm) > 1000

    # Event at t=3000s on host_b (original normalized time is 10:51:10, real target time t0 + 3070s)
    event_at_end = Event(
        event_id="evt_end",
        investigation_id="inv1",
        evidence_id="ev1",
        original_filename="host_b.log",
        line_number=1,
        raw_text="Event at end of window",
        original_timestamp_str="2026-10-12 10:51:10",
        normalized_utc_iso="2026-10-12T10:51:10.000000Z",
        source_host="host_b",
        severity="INFO",
        category="SYSTEM",
    )

    corrected_events = analyzer.apply_corrections([event_at_end], {"host_b": estimate})
    corr = corrected_events[0]

    # Without drift correction, median offset 65.0s is applied -> 10:51:10 - 65s = 10:50:05 (5 seconds off!)
    # With drift correction, offset at t=3000s is 70.0s -> 10:51:10 - 70s = 10:50:00
    assert corr.corrected_utc_iso is not None
    dt_corr = datetime.fromisoformat(corr.corrected_utc_iso.replace("Z", "+00:00"))
    assert dt_corr.strftime("%H:%M:%S") == "10:50:00", (
        f"Expected drift-corrected time 10:50:00, got {dt_corr.strftime('%H:%M:%S')} "
        f"(constant median offset was incorrectly applied without drift)"
    )


def test_default_reference_source_is_source_with_most_anchors():
    """Reproduce F-15 defect 3: Default reference source must be the source with the most anchors, not alphabetical first."""
    import shutil
    import tempfile
    from pathlib import Path
    from src.pipeline import ForensicPipeline
    from src.storage.repository import InvestigationRepository

    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_ref_src_test_"))
    try:
        repo = InvestigationRepository(temp_dir)
        repo.create_investigation("inv_ref_test", "Ref Test", "Testing ref source")
        pipeline = ForensicPipeline(repo)

        # host_00_isolated: alphabetically first ('h...00'), but has 0 anchors
        # host_central: has shared request IDs with host_leaf1 and host_leaf2 (2 anchors)
        # host_leaf1: has 1 anchor with host_central
        # host_leaf2: has 1 anchor with host_central
        raw_lines_00 = b'{"timestamp": "2026-10-12T10:00:00Z", "message": "isolated", "host": "host_00_isolated"}\n'
        raw_lines_central = (
            b'{"timestamp": "2026-10-12T10:00:00Z", "request_id": "req-101", "host": "host_central"}\n'
            b'{"timestamp": "2026-10-12T10:05:00Z", "request_id": "req-102", "host": "host_central"}\n'
        )
        raw_lines_leaf1 = b'{"timestamp": "2026-10-12T10:00:05Z", "request_id": "req-101", "host": "host_leaf1"}\n'
        raw_lines_leaf2 = b'{"timestamp": "2026-10-12T10:05:05Z", "request_id": "req-102", "host": "host_leaf2"}\n'

        pipeline.ingest_evidence_bytes("inv_ref_test", "iso.json", raw_lines_00, source_host="host_00_isolated", explicit_format="custom_regex")
        pipeline.ingest_evidence_bytes("inv_ref_test", "central.json", raw_lines_central, source_host="host_central", explicit_format="custom_regex")
        pipeline.ingest_evidence_bytes("inv_ref_test", "leaf1.json", raw_lines_leaf1, source_host="host_leaf1", explicit_format="custom_regex")
        pipeline.ingest_evidence_bytes("inv_ref_test", "leaf2.json", raw_lines_leaf2, source_host="host_leaf2", explicit_format="custom_regex")

        results = pipeline.analyze_investigation("inv_ref_test")
        ref_used = results.get("reference_source")

        # Alphabetically first is 'host_00_isolated', but the source with the most anchors is 'host_central'
        assert ref_used == "host_central", f"Expected default reference 'host_central', got '{ref_used}'"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_adversarial_uncertainty_covers_residuals_in_drifting_scenario():
    """Adversarial check 1: Reported uncertainty must cover actual residuals in drifting scenario (60 to 70s)."""
    analyzer = ClockSkewAnalyzer(min_anchors_required=3)
    t0_ref = 1791799200.0
    anchors = [
        AnchorPair("a1", "t1", "h_b", "ts1", t0_ref + 60.0, "r1", "h_a", "rs1", t0_ref, "REQ", "k1", 60.0),
        AnchorPair("a2", "t2", "h_b", "ts2", t0_ref + 1500.0 + 65.0, "r2", "h_a", "rs2", t0_ref + 1500.0, "REQ", "k2", 65.0),
        AnchorPair("a3", "t3", "h_b", "ts3", t0_ref + 3000.0 + 70.0, "r3", "h_a", "rs3", t0_ref + 3000.0, "REQ", "k3", 70.0),
    ]
    est = analyzer.estimate_skew(anchors, target_source="h_b", reference_source="h_a")
    assert est.drift_applied is True
    assert est.uncertainty_sec is not None
    # Model residuals after detrending are 0.0s, and uncertainty is at least 0.5s floor + sample penalty
    residuals = [
        abs(a.raw_offset_sec - (est.estimated_offset_sec + (est.drift_rate_ppm / 1_000_000.0) * (a.reference_utc_epoch - est.drift_base_epoch)))
        for a in anchors
    ]
    max_residual = max(residuals)
    assert est.uncertainty_sec >= max_residual, f"Uncertainty {est.uncertainty_sec} must cover actual max residual {max_residual}"


def test_adversarial_insignificant_drift_ignored_and_tz_misconfiguration_flagged():
    """Adversarial check 2: Insignificant drift (<10 ppm) is ignored, and whole-hour offsets flag timezone misconfiguration."""
    analyzer = ClockSkewAnalyzer(min_anchors_required=3)
    t0_ref = 1791799200.0
    # +3600.00s offset (exactly 1 hour) with 1 ppm drift (insignificant)
    anchors = [
        AnchorPair("a1", "t1", "h_b", "ts1", t0_ref + 3600.00, "r1", "h_a", "rs1", t0_ref, "REQ", "k1", 3600.00),
        AnchorPair("a2", "t2", "h_b", "ts2", t0_ref + 1000.0 + 3600.001, "r2", "h_a", "rs2", t0_ref + 1000.0, "REQ", "k2", 3600.001),
        AnchorPair("a3", "t3", "h_b", "ts3", t0_ref + 2000.0 + 3600.002, "r3", "h_a", "rs3", t0_ref + 2000.0, "REQ", "k3", 3600.002),
    ]
    est = analyzer.estimate_skew(anchors, target_source="h_b", reference_source="h_a")
    assert est.drift_applied is False
    assert "insignificant" in est.explanation.lower() or "ignored" in est.explanation.lower()
    assert est.probable_tz_misconfiguration is True
    assert "timezone misconfiguration" in est.explanation.lower()


