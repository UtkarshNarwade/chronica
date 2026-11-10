"""Tests reproducing and verifying F-21:
1. README test counts synchronized with actual test suite results (no hardcoded numbers).
2. Synthetic generator supports realistic noise: jitter, drift, packet loss, duplicates, and out-of-order lines.
3. Benchmark evaluation reports error distribution (median, p95, max), not just a single-pass mean.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from src.evaluation.ground_truth import GroundTruthEvent, ScenarioGroundTruth
from src.evaluation.metrics import BenchmarkEvaluator, SkewEvaluationMetric
from src.timeline.clock_skew import ClockSkewEstimate
from src.timeline.schema import Event
from synthetic_data.generator import ScenarioGenerator


REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_reproduce_readme_test_counts_inconsistency():
    """README must reflect current test suite count and not have stale '104 passed' or '127 passed'."""
    readme_path = REPO_ROOT / "README.md"
    assert readme_path.exists(), "README.md must exist"
    readme_text = readme_path.read_text(encoding="utf-8")

    # Stale hardcoded counts from prior hackathon build
    assert "104 passed in" not in readme_text, "README.md contains stale '104 passed' summary"
    assert "pytest-127%20passed" not in readme_text, "README.md badge contains stale 127 passed count"


def test_reproduce_synthetic_generator_supports_jitter_drift_loss_duplicates(tmp_path: Path):
    """ScenarioGenerator must support generating evidence with jitter, drift, packet loss, duplicates, and out-of-order events."""
    generator = ScenarioGenerator(output_root=tmp_path)
    assert hasattr(generator, "inject_evidence_noise"), (
        "ScenarioGenerator must provide methods to inject jitter, drift, packet loss, duplicates, and out-of-order records"
    )

    # Test noise injection
    lines = [
        '10.0.0.50 - bob [12/Oct/2026:10:00:00 +0000] "POST /api/transfer HTTP/1.1" 200 120 "-" "AppClient/1.0" "req-tx-201"',
        '10.0.0.50 - bob [12/Oct/2026:10:01:00 +0000] "GET /api/balance HTTP/1.1" 200 85 "-" "AppClient/1.0" "req-tx-202"',
        '10.0.0.50 - bob [12/Oct/2026:10:02:00 +0000] "POST /api/audit HTTP/1.1" 200 95 "-" "AppClient/1.0" "req-tx-203"',
        '10.0.0.50 - bob [12/Oct/2026:10:03:00 +0000] "POST /api/logout HTTP/1.1" 200 45 "-" "AppClient/1.0" "req-tx-204"',
    ]
    noisy_lines, stats = generator.inject_evidence_noise(
        lines=lines,
        jitter_std_sec=0.25,
        drift_ppm=50.0,
        packet_loss_rate=0.25,
        duplicate_rate=0.25,
        out_of_order_prob=0.5,
        seed=42,
    )
    assert isinstance(noisy_lines, list)
    assert "jitter_applied" in stats
    assert "duplicates_added" in stats
    assert "lines_dropped" in stats


def test_reproduce_skew_metrics_reports_error_distribution():
    """BenchmarkEvaluator and SkewEvaluationMetric must compute and report error distribution (median, p95, max)."""
    metric = SkewEvaluationMetric(
        target_source="srv-01",
        known_ground_truth_offset_sec=10.0,
        estimated_offset_sec=9.8,
        absolute_estimation_error_sec=0.2,
        estimation_status="ESTIMATED",
    )
    # Must report error distribution fields
    assert hasattr(metric, "post_correction_median_abs_error_sec"), "Must report median error"
    assert hasattr(metric, "post_correction_p95_abs_error_sec"), "Must report p95 error"
    assert hasattr(metric, "post_correction_max_abs_error_sec"), "Must report max error"


def test_skew_metrics_calculates_percentiles_correctly():
    """BenchmarkEvaluator.evaluate_clock_skew must compute median, p95, and max on residuals."""
    gt_events = [
        GroundTruthEvent("gt1", 1, "2026-10-12T10:00:00.000000Z", "host-b", "event 1", "req-1"),
        GroundTruthEvent("gt2", 2, "2026-10-12T10:01:00.000000Z", "host-b", "event 2", "req-2"),
        GroundTruthEvent("gt3", 3, "2026-10-12T10:02:00.000000Z", "host-b", "event 3", "req-3"),
        GroundTruthEvent("gt4", 4, "2026-10-12T10:03:00.000000Z", "host-b", "event 4", "req-4"),
    ]
    gt = ScenarioGroundTruth(
        scenario_id="scen_eval_test",
        scenario_name="Eval Test",
        description="Eval Test",
        reference_source="ref",
        known_clock_offsets_sec={"host-b": 10.0},
        known_timezones={"host-b": "UTC"},
        expected_events=gt_events,
    )
    # Host B events with residual errors: 0.1s, 0.2s, 0.5s, 1.2s
    evs = [
        Event("e1", "inv1", "ev1", "file.log", 1, "event 1", "2026-10-12T10:00:10.100Z", normalized_utc_iso="2026-10-12T10:00:10.100000Z", corrected_utc_iso="2026-10-12T10:00:00.100000Z", source_host="host-b", request_id="req-1"),
        Event("e2", "inv1", "ev1", "file.log", 2, "event 2", "2026-10-12T10:01:10.200Z", normalized_utc_iso="2026-10-12T10:01:10.200000Z", corrected_utc_iso="2026-10-12T10:01:00.200000Z", source_host="host-b", request_id="req-2"),
        Event("e3", "inv1", "ev1", "file.log", 3, "event 3", "2026-10-12T10:02:10.500Z", normalized_utc_iso="2026-10-12T10:02:10.500000Z", corrected_utc_iso="2026-10-12T10:02:00.500000Z", source_host="host-b", request_id="req-3"),
        Event("e4", "inv1", "ev1", "file.log", 4, "event 4", "2026-10-12T10:03:11.200Z", normalized_utc_iso="2026-10-12T10:03:11.200000Z", corrected_utc_iso="2026-10-12T10:03:01.200000Z", source_host="host-b", request_id="req-4"),
    ]
    skew_est = {
        "host-b": ClockSkewEstimate(
            target_source="host-b",
            reference_source="ref",
            anchor_count=4,
            estimated_offset_sec=10.0,
            uncertainty_sec=0.5,
            status="ESTIMATED",
        )
    }

    metrics = BenchmarkEvaluator.evaluate_clock_skew(gt, skew_est, evs)
    b_metric = metrics["host-b"]
    assert b_metric.post_correction_median_abs_error_sec is not None
    assert b_metric.post_correction_max_abs_error_sec is not None
    assert b_metric.post_correction_p95_abs_error_sec is not None
    assert b_metric.post_correction_max_abs_error_sec == pytest.approx(1.2, abs=0.01)
    assert b_metric.post_correction_median_abs_error_sec == pytest.approx(0.35, abs=0.01)


def test_adversarial_noise_generator_edge_cases(tmp_path: Path):
    """Extreme noise parameters (100% loss, no timestamps, 100% duplicate) must not crash."""
    gen = ScenarioGenerator(output_root=tmp_path)

    # 1. 100% packet loss
    empty_res, stats = gen.inject_evidence_noise(["line 1", "line 2"], packet_loss_rate=1.0, seed=1)
    assert len(empty_res) == 0
    assert stats["lines_dropped"] == 2

    # 2. Lines without timestamps
    raw_lines = ["plain text error without date", "another unformatted message"]
    noisy_raw, stats_raw = gen.inject_evidence_noise(raw_lines, jitter_std_sec=5.0, drift_ppm=100.0, seed=1)
    assert len(noisy_raw) == 2
    assert noisy_raw == raw_lines  # Unchanged since no timestamp matched

    # 3. 100% duplicates
    dup_res, stats_dup = gen.inject_evidence_noise(["line 1", "line 2"], duplicate_rate=1.0, seed=1)
    assert len(dup_res) == 4
    assert stats_dup["duplicates_added"] == 2


def test_adversarial_skew_metrics_empty_errors_handles_gracefully():
    """Skew evaluation on events with no valid timestamps must produce None stats without ZeroDivisionError."""
    gt = ScenarioGroundTruth(
        scenario_id="scen_empty",
        scenario_name="Empty",
        description="Empty",
        reference_source="ref",
        known_clock_offsets_sec={"host-c": 5.0},
        known_timezones={"host-c": "UTC"},
        expected_events=[],
    )
    metric_res = BenchmarkEvaluator.evaluate_clock_skew(gt, {}, [])
    assert "host-c" in metric_res
    c_m = metric_res["host-c"]
    assert c_m.pre_correction_mean_abs_error_sec is None
    assert c_m.post_correction_median_abs_error_sec is None
    assert c_m.post_correction_p95_abs_error_sec is None
    assert c_m.post_correction_max_abs_error_sec is None

