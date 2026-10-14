"""Quantitative benchmark metrics evaluating Chronica against synthetic ground truth."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from src.diagnostics.gap_analysis import ParsingCoverageStats
from src.evaluation.ground_truth import ScenarioGroundTruth
from src.timeline.clock_skew import ClockSkewEstimate
from src.timeline.schema import Event


@dataclass
class SkewEvaluationMetric:
    """Quantitative evaluation of clock skew estimation accuracy."""
    target_source: str
    known_ground_truth_offset_sec: float
    estimated_offset_sec: Optional[float]
    absolute_estimation_error_sec: Optional[float]
    estimation_status: str
    pre_correction_mean_abs_error_sec: Optional[float] = None
    post_correction_mean_abs_error_sec: Optional[float] = None


@dataclass
class OrderingEvaluationMetric:
    """Pairwise ordering and ranking accuracy metrics."""
    total_comparable_pairs: int
    concordant_pairs: int
    inverted_pairs: int
    tied_pairs: int
    pairwise_ordering_accuracy_percent: float
    kendall_tau: float
    excluded_records_count: int
    explanation_of_exclusions: str


@dataclass
class CompleteEvaluationReport:
    """Comprehensive benchmark evaluation summarizing all 4 measurable axes."""
    scenario_id: str
    scenario_name: str
    evaluation_time_utc: str
    coverage_stats: ParsingCoverageStats
    skew_metrics: Dict[str, SkewEvaluationMetric]
    ordering_metric_normalized: OrderingEvaluationMetric
    ordering_metric_corrected: Optional[OrderingEvaluationMetric]
    overall_findings: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "evaluation_time_utc": self.evaluation_time_utc,
            "coverage_stats": self.coverage_stats.to_dict(),
            "skew_metrics": {k: asdict(v) for k, v in self.skew_metrics.items()},
            "ordering_metric_normalized": asdict(self.ordering_metric_normalized),
            "ordering_metric_corrected": asdict(self.ordering_metric_corrected) if self.ordering_metric_corrected else None,
            "overall_findings": self.overall_findings,
        }


class BenchmarkEvaluator:
    """Evaluates Chronica's output against scenario ground truth."""

    @staticmethod
    def evaluate_clock_skew(
        ground_truth: ScenarioGroundTruth,
        skew_estimates: Dict[str, ClockSkewEstimate],
        events: List[Event],
    ) -> Dict[str, SkewEvaluationMetric]:
        """Compute clock-skew offset estimation errors and pre/post correction timing residuals."""
        results: Dict[str, SkewEvaluationMetric] = {}

        for host, true_offset in ground_truth.known_clock_offsets_sec.items():
            est = skew_estimates.get(host)
            est_offset = est.estimated_offset_sec if est and est.status == "ESTIMATED" else None
            abs_err = round(abs(est_offset - true_offset), 4) if est_offset is not None else None
            status = est.status if est else "NOT_ANALYZED"

            # Calculate pre- and post-correction timing error for events from this host
            host_events = [e for e in events if (e.source_host or e.original_filename) == host and e.normalized_utc_iso]
            
            # Map events to ground truth
            pre_errors: List[float] = []
            post_errors: List[float] = []

            for ev in host_events:
                # Find matching ground truth event by request_id or raw text snippet
                matching_gt = None
                for gt in ground_truth.expected_events:
                    if ev.request_id and gt.expected_request_id and ev.request_id == gt.expected_request_id:
                        matching_gt = gt
                        break
                    elif gt.expected_raw_pattern in ev.raw_text:
                        matching_gt = gt
                        break

                if matching_gt and matching_gt.true_utc_iso:
                    true_dt = datetime.fromisoformat(matching_gt.true_utc_iso.replace("Z", "+00:00")).timestamp()
                    norm_dt = datetime.fromisoformat(ev.normalized_utc_iso.replace("Z", "+00:00")).timestamp()
                    pre_errors.append(abs(norm_dt - true_dt))

                    if ev.corrected_utc_iso:
                        corr_dt = datetime.fromisoformat(ev.corrected_utc_iso.replace("Z", "+00:00")).timestamp()
                        post_errors.append(abs(corr_dt - true_dt))

            pre_mean = round(sum(pre_errors) / len(pre_errors), 3) if pre_errors else None
            post_mean = round(sum(post_errors) / len(post_errors), 3) if post_errors else None

            results[host] = SkewEvaluationMetric(
                target_source=host,
                known_ground_truth_offset_sec=true_offset,
                estimated_offset_sec=est_offset,
                absolute_estimation_error_sec=abs_err,
                estimation_status=status,
                pre_correction_mean_abs_error_sec=pre_mean,
                post_correction_mean_abs_error_sec=post_mean,
            )

        return results

    @staticmethod
    def evaluate_event_ordering(
        reconstructed_events: List[Event],
        ground_truth: ScenarioGroundTruth,
        use_corrected_timestamps: bool = False,
    ) -> OrderingEvaluationMetric:
        """Calculate pairwise concordance and Kendall's tau against ground-truth order."""
        # Align reconstructed events with ground truth expected events
        aligned_pairs: List[Tuple[int, float]] = []  # (gt_expected_order, reconstructed_timestamp_epoch)
        excluded_count = 0

        for gt_ev in ground_truth.expected_events:
            # Exclude deliberate anomalies that lack a valid ground truth timestamp
            if gt_ev.is_anomaly and gt_ev.anomaly_type in ("MALFORMED", "INVALID_TS"):
                excluded_count += 1
                continue

            matched_ev = None
            for rev in reconstructed_events:
                if rev.request_id and gt_ev.expected_request_id and rev.request_id == gt_ev.expected_request_id:
                    matched_ev = rev
                    break
                elif gt_ev.expected_raw_pattern in rev.raw_text:
                    matched_ev = rev
                    break

            if matched_ev:
                ts_str = (
                    matched_ev.corrected_utc_iso if use_corrected_timestamps else matched_ev.normalized_utc_iso
                ) or matched_ev.normalized_utc_iso

                if ts_str:
                    try:
                        epoch = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
                        aligned_pairs.append((gt_ev.expected_order_index, epoch))
                    except Exception:
                        excluded_count += 1
                else:
                    excluded_count += 1
            else:
                excluded_count += 1

        n = len(aligned_pairs)
        if n < 2:
            return OrderingEvaluationMetric(
                total_comparable_pairs=0,
                concordant_pairs=0,
                inverted_pairs=0,
                tied_pairs=0,
                pairwise_ordering_accuracy_percent=100.0,
                kendall_tau=1.0,
                excluded_records_count=excluded_count,
                explanation_of_exclusions="Fewer than 2 comparable events found.",
            )

        concordant = 0
        inverted = 0
        tied = 0
        total_pairs = 0

        for i in range(n):
            for j in range(i + 1, n):
                gt_i, rec_i = aligned_pairs[i]
                gt_j, rec_j = aligned_pairs[j]

                # Ensure gt_i < gt_j
                if gt_i > gt_j:
                    gt_i, gt_j = gt_j, gt_i
                    rec_i, rec_j = rec_j, rec_i

                total_pairs += 1
                if rec_i < rec_j:
                    concordant += 1
                elif rec_i > rec_j:
                    inverted += 1
                else:
                    tied += 1

        accuracy = round((concordant / total_pairs) * 100.0, 2) if total_pairs > 0 else 100.0
        # Kendall's tau = (concordant - inverted) / sqrt((total)*(total - tied))
        denom = math.sqrt(total_pairs * (total_pairs - tied)) if (total_pairs - tied) > 0 else total_pairs
        tau = round((concordant - inverted) / denom, 3) if denom > 0 else 1.0

        return OrderingEvaluationMetric(
            total_comparable_pairs=total_pairs,
            concordant_pairs=concordant,
            inverted_pairs=inverted,
            tied_pairs=tied,
            pairwise_ordering_accuracy_percent=accuracy,
            kendall_tau=tau,
            excluded_records_count=excluded_count,
            explanation_of_exclusions=(
                f"{excluded_count} record(s) excluded from pairwise evaluation: "
                "deliberately corrupted lines, unparseable timestamps, or events lacking ground-truth temporal sequence."
            ),
        )
