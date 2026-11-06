"""Automated quantitative benchmark runner for Chronica.

Evaluates ground-truth scenarios (Scenario 1 Baseline, Scenario 2 Clock Skew,
Scenario 3 Degraded Evidence) and computes parsing coverage, clock-skew offsets,
event ordering accuracy (Kendall's tau), and diagnostic anomaly categorization.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from src.evaluation.ground_truth import ScenarioGroundTruth
from src.evaluation.metrics import BenchmarkEvaluator, CompleteEvaluationReport
from src.pipeline import ForensicPipeline
from src.storage.repository import InvestigationRepository
from synthetic_data.generator import ScenarioGenerator


def run_evaluation(
    data_dir: Optional[Path | str] = None,
    synthetic_dir: Optional[Path | str] = None,
    verbose: bool = True,
) -> List[CompleteEvaluationReport]:
    """Execute quantitative benchmark evaluation across all synthetic scenarios.

    Args:
        data_dir: Directory where benchmark results JSON will be written.
        synthetic_dir: Directory where synthetic scenario files reside or are generated.
        verbose: Whether to print progress to stdout.

    Returns:
        List of CompleteEvaluationReport objects, one per evaluated scenario.
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    synth_path = Path(synthetic_dir) if synthetic_dir else repo_root / "synthetic_data"
    out_path = Path(data_dir) if data_dir else repo_root / "data"

    if verbose:
        print("\n" + "=" * 70)
        print("AIORI-3 PS-013: Chronica Benchmark Evaluation Suite")
        print("=" * 70)

    # 1. Ensure scenarios exist
    generator = ScenarioGenerator(output_root=synth_path)
    scenarios_meta = generator.generate_all()

    # Create temporary evaluation workspace to prevent cross-case contamination
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_eval_"))
    repo = InvestigationRepository(data_root=temp_dir)
    pipeline = ForensicPipeline(repository=repo)

    benchmark_results: Dict[str, Any] = {}
    reports: List[CompleteEvaluationReport] = []

    try:
        for scen_id, (scen_dir, gt_file) in scenarios_meta.items():
            if verbose:
                print(f"\n---> Evaluating {scen_id.upper()} from: {scen_dir.name}")
            gt = ScenarioGroundTruth.load_from_file(gt_file)
            if verbose:
                print(f"     Title: {gt.scenario_name}")

            # Create test investigation
            inv_meta = repo.create_investigation(
                investigation_id=f"eval_{scen_id}",
                title=gt.scenario_name,
                description=gt.description,
                assigned_timezone=gt.known_timezones.get(gt.reference_source, "UTC"),
            )

            # Ingest all evidence files in scenario folder
            for ev_file in sorted(scen_dir.iterdir()):
                if ev_file.is_file() and not ev_file.name.endswith(".json"):
                    data = ev_file.read_bytes()
                    file_tz = gt.known_timezones.get(ev_file.name, "UTC")
                    pipeline.ingest_evidence_bytes(
                        investigation_id=inv_meta.investigation_id,
                        filename=ev_file.name,
                        data=data,
                        assigned_timezone=file_tz,
                    )

            # Run pipeline analysis
            analysis = pipeline.analyze_investigation(
                investigation_id=inv_meta.investigation_id,
                reference_source=gt.reference_source,
                clock_skew_enabled=True,
            )

            # Quantitative evaluation
            coverage_stats = analysis["coverage_stats"]
            skew_metrics = BenchmarkEvaluator.evaluate_clock_skew(
                ground_truth=gt,
                skew_estimates=analysis["skew_estimates"],
                events=analysis["events"],
            )
            ordering_norm = BenchmarkEvaluator.evaluate_event_ordering(
                reconstructed_events=analysis["events"],
                ground_truth=gt,
                use_corrected_timestamps=False,
            )
            ordering_corr = BenchmarkEvaluator.evaluate_event_ordering(
                reconstructed_events=analysis["events"],
                ground_truth=gt,
                use_corrected_timestamps=True,
            )

            if verbose:
                print(f"     [A] Parsing Coverage:")
                print(f"         Total records encountered: {coverage_stats.total_records_encountered}")
                print(f"         Successfully parsed:       {coverage_stats.successfully_parsed_records} ({coverage_stats.parsing_success_rate}%)")
                print(f"         Failed / Malformed:        {coverage_stats.failed_records} ({coverage_stats.parsing_failure_rate}%)")
                print(f"         Usable timestamps:         {coverage_stats.records_with_usable_timestamps} ({coverage_stats.timestamp_usability_rate}%)")

                print(f"     [B] Clock-Skew Analysis:")
                for host, sm in skew_metrics.items():
                    print(f"         Host '{host}':")
                    print(f"           True Offset:      {sm.known_ground_truth_offset_sec:+.2f}s")
                    print(f"           Estimated Offset: {sm.estimated_offset_sec if sm.estimated_offset_sec is not None else 'N/A'}")
                    print(f"           Abs Error:        {sm.absolute_estimation_error_sec if sm.absolute_estimation_error_sec is not None else 'N/A'}s")
                    print(f"           Status:           {sm.estimation_status}")
                    if sm.pre_correction_mean_abs_error_sec is not None:
                        print(f"           Pre-Correction Timing Residual:  {sm.pre_correction_mean_abs_error_sec:.2f}s")
                        print(f"           Post-Correction Timing Residual: {sm.post_correction_mean_abs_error_sec:.2f}s")

                print(f"     [C] Event Ordering Concordance:")
                print(f"         Normalized (Uncorrected) Order Accuracy: {ordering_norm.pairwise_ordering_accuracy_percent}% (Kendall's Tau: {ordering_norm.kendall_tau})")
                print(f"         Corrected Order Accuracy:                {ordering_corr.pairwise_ordering_accuracy_percent}% (Kendall's Tau: {ordering_corr.kendall_tau})")

                print(f"     [D] Diagnostics Detected: {len(analysis['diagnostics'])}")

            diag_counts: Dict[str, int] = {}
            for d in analysis["diagnostics"]:
                diag_counts[d.category.value] = diag_counts.get(d.category.value, 0) + 1
            if verbose:
                for cat, count in diag_counts.items():
                    print(f"         - {cat}: {count}")

            benchmark_results[scen_id] = {
                "scenario_name": gt.scenario_name,
                "coverage": coverage_stats.to_dict(),
                "skew_metrics": {k: sm.__dict__ for k, sm in skew_metrics.items()},
                "ordering_normalized": ordering_norm.__dict__,
                "ordering_corrected": ordering_corr.__dict__,
                "diagnostics_count": len(analysis["diagnostics"]),
                "diagnostics_breakdown": diag_counts,
            }

            findings = [
                f"Parsing success rate: {coverage_stats.parsing_success_rate}%",
                f"Diagnostics flagged: {len(analysis['diagnostics'])}",
            ]
            for cat, count in diag_counts.items():
                findings.append(f"{cat}: {count}")

            rep = CompleteEvaluationReport(
                scenario_id=scen_id,
                scenario_name=gt.scenario_name,
                evaluation_time_utc=datetime.now(timezone.utc).isoformat(),
                coverage_stats=coverage_stats,
                skew_metrics=skew_metrics,
                ordering_metric_normalized=ordering_norm,
                ordering_metric_corrected=ordering_corr,
                overall_findings=findings,
            )
            reports.append(rep)

        out_file = out_path / "benchmark_evaluation_results.json"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(benchmark_results, f, indent=2)

        if verbose:
            print("\n" + "=" * 70)
            print(f"Benchmark run complete! Results written to: {out_file}")
            print("=" * 70 + "\n")

        return reports

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def run_benchmark() -> List[CompleteEvaluationReport]:
    """CLI entrypoint alias for run_evaluation()."""
    return run_evaluation()

