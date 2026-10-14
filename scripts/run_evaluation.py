"""Automated benchmark evaluation across all three synthetic scenarios."""

import json
from pathlib import Path
import shutil
import sys
import tempfile

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from src.evaluation.ground_truth import ScenarioGroundTruth
from src.evaluation.metrics import BenchmarkEvaluator
from src.pipeline import ForensicPipeline
from src.storage.repository import InvestigationRepository
from synthetic_data.generator import ScenarioGenerator


def run_benchmark() -> None:
    print("\n" + "=" * 70)
    print("AIORI-3 PS-013: Chronica Benchmark Evaluation Suite")
    print("=" * 70)

    # 1. Ensure scenarios exist
    data_dir = repo_root / "synthetic_data"
    generator = ScenarioGenerator(output_root=data_dir)
    scenarios_meta = generator.generate_all()

    # Create temporary evaluation workspace
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_eval_"))
    repo = InvestigationRepository(data_root=temp_dir)
    pipeline = ForensicPipeline(repository=repo)

    benchmark_results = {}

    try:
        for scen_id, (scen_dir, gt_file) in scenarios_meta.items():
            print(f"\n---> Evaluating {scen_id.upper()} from: {scen_dir.name}")
            gt = ScenarioGroundTruth.load_from_file(gt_file)
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
                if ev_file.is_file():
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
            diag_counts = {}
            for d in analysis["diagnostics"]:
                diag_counts[d.category.value] = diag_counts.get(d.category.value, 0) + 1
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

        out_file = repo_root / "data" / "benchmark_evaluation_results.json"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(benchmark_results, f, indent=2)

        print("\n" + "=" * 70)
        print(f"Benchmark run complete! Results written to: {out_file}")
        print("=" * 70 + "\n")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_benchmark()
