"""End-to-end tests executing the complete Chronica pipeline on all 3 synthetic scenarios."""

from pathlib import Path
import pytest

from src.evaluation.ground_truth import ScenarioGroundTruth
from src.evaluation.metrics import BenchmarkEvaluator
from src.pipeline import ForensicPipeline
from src.reporting.csv_export import export_timeline_csv
from src.reporting.json_export import export_investigation_json
from src.reporting.markdown_export import export_markdown_report
from src.reporting.pdf_export import export_pdf_report
from src.storage.repository import InvestigationRepository
from synthetic_data.generator import ScenarioGenerator


@pytest.fixture(scope="module")
def generated_scenarios(tmp_path_factory):
    root = tmp_path_factory.mktemp("e2e_scenarios")
    generator = ScenarioGenerator(output_root=root)
    scenarios_meta = generator.generate_all()
    return root, scenarios_meta


def test_scenario_1_e2e(generated_scenarios, tmp_path: Path):
    root, scenarios_meta = generated_scenarios
    scen_dir, gt_file = scenarios_meta["scenario_1"]
    gt = ScenarioGroundTruth.load_from_file(gt_file)

    repo = InvestigationRepository(data_root=tmp_path)
    pipeline = ForensicPipeline(repository=repo)

    inv = repo.create_investigation("case_s1", gt.scenario_name)

    # Ingest all files
    for f in sorted(scen_dir.iterdir()):
        if f.is_file():
            pipeline.ingest_evidence_bytes(inv.investigation_id, f.name, f.read_bytes())

    analysis = pipeline.analyze_investigation(inv.investigation_id, reference_source=gt.reference_source)

    # Assertions
    assert analysis["coverage_stats"].total_records_encountered == 11
    assert analysis["coverage_stats"].parsing_success_rate == 100.0
    assert analysis["integrity_summary"].all_verified is True
    assert len(analysis["events"]) == 11

    # Verify report exports execute without error
    manifest = repo.get_manifest(inv.investigation_id)
    json_rep = export_investigation_json(inv, manifest, analysis["events"], analysis["diagnostics"], analysis["coverage_stats"])
    assert len(json_rep) > 500

    csv_rep = export_timeline_csv(analysis["events"])
    assert len(csv_rep.splitlines()) == 12  # Header + 11 records

    md_rep = export_markdown_report(inv, manifest, analysis["events"], analysis["diagnostics"], analysis["coverage_stats"])
    assert "## 1. Investigation Overview" in md_rep

    pdf_rep = export_pdf_report(inv, manifest, analysis["events"], analysis["diagnostics"], analysis["coverage_stats"])
    assert pdf_rep.startswith(b"%PDF-")


def test_scenario_2_e2e_clock_skew(generated_scenarios, tmp_path: Path):
    root, scenarios_meta = generated_scenarios
    scen_dir, gt_file = scenarios_meta["scenario_2"]
    gt = ScenarioGroundTruth.load_from_file(gt_file)

    repo = InvestigationRepository(data_root=tmp_path)
    pipeline = ForensicPipeline(repository=repo)

    inv = repo.create_investigation(
        "case_s2",
        gt.scenario_name,
        assigned_timezone="UTC",
    )

    for f in sorted(scen_dir.iterdir()):
        if f.is_file():
            # Pass source timezone
            tz = gt.known_timezones.get(f.name, "UTC")
            pipeline.ingest_evidence_bytes(inv.investigation_id, f.name, f.read_bytes(), assigned_timezone=tz)

    analysis = pipeline.analyze_investigation(
        inv.investigation_id,
        reference_source=gt.reference_source,
        clock_skew_enabled=True,
    )

    skew_est = analysis["skew_estimates"].get("db-backend-02")
    assert skew_est is not None
    assert skew_est.status == "ESTIMATED"
    # Expected offset: +180.0 seconds
    assert abs(skew_est.estimated_offset_sec - 180.0) < 0.1

    # Residual timing error after correction must be near 0
    skew_metrics = BenchmarkEvaluator.evaluate_clock_skew(gt, analysis["skew_estimates"], analysis["events"])
    assert skew_metrics["db-backend-02"].post_correction_mean_abs_error_sec < 0.1


def test_scenario_3_e2e_degraded_evidence(generated_scenarios, tmp_path: Path):
    root, scenarios_meta = generated_scenarios
    scen_dir, gt_file = scenarios_meta["scenario_3"]
    gt = ScenarioGroundTruth.load_from_file(gt_file)

    repo = InvestigationRepository(data_root=tmp_path)
    pipeline = ForensicPipeline(repository=repo)

    inv = repo.create_investigation("case_s3", gt.scenario_name)

    for f in sorted(scen_dir.iterdir()):
        if f.is_file():
            pipeline.ingest_evidence_bytes(inv.investigation_id, f.name, f.read_bytes())

    analysis = pipeline.analyze_investigation(inv.investigation_id, reference_source=gt.reference_source)

    # Must have encountered malformed records and invalid timestamps without crashing
    assert analysis["coverage_stats"].failed_records >= 1
    assert len(analysis["diagnostics"]) > 0

    # Must flag insufficient anchors for host-sensor-99
    sensor_skew = analysis["skew_estimates"].get("host-sensor-99")
    assert sensor_skew is not None
    assert sensor_skew.status == "INCONCLUSIVE_INSUFFICIENT_ANCHORS"
