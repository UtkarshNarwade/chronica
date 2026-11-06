#!/usr/bin/env python3
"""Chronica Enterprise DFIR Platform - Unified Headless CLI.

Automates evidence acquisition, cryptographic preservation, clock-skew analysis,
gap diagnostics, and multi-format forensic report generation without launching the UI.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Tuple

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.diagnostics.gap_analysis import ParsingCoverageStats
from src.evidence.verification import verify_evidence_integrity
from src.pipeline import ForensicPipeline
from src.reporting.csv_export import export_timeline_csv
from src.reporting.json_export import export_investigation_json
from src.reporting.markdown_export import export_markdown_report
from src.reporting.pdf_export import export_pdf_report
from src.storage.repository import InvestigationMetadata, InvestigationRepository


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="chronica",
        description="Chronica Enterprise DFIR Platform - Headless Investigation & Reconstruction CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--case-id",
        required=True,
        help="Unique alphanumeric investigation case identifier (e.g. case_2026_leak)",
    )
    parser.add_argument(
        "--title",
        default="Chronica Headless Forensic Investigation",
        help="Human-readable title for the investigation report",
    )
    parser.add_argument(
        "--ingest",
        nargs="+",
        required=True,
        help="One or more log file paths, directory trees, or archive bundles (.zip, .tar.gz, .tgz) to ingest",
    )
    parser.add_argument(
        "--timezone",
        default="UTC",
        help="Default timezone assigned to naive timestamps lacking offset metadata (default: UTC)",
    )
    parser.add_argument(
        "--reference-source",
        default=None,
        help="Authoritative reference clock source host (auto-selected if omitted)",
    )
    parser.add_argument(
        "--output-dir",
        default="./output",
        help="Directory where PDF, Markdown, CSV, and JSON reports will be written (default: ./output)",
    )
    parser.add_argument(
        "--data-dir",
        default=None,
        help="Root repository data directory for SQLite and evidence storage (default: ./data)",
    )
    return parser.parse_args()


def collect_file_targets(input_paths: List[str]) -> List[Path]:
    """Resolve files, expanding directories recursively."""
    targets: List[Path] = []
    for raw in input_paths:
        p = Path(raw)
        if not p.exists():
            print(f"[WARN] Ingest target does not exist: {raw}", file=sys.stderr)
            continue
        if p.is_file():
            targets.append(p)
        elif p.is_dir():
            for root, _, files in os.walk(p):
                for f in sorted(files):
                    if f.startswith(".") or f.endswith(".bak") or f.endswith("_ground_truth.json"):
                        continue
                    targets.append(Path(root) / f)
    return targets


def main() -> int:
    args = parse_args()
    data_dir = Path(args.data_dir) if args.data_dir else (REPO_ROOT / "data")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("CHRONICA ENTERPRISE DFIR PLATFORM - HEADLESS RECONSTRUCTION CLI")
    print("=" * 70)
    print(f"Case ID:          {args.case_id}")
    print(f"Case Title:       {args.title}")
    print(f"Default Timezone: {args.timezone}")
    print(f"Output Directory: {output_dir.resolve()}")
    print("-" * 70)

    # Initialize repository and investigation workspace
    repo = InvestigationRepository(data_dir)
    meta = repo.get_investigation(args.case_id)
    if not meta:
        meta = repo.create_investigation(
            investigation_id=args.case_id,
            title=args.title,
            assigned_timezone=args.timezone,
            reference_source=args.reference_source,
        )
    else:
        if args.reference_source and meta.reference_source != args.reference_source:
            meta.reference_source = args.reference_source
            repo.update_investigation(meta)

    pipeline = ForensicPipeline(repo)

    # Resolve input files
    target_files = collect_file_targets(args.ingest)
    if not target_files:
        print("[ERROR] No valid files found to ingest.", file=sys.stderr)
        return 1

    print(f"Processing {len(target_files)} input path target(s)...")

    # Ingest, hash, and expand archives
    total_ingested = 0
    total_events = 0
    total_duplicates_skipped = 0

    for tf in target_files:
        try:
            raw_bytes = tf.read_bytes()
        except Exception as e:
            print(f"[ERROR] Failed to read {tf}: {e}", file=sys.stderr)
            continue

        expanded = pipeline.expand_archive_bytes(tf.name, raw_bytes)
        for member_name, member_bytes in expanded:
            pe, evs = pipeline.ingest_evidence_bytes(
                investigation_id=args.case_id,
                filename=member_name,
                data=member_bytes,
                assigned_timezone=args.timezone,
            )
            if len(evs) == 0:
                total_duplicates_skipped += 1
            else:
                total_ingested += 1
                total_events += len(evs)
                print(f"  [+] Ingested '{member_name}': {len(evs)} events (SHA-256: {pe.sha256_digest[:16]}...)")

    print(f"\nIngestion Complete: {total_ingested} artifact(s) indexed ({total_events} events).")
    if total_duplicates_skipped > 0:
        print(f"  (*) {total_duplicates_skipped} duplicate file(s) skipped by cryptographic invariant.")

    # Execute timeline analysis & clock-skew synchronization
    print("\nExecuting timeline assembly, transitive clock-skew sync, and diagnostics...")
    analysis = pipeline.analyze_investigation(
        investigation_id=args.case_id,
        reference_source=args.reference_source,
        clock_skew_enabled=True,
    )

    events = analysis.get("events", [])
    diagnostics = analysis.get("diagnostics", [])
    coverage_stats = analysis.get("coverage_stats") or ParsingCoverageStats(0, 0, 0, 0, 0, 0)
    skew_estimates = analysis.get("skew_estimates", {})
    anchors = analysis.get("anchors", [])
    integrity_summary = analysis.get("integrity_summary")
    manifest = repo.get_manifest(args.case_id)
    audit_ledger = repo.get_audit_ledger(args.case_id)
    chain_entries = audit_ledger.list_entries()

    # Verify audit chain integrity
    chain_ok, chain_cnt, chain_err = audit_ledger.verify_chain()
    integ_ok = integrity_summary.all_verified if integrity_summary else True

    print("\n" + "=" * 70)
    print("FORENSIC TELEMETRY & INTEGRITY AUDIT")
    print("=" * 70)
    print(f"Cryptographic Hash Status:  {'VERIFIED (All Hashes Match)' if integ_ok else 'FAILED (Integrity Mismatch)'}")
    print(f"Audit Chain-of-Custody:     {'INTACT (' + str(chain_cnt) + ' Blocks Verified)' if chain_ok else 'BROKEN at: ' + str(chain_err)}")
    print(f"Total Normalized Events:    {len(events):,}")
    print(f"Parsing Coverage:           {coverage_stats.parsing_success_rate}%")
    print(f"Clock-Skew Hosts Resolved:  {len(skew_estimates)}")
    print(f"Diagnostic Findings:        {len(diagnostics)}")

    # Generate Reports
    print("\nGenerating forensic export package...")

    pdf_file = output_dir / f"{args.case_id}_report.pdf"
    md_file = output_dir / f"{args.case_id}_report.md"
    csv_file = output_dir / f"{args.case_id}_timeline.csv"
    json_file = output_dir / f"{args.case_id}_backup.json"

    pdf_bytes = export_pdf_report(
        metadata=meta,
        manifest=manifest,
        events=events,
        diagnostics=diagnostics,
        coverage_stats=coverage_stats,
        skew_estimates=skew_estimates,
        integrity_summary=integrity_summary,
    )
    pdf_file.write_bytes(pdf_bytes)
    print(f"  [+] PDF Report:      {pdf_file}")

    md_text = export_markdown_report(
        metadata=meta,
        manifest=manifest,
        events=events,
        diagnostics=diagnostics,
        coverage_stats=coverage_stats,
        anchors=anchors,
        skew_estimates=skew_estimates,
        integrity_summary=integrity_summary,
        audit_entries=chain_entries,
    )
    md_file.write_text(md_text, encoding="utf-8")
    print(f"  [+] Markdown Report: {md_file}")

    csv_text = export_timeline_csv(events)
    csv_file.write_text(csv_text, encoding="utf-8")
    print(f"  [+] CSV Timeline:    {csv_file}")

    json_text = export_investigation_json(
        metadata=meta,
        manifest=manifest,
        events=events,
        diagnostics=diagnostics,
        coverage_stats=coverage_stats,
    )
    json_file.write_text(json_text, encoding="utf-8")
    print(f"  [+] JSON Case Data:  {json_file}")

    print("\n[SUCCESS] Headless investigation successfully executed and exported.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
