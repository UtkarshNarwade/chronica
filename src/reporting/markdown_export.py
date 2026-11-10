"""Comprehensive Markdown Forensic Incident Report Generator.

Produces detailed forensic reports conforming to the 17 required reporting sections,
distinguishing recorded facts, inferences, timing estimates, and uncertainties.
All dynamic values interpolated into table rows are escaped to prevent Markdown table breakage.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.diagnostics.gap_analysis import DiagnosticItem, ParsingCoverageStats
from src.evidence.manifest import EvidenceManifest
from src.evidence.verification import InvestigationIntegritySummary
from src.storage.repository import InvestigationMetadata
from src.timeline.clock_skew import AnchorPair, ClockSkewEstimate
from src.timeline.schema import Event
from src.timeline.search import FilterCriteria


def _sanitize_md_text(val: Any) -> str:
    """Sanitize untrusted text for safe rendering in Markdown documents.

    Escapes raw HTML tags (< and >), neutralizes Markdown image syntax (![),
    and escapes markdown links and square brackets to prevent outbound SSRF/beacons
    and phishing link injection.
    """
    if val is None:
        return ""
    s = str(val)
    # Neutralize HTML tags
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    # Neutralize markdown image marker
    s = s.replace("!", r"\!")
    # Neutralize markdown links / brackets
    s = s.replace("[", r"\[").replace("]", r"\]")
    return s


def _md_cell(val: Any) -> str:
    """Escape a value for safe use inside a Markdown table cell.

    Converts to string, collapses newlines/carriage returns to a space,
    escapes pipe characters to prevent table column breakage, neutralizes
    Markdown image/link markup, and escapes raw HTML tags.
    """
    s = str(val if val is not None else "")
    s = s.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    s = s.replace("|", r"\|")
    return _sanitize_md_text(s)


def export_markdown_report(
    metadata: InvestigationMetadata,
    manifest: EvidenceManifest,
    events: List[Event],
    diagnostics: List[DiagnosticItem],
    coverage_stats: ParsingCoverageStats,
    anchors: Optional[List[AnchorPair]] = None,
    skew_estimates: Optional[Dict[str, ClockSkewEstimate]] = None,
    integrity_summary: Optional[InvestigationIntegritySummary] = None,
    filter_criteria: Optional[FilterCriteria] = None,
    evaluation_summary: Optional[Dict[str, Any]] = None,
    audit_entries: Optional[List[Any]] = None,
) -> str:
    # Defensive handling if arguments were passed positionally in alternate order
    if isinstance(diagnostics, dict) and (skew_estimates is None or isinstance(skew_estimates, list)):
        diagnostics, skew_estimates = skew_estimates or [], diagnostics
    elif isinstance(coverage_stats, dict) and isinstance(skew_estimates, ParsingCoverageStats):
        coverage_stats, skew_estimates = skew_estimates, coverage_stats

    if isinstance(skew_estimates, list):
        skew_estimates = {getattr(e, "target_source", f"src_{i}"): e for i, e in enumerate(skew_estimates) if hasattr(e, "target_source") or hasattr(e, "status")}

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    is_filtered = filter_criteria and not filter_criteria.is_empty()

    md = []

    md.append("# Digital Forensics Incident Investigation Report")
    md.append("**Chronica Forensic System — PS-013 Incident Timeline & Evidence Collection**\n")
    md.append("---\n")

    # 1. Investigation Title and ID
    md.append("## 1. Investigation Overview")
    md.append(f"- **Title:** {_sanitize_md_text(metadata.title)}")
    md.append(f"- **Investigation ID:** `{_sanitize_md_text(metadata.investigation_id)}`")
    md.append(f"- **Description:** {_sanitize_md_text(metadata.description) if metadata.description else 'No case description provided.'}")
    md.append(f"- **Created At (UTC):** {metadata.created_at_utc}")
    md.append(f"- **Investigation Timezone Baseline:** `{metadata.assigned_timezone}`\n")

    # 2. Report Generation Timestamp
    md.append("## 2. Report Metadata")
    md.append(f"- **Report Generated At:** `{now_utc}`")
    md.append("- **Software Version:** Chronica v1.0.0 (Forensic Reference Pipeline)\n")

    # 3. Scope and Data Sources
    md.append("## 3. Scope and Data Sources")
    sources = sorted(list({_sanitize_md_text(e.source_host or e.original_filename) for e in events}))
    md.append(f"- **Total Ingested Evidence Files:** {len(manifest.entries)}")
    md.append(f"- **Sources / Systems Encompassed:** {', '.join(sources) if sources else 'None'}")
    md.append(f"- **Investigation Mode:** {'Filtered Event Scope' if is_filtered else 'Complete Evidence Inventory'}\n")

    # 4. Files Collected
    md.append("## 4. Collected Evidence Files")
    if manifest.entries:
        md.append("| Evidence ID | Original Filename | Stored Filename | Size (Bytes) | Ingested At (UTC) | Detected Format |")
        md.append("|---|---|---|---|---|---|")
        for ent in manifest.entries:
            md.append(
                f"| `{_md_cell(ent.evidence_id)}` | `{_md_cell(ent.original_filename)}` "
                f"| `{_md_cell(ent.stored_filename)}` | {ent.file_size_bytes:,} "
                f"| {_md_cell(ent.collection_time_utc)} | `{_md_cell(ent.detected_format or 'Unknown')}` |"
            )
    else:
        md.append("_No evidence files recorded in this investigation._")
    md.append("")

    # 5. SHA-256 Evidence Manifest
    md.append("## 5. Cryptographic Evidence Manifest (SHA-256)")
    md.append("> **Forensic Note:** SHA-256 hashes were calculated directly from the original bytes before any parsing, transformation, or normalization took place.\n")
    if manifest.entries:
        md.append("| Evidence ID | Original Filename | SHA-256 Digest | Status |")
        md.append("|---|---|---|---|")
        for ent in manifest.entries:
            md.append(
                f"| `{_md_cell(ent.evidence_id)}` | `{_md_cell(ent.original_filename)}` "
                f"| `{_md_cell(ent.sha256_digest)}` | `{_md_cell(ent.ingestion_status)}` |"
            )
        md.append(f"\n- **Manifest Composite SHA-256:** `{manifest.calculate_manifest_digest()}`")
    else:
        md.append("_Manifest is currently empty._")
    md.append("")

    # 6. Verification Results
    md.append("## 6. Evidence Integrity Verification")
    if integrity_summary and integrity_summary.results:
        md.append(f"- **Audit Executed At:** `{integrity_summary.verification_time_utc}`")
        md.append(f"- **Verification Outcome:** {'✅ ALL FILES VERIFIED INTACT' if integrity_summary.all_verified else '⚠️ INTEGRITY AUDIT WARNINGS DETECTED'}")
        md.append(f"- **Verified Intact:** {integrity_summary.verified_files} / {integrity_summary.total_files}")
        md.append(f"- **Mismatched / Tampered:** {integrity_summary.mismatched_files}")
        md.append(f"- **Unavailable / Missing:** {integrity_summary.unavailable_files}\n")

        md.append("| Evidence File | Verification Status | Calculated Digest | Recorded Baseline | Audit Findings |")
        md.append("|---|---|---|---|---|")
        for res in integrity_summary.results:
            status_badge = "✅ VERIFIED" if res.status == "VERIFIED" else ("❌ MISMATCH" if res.status == "MISMATCH" else "❓ UNAVAILABLE")
            calc_hash = f"`{_md_cell(res.calculated_sha256)}`" if res.calculated_sha256 else "N/A"
            md.append(
                f"| `{_md_cell(res.original_filename)}` | **{status_badge}** "
                f"| {calc_hash} | `{_md_cell(res.recorded_sha256)}` | {_md_cell(res.details)} |"
            )
    else:
        md.append("_No verification audit has been recorded yet._")
    md.append("")

    # 7. Parsing Statistics
    md.append("## 7. Parsing Statistics and Coverage Metrics")
    md.append(f"- **Total Records Encountered:** {coverage_stats.total_records_encountered:,}")
    md.append(f"- **Successfully Parsed Records:** {coverage_stats.successfully_parsed_records:,} ({coverage_stats.parsing_success_rate}% of total)")
    md.append(f"- **Failed / Malformed Records:** {coverage_stats.failed_records:,} ({coverage_stats.parsing_failure_rate}% of total)")
    md.append(f"- **Records with Usable Timestamps:** {coverage_stats.records_with_usable_timestamps:,} ({coverage_stats.timestamp_usability_rate}% of parsed)")
    md.append(f"- **Timestamps Requiring Inference/Assumptions:** {coverage_stats.records_requiring_assumptions:,} ({coverage_stats.assumption_rate}% of usable)")
    md.append(f"- **Unresolved Records:** {coverage_stats.unresolved_records:,}\n")

    # 8. Timestamp Normalization Assumptions
    md.append("## 8. Timestamp Normalization Assumptions")
    md.append("The following normalization policies were applied to convert disparate records into a standard UTC timeline:")
    md.append("1. **Explicit Offsets:** When timestamps contained explicit offsets (`Z`, `+HH:MM`, `-HH:MM`), they were converted directly using true timezone offsets.")
    md.append(f"2. **Yearless BSD Syslog:** Source logs formatted as `MMM dd HH:mm:ss` lack year information. Chronica assigned the baseline year `{metadata.assigned_timezone}`/configured investigation year and recorded a diagnostic note.")
    md.append(f"3. **Local Naive Timestamps:** When no timezone indicator was present in raw lines, the configured case timezone (`{metadata.assigned_timezone}`) was applied rather than assuming UTC silently.")
    md.append("4. **Original Timestamps Preserved:** In all instances, the pristine original timestamp string has been retained alongside the normalized value.\n")

    # 9. Clock-Skew Estimates and Methods
    md.append("## 9. Clock-Skew Analysis and Offset Estimates")
    md.append("> **Sign Convention:** `offset = target_clock - reference_clock`. If offset is positive (+s), the target was running ahead of reference. Corrected time = `target_time - offset`.\n")
    if skew_estimates:
        md.append("| Target Host / Source | Reference | Anchors | Estimated Offset | MAD Spread | Range [Min, Max] | Status |")
        md.append("|---|---|---|---|---|---|---|")
        for host, est in skew_estimates.items():
            offset_str = f"{est.estimated_offset_sec:+.3f}s" if est.estimated_offset_sec is not None else "N/A"
            mad_str = f"±{est.spread_mad_sec:.3f}s" if est.spread_mad_sec is not None else "N/A"
            range_str = f"[{est.min_offset_sec:.2f}s, {est.max_offset_sec:.2f}s]" if est.min_offset_sec is not None else "N/A"
            md.append(
                f"| `{_md_cell(host)}` | `{_md_cell(est.reference_source)}` | {est.anchor_count} "
                f"| **{_md_cell(offset_str)}** | {_md_cell(mad_str)} | {_md_cell(range_str)} | `{_md_cell(est.status)}` |"
            )
    else:
        md.append("_No clock-skew estimates calculated._")
    md.append("")

    # 10. Anchor Evidence Used for Corrections
    md.append("## 10. Correlated Anchor Pairs")
    if anchors:
        md.append("| Anchor ID | Type | Shared Identifier | Target Source & Timestamp | Reference Source & Timestamp | Raw Offset | Status |")
        md.append("|---|---|---|---|---|---|---|")
        for a in anchors[:20]:  # Show first 20 anchors
            conf = "Confirmed" if a.is_confirmed else "Unconfirmed"
            md.append(
                f"| `{_md_cell(a.anchor_id)}` | `{_md_cell(a.anchor_type)}` | `{_md_cell(a.anchor_key)}` "
                f"| `{_md_cell(a.target_source)}` (`{_md_cell(a.target_utc_iso)}`) "
                f"| `{_md_cell(a.reference_source)}` (`{_md_cell(a.reference_utc_iso)}`) "
                f"| {a.raw_offset_sec:+.3f}s | {conf} |"
            )
        if len(anchors) > 20:
            md.append(f"\n_... and {len(anchors) - 20} additional anchor pairs recorded in system database._")
    else:
        md.append("_No cross-source anchors established._")
    md.append("")

    # 11. Timeline of Significant Events
    md.append("## 11. Chronological Timeline of Significant Events")
    md.append(f"Displaying {min(len(events), 50)} of {len(events)} events (sorted by normalized UTC):\n")
    if events:
        md.append("| Normalized UTC | Corrected UTC | Source | Severity | Category | User / IP | Event Description | Provenance |")
        md.append("|---|---|---|---|---|---|---|---|")
        for ev in events[:50]:
            actor = f"{ev.username or '-'}" + (f" ({ev.src_ip})" if ev.src_ip else "")
            norm_ts = ev.normalized_utc_iso or "UNRESOLVED"
            corr_ts = ev.corrected_utc_iso or "-"
            prov = f"`{ev.original_filename}:L{ev.line_number}`"
            md.append(
                f"| `{_md_cell(norm_ts)}` | `{_md_cell(corr_ts)}` "
                f"| `{_md_cell(ev.source_host or ev.source_app)}` | `{_md_cell(ev.severity)}` "
                f"| `{_md_cell(ev.category)}` | {_md_cell(actor)} "
                f"| {_md_cell(ev.description)} | {prov} |"
            )
        if len(events) > 50:
            md.append(f"\n_... {len(events) - 50} additional timeline records omitted from Markdown preview. Refer to CSV export for complete table._")
    else:
        md.append("_No timeline events present._")
    md.append("")

    # 12. Search or Filtering Scope
    md.append("## 12. Search and Filtering Scope")
    if is_filtered:
        md.append("- **Scope:** Active Filter Criteria Applied")
        md.append(f"- **Keyword:** `{_sanitize_md_text(filter_criteria.keyword or 'None')}`")
        md.append(f"- **Host:** `{_sanitize_md_text(filter_criteria.source_host or 'All')}`")
        md.append(f"- **User:** `{_sanitize_md_text(filter_criteria.username or 'All')}`")
        md.append(f"- **IP:** `{_sanitize_md_text(filter_criteria.src_ip or 'All')}`")
        md.append(f"- **Severity:** `{_sanitize_md_text(filter_criteria.severity or 'All')}`")
        md.append(f"- **Time Range:** `{_sanitize_md_text(filter_criteria.start_time_iso or 'Start')} to {_sanitize_md_text(filter_criteria.end_time_iso or 'End')}`")
    else:
        md.append("- **Scope:** Complete unfiltered investigation.")
    md.append("")

    # 13. Parsing Gaps and Data-Quality Limitations
    md.append("## 13. Evidence Gaps & Parsing Diagnostics")
    if diagnostics:
        md.append("| Diagnostic ID | Severity | Category | Target | Explanation | Suggested Action |")
        md.append("|---|---|---|---|---|---|")
        for d in diagnostics[:25]:
            md.append(
                f"| `{_md_cell(d.diag_id)}` | `{_md_cell(d.severity.value)}` "
                f"| `{_md_cell(d.category.value)}` | `{_md_cell(d.affected_target)}` "
                f"| {_md_cell(d.explanation)} | {_md_cell(d.suggested_action)} |"
            )
        if len(diagnostics) > 25:
            md.append(f"\n_... and {len(diagnostics) - 25} additional diagnostic findings._")
    else:
        md.append("_No open diagnostic findings detected._")
    md.append("")

    # 14. Important Uncertainties
    md.append("## 14. Forensic Uncertainties and Ambiguities")
    md.append("- **Uncalibrated Clocks:** Network delays, virtual machine scheduling jitter, and unmonitored local hardware clocks introduce unavoidable timing uncertainty.")
    md.append("- **Quiet Periods vs Erasure:** As noted in Diagnostic Category F, gaps between events represent periods where no matching logs were collected; this does not establish deliberate log deletion without external corroboration.")
    md.append("- **Unparsed Content:** Records flagged with MALFORMED status require manual investigator examination as automated regexes could not establish field boundaries.\n")

    # 15. Evaluation Metrics
    md.append("## 15. Benchmark Evaluation Metrics (Synthetic Ground Truth)")
    if evaluation_summary:
        md.append(f"- **Synthetic Scenario:** `{evaluation_summary.get('scenario_name', 'N/A')}`")
        md.append(f"- **Known Synthetic Offset:** `{evaluation_summary.get('known_offset_sec', 'N/A')}s`")
        md.append(f"- **Estimated Offset:** `{evaluation_summary.get('estimated_offset_sec', 'N/A')}s`")
        md.append(f"- **Offset Estimation Error:** `{evaluation_summary.get('offset_error_sec', 'N/A')}s`")
        md.append(f"- **Pairwise Event Ordering Accuracy:** `{evaluation_summary.get('ordering_accuracy_percent', 'N/A')}%`")
        md.append(f"- **Kendall's Tau Rank Correlation:** `{evaluation_summary.get('kendall_tau', 'N/A')}`")
    else:
        md.append("_Investigation represents live or unbenchmarked evidence. Synthetic evaluation metrics not applicable._")
    md.append("")

    # 16. Investigator Notes
    md.append("## 16. Investigator Observations & Case Notes")
    notes_clean = _sanitize_md_text(metadata.notes)
    md.append(notes_clean if notes_clean.strip() else "_No investigator notes entered for this case._")
    md.append("")

    # 17. Formal Forensic Disclaimer
    md.append("## 17. Forensic Disclaimer & Admissibility Notice")
    md.append("> **IMPORTANT NOTICE:** Findings in this report are based strictly and exclusively on the digital evidence files provided to Chronica. This application is an engineering prototype designed for small IT teams and laboratory research. Cryptographic hashes certify that evidence files match their collected state. Clock corrections represent defensible statistical estimations derived from documented anchors and must be corroborated by physical device analysis in formal judicial proceedings.\n")

    # 18. Pinned Key Evidence & Chain-of-Custody Audit Trail
    bookmarked_events = [ev for ev in events if ev.extra_fields.get("bookmarked")]
    md.append("## 18. Pinned Key Evidence & Chain-of-Custody Audit Trail")
    if audit_entries and len(audit_entries) > 0:
        md.append(f"**Audit Ledger Entries: {len(audit_entries)}**\n")
        md.append("| Seq | Timestamp (UTC) | Action | Actor | Summary |")
        md.append("|---|---|---|---|---|")
        for entry in audit_entries[:30]:
            md.append(
                f"| {_md_cell(entry.seq_id)} | `{_md_cell(entry.timestamp_utc[:19])}` "
                f"| `{_md_cell(entry.action)}` | {_md_cell(entry.actor)} "
                f"| {_md_cell(entry.summary)} |"
            )
        if len(audit_entries) > 30:
            md.append(f"\n_... and {len(audit_entries) - 30} additional audit entries._")
        md.append("")
    if bookmarked_events:
        md.append(f"**Bookmarked / Pinned Evidence Events: {len(bookmarked_events)}**\n")
        md.append("| Event ID | Normalized UTC | Source | Severity | Description | Tags | Analyst Note |")
        md.append("|---|---|---|---|---|---|---|")
        for ev in bookmarked_events[:20]:
            tags = ", ".join(ev.extra_fields.get("tags", []))
            note = ev.extra_fields.get("analyst_note", "")
            md.append(
                f"| `{_md_cell(ev.event_id[:12])}` | `{_md_cell(ev.normalized_utc_iso or 'N/A')}` "
                f"| `{_md_cell(ev.source_host or ev.original_filename)}` | `{_md_cell(ev.severity)}` "
                f"| {_md_cell(ev.description[:80])} | {_md_cell(tags)} | {_md_cell(note[:100])} |"
            )
        md.append("")
    if not (audit_entries and len(audit_entries) > 0) and not bookmarked_events:
        md.append("_No pinned evidence bookmarks or audit ledger entries recorded._\n")

    return "\n".join(md)
