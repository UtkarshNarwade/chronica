"""Chronica: Digital Forensics Incident Timeline & Evidence Collection Tool.

AIORI-3 PS-013 Reference Implementation
Streamlit Interactive Application
"""

from __future__ import annotations

import io
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import streamlit as st

# Configure page
st.set_page_config(
    page_title="Chronica | Digital Forensics Incident Timeline",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Project imports
from src.diagnostics.gap_analysis import DiagnosticCategory, DiagnosticSeverity
from src.evaluation.ground_truth import ScenarioGroundTruth
from src.evaluation.metrics import BenchmarkEvaluator
from src.evaluation.triage import TriageEvaluationProtocol
from src.evidence.verification import IntegrityStatus
from src.parsers.detector import ParserRegistry
from src.pipeline import ForensicPipeline
from src.reporting.csv_export import export_timeline_csv
from src.reporting.json_export import export_investigation_json
from src.reporting.markdown_export import export_markdown_report
from src.reporting.pdf_export import export_pdf_report
from src.storage.repository import InvestigationMetadata, InvestigationRepository
from src.timeline.clock_skew import SIGN_CONVENTION_DOC
from src.timeline.schema import CorrectionStatus, NormalizationStatus
from src.timeline.search import FilterCriteria, TimelineSearchEngine
from synthetic_data.generator import ScenarioGenerator

# Constants & Paths
REPO_ROOT = Path(__file__).resolve().parent
DATA_DIR = REPO_ROOT / "data"
SYNTHETIC_DIR = REPO_ROOT / "synthetic_data"


@st.cache_resource
def get_repository() -> InvestigationRepository:
    return InvestigationRepository(data_root=DATA_DIR)


@st.cache_resource
def get_pipeline() -> ForensicPipeline:
    return ForensicPipeline(repository=get_repository())


repo = get_repository()
pipeline = get_pipeline()

# Session State Initialization
if "active_investigation_id" not in st.session_state:
    all_invs = repo.list_investigations()
    if all_invs:
        st.session_state.active_investigation_id = all_invs[0].investigation_id
    else:
        # Create default initial investigation
        default_inv = repo.create_investigation(
            investigation_id="case_default",
            title="Operation ChronoShield",
            description="Initial default forensic triage investigation.",
            assigned_timezone="UTC",
        )
        st.session_state.active_investigation_id = default_inv.investigation_id

if "timeline_sort" not in st.session_state:
    st.session_state.timeline_sort = "normalized_utc"

if "clock_skew_enabled" not in st.session_state:
    st.session_state.clock_skew_enabled = True


# Sidebar Navigation & Investigation Selector
st.sidebar.title("🛡️ Chronica Forensics")
st.sidebar.caption("AIORI-3 PS-013 Incident Timeline & Evidence Collection")

investigations = repo.list_investigations()
inv_options = {inv.investigation_id: f"{inv.title} ({inv.investigation_id})" for inv in investigations}

selected_inv_id = st.sidebar.selectbox(
    "Active Case / Investigation",
    options=list(inv_options.keys()),
    format_func=lambda x: inv_options.get(x, x),
    index=list(inv_options.keys()).index(st.session_state.active_investigation_id) if st.session_state.active_investigation_id in inv_options else 0,
)

if selected_inv_id != st.session_state.active_investigation_id:
    st.session_state.active_investigation_id = selected_inv_id
    st.rerun()

active_inv = repo.get_investigation(st.session_state.active_investigation_id)

nav_section = st.sidebar.radio(
    "Investigation Workflows",
    [
        "📊 Dashboard",
        "📁 Evidence Ingestion",
        "🔒 Evidence Integrity (SHA-256)",
        "⏱️ Timeline Explorer",
        "🔍 Search & Filter",
        "⏳ Clock-Skew Analysis",
        "⚠️ Gaps & Diagnostics",
        "📑 Reports & Export",
        "🧪 Synthetic Scenarios & Benchmark",
        "📂 Case Management",
        "📖 Documentation & Disclaimers",
    ],
)

st.sidebar.divider()
st.sidebar.markdown(f"**Case Timezone:** `{active_inv.assigned_timezone if active_inv else 'UTC'}`")
st.sidebar.markdown(f"**Integrity Engine:** `SHA-256`")
st.sidebar.caption("Offline Digital Forensics Lab Mode • v1.0.0")

# Run analysis on active investigation
analysis = pipeline.analyze_investigation(
    investigation_id=st.session_state.active_investigation_id,
    clock_skew_enabled=st.session_state.clock_skew_enabled,
)
manifest = repo.get_manifest(st.session_state.active_investigation_id)
events = analysis["events"]
unresolved = analysis["unresolved_events"]
coverage_stats = analysis["coverage_stats"]
integrity_summary = analysis["integrity_summary"]
skew_estimates = analysis["skew_estimates"]
anchors = analysis["anchors"]
diagnostics = analysis["diagnostics"]


# -------------------------------------------------------------------------------------------------
# 1. DASHBOARD
# -------------------------------------------------------------------------------------------------
if nav_section == "📊 Dashboard":
    st.title("Incident Investigation Dashboard")
    st.caption(f"Active Case: **{active_inv.title}** (`{active_inv.investigation_id}`)")

    # KPI Metric Cards
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Evidence Files", len(manifest.entries))
    with col2:
        st.metric("Total Events", f"{coverage_stats.total_records_encountered:,}")
    with col3:
        status_text = "Verified Intact" if integrity_summary.all_verified else ("Issues Detected" if integrity_summary.mismatched_files else "Pending")
        st.metric("Integrity Status", status_text, delta="100% SHA-256" if integrity_summary.all_verified else None)
    with col4:
        st.metric("Parsing Success Rate", f"{coverage_stats.parsing_success_rate}%")
    with col5:
        st.metric("Diagnostic Findings", len(diagnostics), delta_color="inverse")

    st.divider()

    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.subheader("Recent Chronological Events")
        if events:
            preview_rows = []
            for e in events[:8]:
                preview_rows.append({
                    "Timestamp (UTC)": e.corrected_utc_iso or e.normalized_utc_iso,
                    "Host / Source": e.source_host or e.source_app,
                    "Severity": e.severity,
                    "Category": e.category,
                    "Description": e.description[:70],
                })
            st.dataframe(preview_rows, use_container_width=True, hide_index=True)
            st.info(f"Showing 8 of {len(events):,} events. Open 'Timeline Explorer' for complete event navigation.")
        else:
            st.warning("No evidence events imported into this case yet. Use 'Evidence Ingestion' to collect logs.")

    with col_right:
        st.subheader("Data-Quality & Timing Health")
        st.write(f"- **Usable Timestamps:** {coverage_stats.records_with_usable_timestamps} / {coverage_stats.successfully_parsed_records}")
        st.write(f"- **Inferred Timestamps / Assumptions:** {coverage_stats.records_requiring_assumptions}")
        st.write(f"- **Unresolved Records:** {coverage_stats.unresolved_records}")
        st.write(f"- **Clock-Skew Sources Analyzed:** {len(skew_estimates)}")

        critical_diags = sum(1 for d in diagnostics if d.severity == DiagnosticSeverity.CRITICAL)
        warn_diags = sum(1 for d in diagnostics if d.severity == DiagnosticSeverity.WARNING)
        if critical_diags > 0:
            st.error(f"⚠️ {critical_diags} Critical diagnostic alert(s) requiring immediate attention.")
        elif warn_diags > 0:
            st.warning(f"⚡ {warn_diags} Data-quality warning(s) identified.")
        else:
            st.success("✅ No critical parsing or integrity anomalies.")

    # Case Notes Box
    st.subheader("Investigator Observations & Case Notes")
    updated_notes = st.text_area("Case Notes (Saved automatically)", value=active_inv.notes, height=90)
    if updated_notes != active_inv.notes:
        active_inv.notes = updated_notes
        repo.update_investigation(active_inv)
        st.toast("Case notes updated successfully.")


# -------------------------------------------------------------------------------------------------
# 2. EVIDENCE INGESTION
# -------------------------------------------------------------------------------------------------
elif nav_section == "📁 Evidence Ingestion":
    st.title("Digital Evidence Collection & Preservation")
    st.caption("Securely import forensic log files, compute cryptographic SHA-256 hashes, and preserve pristine bytes.")

    st.info(
        "**Forensic Preservation Principle:** Uploaded files are hashed *before* parsing and stored "
        "bit-for-bit unchanged in the dedicated investigation evidence directory. Original raw files "
        "are never overwritten or modified."
    )

    with st.expander("Upload Evidence Files", expanded=True):
        col_up1, col_up2 = st.columns([2, 1])
        with col_up1:
            uploaded_files = st.file_uploader(
                "Select one or more log files (Linux Syslog, JSONL, Apache/Nginx, CSV Firewall)",
                accept_multiple_files=True,
                type=["log", "txt", "json", "jsonl", "csv"],
            )
        with col_up2:
            parser_choice = st.selectbox(
                "Parser Selection",
                options=["autodetect", "syslog", "jsonl", "web_access", "csv_firewall"],
                format_func=lambda x: "Auto-Detect Format (Explainable)" if x == "autodetect" else x.upper(),
            )
            file_tz = st.text_input("Source System Timezone (if naive)", value=active_inv.assigned_timezone)

        if uploaded_files:
            st.markdown(f"**Files selected for ingestion:** `{len(uploaded_files)}`")
            if st.button("🚀 Ingest, Hash & Parse Evidence", type="primary"):
                progress_bar = st.progress(0)
                for idx, uf in enumerate(uploaded_files):
                    file_bytes = uf.read()
                    preserved, ingested_events = pipeline.ingest_evidence_bytes(
                        investigation_id=active_inv.investigation_id,
                        filename=uf.name,
                        data=file_bytes,
                        explicit_format=None if parser_choice == "autodetect" else parser_choice,
                        assigned_timezone=file_tz,
                    )
                    progress_bar.progress((idx + 1) / len(uploaded_files))
                st.success(f"Successfully ingested and preserved {len(uploaded_files)} evidence file(s)!")
                st.rerun()

    # Preserved Evidence Inventory
    st.subheader("Preserved Evidence Inventory")
    if manifest.entries:
        inv_table = []
        for e in manifest.entries:
            inv_table.append({
                "Evidence ID": e.evidence_id,
                "Original Filename": e.original_filename,
                "Stored Path": e.stored_filename,
                "Size (Bytes)": f"{e.file_size_bytes:,}",
                "SHA-256 Digest": f"{e.sha256_digest[:16]}...{e.sha256_digest[-8:]}",
                "Parser / Format": e.detected_format or "Unknown",
                "Records Extracted": e.record_count,
                "Collected UTC": e.collection_time_utc,
            })
        st.dataframe(inv_table, use_container_width=True, hide_index=True)
    else:
        st.info("No evidence files currently preserved for this case.")


# -------------------------------------------------------------------------------------------------
# 3. EVIDENCE INTEGRITY (SHA-256)
# -------------------------------------------------------------------------------------------------
elif nav_section == "🔒 Evidence Integrity (SHA-256)":
    st.title("Evidence Cryptographic Integrity Verification")
    st.caption("Re-hash preserved files on disk and compare against the recorded collection manifest.")

    st.markdown(
        "> **Important Forensic Limitation:** A matching SHA-256 hash proves byte-for-byte consistency "
        "since the moment of collection. It does not establish that the source log was authentic, "
        "that clocks were synchronized, or that tampering did not occur prior to collection."
    )

    col_btn1, col_btn2 = st.columns([1, 3])
    with col_btn1:
        if st.button("🔄 Verify All Evidence Now", type="primary"):
            evidence_dir = repo.get_evidence_dir(active_inv.investigation_id)
            integrity_summary = pipeline.repo.get_evidence_collector(active_inv.investigation_id)
            st.rerun()

    st.write(f"**Manifest Composite SHA-256:** `{manifest.calculate_manifest_digest()}`")

    # Integrity Status Grid
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Preserved Files", integrity_summary.total_files)
    c2.metric("Verified Intact", integrity_summary.verified_files)
    c3.metric("Integrity Mismatches", integrity_summary.mismatched_files)
    c4.metric("Missing Files", integrity_summary.unavailable_files)

    st.subheader("Verification Audit Results")
    if integrity_summary.results:
        verif_data = []
        for r in integrity_summary.results:
            badge = "✅ VERIFIED" if r.status == IntegrityStatus.VERIFIED else ("❌ MISMATCH" if r.status == IntegrityStatus.MISMATCH else "❓ UNAVAILABLE")
            verif_data.append({
                "Filename": r.original_filename,
                "Verification Status": badge,
                "Recorded Digest": r.recorded_sha256,
                "Calculated Digest": r.calculated_sha256 or "N/A",
                "Audit Details": r.details,
            })
        st.dataframe(verif_data, use_container_width=True, hide_index=True)
    else:
        st.info("No files available for verification audit.")

    # Demonstration Lab Tamper Simulation
    with st.expander("🧪 Laboratory Tamper Simulation (Demonstration Test)", expanded=False):
        st.warning(
            "Use this testing control to simulate a malicious or accidental single-byte modification "
            "to preserved evidence on disk and confirm that Chronica detects the integrity violation."
        )
        if manifest.entries:
            target_entry = st.selectbox("Select evidence file to tamper with:", options=manifest.entries, format_func=lambda x: x.original_filename)
            if st.button("💥 Simulate 1-Byte File Tampering", type="secondary"):
                evidence_dir = repo.get_evidence_dir(active_inv.investigation_id)
                target_path = evidence_dir / target_entry.stored_filename
                try:
                    os.chmod(target_path, stat.S_IWRITE)
                    with open(target_path, "ab") as f:
                        f.write(b"\n# MALICIOUS_TAMPERED_RECORD_APPENDED")
                    os.chmod(target_path, stat.S_IREAD)
                    st.error(f"Modified 1 byte in '{target_entry.stored_filename}'. Re-verify to observe detection!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error tampering file: {e}")


# -------------------------------------------------------------------------------------------------
# 4. TIMELINE EXPLORER
# -------------------------------------------------------------------------------------------------
elif nav_section == "⏱️ Timeline Explorer":
    st.title("Chronological Incident Timeline Explorer")
    st.caption("Searchable multi-source timeline unified across disparate timestamps and clock offsets.")

    col_ctrl1, col_ctrl2, col_ctrl3 = st.columns([1, 1, 1])
    with col_ctrl1:
        sort_mode = st.radio(
            "Chronological Sorting Axis",
            ["normalized_utc", "corrected_utc", "original_order"],
            format_func=lambda x: "1. Normalized UTC (Standard)" if x == "normalized_utc" else ("2. Clock-Corrected UTC (Skew-Adjusted)" if x == "corrected_utc" else "3. Original Line Sequence"),
            horizontal=False,
        )
    with col_ctrl2:
        st.write(f"**Clock-Skew Correction:** `{'ENABLED' if st.session_state.clock_skew_enabled else 'DISABLED'}`")
        if st.button("Toggle Clock-Skew Correction"):
            st.session_state.clock_skew_enabled = not st.session_state.clock_skew_enabled
            st.rerun()
    with col_ctrl3:
        st.metric("Total Usable Timeline Events", len(events))
        if unresolved:
            st.warning(f"{len(unresolved)} unparseable / missing timestamp records.")

    # Re-sort timeline based on user choice
    sorted_events, _ = pipeline.skew_analyzer.apply_corrections(events, skew_estimates, enabled=st.session_state.clock_skew_enabled), unresolved
    from src.timeline.assembler import TimelineAssembler
    display_events, _ = TimelineAssembler.sort_timeline(events, sort_by=sort_mode)

    # Event Table
    if display_events:
        table_rows = []
        for e in display_events:
            ts_display = e.corrected_utc_iso if sort_mode == "corrected_utc" else e.normalized_utc_iso
            actor = f"{e.username or '-'}" + (f" ({e.src_ip})" if e.src_ip else "")
            table_rows.append({
                "Event ID": e.event_id,
                "Time (UTC)": ts_display,
                "Original Time": e.original_timestamp_str or "-",
                "Host": e.source_host or "-",
                "App": e.source_app or "-",
                "Severity": e.severity,
                "Category": e.category,
                "Actor (User/IP)": actor,
                "Request ID": e.request_id or "-",
                "Description": e.description,
                "Provenance": f"{e.original_filename}:L{e.line_number}",
            })

        st.dataframe(table_rows, use_container_width=True, hide_index=True)

        # Event Detail Inspector Drawer
        st.subheader("Event Detail Inspector")
        selected_event_id = st.selectbox("Inspect Event Details", options=[e.event_id for e in display_events], format_func=lambda x: f"{x} — {[e.description[:50] for e in display_events if e.event_id == x][0]}")
        selected_ev = next((e for e in display_events if e.event_id == selected_event_id), None)

        if selected_ev:
            c_det1, c_det2 = st.columns([1, 1])
            with c_det1:
                st.markdown(f"**Raw Log Line:**")
                st.code(selected_ev.raw_text, language="text")
                st.markdown(f"- **Provenance:** `{selected_ev.original_filename}` line `{selected_ev.line_number}`")
                st.markdown(f"- **Parsing Status:** `{selected_ev.parsing_status}`")
                st.markdown(f"- **Severity:** `{selected_ev.severity}` | **Category:** `{selected_ev.category}`")
            with c_det2:
                st.markdown(f"- **Original Timestamp:** `{selected_ev.original_timestamp_str}`")
                st.markdown(f"- **Normalized UTC:** `{selected_ev.normalized_utc_iso}` (`{selected_ev.normalization_status}`)")
                st.markdown(f"- **Corrected UTC:** `{selected_ev.corrected_utc_iso}` (`{selected_ev.correction_status}`)")
                st.markdown(f"- **Clock Offset Applied:** `{selected_ev.estimated_clock_offset_sec}s`")
                if selected_ev.data_quality_warnings:
                    st.warning(f"Warnings: {'; '.join(selected_ev.data_quality_warnings)}")
    else:
        st.info("No events to display.")


# -------------------------------------------------------------------------------------------------
# 5. SEARCH & FILTER
# -------------------------------------------------------------------------------------------------
elif nav_section == "🔍 Search & Filter":
    st.title("Multi-Faceted Timeline Search")
    st.caption("Conjunctive search across full text, hosts, time ranges, accounts, IPs, and severities.")

    c_s1, c_s2 = st.columns([2, 1])
    with c_s1:
        keyword = st.text_input("Full-text Keyword Query", placeholder="e.g., admin, sshd, 192.168.1.100, SQL")
    with c_s2:
        host_opts = ["All"] + sorted(list({e.source_host for e in events if e.source_host}))
        selected_host = st.selectbox("Host Filter", options=host_opts)

    c_f1, c_f2, c_f3, c_f4 = st.columns(4)
    with c_f1:
        user_opts = ["All"] + sorted(list({e.username for e in events if e.username}))
        selected_user = st.selectbox("Username / Account", options=user_opts)
    with c_f2:
        ip_opts = ["All"] + sorted(list({e.src_ip for e in events if e.src_ip}))
        selected_ip = st.selectbox("Source IP", options=ip_opts)
    with c_f3:
        sev_opts = ["All", "INFO", "WARNING", "ERROR", "AUTH_SUCCESS", "AUTH_FAIL"]
        selected_sev = st.selectbox("Severity Level", options=sev_opts)
    with c_f4:
        cat_opts = ["All", "AUTHENTICATION", "WEB_REQUEST", "SYSTEM", "NETWORK", "APPLICATION"]
        selected_cat = st.selectbox("Category", options=cat_opts)

    warnings_only = st.checkbox("Show only records with data-quality warnings")

    criteria = FilterCriteria(
        keyword=keyword if keyword.strip() else None,
        source_host=selected_host if selected_host != "All" else None,
        username=selected_user if selected_user != "All" else None,
        src_ip=selected_ip if selected_ip != "All" else None,
        severity=selected_sev if selected_sev != "All" else None,
        category=selected_cat if selected_cat != "All" else None,
        has_warnings_only=warnings_only,
    )

    search_result = TimelineSearchEngine.filter_events(events, criteria)

    col_cnt1, col_cnt2 = st.columns([1, 3])
    col_cnt1.metric("Matching Events", f"{search_result.filtered_events} / {search_result.total_events}")

    if search_result.events:
        filtered_table = [
            {
                "Time (UTC)": e.corrected_utc_iso or e.normalized_utc_iso,
                "Host": e.source_host or "-",
                "Severity": e.severity,
                "Category": e.category,
                "User": e.username or "-",
                "IP": e.src_ip or "-",
                "Description": e.description,
                "File:Line": f"{e.original_filename}:L{e.line_number}",
            }
            for e in search_result.events
        ]
        st.dataframe(filtered_table, use_container_width=True, hide_index=True)
    else:
        st.warning("No records matched the filter criteria.")


# -------------------------------------------------------------------------------------------------
# 6. CLOCK-SKEW ANALYSIS
# -------------------------------------------------------------------------------------------------
elif nav_section == "⏳ Clock-Skew Analysis":
    st.title("Clock-Skew Analysis & Correction")
    st.caption("Defensible offset estimation using confirmed anchor pairs and robust median statistics.")

    st.markdown(
        f"> **Documented Sign Convention:** {SIGN_CONVENTION_DOC}\n"
        f"> Reference clock source: `{analysis.get('reference_source', 'None')}`."
    )

    # Host Offset Estimation Table
    st.subheader("Host Clock Offset Estimates")
    if skew_estimates:
        skew_rows = []
        for host, est in skew_estimates.items():
            off_display = f"{est.estimated_offset_sec:+.3f}s" if est.estimated_offset_sec is not None else "N/A"
            mad_display = f"±{est.spread_mad_sec:.3f}s" if est.spread_mad_sec is not None else "N/A"
            range_display = f"[{est.min_offset_sec:.2f}s, {est.max_offset_sec:.2f}s]" if est.min_offset_sec is not None else "N/A"
            skew_rows.append({
                "Target Source": host,
                "Reference Source": est.reference_source,
                "Anchor Count": est.anchor_count,
                "Estimated Offset (s)": off_display,
                "MAD Spread": mad_display,
                "Spread Range": range_display,
                "Status": est.status,
                "Explanation": est.explanation,
            })
        st.dataframe(skew_rows, use_container_width=True, hide_index=True)
    else:
        st.info("No remote clock sources available for skew comparison.")

    # Anchor Pairs Inspector
    st.subheader(f"Correlated Anchor Pairs ({len(anchors)})")
    if anchors:
        anc_rows = []
        for a in anchors:
            anc_rows.append({
                "Anchor ID": a.anchor_id,
                "Shared Key": a.anchor_key,
                "Type": a.anchor_type,
                "Target Source": a.target_source,
                "Target Time (UTC)": a.target_utc_iso,
                "Reference Source": a.reference_source,
                "Reference Time (UTC)": a.reference_utc_iso,
                "Raw Offset (s)": f"{a.raw_offset_sec:+.3f}",
                "Confirmed": "✅ Yes" if a.is_confirmed else "❌ No",
            })
        st.dataframe(anc_rows, use_container_width=True, hide_index=True)
    else:
        st.warning("No shared anchor identifiers (e.g., shared request_id or session_id) found between sources.")


# -------------------------------------------------------------------------------------------------
# 7. GAPS & DIAGNOSTICS
# -------------------------------------------------------------------------------------------------
elif nav_section == "⚠️ Gaps & Diagnostics":
    st.title("Data-Quality Diagnostics & Gap Analysis")
    st.caption("Explainable taxonomy of parsing failures, coverage gaps, quiet periods, and clock uncertainties.")

    # Parsing Coverage with Explicit Denominators
    st.subheader("Parsing Coverage & Metrics (Explicit Denominators)")
    cov_c1, cov_c2, cov_c3, cov_c4 = st.columns(4)
    cov_c1.metric("Encountered Records", f"{coverage_stats.total_records_encountered:,}")
    cov_c2.metric("Parsing Success Rate", f"{coverage_stats.parsing_success_rate}%", delta=f"{coverage_stats.successfully_parsed_records} parsed")
    cov_c3.metric("Timestamp Usability", f"{coverage_stats.timestamp_usability_rate}%", delta=f"{coverage_stats.records_with_usable_timestamps} usable")
    cov_c4.metric("Assumptions Required", f"{coverage_stats.assumption_rate}%", delta=f"{coverage_stats.records_requiring_assumptions} assumed")

    # Diagnostic Findings Table
    st.subheader(f"Active Diagnostic Findings ({len(diagnostics)})")
    if diagnostics:
        diag_rows = []
        for d in diagnostics:
            diag_rows.append({
                "Finding ID": d.diag_id,
                "Category": d.category.value,
                "Severity": d.severity.value,
                "Affected Target": d.affected_target,
                "Explanation": d.explanation,
                "Suggested Action": d.suggested_action,
            })
        st.dataframe(diag_rows, use_container_width=True, hide_index=True)
    else:
        st.success("No open diagnostic findings detected in current evidence.")


# -------------------------------------------------------------------------------------------------
# 8. REPORTS & EXPORT
# -------------------------------------------------------------------------------------------------
elif nav_section == "📑 Reports & Export":
    st.title("Forensic Investigation Export & Incident Reports")
    st.caption("Generate complete, verified forensic incident reports in JSON, CSV, Markdown, and PDF formats.")

    st.markdown(
        "> **Report Standard:** Conforms strictly to the 17 required forensic sections, "
        "separating recorded facts from inferences and clock-skew estimates."
    )

    # 1. JSON Export
    json_data = export_investigation_json(
        metadata=active_inv,
        manifest=manifest,
        events=events,
        diagnostics=diagnostics,
        coverage_stats=coverage_stats,
        skew_estimates=skew_estimates,
        integrity_summary=integrity_summary,
    )

    # 2. CSV Timeline Export
    csv_data = export_timeline_csv(events)

    # 3. Markdown Incident Report
    md_data = export_markdown_report(
        metadata=active_inv,
        manifest=manifest,
        events=events,
        diagnostics=diagnostics,
        coverage_stats=coverage_stats,
        anchors=anchors,
        skew_estimates=skew_estimates,
        integrity_summary=integrity_summary,
    )

    # 4. PDF Incident Report
    pdf_bytes = export_pdf_report(
        metadata=active_inv,
        manifest=manifest,
        events=events,
        diagnostics=diagnostics,
        coverage_stats=coverage_stats,
        skew_estimates=skew_estimates,
        integrity_summary=integrity_summary,
    )

    col_exp1, col_exp2, col_exp3, col_exp4 = st.columns(4)

    with col_exp1:
        st.download_button(
            "📥 Download Report (PDF)",
            data=pdf_bytes,
            file_name=f"Chronica_Report_{active_inv.investigation_id}.pdf",
            mime="application/pdf",
            type="primary",
        )
    with col_exp2:
        st.download_button(
            "📥 Download Report (Markdown)",
            data=md_data,
            file_name=f"Chronica_Report_{active_inv.investigation_id}.md",
            mime="text/markdown",
        )
    with col_exp3:
        st.download_button(
            "📥 Download Timeline (CSV)",
            data=csv_data,
            file_name=f"Chronica_Timeline_{active_inv.investigation_id}.csv",
            mime="text/csv",
        )
    with col_exp4:
        st.download_button(
            "📥 Download Case (JSON)",
            data=json_data,
            file_name=f"Chronica_Investigation_{active_inv.investigation_id}.json",
            mime="application/json",
        )

    st.subheader("Markdown Report Preview")
    st.markdown(md_data)


# -------------------------------------------------------------------------------------------------
# 9. SYNTHETIC SCENARIOS & BENCHMARK
# -------------------------------------------------------------------------------------------------
elif nav_section == "🧪 Synthetic Scenarios & Benchmark":
    st.title("Reproducible Synthetic Scenarios & Evaluation")
    st.caption("Benchmark Chronica against known ground truth without touching live production infrastructure.")

    st.subheader("1. Load Synthetic Demonstration Scenario")
    col_sc1, col_sc2, col_sc3 = st.columns(3)

    with col_sc1:
        st.markdown("**Scenario 1: Clean Baseline**")
        st.write("Multi-tier sequence (Nginx, Auth.log, JSONL) with clean timestamps and perfect chronological ordering.")
        if st.button("Load Scenario 1"):
            generator = ScenarioGenerator(SYNTHETIC_DIR)
            s_dir, _ = generator.generate_scenario_1()
            inv1 = repo.create_investigation(f"demo_s1_{datetime.now().strftime('%H%M%S')}", "Demo: Clean Baseline")
            for f in sorted(s_dir.iterdir()):
                pipeline.ingest_evidence_bytes(inv1.investigation_id, f.name, f.read_bytes())
            st.session_state.active_investigation_id = inv1.investigation_id
            st.rerun()

    with col_sc2:
        st.markdown("**Scenario 2: Clock Skew & TZ Mismatch**")
        st.write("Host B clock runs +180.0s fast with America/New_York (-0400) timezone. Anchors allow offset estimation.")
        if st.button("Load Scenario 2", type="primary"):
            generator = ScenarioGenerator(SYNTHETIC_DIR)
            s_dir, _ = generator.generate_scenario_2()
            inv2 = repo.create_investigation(f"demo_s2_{datetime.now().strftime('%H%M%S')}", "Demo: Clock Skew (+180s)")
            for f in sorted(s_dir.iterdir()):
                pipeline.ingest_evidence_bytes(inv2.investigation_id, f.name, f.read_bytes())
            st.session_state.active_investigation_id = inv2.investigation_id
            st.rerun()

    with col_sc3:
        st.markdown("**Scenario 3: Degraded Evidence**")
        st.write("Malformed JSON, corrupted timestamp, missing fields, 45-min quiet gap, duplicate lines, inconclusive skew.")
        if st.button("Load Scenario 3"):
            generator = ScenarioGenerator(SYNTHETIC_DIR)
            s_dir, _ = generator.generate_scenario_3()
            inv3 = repo.create_investigation(f"demo_s3_{datetime.now().strftime('%H%M%S')}", "Demo: Degraded Evidence")
            for f in sorted(s_dir.iterdir()):
                pipeline.ingest_evidence_bytes(inv3.investigation_id, f.name, f.read_bytes())
            st.session_state.active_investigation_id = inv3.investigation_id
            st.rerun()

    st.divider()

    # Triage Protocol Template
    st.subheader("2. Human-in-the-Loop Triage Evaluation Protocol")
    protocol = TriageEvaluationProtocol()
    st.markdown(f"**Target Scenario:** `{protocol.scenario_target}`")
    st.markdown(f"- **Start Boundary:** {protocol.start_definition}")
    st.markdown(f"- **End Boundary:** {protocol.end_definition}")

    st.write("**Task Checklist:**")
    for t in protocol.tasks:
        st.write(f"- **[{t.task_id}]** {t.description} *(Target Finding: {t.target_finding})*")

    st.info(f"**Methodology Notice:** {protocol.notes}")


# -------------------------------------------------------------------------------------------------
# 10. CASE MANAGEMENT
# -------------------------------------------------------------------------------------------------
elif nav_section == "📂 Case Management":
    st.title("Investigation & Case Management")
    st.caption("Create, switch, or securely remove investigation workspaces.")

    col_new1, col_new2 = st.columns([2, 1])
    with col_new1:
        with st.form("new_case_form"):
            st.subheader("Create New Investigation")
            new_id = st.text_input("Investigation Case ID", value=f"case_{datetime.now().strftime('%Y%m%d_%H%M')}")
            new_title = st.text_input("Investigation Title", placeholder="e.g., Q3 Web Application Incident")
            new_desc = st.text_area("Scope & Description", placeholder="e.g., Triage of suspected web shell activity.")
            new_tz = st.selectbox("Investigation Baseline Timezone", ["UTC", "America/New_York", "America/Los_Angeles", "Europe/London", "Asia/Kolkata"])
            submitted = st.form_submit_button("Create Case Workspace", type="primary")

            if submitted:
                if new_id and new_title:
                    try:
                        new_meta = repo.create_investigation(
                            investigation_id=new_id,
                            title=new_title,
                            description=new_desc,
                            assigned_timezone=new_tz,
                        )
                        st.session_state.active_investigation_id = new_meta.investigation_id
                        st.success(f"Investigation '{new_title}' created successfully!")
                        st.rerun()
                    except ValueError as err:
                        st.error(f"Error: {err}")

    with col_new2:
        st.subheader("Delete Investigation")
        st.warning(f"Deleting will permanently remove `{active_inv.investigation_id}` and its preserved evidence.")
        confirm_del = st.checkbox("Confirm permanent deletion")
        if st.button("🗑️ Delete Active Case", type="secondary", disabled=not confirm_del):
            repo.delete_investigation(active_inv.investigation_id)
            all_remaining = repo.list_investigations()
            if all_remaining:
                st.session_state.active_investigation_id = all_remaining[0].investigation_id
            st.success("Investigation deleted.")
            st.rerun()


# -------------------------------------------------------------------------------------------------
# 11. DOCUMENTATION & DISCLAIMERS
# -------------------------------------------------------------------------------------------------
elif nav_section == "📖 Documentation & Disclaimers":
    st.title("Chronica Documentation & Forensic Methodology")
    st.caption("Architecture, threat model, forensic principles, and legal boundaries.")

    st.markdown("""
    ### Forensic Core Principles (PS-013)
    1. **Evidence is immutable:** Uploaded evidence bytes are hashed with SHA-256 and preserved untouched.
    2. **Distinguish facts from inferences:** Original timestamp strings are preserved alongside normalized UTC values.
    3. **Timezones vs Clock Skew:** Timezone conversion does not fix hardware clock skew. Offsets must be separately estimated from strong anchors.
    4. **Silence does not equal deletion:** Inactivity or quiet periods between logs are documented honestly without fabricating malicious activity.

    ### Threat Model
    - **Threat Actor:** Malicious logs containing path traversal (`../../`), unescaped JSON, null bytes, or excessive file sizes.
    - **Mitigations:** Path sanitization via regex, byte-stream hashing, configurable file limits (100MB), parameterized SQLite queries, no eval/exec of uploaded content.

    ### Legal and Forensic Disclaimer
    *Chronica is an offline open-source digital forensics tool designed for small IT teams, defenders, and researchers. Outputs must be interpreted in context and verified against original log records for formal judicial admissibility.*
    """)
