"""Chronica: Enterprise Digital Forensics & Incident Response (DFIR) Platform.

AIORI-3 PS-013 Reference Implementation.
Commercial Enterprise Dual-Tone UI Architecture:
Dark Slate Left Navigation Rail (#111622) + Crisp Analytical Light Canvas (#F4F6F9).
100% Offline, Air-Gapped, Cryptographically Hardened Forensic Reconstruction OS.
"""

from __future__ import annotations

import html as html_lib
import io
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Configure page with Chronica Enterprise identity
st.set_page_config(
    page_title="Chronica - Enterprise DFIR Platform",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Project imports
from src.diagnostics.gap_analysis import DiagnosticCategory, DiagnosticSeverity, ParsingCoverageStats
from src.diagnostics.heuristics import ForensicHeuristicEngine, HeuristicLead
from src.evaluation.ground_truth import ScenarioGroundTruth
from src.evaluation.metrics import BenchmarkEvaluator
from src.evaluation.triage import TriageEvaluationProtocol
from src.evidence.audit_chain import AuditChainLedger, AuditEntry
from src.evidence.verification import IntegrityStatus, simulate_isolated_tamper_check
from src.forensic_tools import EntityGraphBuilder, ForensicPayloadBaker
from src.parsers.custom_regex_parser import CustomRegexParser
from src.parsers.detector import ParserRegistry
from src.pipeline import ForensicPipeline
from src.reporting.csv_export import export_timeline_csv
from src.reporting.json_export import export_investigation_json
from src.reporting.markdown_export import export_markdown_report
from src.reporting.pdf_export import export_pdf_report
from src.storage.repository import InvestigationMetadata, InvestigationRepository
from src.timeline.clock_skew import AnchorPair, ClockSkewAnalyzer, ClockSkewEstimate, SIGN_CONVENTION_DOC
from src.timeline.correlation import EventCorrelator
from src.timeline.schema import CorrectionStatus, Event, NormalizationStatus
from src.timeline.search import FilterCriteria, TimelineSearchEngine
from synthetic_data.generator import ScenarioGenerator

# Constants & Paths
REPO_ROOT = Path(__file__).resolve().parent
DATA_DIR = REPO_ROOT / "data"
SYNTHETIC_DIR = REPO_ROOT / "synthetic_data"

# Clean instantiation without stale cache poisoning
repo = InvestigationRepository(data_root=DATA_DIR)
pipeline = ForensicPipeline(repository=repo)

# Helper to match scenarios by prefix or full name
def find_scenario(scens_dict, target):
    if target in scens_dict:
        return scens_dict[target]
    for k, v in scens_dict.items():
        if k in target or target in k:
            return v
    return None

# Auto-seed case_default with Scenario 2 on first launch if empty
all_existing_invs = repo.list_investigations()
if not any(i.investigation_id == "case_default" for i in all_existing_invs):
    repo.create_investigation(
        investigation_id="case_default",
        title="Operation ChronoShield",
        description="Tactical Multi-Host Incident Timeline & Evidence Reconstruction.",
        assigned_timezone="UTC",
    )

default_manifest = repo.get_manifest("case_default")
default_events = repo.load_events("case_default")
if len(default_manifest.entries) == 0 and len(default_events) == 0:
    scen_gen = ScenarioGenerator(output_root=SYNTHETIC_DIR)
    scenarios_meta = scen_gen.generate_all()
    s2_match = find_scenario(scenarios_meta, "scenario_2")
    if s2_match:
        s2_dir, gt_file = s2_match
        gt = ScenarioGroundTruth.load_from_file(gt_file)
        inv = repo.get_investigation("case_default")
        if inv and gt.reference_source:
            inv.reference_source = gt.reference_source
            repo.update_investigation(inv)
        for f in sorted(s2_dir.iterdir()):
            if f.is_file() and not f.name.endswith(".json"):
                tz = gt.known_timezones.get(f.name, "UTC")
                pipeline.ingest_evidence_bytes(
                    investigation_id="case_default",
                    filename=f.name,
                    data=f.read_bytes(),
                    assigned_timezone=tz,
                )

# -------------------------------------------------------------------------------------------------
# Dual-Tone Enterprise SIEM/DFIR CSS Architecture
# Dark Slate Left Rail (#111622) + Crisp Analytical Light Canvas (#F4F6F9)
# -------------------------------------------------------------------------------------------------
ENTERPRISE_DUAL_TONE_CSS = """
<style>
/* 1. Eliminate Streamlit Header Chrome & Reduce Padding */
header[data-testid="stHeader"] {
    height: 0px !important;
    min-height: 0px !important;
    background: transparent !important;
}

div.block-container {
    padding-top: 0.75rem !important;
    padding-bottom: 2rem !important;
    padding-left: 1.5rem !important;
    padding-right: 1.5rem !important;
    max-width: 100% !important;
}

/* 2. Analytical Light Canvas Base */
.stApp {
    background-color: #F4F6F9 !important;
    color: #0F172A !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

/* 3. Tactical Steel Slate Left Navigation Rail */
section[data-testid="stSidebar"] {
    background-color: #EEF2F6 !important;
    border-right: 1px solid #CBD5E1 !important;
    width: 255px !important;
}

section[data-testid="stSidebar"] > div:first-child {
    padding-top: 0.75rem !important;
}

section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] span,
section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] div {
    color: #334155;
}

/* Sidebar Selectbox */
section[data-testid="stSidebar"] div[data-baseweb="select"] > div {
    background-color: #FFFFFF !important;
    border: 1px solid #CBD5E1 !important;
    border-radius: 5px !important;
    color: #0F172A !important;
    min-height: 36px !important;
    box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04) !important;
}
section[data-testid="stSidebar"] div[data-baseweb="select"] span,
section[data-testid="stSidebar"] div[data-baseweb="select"] div {
    color: #0F172A !important;
    font-size: 12.5px !important;
    font-weight: 600 !important;
}
section[data-testid="stSidebar"] svg {
    fill: #475569 !important;
}

/* Dropdown popover and menu for selectbox */
div[data-baseweb="popover"], div[data-baseweb="menu"], ul[data-baseweb="menu"] {
    background-color: #FFFFFF !important;
    border: 1px solid #CBD5E1 !important;
    border-radius: 5px !important;
}
ul[data-baseweb="menu"] li {
    background-color: #FFFFFF !important;
    color: #0F172A !important;
    font-size: 12.5px !important;
}
ul[data-baseweb="menu"] li:hover {
    background-color: #EEF2F6 !important;
    color: #0066CC !important;
}

/* 4. Enterprise Navigation Buttons Inside Sidebar (Flat Rows with Left Active Indicator Bar) */
.ch-nav-group {
    color: #64748B !important;
    font-size: 10px !important;
    font-weight: 700 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.08em !important;
    padding: 14px 6px 4px 6px !important;
    border-top: 1px solid #E2E8F0 !important;
    margin-top: 8px !important;
}
section[data-testid="stSidebar"] .stButton {
    margin-bottom: 2px !important;
}
/* Inactive Nav Row (type="secondary") */
section[data-testid="stSidebar"] .stButton > button[kind="secondary"],
section[data-testid="stSidebar"] .stButton > button[data-testid="baseButton-secondary"] {
    background-color: transparent !important;
    color: #334155 !important;
    border: 1px solid transparent !important;
    border-left: 3px solid transparent !important;
    border-radius: 5px !important;
    padding: 7px 12px !important;
    min-height: 35px !important;
    justify-content: flex-start !important;
    text-align: left !important;
    box-shadow: none !important;
    transition: all 0.12s ease !important;
}
section[data-testid="stSidebar"] .stButton > button[kind="secondary"] p,
section[data-testid="stSidebar"] .stButton > button[data-testid="baseButton-secondary"] p {
    color: #334155 !important;
    font-size: 13px !important;
    font-weight: 500 !important;
}
section[data-testid="stSidebar"] .stButton > button[kind="secondary"]:hover,
section[data-testid="stSidebar"] .stButton > button[data-testid="baseButton-secondary"]:hover {
    background-color: #E2E8F0 !important;
    color: #0F172A !important;
    border-left: 3px solid #94A3B8 !important;
}
section[data-testid="stSidebar"] .stButton > button[kind="secondary"]:hover p,
section[data-testid="stSidebar"] .stButton > button[data-testid="baseButton-secondary"]:hover p {
    color: #0F172A !important;
    font-weight: 600 !important;
}
/* Active Nav Row (type="primary") */
section[data-testid="stSidebar"] .stButton > button[kind="primary"],
section[data-testid="stSidebar"] .stButton > button[data-testid="baseButton-primary"] {
    background-color: #FFFFFF !important;
    color: #0066CC !important;
    border: 1px solid #CBD5E1 !important;
    border-left: 4px solid #0066CC !important;
    border-radius: 5px !important;
    padding: 7px 12px !important;
    min-height: 35px !important;
    justify-content: flex-start !important;
    text-align: left !important;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.06) !important;
}
section[data-testid="stSidebar"] .stButton > button[kind="primary"] p,
section[data-testid="stSidebar"] .stButton > button[data-testid="baseButton-primary"] p {
    color: #0066CC !important;
    font-size: 13px !important;
    font-weight: 700 !important;
}
section[data-testid="stSidebar"] .stButton > button > div {
    justify-content: flex-start !important;
    width: 100% !important;
}

/* 5. Enterprise App Header (.ch-appbar) */
.ch-appbar {
    background: #FFFFFF;
    border: 1px solid #DCE3EC;
    border-top: 3px solid #0066CC;
    border-radius: 4px;
    padding: 9px 16px;
    margin-bottom: 12px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03);
    flex-wrap: wrap;
    gap: 8px;
}

.ch-appbar-brand {
    font-size: 14px;
    font-weight: 700;
    color: #0066CC;
    letter-spacing: 0.5px;
}

.ch-appbar-crumb {
    font-size: 12px;
    color: #64748B;
    margin-left: 10px;
}

.ch-appbar-crumb strong {
    color: #0F172A;
}

/* 6. Semantic Status Pills */
.ch-pill-ok {
    background: #E6F7F2;
    color: #047857;
    border: 1px solid #A7F3D0;
    border-radius: 3px;
    padding: 2px 7px;
    font-size: 11px;
    font-weight: 600;
    display: inline-block;
}

.ch-pill-err {
    background: #FEF2F2;
    color: #B91C1C;
    border: 1px solid #FECACA;
    border-radius: 3px;
    padding: 2px 7px;
    font-size: 11px;
    font-weight: 600;
    display: inline-block;
}

.ch-pill-warn {
    background: #FFFBEB;
    color: #B45309;
    border: 1px solid #FDE68A;
    border-radius: 3px;
    padding: 2px 7px;
    font-size: 11px;
    font-weight: 600;
    display: inline-block;
}

.ch-pill-info {
    background: #EFF6FF;
    color: #1D4ED8;
    border: 1px solid #BFDBFE;
    border-radius: 3px;
    padding: 2px 7px;
    font-size: 11px;
    font-weight: 600;
    display: inline-block;
}

.ch-pill-slate {
    background: #F1F5F9;
    color: #475569;
    border: 1px solid #CBD5E1;
    border-radius: 3px;
    padding: 2px 7px;
    font-size: 11px;
    font-weight: 600;
    display: inline-block;
}

/* 7. Enterprise KPI Grid & Cards */
.ch-kpi-card {
    background: #FFFFFF;
    border: 1px solid #DCE3EC;
    border-radius: 4px;
    padding: 10px 12px;
    text-align: center;
    box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03);
    height: 100%;
}

.ch-kpi-label {
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #64748B;
}

.ch-kpi-val {
    font-size: 22px;
    font-weight: 700;
    font-family: monospace;
    margin: 3px 0 1px 0;
    line-height: 1.1;
}

.ch-kpi-sub {
    font-size: 10px;
    color: #64748B;
}

/* 8. Enterprise Analytical Panel (.ch-panel) */
.ch-panel {
    background: #FFFFFF;
    border: 1px solid #DCE3EC;
    border-radius: 4px;
    margin-bottom: 12px;
    box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03);
    overflow: hidden;
}

.ch-panel-header {
    background: #F8FAFC;
    border-bottom: 1px solid #E2E8F0;
    padding: 8px 14px;
    font-size: 12px;
    font-weight: 600;
    color: #1E293B;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.ch-panel-body {
    padding: 12px 14px;
}

/* 9. CQL Query Bar & Filter Chips */
.ch-query-bar {
    background: #FFFFFF;
    border: 1px solid #DCE3EC;
    border-radius: 4px;
    padding: 6px 10px;
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 10px;
}

.ch-query-badge {
    background: #EFF6FF;
    color: #0066CC;
    border: 1px solid #BFDBFE;
    border-radius: 3px;
    padding: 2px 7px;
    font-size: 11px;
    font-weight: 700;
    font-family: monospace;
}

.ch-filter-chip {
    background: #F1F5F9;
    border: 1px solid #CBD5E1;
    color: #0066CC;
    border-radius: 3px;
    padding: 2px 7px;
    font-size: 11px;
    font-family: monospace;
    display: inline-block;
    margin-right: 5px;
    margin-bottom: 5px;
}

.ch-field-tag {
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    color: #0F172A;
    border-radius: 3px;
    padding: 1px 5px;
    font-family: monospace;
    font-size: 11px;
}

/* 10. Table & Inspector Styles */
.ch-inspect-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
}

.ch-inspect-table td {
    padding: 5px 10px;
    border-bottom: 1px solid #F1F5F9;
    vertical-align: top;
}

.ch-inspect-table tr:hover {
    background-color: #F8FAFC;
}

.ch-inspect-key {
    font-family: monospace;
    font-weight: 600;
    color: #0066CC;
    width: 220px;
}

.ch-inspect-val {
    color: #0F172A;
}

/* Buttons */
div.stButton > button {
    border-radius: 4px;
    font-weight: 500;
    font-size: 12px;
    border: 1px solid #DCE3EC;
}

div.stButton > button[kind="primary"] {
    background-color: #0066CC !important;
    border-color: #0066CC !important;
    color: #FFFFFF !important;
}
</style>
"""
st.markdown(ENTERPRISE_DUAL_TONE_CSS, unsafe_allow_html=True)

# -------------------------------------------------------------------------------------------------
# Session State Initialization
# -------------------------------------------------------------------------------------------------
if "active_investigation_id" not in st.session_state:
    st.session_state.active_investigation_id = "case_default"

# Handle pending case switch requested by scenario loader or case switcher
if "pending_case_switch" in st.session_state:
    target_id = st.session_state["pending_case_switch"]
    st.session_state.active_investigation_id = target_id
    st.session_state["ch_case_selector"] = target_id
    del st.session_state["pending_case_switch"]

if "clock_skew_enabled" not in st.session_state:
    st.session_state.clock_skew_enabled = True

if "latency_tolerance_sec" not in st.session_state:
    st.session_state.latency_tolerance_sec = 2.0

if "timeline_sort" not in st.session_state:
    st.session_state.timeline_sort = "corrected_utc"

if "selected_event_id" not in st.session_state:
    st.session_state.selected_event_id = None

# Ensure active investigation exists
invs = repo.list_investigations()
if not invs:
    repo.create_investigation("case_default", "Operation ChronoShield", assigned_timezone="UTC")
    invs = repo.list_investigations()

active_id = st.session_state.active_investigation_id
if not any(i.investigation_id == active_id for i in invs):
    st.session_state.active_investigation_id = invs[0].investigation_id

active_inv = repo.get_investigation(st.session_state.active_investigation_id) or invs[0]

# -------------------------------------------------------------------------------------------------
# Left Sidebar: Tactical Steel Slate Rail Navigation & Brand
# -------------------------------------------------------------------------------------------------
# Brand Header Box
st.sidebar.markdown(
    """
    <div style="background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%); border: 1px solid #334155; border-left: 4px solid #0066CC; border-radius: 6px; padding: 12px 14px; box-shadow: 0 2px 4px rgba(15,23,42,0.08); margin-bottom: 12px;">
        <div style="display: flex; align-items: center; gap: 10px;">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="flex-shrink: 0;">
                <path d="M12 2L3 6V11.5C3 16.5 6.8 21.2 12 22.5C17.2 21.2 21 16.5 21 11.5V6L12 2Z" fill="#0066CC" stroke="#38BDF8" stroke-width="1.5"/>
                <circle cx="12" cy="12.5" r="4" stroke="#FFFFFF" stroke-width="1.2" fill="#0F172A"/>
                <path d="M12 10.5V12.5L13.5 13.5" stroke="#38BDF8" stroke-width="1.3" stroke-linecap="round"/>
            </svg>
            <div style="font-size: 15px; font-weight: 700; color: #FFFFFF; letter-spacing: 0.5px;">CHRONICA</div>
        </div>
        <div style="font-size: 10px; color: #38BDF8; font-family: monospace; margin-top: 4px; letter-spacing: 0.5px;">
            INCIDENT TIMELINE & DFIR PLATFORM
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Active Case Selector
inv_titles = {i.investigation_id: f"{i.title}" for i in invs}
st.sidebar.markdown("<div style='color: #475569 !important; font-size: 10.5px !important; font-weight: 700 !important; text-transform: uppercase !important; letter-spacing: 0.06em !important; margin-bottom: 3px;'>ACTIVE CASE WORKSPACE</div>", unsafe_allow_html=True)
sel_case = st.sidebar.selectbox(
    "Active Workspace",
    options=list(inv_titles.keys()),
    format_func=lambda x: inv_titles.get(x, x),
    index=None if "ch_case_selector" in st.session_state else list(inv_titles.keys()).index(active_inv.investigation_id),
    key="ch_case_selector",
    label_visibility="collapsed",
)
if sel_case != active_inv.investigation_id:
    st.session_state.active_investigation_id = sel_case
    st.session_state.selected_event_id = None
    if "pipeline_cache" in st.session_state:
        del st.session_state["pipeline_cache"]
    st.rerun()

# Display Case ID and Timezone as crisp monospace micro-badges right below the selectbox
st.sidebar.markdown(
    f"""
    <div style="display: flex; gap: 6px; margin-top: 5px; margin-bottom: 8px;">
        <span style="background: #E2E8F0; color: #334155; border: 1px solid #CBD5E1; border-radius: 4px; padding: 2px 7px; font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 500;">ID: {active_inv.investigation_id}</span>
        <span style="background: #E2E8F0; color: #334155; border: 1px solid #CBD5E1; border-radius: 4px; padding: 2px 7px; font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 500;">TZ: {active_inv.assigned_timezone}</span>
    </div>
    """,
    unsafe_allow_html=True,
)

# Grouped Enterprise SIEM Navigation Buttons
if "nav_section" not in st.session_state:
    st.session_state.nav_section = "Security Overview"

NAV_GROUPS = [
    (
        "OPERATIONS & HUNTING",
        [
            "Security Overview",
            "Event Discovery & Timeline",
            "Threat Hunting & Topology",
            "Payload & IOC Analyzer",
        ],
    ),
    (
        "FORENSIC ENGINES",
        [
            "Log Acquisition & Parsers",
            "Evidence Integrity & Ledger",
            "Clock-Skew Synchronization",
            "Diagnostics & Gap Taxonomy",
        ],
    ),
    (
        "REPORTING & SYSTEM",
        [
            "Forensic Reports & Export",
            "Synthetic Benchmark Suite",
            "Workspace & System Specs",
        ],
    ),
]

NAV_MODULES = [mod for _, mods in NAV_GROUPS for mod in mods]

for grp_title, mod_list in NAV_GROUPS:
    st.sidebar.markdown(f'<div class="ch-nav-group">{grp_title}</div>', unsafe_allow_html=True)
    for mod_name in mod_list:
        is_active = (st.session_state.nav_section == mod_name)
        if st.sidebar.button(
            mod_name,
            key=f"nav_{mod_name}",
            use_container_width=True,
            type="primary" if is_active else "secondary",
        ):
            st.session_state.nav_section = mod_name
            st.rerun()

nav_section = st.session_state.nav_section

# Bottom Sidebar Telemetry Footer
st.sidebar.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
st.sidebar.markdown(
    f"""
    <div style="background: #E2E8F0; border: 1px solid #CBD5E1; border-radius: 5px; padding: 10px 12px; color: #334155; font-size: 11px; font-family: 'JetBrains Mono', monospace; line-height: 1.6;">
        <div>TIMEZONE: <span style="color: #0F172A; font-weight: 600;">{active_inv.assigned_timezone}</span></div>
        <div>HASH ENGINE: <span style="color: #0F172A; font-weight: 600;">SHA-256</span></div>
        <div>STORAGE: <span style="color: #0F172A; font-weight: 600;">SQLite WAL</span></div>
        <div>MODE: <span style="color: #0066CC; font-weight: 600;">Air-Gapped Local</span></div>
    </div>
    """,
    unsafe_allow_html=True,
)

# -------------------------------------------------------------------------------------------------
# Pipeline Execution & Caching
# -------------------------------------------------------------------------------------------------
manifest = repo.get_manifest(active_inv.investigation_id)
manifest_digest = manifest.calculate_manifest_digest()
manual_anchors_count = len(getattr(active_inv, "manual_anchors", []) or [])

cache_key = (
    active_inv.investigation_id,
    manifest_digest,
    active_inv.reference_source,
    st.session_state.clock_skew_enabled,
    st.session_state.latency_tolerance_sec,
    manual_anchors_count,
)

if "pipeline_cache" not in st.session_state or st.session_state.get("pipeline_cache_key") != cache_key:
    analysis = pipeline.analyze_investigation(
        investigation_id=active_inv.investigation_id,
        reference_source=active_inv.reference_source,
        clock_skew_enabled=st.session_state.clock_skew_enabled,
        latency_tolerance_sec=st.session_state.latency_tolerance_sec,
    )
    st.session_state["pipeline_cache"] = analysis
    st.session_state["pipeline_cache_key"] = cache_key
else:
    analysis = st.session_state["pipeline_cache"]

events: List[Event] = analysis.get("events", [])
unresolved = analysis.get("unresolved_events", [])
coverage_stats = analysis.get("coverage_stats")
integrity_summary = analysis.get("integrity_summary")
skew_estimates: Dict[str, ClockSkewEstimate] = analysis.get("skew_estimates", {})
anchors: List[AnchorPair] = analysis.get("anchors", [])
diagnostics = analysis.get("diagnostics", [])
heuristic_leads: List[HeuristicLead] = analysis.get("heuristic_leads", [])
correlation_clusters: List[Any] = analysis.get("correlation_clusters", [])

# Audit ledger
audit_ledger = repo.get_audit_ledger(active_inv.investigation_id)
chain_entries = audit_ledger.get_entries()
chain_intact, chain_count, chain_err = audit_ledger.verify_chain()

# -------------------------------------------------------------------------------------------------
# Enterprise Top Header Bar (.ch-appbar)
# -------------------------------------------------------------------------------------------------
appbar_c1, appbar_c2 = st.columns([5.2, 1.0])
with appbar_c1:
    integ_pill = (
        '<span class="ch-pill-ok">SHA-256 Invariant: Verified</span>'
        if (integrity_summary and integrity_summary.all_verified)
        else '<span class="ch-pill-err">SHA-256 Mismatch Detected</span>'
    )
    chain_pill = (
        f'<span class="ch-pill-ok">Audit Chain: Intact ({chain_count})</span>'
        if chain_intact
        else f'<span class="ch-pill-err">Audit Chain Broken</span>'
    )
    ref_label = active_inv.reference_source or "Auto"
    esc_inv_title = html_lib.escape(str(active_inv.title))
    esc_inv_id = html_lib.escape(str(active_inv.investigation_id))
    esc_ref_label = html_lib.escape(str(ref_label))
    skew_pill = (
        f'<span class="ch-pill-info">Clock-Skew: Active ({esc_ref_label} | ±{st.session_state.latency_tolerance_sec:.1f}s)</span>'
        if st.session_state.clock_skew_enabled
        else '<span class="ch-pill-warn">Clock-Skew: Bypassed</span>'
    )
    st.markdown(
        f"""
        <div class="ch-appbar">
            <div>
                <span class="ch-appbar-brand">CHRONICA PLATFORM</span>
                <span class="ch-appbar-crumb">/ {nav_section.upper()} &nbsp;|&nbsp; Case: <strong>{esc_inv_title}</strong> [<code>{esc_inv_id}</code>]</span>
            </div>
            <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
                {integ_pill}
                {chain_pill}
                {skew_pill}
                <span class="ch-pill-slate">{len(events)} Events Indexed</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with appbar_c2:
    if st.button("Sync Telemetry", key="hud_sync_btn", use_container_width=True):
        if "pipeline_cache" in st.session_state:
            del st.session_state["pipeline_cache"]
        st.toast("Telemetry refreshed.")
        st.rerun()

# Plotly theme configuration
PLOTLY_THEME = dict(
    paper_bgcolor="#FFFFFF",
    plot_bgcolor="#FFFFFF",
    font=dict(family="-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif", color="#0F172A", size=11),
    xaxis=dict(gridcolor="#F1F5F9", linecolor="#CBD5E1"),
    yaxis=dict(gridcolor="#F1F5F9", linecolor="#CBD5E1"),
    colorway=["#0066CC", "#059669", "#D97706", "#DC2626", "#7C3AED", "#2563EB"],
    margin=dict(l=10, r=10, t=24, b=10),
)


# =================================================================================================
# MODULE 1: SECURITY OVERVIEW
# =================================================================================================
if nav_section == "Security Overview":
    # 6-Card Enterprise KPI Grid
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    with k1:
        st.markdown(
            f"""
            <div class="ch-kpi-card">
                <div class="ch-kpi-label">Evidence Artifacts</div>
                <div class="ch-kpi-val" style="color: #0066CC;">{len(manifest.entries)}</div>
                <div class="ch-kpi-sub">Preserved Logs</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k2:
        st.markdown(
            f"""
            <div class="ch-kpi-card">
                <div class="ch-kpi-label">Indexed Events</div>
                <div class="ch-kpi-val" style="color: #0F172A;">{len(events):,}</div>
                <div class="ch-kpi-sub">Normalized Timeline</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k3:
        integ_txt = "VERIFIED" if (integrity_summary and integrity_summary.all_verified) else "MISMATCH"
        integ_color = "#047857" if integ_txt == "VERIFIED" else "#B91C1C"
        st.markdown(
            f"""
            <div class="ch-kpi-card">
                <div class="ch-kpi-label">Integrity Status</div>
                <div class="ch-kpi-val" style="color: {integ_color};">{integ_txt}</div>
                <div class="ch-kpi-sub">SHA-256 Hashes</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k4:
        p_rate = coverage_stats.parsing_success_rate if coverage_stats else 100.0
        st.markdown(
            f"""
            <div class="ch-kpi-card">
                <div class="ch-kpi-label">Parse Coverage</div>
                <div class="ch-kpi-val" style="color: #0066CC;">{p_rate}%</div>
                <div class="ch-kpi-sub">{coverage_stats.failed_records if coverage_stats else 0} Malformed</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k5:
        skew_hosts_count = sum(1 for est in skew_estimates.values() if est.status == "ESTIMATED" and not est.within_latency_tolerance)
        st.markdown(
            f"""
            <div class="ch-kpi-card">
                <div class="ch-kpi-label">Clock-Skew Hosts</div>
                <div class="ch-kpi-val" style="color: #D97706;">{skew_hosts_count}</div>
                <div class="ch-kpi-sub">Corrected Offsets</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k6:
        st.markdown(
            f"""
            <div class="ch-kpi-card">
                <div class="ch-kpi-label">Active Diagnostics</div>
                <div class="ch-kpi-val" style="color: #475569;">{len(diagnostics)}</div>
                <div class="ch-kpi-sub">Taxonomy Flags</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # 7-Stage ATT&CK Tactic Matrix Strip
    tactic_defs = [
        ("Initial Access", ["Initial Access", "TA0001"], ["unauthorized", "login", "ssh"]),
        ("Execution", ["Execution", "TA0002"], ["exec", "powershell", "cmd.exe", "/bin/sh", "/bin/bash"]),
        ("Persistence", ["Persistence", "TA0003"], ["cron", "service", "systemd", "registry", "scheduled"]),
        ("Privilege Escalation", ["Privilege Escalation", "TA0004"], ["sudo", "shadow", "setuid", "runas"]),
        ("Defense Evasion", ["Defense Evasion", "TA0005"], ["tamper", "1102", "4616", "clear", "deleted"]),
        ("Credential Access", ["Credential Access", "TA0006"], ["auth_fail", "brute", "dump", "shadow"]),
        ("Lateral Movement", ["Lateral Movement", "TA0008"], ["psexec", "smb", "rdp", "remote"]),
    ]

    tac_cols = st.columns(7)
    for t_idx, (t_name, t_tags, t_indicators) in enumerate(tactic_defs):
        counted_eids: Set[str] = set()
        for lead in heuristic_leads:
            l_tactic = (getattr(lead, "mitre_tactic", "") or "").lower()
            if any(tag.lower() in l_tactic for tag in t_tags):
                counted_eids.update(getattr(lead, "involved_event_ids", []))

        for ev in events:
            if ev.event_id in counted_eids:
                continue
            ev_tags = [str(t).lower() for t in ev.extra_fields.get("tags", [])]
            if any(tag.lower() in ev_tags for tag in t_tags):
                counted_eids.add(ev.event_id)
                continue
            if ev.severity in ("AUTH_FAIL", "WARNING", "ERROR", "CRITICAL"):
                ev_desc = (ev.description or "").lower()
                ev_raw = (ev.raw_text or "").lower()
                if any(ind.lower() in ev_desc or ind.lower() in ev_raw for ind in t_indicators):
                    counted_eids.add(ev.event_id)

        m_count = len(counted_eids)

        bg_color = "#FEF2F2" if m_count > 5 else ("#FFFBEB" if m_count > 0 else "#FFFFFF")
        border_color = "#F87171" if m_count > 5 else ("#FBBF24" if m_count > 0 else "#E2E8F0")
        num_color = "#DC2626" if m_count > 5 else ("#D97706" if m_count > 0 else "#64748B")

        with tac_cols[t_idx]:
            st.markdown(
                f"""
                <div style="background: {bg_color}; border: 1px solid {border_color}; border-radius: 6px; padding: 7px 8px; text-align: center; margin-bottom: 12px; box-shadow: 0 1px 2px rgba(15,23,42,0.03);">
                    <div style="font-size: 10px; font-weight: 700; color: #475569; text-transform: uppercase; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="{t_name}">{t_name}</div>
                    <div style="font-size: 16px; font-weight: 800; color: {num_color}; margin-top: 2px;">{m_count}</div>
                    <div style="font-size: 9px; color: #94A3B8;">Events & Leads</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)

    # Row 1: Swimlane & Donut
    r1_col1, r1_col2 = st.columns([2.2, 1])
    with r1_col1:
        st.markdown(
            """
            <div class="ch-panel-header">Chronological Event Timeline & Host Swimlanes (UTC)</div>
            """,
            unsafe_allow_html=True,
        )
        if events:
            plot_recs = []
            for e in events:
                t = e.corrected_utc_iso or e.normalized_utc_iso
                if t:
                    plot_recs.append({
                        "time": t,
                        "severity": e.severity or "INFO",
                        "host": e.source_host or e.original_filename or "unknown",
                        "desc": e.description[:80],
                    })
            if plot_recs:
                df_vol = pd.DataFrame(plot_recs)
                df_vol["datetime"] = pd.to_datetime(df_vol["time"])
                
                sev_colors = {
                    "CRITICAL": "#DC2626",
                    "AUTH_FAIL": "#EF4444",
                    "HIGH": "#D97706",
                    "WARNING": "#F59E0B",
                    "MEDIUM": "#F59E0B",
                    "LOW": "#0066CC",
                    "AUTH_SUCCESS": "#059669",
                    "INFO": "#64748B",
                }

                fig_vol = px.scatter(
                    df_vol,
                    x="datetime",
                    y="host",
                    color="severity",
                    color_discrete_map=sev_colors,
                    hover_data=["severity", "desc"],
                    labels={"datetime": "UTC Timestamp", "host": "Source Host"},
                    height=270,
                )
                fig_vol.update_layout(
                    paper_bgcolor="#FFFFFF",
                    plot_bgcolor="#FFFFFF",
                    font=dict(color="#0F172A", size=11),
                    margin=dict(l=20, r=20, t=10, b=20),
                    xaxis=dict(gridcolor="#F1F5F9", linecolor="#CBD5E1"),
                    yaxis=dict(gridcolor="#F1F5F9", linecolor="#CBD5E1"),
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                )

                # Translucent amber bands for Category F Coverage Gaps
                for diag in diagnostics:
                    if diag.category == DiagnosticCategory.F_COVERAGE_GAP and diag.metadata:
                        g_start = diag.metadata.get("gap_start_utc")
                        g_end = diag.metadata.get("gap_end_utc")
                        if g_start and g_end:
                            try:
                                fig_vol.add_vrect(
                                    x0=g_start,
                                    x1=g_end,
                                    fillcolor="#FFFBEB",
                                    opacity=0.65,
                                    line_width=1,
                                    line_dash="dash",
                                    line_color="#D97706",
                                    annotation_text="Coverage Gap",
                                    annotation_position="top left",
                                    annotation_font_size=10,
                                    annotation_font_color="#B45309",
                                )
                            except Exception:
                                pass

                st.plotly_chart(fig_vol, use_container_width=True)
        else:
            st.info("No events ingested yet.")

    with r1_col2:
        st.markdown(
            """
            <div class="ch-panel-header">Severity & Category Distribution</div>
            """,
            unsafe_allow_html=True,
        )
        if events:
            cat_counts = pd.Series([e.category for e in events]).value_counts().reset_index()
            cat_counts.columns = ["Category", "Count"]
            fig_donut = px.pie(
                cat_counts,
                names="Category",
                values="Count",
                hole=0.68,
                height=290,
                color_discrete_sequence=["#0066CC", "#059669", "#D97706", "#DC2626", "#7C3AED", "#2563EB"],
            )
            fig_donut.update_layout(
                paper_bgcolor="#FFFFFF",
                plot_bgcolor="#FFFFFF",
                font=dict(color="#0F172A", size=11),
                margin=dict(l=16, r=16, t=16, b=40),
                legend=dict(orientation="h", yanchor="top", y=-0.08, xanchor="center", x=0.5, font=dict(size=11, color="#334155")),
            )
            st.plotly_chart(fig_donut, use_container_width=True)
        else:
            st.info("No categories available.")

    # Row 2: Behavioral Leads & Notes
    r2_col1, r2_col2 = st.columns([1.4, 1])
    with r2_col1:
        st.markdown(
            """
            <div class="ch-panel-header">Behavioral Threat Leads & ATT&CK Correlations</div>
            """,
            unsafe_allow_html=True,
        )
        if heuristic_leads:
            for lead in heuristic_leads:
                esc_tactic = html_lib.escape(str(lead.mitre_tactic or ""))
                esc_sev = html_lib.escape(str(lead.severity or ""))
                esc_title = html_lib.escape(str(lead.title or ""))
                esc_rule = html_lib.escape(str(lead.rule_name or ""))
                esc_expl = html_lib.escape(str(lead.explanation or ""))
                esc_hosts = html_lib.escape(", ".join(str(h) for h in lead.hosts))
                esc_span = html_lib.escape(str(lead.time_span_utc or ""))

                tactic_badge = f'<span class="ch-pill-info">{esc_tactic}</span>'
                sev_badge = f'<span class="ch-pill-err">{esc_sev}</span>'
                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #DCE3EC; border-radius: 4px; padding: 10px; margin-bottom: 8px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                            <div>
                                {tactic_badge} {sev_badge}
                                <strong style="margin-left: 8px; color: #0F172A; font-size: 13px;">{esc_title}</strong>
                            </div>
                            <span class="ch-field-tag">{esc_rule}</span>
                        </div>
                        <div style="font-size: 12px; color: #475569; margin: 4px 0;">{esc_expl}</div>
                        <div style="font-size: 11px; color: #64748B;">
                            Hosts: <code>{esc_hosts}</code> | Time: <code>{esc_span}</code>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(
                """
                <div style="background: #FFFFFF; border: 1px solid #DCE3EC; border-radius: 4px; padding: 12px; text-align: center;">
                    <span class="ch-pill-ok">No High-Confidence Threat Anomalies Detected</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

    with r2_col2:
        st.markdown(
            """
            <div class="ch-panel-header">Investigator Case Notes & Timing Health</div>
            """,
            unsafe_allow_html=True,
        )
        if events:
            host_counts = pd.Series([e.source_host or e.original_filename for e in events]).value_counts().head(4)
            host_items = "".join(
                f"<div style='display: flex; justify-content: space-between; padding: 3px 0; border-bottom: 1px solid #F1F5F9; font-size: 11px;'>"
                f"<code>{html_lib.escape(str(h))}</code><span class='ch-pill-slate'>{c} events</span></div>"
                for h, c in host_counts.items()
            )
            st.markdown(f"<div style='margin-bottom: 8px;'>{host_items}</div>", unsafe_allow_html=True)

        updated_notes = st.text_area(
            "Persistent Case Notes (SQLite WAL)",
            value=active_inv.notes,
            height=85,
            key="cmd_telemetry_notes",
        )
        if updated_notes != active_inv.notes:
            active_inv.notes = updated_notes
            repo.update_investigation(active_inv)
            st.toast("Case notes persisted.")


# =================================================================================================
# MODULE 2: EVENT DISCOVERY & TIMELINE
# =================================================================================================
elif nav_section == "Event Discovery & Timeline":
    # Top CQL Control Strip
    cql_c1, cql_c2, cql_c3, cql_c4 = st.columns([2, 2, 2, 1.2])
    with cql_c1:
        sort_opts = {
            "corrected_utc": "Clock-Corrected UTC (Skew Subtracted)",
            "normalized_utc": "Normalized UTC (Raw)",
            "line_sequence": "Original Acquisition Sequence",
        }
        sort_choice = st.selectbox(
            "Time Axis Sorting",
            options=list(sort_opts.keys()),
            format_func=lambda x: sort_opts.get(x, x),
            index=list(sort_opts.keys()).index(st.session_state.timeline_sort),
            key="tb_sort_axis_select",
        )
        if sort_choice != st.session_state.timeline_sort:
            st.session_state.timeline_sort = sort_choice
            st.rerun()

    with cql_c2:
        available_sources = sorted(list({e.source_host or e.original_filename for e in events if e.source_host or e.original_filename}))
        ref_options = ["(Auto-Detect Dominant Clock)"] + available_sources
        cur_ref_idx = 0
        if active_inv.reference_source in available_sources:
            cur_ref_idx = available_sources.index(active_inv.reference_source) + 1

        selected_ref = st.selectbox("Reference Clock Source", options=ref_options, index=cur_ref_idx, key="tb_ref_src_select")
        new_ref = None if selected_ref.startswith("(Auto") else selected_ref
        if new_ref != active_inv.reference_source:
            active_inv.reference_source = new_ref
            repo.update_investigation(active_inv)
            if "pipeline_cache" in st.session_state:
                del st.session_state["pipeline_cache"]
            st.rerun()

    with cql_c3:
        new_tol = st.slider("Latency Tolerance Guard (s)", min_value=0.0, max_value=10.0, value=float(st.session_state.latency_tolerance_sec), step=0.1, key="tb_lat_guard_slider")
        if new_tol != st.session_state.latency_tolerance_sec:
            st.session_state.latency_tolerance_sec = new_tol
            if "pipeline_cache" in st.session_state:
                del st.session_state["pipeline_cache"]
            st.rerun()

    with cql_c4:
        st.write("")
        st.write("")
        new_skew_toggle = st.toggle("Skew Correction", value=st.session_state.clock_skew_enabled, key="tb_skew_toggle_widget")
        if new_skew_toggle != st.session_state.clock_skew_enabled:
            st.session_state.clock_skew_enabled = new_skew_toggle
            if "pipeline_cache" in st.session_state:
                del st.session_state["pipeline_cache"]
            st.rerun()

    if events:
        # Sort events
        if st.session_state.timeline_sort == "corrected_utc":
            sorted_events = sorted(events, key=lambda e: (e.corrected_utc_iso or e.normalized_utc_iso or "9999", e.line_number))
        elif st.session_state.timeline_sort == "normalized_utc":
            sorted_events = sorted(events, key=lambda e: (e.normalized_utc_iso or "9999", e.line_number))
        else:
            sorted_events = sorted(events, key=lambda e: (e.original_filename, e.line_number))

        events_by_id = {e.event_id: e for e in sorted_events}

        # 2-Column SIEM Discover Layout (col_facets [1], col_table [3.6])
        col_facets, col_table = st.columns([1, 3.6])

        with col_facets:
            st.markdown(
                """
                <div class="ch-panel-header">Field Facets & Top Values</div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown(
                """
                <div style="font-size: 11px; margin-bottom: 8px;">
                    <span class="ch-field-tag">timestamp</span>
                    <span class="ch-field-tag">source_host</span>
                    <span class="ch-field-tag">severity</span>
                    <span class="ch-field-tag">category</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Facet: Top Hosts
            st.markdown("<div style='font-size: 11px; font-weight: 600; color: #1E293B;'>Top Hosts</div>", unsafe_allow_html=True)
            top_hosts = pd.Series([e.source_host or e.original_filename for e in sorted_events]).value_counts().head(4)
            for h, c in top_hosts.items():
                pct = int((c / len(sorted_events)) * 100)
                st.markdown(
                    f"""
                    <div style="margin-bottom: 4px;">
                        <div style="font-size: 11px; display: flex; justify-content: space-between;">
                            <code>{html_lib.escape(str(h[:14]))}</code><span>{c} ({pct}%)</span>
                        </div>
                        <div style="background: #E2E8F0; border-radius: 2px; height: 3px; width: 100%;">
                            <div style="background: #0066CC; border-radius: 2px; height: 3px; width: {pct}%;"></div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            # Facet: Severities
            st.markdown("<div style='font-size: 11px; font-weight: 600; color: #1E293B; margin-top: 8px;'>Severities</div>", unsafe_allow_html=True)
            top_sevs = pd.Series([e.severity for e in sorted_events]).value_counts().head(4)
            for s, c in top_sevs.items():
                pct = int((c / len(sorted_events)) * 100)
                st.markdown(
                    f"""
                    <div style="margin-bottom: 4px;">
                        <div style="font-size: 11px; display: flex; justify-content: space-between;">
                            <span>{s}</span><span>{c}</span>
                        </div>
                        <div style="background: #E2E8F0; border-radius: 2px; height: 3px; width: 100%;">
                            <div style="background: #D97706; border-radius: 2px; height: 3px; width: {pct}%;"></div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            # Facet: Normalization Statuses
            st.markdown("<div style='font-size: 11px; font-weight: 600; color: #1E293B; margin-top: 8px;'>Normalization Status</div>", unsafe_allow_html=True)
            norm_stats = pd.Series([e.normalization_status for e in sorted_events]).value_counts().head(3)
            for s, c in norm_stats.items():
                st.markdown(f"<div style='font-size: 10px; display: flex; justify-content: space-between;'><code>{s[:16]}</code><span class='ch-pill-slate'>{c}</span></div>", unsafe_allow_html=True)

        with col_table:
            # Event Histogram
            df_hist = pd.DataFrame([{
                "time": pd.to_datetime(e.corrected_utc_iso or e.normalized_utc_iso),
                "severity": e.severity,
            } for e in sorted_events if e.corrected_utc_iso or e.normalized_utc_iso])

            if not df_hist.empty:
                fig_hist = px.histogram(
                    df_hist,
                    x="time",
                    color="severity",
                    nbins=30,
                    height=130,
                    color_discrete_map={
                        "CRITICAL": "#DC2626",
                        "AUTH_FAIL": "#EF4444",
                        "HIGH": "#D97706",
                        "WARNING": "#F59E0B",
                        "MEDIUM": "#F59E0B",
                        "LOW": "#0066CC",
                        "AUTH_SUCCESS": "#059669",
                        "INFO": "#64748B",
                    },
                )
                fig_hist.update_layout(
                    paper_bgcolor="#FFFFFF",
                    plot_bgcolor="#FFFFFF",
                    font=dict(color="#0F172A", size=10),
                    margin=dict(l=10, r=10, t=10, b=10),
                    xaxis=dict(gridcolor="#F1F5F9", linecolor="#CBD5E1", showticklabels=True),
                    yaxis=dict(gridcolor="#F1F5F9", linecolor="#CBD5E1"),
                    showlegend=False,
                )
                st.plotly_chart(fig_hist, use_container_width=True)

            # Event Stream Table
            table_rows = []
            for e in sorted_events:
                bm = "★" if e.extra_fields.get("bookmarked") else ""
                t_display = e.corrected_utc_iso or e.normalized_utc_iso or "Unresolved"
                table_rows.append({
                    "Pin": bm,
                    "Timestamp (UTC)": t_display,
                    "Host": e.source_host or e.original_filename,
                    "Severity": e.severity,
                    "Category": e.category,
                    "User": e.actor or "-",
                    "Description": e.description[:85],
                    "Event ID": e.event_id,
                })

            df_table = pd.DataFrame(table_rows)

            display_df = df_table
            start_row_offset = 0
            if len(df_table) > 100:
                p_c1, p_c2 = st.columns([1, 3])
                with p_c1:
                    page_size = st.selectbox("Page Size", options=[100, 250, 500], index=0, key="tb_page_size")
                total_pages = max(1, (len(df_table) + page_size - 1) // page_size)
                with p_c2:
                    page_num = st.number_input("Page #", min_value=1, max_value=total_pages, value=1, step=1, key="tb_page_num")
                start_row_offset = (page_num - 1) * page_size
                display_df = df_table.iloc[start_row_offset : start_row_offset + page_size]

            selected_row_indices = []
            try:
                df_event = st.dataframe(
                    display_df,
                    use_container_width=True,
                    hide_index=True,
                    selection_mode="single-row",
                    on_select="rerun",
                    key="tb_events_dataframe",
                )
                if hasattr(df_event, "selection") and df_event.selection and hasattr(df_event.selection, "rows"):
                    selected_row_indices = df_event.selection.rows or []
            except (TypeError, Exception):
                try:
                    st.dataframe(display_df, use_container_width=True, hide_index=True, key="tb_events_df_fallback")
                except Exception:
                    pass

            if selected_row_indices and len(selected_row_indices) > 0:
                s_idx = start_row_offset + selected_row_indices[0]
                if 0 <= s_idx < len(sorted_events):
                    st.session_state.selected_event_id = sorted_events[s_idx].event_id

            all_ids = list(events_by_id.keys())
            cur_id = st.session_state.selected_event_id or all_ids[0]
            if cur_id not in events_by_id:
                cur_id = all_ids[0]

            sel_ev_inspect = st.selectbox(
                "Document Selection for Deep Inspection",
                options=all_ids,
                index=all_ids.index(cur_id),
                format_func=lambda eid: f"{eid} | {events_by_id[eid].corrected_utc_iso or events_by_id[eid].normalized_utc_iso} | {events_by_id[eid].source_host} | {events_by_id[eid].description[:40]}",
                key="doc_inspect_select",
            )
            selected_event = events_by_id[sel_ev_inspect]

            # Tabbed Document Inspector Drawer
            st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
            insp_tab1, insp_tab2, insp_tab3 = st.tabs([
                "Structured Fields & Tri-State Time",
                "Raw Record & Provenance",
                "Annotations, MITRE Tags & Sibling Events",
            ])

            with insp_tab1:
                import html as html_lib
                off_sec = f"{selected_event.estimated_clock_offset_sec:+.3f}s" if selected_event.estimated_clock_offset_sec is not None else "0.000s (Uncorrected)"
                esc_id = html_lib.escape(str(selected_event.event_id or ""))
                esc_raw_ts = html_lib.escape(str(selected_event.original_timestamp_str or "None"))
                esc_norm_ts = html_lib.escape(str(selected_event.normalized_utc_iso or "Unresolved"))
                esc_norm_st = html_lib.escape(str(selected_event.normalization_status or ""))
                esc_corr_ts = html_lib.escape(str(selected_event.corrected_utc_iso or "Unresolved"))
                esc_corr_st = html_lib.escape(str(selected_event.correction_status or ""))
                esc_host = html_lib.escape(str(selected_event.source_host or selected_event.original_filename or ""))
                esc_app = html_lib.escape(str(selected_event.source_app or "N/A"))
                esc_sev = html_lib.escape(str(selected_event.severity or "INFO"))
                esc_cat = html_lib.escape(str(selected_event.category or ""))
                esc_user = html_lib.escape(str(selected_event.actor or "N/A"))
                esc_ip = html_lib.escape(str(selected_event.src_ip or "N/A"))
                esc_req = html_lib.escape(str(selected_event.request_id or "N/A"))
                esc_sess = html_lib.escape(str(selected_event.session_id or "N/A"))
                esc_desc = html_lib.escape(str(selected_event.description or ""))
                esc_raw = html_lib.escape(str(selected_event.raw_text or ""))

                rows_html = f"""
                <table class="ch-inspect-table">
                    <tr><td class="ch-inspect-key">_id</td><td class="ch-inspect-val"><code>{esc_id}</code></td></tr>
                    <tr><td class="ch-inspect-key">timestamp.raw</td><td class="ch-inspect-val"><code>{esc_raw_ts}</code></td></tr>
                    <tr><td class="ch-inspect-key">timestamp.normalized_utc</td><td class="ch-inspect-val"><code>{esc_norm_ts}</code> ({esc_norm_st})</td></tr>
                    <tr><td class="ch-inspect-key">timestamp.corrected_utc</td><td class="ch-inspect-val"><code>{esc_corr_ts}</code> ({esc_corr_st})</td></tr>
                    <tr><td class="ch-inspect-key">clock.offset_sec</td><td class="ch-inspect-val"><code>{off_sec}</code></td></tr>
                    <tr><td class="ch-inspect-key">source_host</td><td class="ch-inspect-val"><code>{esc_host}</code></td></tr>
                    <tr><td class="ch-inspect-key">source_app</td><td class="ch-inspect-val"><code>{esc_app}</code></td></tr>
                    <tr><td class="ch-inspect-key">severity</td><td class="ch-inspect-val"><span class="ch-pill-slate">{esc_sev}</span></td></tr>
                    <tr><td class="ch-inspect-key">category</td><td class="ch-inspect-val"><code>{esc_cat}</code></td></tr>
                    <tr><td class="ch-inspect-key">username</td><td class="ch-inspect-val"><code>{esc_user}</code></td></tr>
                    <tr><td class="ch-inspect-key">src_ip</td><td class="ch-inspect-val"><code>{esc_ip}</code></td></tr>
                    <tr><td class="ch-inspect-key">request_id</td><td class="ch-inspect-val"><code>{esc_req}</code></td></tr>
                    <tr><td class="ch-inspect-key">session_id</td><td class="ch-inspect-val"><code>{esc_sess}</code></td></tr>
                    <tr><td class="ch-inspect-key">description</td><td class="ch-inspect-val">{esc_desc}</td></tr>
                    <tr><td class="ch-inspect-key">raw_text</td><td class="ch-inspect-val" style="font-family: monospace; font-size: 11px;">{esc_raw}</td></tr>
                </table>
                """
                st.markdown(rows_html, unsafe_allow_html=True)

            with insp_tab2:
                st.json(selected_event.to_dict())

            with insp_tab3:
                ann_c1, ann_c2 = st.columns(2)
                with ann_c1:
                    st.markdown("<strong>Acquisition Provenance</strong>", unsafe_allow_html=True)
                    st.markdown(
                        f"""
                        <div style="font-size: 12px; color: #475569; line-height: 1.6;">
                            <div>Evidence File: <code>{html_lib.escape(str(selected_event.original_filename))}</code></div>
                            <div>Line Offset: <code>Line {selected_event.line_number}</code></div>
                            <div>Artifact ID: <code>{selected_event.evidence_id}</code></div>
                            <div>SHA-256 Digest: <code>{selected_event.provenance.get('sha256', 'N/A')}</code></div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                with ann_c2:
                    st.markdown("<strong>Analyst Annotations</strong>", unsafe_allow_html=True)
                    is_bookmarked = st.checkbox("Pin / Bookmark as Key Milestone", value=bool(selected_event.extra_fields.get("bookmarked")), key=f"bm_{selected_event.event_id}")
                    cur_tags = selected_event.extra_fields.get("tags", [])
                    tag_options = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact"]
                    sel_tags = st.multiselect("MITRE ATT&CK Tags", options=tag_options, default=[t for t in cur_tags if t in tag_options], key=f"tags_{selected_event.event_id}")
                    note_val = st.text_input("Analyst Finding Note", value=str(selected_event.extra_fields.get("analyst_note") or ""), key=f"note_{selected_event.event_id}")

                    if st.button("Save Annotation", key=f"save_ann_{selected_event.event_id}"):
                        repo.annotate_event(
                            investigation_id=active_inv.investigation_id,
                            event_id=selected_event.event_id,
                            bookmarked=is_bookmarked,
                            tags=sel_tags,
                            analyst_note=note_val,
                        )
                        if "pipeline_cache" in st.session_state:
                            del st.session_state["pipeline_cache"]
                        st.toast("Annotation recorded to audit chain.")
                        st.rerun()

                st.markdown("<hr style='border: none; border-top: 1px solid #E2E8F0; margin: 12px 0;'>", unsafe_allow_html=True)
                st.markdown("<strong>Correlated Sibling Events</strong>", unsafe_allow_html=True)

                sib_rows = []
                sel_req = selected_event.request_id or selected_event.extra_fields.get("request_id")
                sel_sess = selected_event.session_id or selected_event.extra_fields.get("session_id")
                sel_user = selected_event.actor or selected_event.username
                sel_host = selected_event.source_host

                for e in events:
                    if e.event_id == selected_event.event_id:
                        continue
                    e_req = e.request_id or e.extra_fields.get("request_id")
                    e_sess = e.session_id or e.extra_fields.get("session_id")
                    e_user = e.actor or e.username
                    e_host = e.source_host

                    rel = None
                    if sel_req and e_req and str(sel_req) == str(e_req):
                        rel = f"Matching Request ID ({sel_req})"
                    elif sel_sess and e_sess and str(sel_sess) == str(e_sess):
                        rel = f"Matching Session ID ({sel_sess})"
                    elif sel_user and e_user and str(sel_user).lower() == str(e_user).lower() and e_host != sel_host:
                        rel = f"Cross-Host Actor Activity ({sel_user})"

                    if rel:
                        sib_rows.append({
                            "Event ID": e.event_id,
                            "Corrected UTC": e.corrected_utc_iso or e.normalized_utc_iso or "Unresolved",
                            "Host": e.source_host or e.original_filename,
                            "Relationship": rel,
                            "Description": e.description[:70],
                        })

                if sib_rows:
                    st.dataframe(pd.DataFrame(sib_rows[:25]), use_container_width=True, hide_index=True)
                else:
                    st.caption("No cross-host sibling events correlated by Request ID, Session ID, or Actor.")
    else:
        st.info("No events available in active investigation.")


# =================================================================================================
# MODULE 3: THREAT HUNTING & TOPOLOGY
# =================================================================================================
elif nav_section == "Threat Hunting & Topology":
    # Top CQL Query Bar
    search_col1, search_col2, search_col3 = st.columns([3, 1, 1])
    with search_col1:
        kw = st.text_input("CQL Query Expression", value="", placeholder="e.g. root, accepted, failed, /etc/shadow", key="th_kw_input")
    with search_col2:
        is_regex = st.checkbox("Regex Mode", value=False, key="th_regex_check")
    with search_col3:
        exclude_kw = st.text_input("NOT (Exclude Term)", value="", placeholder="e.g. cron", key="th_exclude_input")
    st.caption("CQL Syntax: `host:web-01,db-02` `user:admin` `ip:10.0.0.1` `severity:CRITICAL,AUTH_FAIL` `req:req-1234` `after:2026-10-12T10:00:00Z` `before:2026-10-12T12:00:00Z` `NOT term`")

    f_c1, f_c2, f_c3, f_c4, f_c5 = st.columns(5)
    with f_c1:
        cidr_subnet = st.text_input("IP / CIDR Subnet", value="", placeholder="e.g. 192.168.1.0/24", key="th_cidr_input")
    with f_c2:
        all_hosts = ["All Hosts"] + sorted(list({e.source_host or e.original_filename for e in events if e.source_host or e.original_filename}))
        sel_h = st.selectbox("Host Filter", options=all_hosts, key="th_host_select")
    with f_c3:
        all_users = ["All Users"] + sorted(list({e.username for e in events if e.username}))
        sel_u = st.selectbox("User Filter", options=all_users, key="th_user_select")
    with f_c4:
        all_sevs = ["All Severities"] + sorted(list({e.severity for e in events if e.severity}))
        sel_s = st.selectbox("Severity Filter", options=all_sevs, key="th_sev_select")
    with f_c5:
        bm_only = st.checkbox("Pinned Only", value=False, key="th_bm_only_check")

    crit = FilterCriteria(
        keyword=kw.strip() if kw.strip() else None,
        use_regex=is_regex,
        exclude_keyword=exclude_kw.strip() if exclude_kw.strip() else None,
        ip_subnet_cidr=cidr_subnet.strip() if cidr_subnet.strip() else None,
        source_host=None if sel_h.startswith("All") else sel_h,
        username=None if sel_u.startswith("All") else sel_u,
        severity=None if sel_s.startswith("All") else sel_s,
        bookmarked_only=bm_only,
    )

    search_res = TimelineSearchEngine.filter_events(events, crit)
    filtered_events = search_res.events

    # Active filter chips
    pills = []
    if crit.keyword:
        pills.append(f"query: {crit.keyword}")
    if crit.exclude_keyword:
        pills.append(f"NOT {crit.exclude_keyword}")
    if crit.ip_subnet_cidr:
        pills.append(f"cidr: {crit.ip_subnet_cidr}")
    if crit.source_host:
        pills.append(f"host: {crit.source_host}")
    if crit.username:
        pills.append(f"user: {crit.username}")
    if crit.severity:
        pills.append(f"severity: {crit.severity}")
    if crit.bookmarked_only:
        pills.append("pinned: true")

    if pills:
        chips_html = " ".join(f"<span class='ch-filter-chip'>{html_lib.escape(str(p))}</span>" for p in pills)
        st.markdown(f"<div style='margin-bottom: 8px;'>{chips_html}</div>", unsafe_allow_html=True)

    tab_graph, tab_results = st.tabs([
        "Entity Link Topology Graph",
        f"Matched Events & Cross-Source Clusters ({len(filtered_events)})",
    ])

    with tab_graph:
        fig_graph = EntityGraphBuilder.build_plotly_graph(filtered_events if filtered_events else events)
        st.plotly_chart(fig_graph, use_container_width=True)

    with tab_results:
        if correlation_clusters:
            st.markdown(f"<strong>Cross-Source Correlation Clusters ({len(correlation_clusters)})</strong>", unsafe_allow_html=True)
            for c in correlation_clusters:
                c_val = getattr(c, "common_value", getattr(c, "cluster_id", ""))
                c_srcs = getattr(c, "sources_involved", getattr(c, "hosts_involved", []))
                c_cnt = len(getattr(c, "event_ids", [])) or getattr(c, "event_count", 0)

                esc_c_type = html_lib.escape(str(c.cluster_type or ""))
                esc_c_val = html_lib.escape(str(c_val or ""))
                esc_c_srcs = html_lib.escape(", ".join(str(s) for s in c_srcs))

                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #DCE3EC; border-radius: 4px; padding: 8px 12px; margin-bottom: 6px;">
                        <span class="ch-pill-info">{esc_c_type}</span>
                        <strong style="margin-left: 8px; font-size: 12px;">Key: <code>{esc_c_val}</code></strong>
                        <span style="font-size: 11px; color: #64748B; margin-left: 12px;">Hosts: <code>{esc_c_srcs}</code></span>
                        <span style="font-size: 11px; color: #64748B; margin-left: 12px;">Events: {c_cnt}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        if filtered_events:
            f_rows = []
            for e in filtered_events:
                f_rows.append({
                    "Timestamp (UTC)": e.corrected_utc_iso or e.normalized_utc_iso,
                    "Host": e.source_host or e.original_filename,
                    "Severity": e.severity,
                    "Category": e.category,
                    "User": e.actor or "-",
                    "IP": e.src_ip or "-",
                    "Description": e.description[:80],
                })
            df_filtered = pd.DataFrame(f_rows)
            display_filtered_df = df_filtered
            if len(df_filtered) > 100:
                th_c1, th_c2 = st.columns([1, 3])
                with th_c1:
                    th_page_size = st.selectbox("Page Size", options=[100, 250, 500], index=0, key="th_page_size")
                th_total_pages = max(1, (len(df_filtered) + th_page_size - 1) // th_page_size)
                with th_c2:
                    th_page_num = st.number_input("Page #", min_value=1, max_value=th_total_pages, value=1, step=1, key="th_page_num")
                th_start = (th_page_num - 1) * th_page_size
                display_filtered_df = df_filtered.iloc[th_start : th_start + th_page_size]
            st.dataframe(display_filtered_df, use_container_width=True, hide_index=True)

            # Instant Filtered Export buttons
            e_c1, e_c2, e_c3 = st.columns(3)
            with e_c1:
                csv_data = export_timeline_csv(filtered_events)
                st.download_button("Export Filtered CSV", data=csv_data, file_name="filtered_timeline.csv", mime="text/csv", use_container_width=True)
            with e_c2:
                json_data = export_investigation_json(active_inv, manifest, filtered_events, diagnostics, coverage_stats)
                st.download_button("Export Filtered JSON", data=json_data, file_name="filtered_investigation.json", mime="application/json", use_container_width=True)
            with e_c3:
                md_data = export_markdown_report(active_inv, manifest, filtered_events, diagnostics, coverage_stats, anchors, skew_estimates, integrity_summary, crit)
                st.download_button("Export Filtered Markdown", data=md_data, file_name="filtered_report.md", mime="text/markdown", use_container_width=True)
        else:
            st.info("No events match active query.")


# =================================================================================================
# MODULE 4: EVIDENCE INTEGRITY & LEDGER
# =================================================================================================
elif nav_section == "Evidence Integrity & Ledger":
    # Action Bar
    act_c1, act_c2 = st.columns([1.5, 3])
    with act_c1:
        if st.button("Verify All Evidence Hashes", key="crypto_verify_btn", type="primary", use_container_width=True):
            audit_res = repo.verify_evidence_integrity(active_inv.investigation_id)
            audit_ledger.append(
                action="INTEGRITY_VERIFIED",
                summary=f"Integrity audit executed: {audit_res.verified_files}/{audit_res.total_files} files verified intact.",
                details={"verified": audit_res.verified_files, "total": audit_res.total_files, "mismatched": audit_res.mismatched_files},
            )
            if "pipeline_cache" in st.session_state:
                del st.session_state["pipeline_cache"]
            st.toast("Integrity audit complete.")
            st.rerun()

    with act_c2:
        if st.button("Verify Cryptographic Audit Chain", key="crypto_verify_chain_btn", use_container_width=True):
            ok, cnt, err = audit_ledger.verify_chain()
            if ok:
                st.success(f"Audit chain intact: All {cnt} entries verified cryptographically against SHA-256 links.")
            else:
                st.error(f"Audit chain broken at entry: {err}")

    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

    # Checksum Matrix
    st.markdown("<strong>Artifact SHA-256 Checksum Matrix</strong>", unsafe_allow_html=True)
    if manifest.entries:
        verif_map = {}
        if integrity_summary:
            for r in integrity_summary.results:
                verif_map[r.evidence_id] = r.status

        m_rows = []
        for ent in manifest.entries:
            v_stat = verif_map.get(ent.evidence_id, "UNVERIFIED")
            status_badge = "VERIFIED" if v_stat == "VERIFIED" else ("MISMATCH" if v_stat == "MISMATCH" else "UNVERIFIED")
            m_rows.append({
                "Evidence ID": ent.evidence_id,
                "Original Filename": ent.original_filename,
                "Size (Bytes)": f"{ent.file_size_bytes:,}",
                "Format": ent.detected_format or "Unknown",
                "SHA-256 Baseline Digest": ent.sha256_digest,
                "Integrity Status": status_badge,
                "Ingested At (UTC)": ent.collection_time_utc,
            })
        st.dataframe(pd.DataFrame(m_rows), use_container_width=True, hide_index=True)
    else:
        st.info("Manifest is empty. Ingest evidence files to monitor integrity.")

    st.markdown("---")

    # Append-Only Audit Ledger
    st.markdown("<strong>Append-Only Chain-of-Custody Audit Ledger (audit_chain.jsonl)</strong>", unsafe_allow_html=True)
    if chain_entries:
        c_rows = []
        for ce in reversed(chain_entries):
            c_rows.append({
                "Seq": ce.seq_id,
                "Timestamp (UTC)": ce.timestamp_utc[:19],
                "Action": ce.action,
                "Actor": ce.actor,
                "Summary": ce.summary,
                "Entry Hash": ce.entry_hash[:16] + "...",
                "Prev Hash": ce.prev_hash[:16] + "...",
            })
        st.dataframe(pd.DataFrame(c_rows), use_container_width=True, hide_index=True)
    else:
        st.info("Audit ledger is empty.")

    # Controlled Non-Destructive Tamper Simulation Lab
    with st.expander("Controlled 1-Byte Tamper Simulation Lab (Testing & Demonstration)", expanded=False):
        st.caption(
            "Verify cryptographic tamper detection non-destructively: creates an ephemeral sandbox copy of the "
            "selected evidence file, flips 1 byte in the copy, and validates that SHA-256 immediately detects "
            "the tampering while leaving the pristine evidence file on disk 100% untouched."
        )
        if manifest.entries:
            target_ent = st.selectbox(
                "Target Evidence File for Simulation",
                options=manifest.entries,
                format_func=lambda e: f"{e.original_filename} ({e.evidence_id})",
                key="fault_target_select",
            )
            if st.button("Run Non-Destructive Tamper Simulation (Sandbox Copy)", key="sim_tamper_btn"):
                p = repo.get_evidence_file_path(active_inv.investigation_id, target_ent.evidence_id)
                if p and p.exists():
                    try:
                        sim_res = simulate_isolated_tamper_check(
                            stored_path=p,
                            recorded_sha256=target_ent.sha256_digest,
                            evidence_id=target_ent.evidence_id,
                            original_filename=target_ent.original_filename,
                        )
                        st.session_state["tamper_sim_result"] = sim_res

                        audit_ledger.append(
                            action="TAMPER_SIMULATED",
                            summary=f"Non-destructive 1-byte alteration verified on ephemeral copy of '{target_ent.original_filename}'. Original evidence remained untouched.",
                            details={
                                "evidence_id": target_ent.evidence_id,
                                "original_filename": target_ent.original_filename,
                                "mode": "ephemeral_sandbox_copy",
                                "tampered_digest": sim_res["tampered_copy"].calculated_sha256,
                                "original_digest": target_ent.sha256_digest,
                            },
                        )
                    except Exception as e:
                        st.error(f"Simulation error: {e}")
                else:
                    st.error("Evidence file could not be located on disk.")

            if "tamper_sim_result" in st.session_state:
                res = st.session_state["tamper_sim_result"]
                st.markdown("#### Simulation Results")
                sim_rows = [
                    {
                        "Target": "Stored Evidence (Pristine On-Disk)",
                        "Recorded SHA-256": target_ent.sha256_digest[:16] + "...",
                        "Computed SHA-256": (res["baseline"].calculated_sha256 or "")[:16] + "...",
                        "Status": res["baseline"].status.value,
                        "Integrity": "INTACT / UNTOUCHED",
                    },
                    {
                        "Target": "Ephemeral Sandbox Copy (1 Byte Flipped)",
                        "Recorded SHA-256": target_ent.sha256_digest[:16] + "...",
                        "Computed SHA-256": (res["tampered_copy"].calculated_sha256 or "")[:16] + "...",
                        "Status": res["tampered_copy"].status.value,
                        "Integrity": "TAMPERING DETECTED",
                    },
                ]
                st.dataframe(pd.DataFrame(sim_rows), use_container_width=True, hide_index=True)
                st.success(
                    "Simulation complete: 1-byte alteration was caught immediately by SHA-256 hash mismatch. "
                    "Stored original evidence file remains completely unaltered on disk."
                )


# =================================================================================================
# MODULE 5: LOG ACQUISITION & PARSERS
# =================================================================================================
elif nav_section == "Log Acquisition & Parsers":
    up_c1, up_c2 = st.columns([2, 1])
    with up_c1:
        uploaded_files = st.file_uploader(
            "Upload Evidence Log Files (.log, .txt, .json, .jsonl, .csv, .audit, .gz, .zip, .tgz)",
            accept_multiple_files=True,
            type=["log", "txt", "json", "jsonl", "csv", "audit", "gz", "zip", "tgz"],
            key="ch_log_uploader",
        )
    with up_c2:
        parser_choices = {
            "autodetect": "Auto-Detect Format (Explainable)",
            "syslog": "RFC 3164 / 5424 Syslog",
            "jsonl": "JSON Lines (Structured)",
            "web_access": "Apache / Nginx Combined",
            "csv_firewall": "CSV Firewall Logs",
            "auditd": "Linux auditd Event Logs",
            "windows_event": "Windows Security Event Logs",
            "custom_regex": "Custom Named Regex",
        }
        sel_parser = st.selectbox(
            "Parser Selection",
            options=list(parser_choices.keys()),
            format_func=lambda x: parser_choices.get(x, x),
            key="ch_parser_select",
        )

        custom_rx = ""
        if sel_parser == "custom_regex":
            custom_rx = st.text_input("Custom Named Regex", value=r"^(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<message>.*)$", key="ch_custom_rx_input")

        assigned_tz = st.selectbox(
            "Timezone for Naive Timestamps",
            options=["UTC", "America/New_York", "America/Chicago", "America/Los_Angeles", "Europe/London", "Asia/Kolkata", "Asia/Tokyo"],
            index=0,
            key="ch_assigned_tz_select",
        )

        assigned_host = st.text_input(
            "Host / Source Label (Optional)",
            value="",
            placeholder="e.g. web-01, db-server (leave blank for auto)",
            key="ch_assigned_host_input",
            help="User-supplied host label distinguishing multi-server log sources.",
        ).strip() or None

    # Format Detection Confidence Table
    if uploaded_files:
        st.markdown("<strong>Live Pre-Ingestion Format Evaluation</strong>", unsafe_allow_html=True)
        det_rows = []
        for uf in uploaded_files:
            preview_bytes = uf.getvalue()[:8192]
            preview_text = preview_bytes.decode("utf-8", errors="replace")
            sample_lines = [ln.strip() for ln in preview_text.splitlines() if ln.strip()][:25]
            det_res = pipeline.parser_registry.detect_format(sample_lines)

            det_rows.append({
                "Filename": uf.name,
                "Size (Bytes)": f"{len(uf.getvalue()):,}",
                "Detected Format": det_res.detected_format or "Inconclusive",
                "Confidence": f"{det_res.confidence * 100:.1f}%",
                "Explanation": det_res.explanation[:80],
            })
        st.dataframe(pd.DataFrame(det_rows), use_container_width=True, hide_index=True)

        if sel_parser == "custom_regex":
            st.markdown("<strong>Custom Named Regex Extraction Preview</strong>", unsafe_allow_html=True)
            from src.parsers.custom_regex_parser import CustomRegexParser
            try:
                rx_tester = CustomRegexParser(pattern=custom_rx)
                uf0_text = uploaded_files[0].getvalue()[:8192].decode("utf-8", errors="replace")
                rx_sample = [ln.strip() for ln in uf0_text.splitlines() if ln.strip()][:5]
                test_recs = rx_tester.test_pattern(rx_sample)
                if test_recs:
                    st.dataframe(pd.DataFrame(test_recs), use_container_width=True, hide_index=True)
                else:
                    st.caption("No sample lines matched the custom pattern.")
            except Exception as rx_err:
                st.caption(f"Regex validation warning: {rx_err}")

        if st.button("Ingest, Hash & Parse Evidence", type="primary", key="ingest_execute_btn"):
            prog = st.progress(0)
            expanded_items: List[Tuple[str, bytes]] = []
            for uf in uploaded_files:
                members = pipeline.expand_archive_bytes(uf.name, uf.getvalue())
                expanded_items.extend(members)

            total_items = max(1, len(expanded_items))
            processed_count = 0
            duplicates_skipped = 0

            for idx, (m_name, m_data) in enumerate(expanded_items):
                pe, evs = pipeline.ingest_evidence_bytes(
                    investigation_id=active_inv.investigation_id,
                    filename=m_name,
                    data=m_data,
                    explicit_format=None if sel_parser == "autodetect" else sel_parser,
                    assigned_timezone=assigned_tz,
                    custom_regex=custom_rx if sel_parser == "custom_regex" else None,
                    source_host=assigned_host,
                )
                if len(evs) == 0:
                    duplicates_skipped += 1
                else:
                    processed_count += 1
                prog.progress((idx + 1) / total_items)

            if "pipeline_cache" in st.session_state:
                del st.session_state["pipeline_cache"]

            msg = f"Successfully processed {processed_count} evidence file(s)."
            if duplicates_skipped > 0:
                msg += f" ({duplicates_skipped} duplicate file(s) skipped by SHA-256 invariant)."
            st.success(msg)
            st.rerun()

    st.markdown("---")
    st.markdown("<strong>Preserved Evidence Manifest</strong>", unsafe_allow_html=True)
    if manifest.entries:
        inv_rows = []
        for ent in manifest.entries:
            inv_rows.append({
                "Evidence ID": ent.evidence_id,
                "Original Filename": ent.original_filename,
                "Format": ent.detected_format,
                "Size (Bytes)": f"{ent.file_size_bytes:,}",
                "Records Parsed": ent.record_count,
                "SHA-256 Digest": ent.sha256_digest,
                "Status": ent.ingestion_status,
            })
        st.dataframe(pd.DataFrame(inv_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No evidence files in active investigation.")


# =================================================================================================
# MODULE 6: CLOCK-SKEW SYNCHRONIZATION
# =================================================================================================
elif nav_section == "Clock-Skew Synchronization":
    st.markdown(
        f"""
        <div style="background: #FFFFFF; border: 1px solid #DCE3EC; border-radius: 4px; padding: 10px 14px; font-size: 12px; color: #475569; margin-bottom: 12px;">
            <strong>Sign Convention:</strong> <code>offset = target_clock - reference_clock</code>.
            Corrected time = <code>target_time - offset</code>.<br>
            <em>Latency Guard:</em> Observed offsets within ±{st.session_state.latency_tolerance_sec:.1f}s are classified as normal execution delay and left uncorrected.
        </div>
        """,
        unsafe_allow_html=True,
    )

    if skew_estimates:
        st.markdown("<strong>Host Clock Offsets & Linear Drift Estimation</strong>", unsafe_allow_html=True)
        sk_rows = []
        for host, est in skew_estimates.items():
            off_str = f"{est.estimated_offset_sec:+.3f}s" if est.estimated_offset_sec is not None else "N/A"
            mad_str = f"±{est.spread_mad_sec:.3f}s" if est.spread_mad_sec is not None else "N/A"
            drift_str = f"{est.drift_rate_ppm:+.2f} ppm" if est.drift_rate_ppm is not None else "N/A"
            tol_str = "Yes (Preserved)" if est.within_latency_tolerance else "No (Subtracted)"
            sk_rows.append({
                "Target Host": host,
                "Reference Host": est.reference_source,
                "Anchors": est.anchor_count,
                "Estimated Offset": off_str,
                "MAD Spread": mad_str,
                "Linear Drift": drift_str,
                "Latency Guard Applied": tol_str,
                "Status": est.status,
            })
        st.dataframe(pd.DataFrame(sk_rows), use_container_width=True, hide_index=True)

        if anchors:
            st.markdown("<strong>Anchor Pair Timing Offsets</strong>", unsafe_allow_html=True)
            df_anc = pd.DataFrame([
                {
                    "Anchor Key": a.anchor_key,
                    "Target Source": a.target_source,
                    "Reference Source": a.reference_source,
                    "Raw Offset (s)": a.raw_offset_sec,
                    "Anchor Type": a.anchor_type,
                }
                for a in anchors
            ])
            fig_anc = px.strip(
                df_anc,
                x="Raw Offset (s)",
                y="Target Source",
                color="Anchor Type",
                hover_data=["Anchor Key", "Reference Source"],
                height=230,
                color_discrete_sequence=["#0066CC", "#059669", "#D97706", "#7C3AED"],
            )
            fig_anc.update_layout(
                paper_bgcolor="#FFFFFF",
                plot_bgcolor="#FFFFFF",
                font=dict(color="#0F172A", size=11),
                margin=dict(l=20, r=20, t=10, b=20),
                xaxis=dict(gridcolor="#F1F5F9", linecolor="#CBD5E1"),
                yaxis=dict(gridcolor="#F1F5F9", linecolor="#CBD5E1"),
            )
            st.plotly_chart(fig_anc, use_container_width=True)

            # Cross-Host Transaction Latency Waterfall Chart
            import plotly.graph_objects as go
            st.markdown("<strong>Cross-Host Transaction Latency & Timing Delta Waterfall</strong>", unsafe_allow_html=True)
            wf_items = []
            for a in anchors[:12]:
                wf_items.append({
                    "step": f"{a.reference_source} -> {a.target_source} ({a.anchor_key[:10]})",
                    "delta": round(a.raw_offset_sec, 3),
                })
            if wf_items:
                wf_steps = [item["step"] for item in wf_items]
                wf_deltas = [item["delta"] for item in wf_items]
                fig_wf = go.Figure(go.Waterfall(
                    name="Timing Delta",
                    orientation="v",
                    measure=["relative"] * len(wf_steps),
                    x=wf_steps,
                    textposition="outside",
                    text=[f"{d:+.3f}s" for d in wf_deltas],
                    y=wf_deltas,
                    connector={"line": {"color": "#94A3B8"}},
                    decreasing={"marker": {"color": "#0066CC"}},
                    increasing={"marker": {"color": "#D97706"}},
                ))
                fig_wf.update_layout(
                    paper_bgcolor="#FFFFFF",
                    plot_bgcolor="#FFFFFF",
                    font=dict(color="#0F172A", size=11),
                    margin=dict(l=20, r=20, t=20, b=40),
                    xaxis=dict(gridcolor="#F1F5F9", tickangle=-25),
                    yaxis=dict(gridcolor="#F1F5F9", title="Timing Delta (seconds)"),
                    height=280,
                )
                st.plotly_chart(fig_wf, use_container_width=True)
    else:
        st.info("No cross-host clock skew estimates available. Requires events from 2 or more hosts.")

    # Manual Anchor Form
    with st.expander("Manual Investigator Anchor Linker", expanded=False):
        st.caption("Link two specific events as simultaneous physical synchronization anchors.")

        event_choices = ["(Manual ID Input)"] + [
            f"{e.event_id} | {e.source_host or e.original_filename} | {e.normalized_utc_iso or e.original_timestamp_str} | {e.description[:35]}"
            for e in events[:200]
        ]

        man_c1, man_c2 = st.columns(2)
        with man_c1:
            sel_tar = st.selectbox("Target Event Selection", options=event_choices, key="man_tar_select")
            if sel_tar.startswith("(Manual"):
                tar_eid = st.text_input("Target Event ID", placeholder="e.g. evt_12345", key="man_tar_eid")
                tar_src = st.text_input("Target Source Host", placeholder="e.g. host-b", key="man_tar_src")
            else:
                tar_eid = sel_tar.split(" | ")[0]
                tar_src = sel_tar.split(" | ")[1]

        with man_c2:
            sel_ref = st.selectbox("Reference Event Selection", options=event_choices, key="man_ref_select")
            if sel_ref.startswith("(Manual"):
                ref_eid = st.text_input("Reference Event ID", placeholder="e.g. evt_67890", key="man_ref_eid")
                ref_src = st.text_input("Reference Source Host", value=active_inv.reference_source or "", key="man_ref_src")
            else:
                ref_eid = sel_ref.split(" | ")[0]
                ref_src = sel_ref.split(" | ")[1]

        anchor_notes = st.text_input("Investigator Anchor Justification", placeholder="e.g. Confirmed NTP handshake", key="man_anc_notes")

        btn_c1, btn_c2 = st.columns(2)
        with btn_c1:
            if st.button("Register Manual Anchor", key="man_anchor_btn"):
                if tar_eid and ref_eid:
                    tar_ev = next((e for e in events if e.event_id == tar_eid), None)
                    ref_ev = next((e for e in events if e.event_id == ref_eid), None)

                    def _get_epoch(ev_obj, fallback_host):
                        if not ev_obj:
                            return datetime.now(timezone.utc).timestamp(), datetime.now(timezone.utc).isoformat(), fallback_host
                        ts_str = ev_obj.normalized_utc_iso or ev_obj.corrected_utc_iso or ev_obj.original_timestamp_str
                        try:
                            ep = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
                        except Exception:
                            ep = datetime.now(timezone.utc).timestamp()
                        return ep, ts_str or datetime.now(timezone.utc).isoformat(), ev_obj.source_host or fallback_host

                    tar_epoch, tar_iso, actual_tar_src = _get_epoch(tar_ev, tar_src)
                    ref_epoch, ref_iso, actual_ref_src = _get_epoch(ref_ev, ref_src)
                    calculated_offset = round(tar_epoch - ref_epoch, 3)

                    new_anchor = {
                        "anchor_id": f"anc_man_{datetime.now().strftime('%H%M%S')}",
                        "target_event_id": tar_eid,
                        "target_source": actual_tar_src,
                        "target_utc_iso": tar_iso,
                        "target_utc_epoch": tar_epoch,
                        "reference_event_id": ref_eid,
                        "reference_source": actual_ref_src,
                        "reference_utc_iso": ref_iso,
                        "reference_utc_epoch": ref_epoch,
                        "anchor_type": "INVESTIGATOR_CONFIRMED",
                        "anchor_key": "manual-sync",
                        "raw_offset_sec": calculated_offset,
                        "is_confirmed": True,
                        "confidence_notes": anchor_notes,
                    }
                    active_inv.manual_anchors.append(new_anchor)
                    audit_ledger.append(
                        action="MANUAL_ANCHOR_ADDED",
                        summary=f"Manual anchor linked between '{actual_tar_src}' and '{actual_ref_src}' (Offset: {calculated_offset:+.3f}s).",
                        details={"target_id": tar_eid, "reference_id": ref_eid, "offset": calculated_offset},
                    )
                    repo.update_investigation(active_inv)
                    if "pipeline_cache" in st.session_state:
                        del st.session_state["pipeline_cache"]
                    st.success(f"Manual anchor registered (Calculated Offset: {calculated_offset:+.3f}s).")
                    st.rerun()
                else:
                    st.warning("Please provide both Target and Reference Event IDs.")

        with btn_c2:
            if active_inv.manual_anchors:
                if st.button("Clear All Manual Anchors", key="clear_man_anchors_btn"):
                    active_inv.manual_anchors = []
                    audit_ledger.append(
                        action="MANUAL_ANCHORS_CLEARED",
                        summary="Investigator cleared all manual synchronization anchors.",
                        details={},
                    )
                    repo.update_investigation(active_inv)
                    if "pipeline_cache" in st.session_state:
                        del st.session_state["pipeline_cache"]
                    st.toast("Manual anchors cleared.")
                    st.rerun()


# =================================================================================================
# MODULE 7: PAYLOAD & IOC ANALYZER
# =================================================================================================
elif nav_section == "Payload & IOC Analyzer":
    ev_choices = ["(Manual Input / Arbitrary Payload)"] + [
        f"{e.event_id} | {e.source_host or e.original_filename} | {e.description[:50]}"
        for e in events[:100]
    ]
    sel_ev = st.selectbox("Select Event Payload or Enter Text", options=ev_choices, key="baker_ev_select")

    payload_text = ""
    if not sel_ev.startswith("(Manual"):
        eid = sel_ev.split(" | ")[0]
        match_ev = next((e for e in events if e.event_id == eid), None)
        if match_ev:
            payload_text = match_ev.raw_text

    input_text = st.text_area("Input Payload / Raw String", value=payload_text, height=120, key="baker_text_input")

    if input_text:
        ent_score = ForensicPayloadBaker.shannon_entropy(input_text)
        iocs = ForensicPayloadBaker.extract_iocs(input_text)

        m_c1, m_c2, m_c3, m_c4 = st.columns(4)
        with m_c1:
            st.markdown(
                f"""
                <div class="ch-kpi-card">
                    <div class="ch-kpi-label">Shannon Entropy</div>
                    <div class="ch-kpi-val" style="color: {'#DC2626' if ent_score > 5.5 else '#0066CC'};">{ent_score:.4f}</div>
                    <div class="ch-kpi-sub">Bits / Byte (0.0 - 8.0)</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with m_c2:
            st.markdown(
                f"""
                <div class="ch-kpi-card">
                    <div class="ch-kpi-label">IP Addresses</div>
                    <div class="ch-kpi-val" style="color: #0066CC;">{len(iocs['ipv4_public']) + len(iocs['ipv4_private'])}</div>
                    <div class="ch-kpi-sub">{len(iocs['ipv4_public'])} Public / {len(iocs['ipv4_private'])} Private</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with m_c3:
            st.markdown(
                f"""
                <div class="ch-kpi-card">
                    <div class="ch-kpi-label">File Paths</div>
                    <div class="ch-kpi-val" style="color: #059669;">{len(iocs['file_paths'])}</div>
                    <div class="ch-kpi-sub">Unix / Windows</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with m_c4:
            st.markdown(
                f"""
                <div class="ch-kpi-card">
                    <div class="ch-kpi-label">Hashes Detected</div>
                    <div class="ch-kpi-val" style="color: #7C3AED;">{len(iocs['sha256_hashes']) + len(iocs['md5_hashes'])}</div>
                    <div class="ch-kpi-sub">SHA-256 & MD5</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
    rec_c1, rec_c2, rec_c3 = st.columns([2, 2, 1])
    with rec_c1:
        recipe_ops = [
            "Auto-Bake All",
            "Hex Decode",
            "Hex Encode",
            "Base64 Decode",
            "Base64 Encode",
            "URL Decode",
            "URL Encode",
            "Defang IOCs",
            "Refang IOCs",
            "Compute SHA-256",
            "Extract IPs & Paths",
            "Regex Extract",
        ]
        sel_op = st.selectbox("Transformation Recipe", options=recipe_ops, key="baker_op_select")
    with rec_c2:
        param_val = st.text_input("Parameter (Regex / Delimiter)", value="", key="baker_param_input")
    with rec_c3:
        st.write("")
        st.write("")
        exec_recipe = st.button("Apply Recipe", key="baker_exec_btn", type="primary", use_container_width=True)

    if exec_recipe and input_text:
        res = ForensicPayloadBaker.apply_recipe(input_text, sel_op, param_val)
        st.markdown("<strong>Recipe Output</strong>", unsafe_allow_html=True)
        st.code(res, language="text")


# =================================================================================================
# MODULE 8: DIAGNOSTICS & GAP TAXONOMY
# =================================================================================================
elif nav_section == "Diagnostics & Gap Taxonomy":
    if coverage_stats:
        d1, d2, d3, d4, d5 = st.columns(5)
        with d1:
            st.markdown(
                f"""
                <div class="ch-kpi-card">
                    <div class="ch-kpi-label">Total Encountered</div>
                    <div class="ch-kpi-val" style="color: #0066CC;">{coverage_stats.total_records_encountered:,}</div>
                    <div class="ch-kpi-sub">100% Baseline</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with d2:
            st.markdown(
                f"""
                <div class="ch-kpi-card">
                    <div class="ch-kpi-label">Parsed Successfully</div>
                    <div class="ch-kpi-val" style="color: #059669;">{coverage_stats.successfully_parsed_records:,}</div>
                    <div class="ch-kpi-sub">{coverage_stats.parsing_success_rate}% of Total</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with d3:
            st.markdown(
                f"""
                <div class="ch-kpi-card">
                    <div class="ch-kpi-label">Malformed Lines</div>
                    <div class="ch-kpi-val" style="color: {'#DC2626' if coverage_stats.failed_records > 0 else '#475569'};">{coverage_stats.failed_records:,}</div>
                    <div class="ch-kpi-sub">{coverage_stats.parsing_failure_rate}% of Total</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with d4:
            st.markdown(
                f"""
                <div class="ch-kpi-card">
                    <div class="ch-kpi-label">Usable Timestamps</div>
                    <div class="ch-kpi-val" style="color: #0066CC;">{coverage_stats.records_with_usable_timestamps:,}</div>
                    <div class="ch-kpi-sub">{coverage_stats.timestamp_usability_rate}% of Parsed</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with d5:
            st.markdown(
                f"""
                <div class="ch-kpi-card">
                    <div class="ch-kpi-label">Assumptions Required</div>
                    <div class="ch-kpi-val" style="color: #D97706;">{coverage_stats.records_requiring_assumptions:,}</div>
                    <div class="ch-kpi-sub">{coverage_stats.assumption_rate}% of Usable</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    if diagnostics:
        cat_counts = pd.Series([d.category.value for d in diagnostics]).value_counts().reset_index()
        cat_counts.columns = ["Category", "Findings"]
        fig_gap = px.bar(
            cat_counts,
            y="Category",
            x="Findings",
            orientation="h",
            color="Findings",
            color_continuous_scale=["#0066CC", "#DC2626"],
            height=260,
        )
        fig_gap.update_layout(
            paper_bgcolor="#FFFFFF",
            plot_bgcolor="#FFFFFF",
            font=dict(color="#0F172A", size=11),
            margin=dict(l=20, r=20, t=10, b=20),
            xaxis=dict(gridcolor="#F1F5F9", linecolor="#CBD5E1"),
            yaxis=dict(gridcolor="#F1F5F9", linecolor="#CBD5E1"),
        )
        st.plotly_chart(fig_gap, use_container_width=True)

        st.markdown("<strong>Diagnostic Findings Log</strong>", unsafe_allow_html=True)
        diag_rows = []
        for d in diagnostics:
            diag_rows.append({
                "Diag ID": d.diag_id,
                "Severity": d.severity.value,
                "Category": d.category.value,
                "Target": d.affected_target,
                "Explanation": d.explanation,
                "Action": d.suggested_action,
            })
        st.dataframe(pd.DataFrame(diag_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No active diagnostic anomalies detected.")


# =================================================================================================
# MODULE 9: FORENSIC REPORTS & EXPORT
# =================================================================================================
elif nav_section == "Forensic Reports & Export":
    exp_c1, exp_c2 = st.columns([1, 2])
    with exp_c1:
        export_scope = st.radio("Export Scope", ["Complete Case Inventory", "Pinned & Key Events Only"], key="ch_exp_scope")
        export_events = [e for e in events if e.extra_fields.get("bookmarked")] if export_scope.startswith("Pinned") else events

        st.markdown(f"<div style='font-size: 12px; color: #475569; margin: 8px 0;'>Records in scope: <strong>{len(export_events)}</strong></div>", unsafe_allow_html=True)

        export_cache_key = (
            active_inv.investigation_id,
            getattr(active_inv, "last_updated_utc", ""),
            export_scope,
            len(export_events),
            len(chain_entries),
        )
        if "export_cache" not in st.session_state:
            st.session_state["export_cache"] = {}

        if st.session_state["export_cache"].get("key") == export_cache_key:
            pdf_bytes, md_text, csv_text, json_text = st.session_state["export_cache"]["data"]
        else:
            effective_coverage = coverage_stats or ParsingCoverageStats(0, 0, 0, 0, 0, 0)
            pdf_bytes = export_pdf_report(
                metadata=active_inv,
                manifest=manifest,
                events=export_events,
                diagnostics=diagnostics,
                coverage_stats=effective_coverage,
                skew_estimates=skew_estimates,
                integrity_summary=integrity_summary,
            )
            md_text = export_markdown_report(
                metadata=active_inv,
                manifest=manifest,
                events=export_events,
                diagnostics=diagnostics,
                coverage_stats=effective_coverage,
                anchors=anchors,
                skew_estimates=skew_estimates,
                integrity_summary=integrity_summary,
                audit_entries=chain_entries,
            )
            csv_text = export_timeline_csv(export_events)
            json_text = export_investigation_json(
                metadata=active_inv,
                manifest=manifest,
                events=export_events,
                diagnostics=diagnostics,
                coverage_stats=effective_coverage,
            )
            st.session_state["export_cache"] = {
                "key": export_cache_key,
                "data": (pdf_bytes, md_text, csv_text, json_text),
            }

        st.download_button(
            "Download PDF Forensic Report",
            data=pdf_bytes,
            file_name=f"{active_inv.investigation_id}_report.pdf",
            mime="application/pdf",
            use_container_width=True,
            type="primary",
        )
        st.download_button(
            "Download 18-Section Markdown Report",
            data=md_text,
            file_name=f"{active_inv.investigation_id}_report.md",
            mime="text/markdown",
            use_container_width=True,
        )
        st.download_button(
            "Download CSV Timeline Spreadsheet",
            data=csv_text,
            file_name=f"{active_inv.investigation_id}_timeline.csv",
            mime="text/csv",
            use_container_width=True,
        )
        st.download_button(
            "Download Structured JSON Case Backup",
            data=json_text,
            file_name=f"{active_inv.investigation_id}_backup.json",
            mime="application/json",
            use_container_width=True,
        )

    with exp_c2:
        st.markdown("<strong>Live Report Preview</strong>", unsafe_allow_html=True)
        prev_tab1, prev_tab2 = st.tabs(["Markdown Report Preview", "JSON Case Structure"])
        with prev_tab1:
            st.markdown(md_text[:4000] + ("\n\n*... [Full report downloaded via button above]*" if len(md_text) > 4000 else ""))
        with prev_tab2:
            st.text(json_text[:2000] + ("\n... [Truncated for preview]" if len(json_text) > 2000 else ""))


# =================================================================================================
# MODULE 10: SYNTHETIC BENCHMARK SUITE
# =================================================================================================
elif nav_section == "Synthetic Benchmark Suite":
    def _ingest_scenario_into_investigation(target_scen_key: str, inv_id: str, inv_title: str, inv_desc: str):
        sg = ScenarioGenerator(output_root=SYNTHETIC_DIR)
        scens = sg.generate_all()
        matched = find_scenario(scens, target_scen_key)
        if not matched:
            st.error(f"Failed to generate or locate scenario data for '{target_scen_key}'.")
            return False
        s_dir, gt_f = matched
        gt = ScenarioGroundTruth.load_from_file(gt_f)

        target_inv = repo.get_investigation(inv_id)
        if not target_inv:
            target_inv = repo.create_investigation(
                investigation_id=inv_id,
                title=inv_title,
                description=inv_desc,
                assigned_timezone=gt.known_timezones.get(gt.reference_source, "UTC"),
            )
        else:
            target_inv.title = inv_title
            target_inv.description = inv_desc
            target_inv.assigned_timezone = gt.known_timezones.get(gt.reference_source, "UTC")

        target_inv.reference_source = gt.reference_source
        repo.update_investigation(target_inv)

        count_ingested = 0
        for f in sorted(s_dir.iterdir()):
            if f.is_file() and not f.name.endswith(".json"):
                tz = gt.known_timezones.get(f.name, "UTC")
                pipeline.ingest_evidence_bytes(inv_id, f.name, f.read_bytes(), assigned_timezone=tz)
                count_ingested += 1

        st.session_state["pending_case_switch"] = inv_id
        st.session_state.selected_event_id = None
        if "pipeline_cache" in st.session_state:
            del st.session_state["pipeline_cache"]

        st.session_state["loaded_scenario_alert"] = {
            "name": gt.scenario_name,
            "inv_id": inv_id,
            "files": count_ingested,
            "ref_source": gt.reference_source or "Auto",
        }
        return True

    st.markdown(
        """
        <div style="font-size: 15px; font-weight: 700; color: #0F172A; margin-bottom: 4px;">Ground-Truth Synthetic Scenarios</div>
        <div style="font-size: 12px; color: #475569; margin-bottom: 12px;">Load any of the three standardized benchmark scenarios into an isolated workspace to analyze reconstructed timelines and test algorithms.</div>
        """,
        unsafe_allow_html=True,
    )

    scen_col1, scen_col2, scen_col3 = st.columns(3)
    with scen_col1:
        st.markdown(
            """
            <div style="background: #FFFFFF; border: 1px solid #DCE3EC; border-radius: 4px; padding: 12px; min-height: 110px;">
                <strong style="color: #0F172A;">Scenario 1: Clean Baseline</strong>
                <p style="font-size: 11px; color: #475569; margin: 4px 0 8px 0;">Synchronized dual hosts, Nginx access, auth, and JSONL app logs. Perfect clock alignment.</p>
                <span style="font-size: 10px; background: #EEF2F6; color: #0066CC; padding: 2px 6px; border-radius: 3px; font-weight: 600;">11 Records | 2 Hosts</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)
        if st.button("Load Scenario 1 Baseline", key="load_scen_1_btn", use_container_width=True, type="primary"):
            if _ingest_scenario_into_investigation(
                "scenario_1",
                "case_scen_1",
                "Scenario 1: Clean Baseline",
                "Synchronized dual-host baseline: Nginx web access and auth events.",
            ):
                st.rerun()

    with scen_col2:
        st.markdown(
            """
            <div style="background: #FFFFFF; border: 1px solid #DCE3EC; border-radius: 4px; padding: 12px; min-height: 110px;">
                <strong style="color: #0F172A;">Scenario 2: Clock Skew (+180s)</strong>
                <p style="font-size: 11px; color: #475569; margin: 4px 0 8px 0;">Host B has a +180s offset and EDT timezone; tests inter-host anchor discovery and robust median skew estimation.</p>
                <span style="font-size: 10px; background: #EEF2F6; color: #0066CC; padding: 2px 6px; border-radius: 3px; font-weight: 600;">8 Records | +180s Drift</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)
        if st.button("Load Scenario 2 Clock Skew", key="load_scen_2_btn", use_container_width=True, type="primary"):
            if _ingest_scenario_into_investigation(
                "scenario_2",
                "case_scen_2",
                "Scenario 2: Clock Skew (+180s)",
                "Host B with +180s clock offset and EDT timezone; testing anchor discovery.",
            ):
                st.rerun()

    with scen_col3:
        st.markdown(
            """
            <div style="background: #FFFFFF; border: 1px solid #DCE3EC; border-radius: 4px; padding: 12px; min-height: 110px;">
                <strong style="color: #0F172A;">Scenario 3: Degraded Evidence</strong>
                <p style="font-size: 11px; color: #475569; margin: 4px 0 8px 0;">Malformed lines, 45-min coverage gap, missing fields, corrupted timestamps; tests defensive diagnostic detection.</p>
                <span style="font-size: 10px; background: #EEF2F6; color: #0066CC; padding: 2px 6px; border-radius: 3px; font-weight: 600;">12 Records | 16 Diagnostics</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)
        if st.button("Load Scenario 3 Degraded", key="load_scen_3_btn", use_container_width=True, type="primary"):
            if _ingest_scenario_into_investigation(
                "scenario_3",
                "case_scen_3",
                "Scenario 3: Degraded Evidence",
                "Malformed records, 45-min coverage gap, corrupted timestamps, missing fields.",
            ):
                st.rerun()

    # Active Scenario Status Banner & Quick Navigation
    if "loaded_scenario_alert" in st.session_state:
        info = st.session_state["loaded_scenario_alert"]
        st.markdown(
            f"""
            <div style="background: #F0FDF4; border: 1px solid #86EFAC; border-left: 4px solid #16A34A; border-radius: 5px; padding: 12px 16px; margin: 16px 0 10px 0;">
                <div style="font-weight: 700; color: #15803D; font-size: 14px;">Active Workspace Loaded: {info['name']}</div>
                <div style="font-size: 12px; color: #166534; margin-top: 4px;">
                    Workspace ID: <code>{info['inv_id']}</code> &nbsp;|&nbsp; Ingested Files: <strong>{info['files']}</strong> &nbsp;|&nbsp; Reference Host: <strong>{info['ref_source']}</strong> &nbsp;|&nbsp; Active Events Indexed: <strong>{len(events)}</strong>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        act_c1, act_c2, act_c3 = st.columns(3)
        with act_c1:
            if st.button("Explore Reconstructed Timeline (Module 2)", key="goto_timeline_btn", use_container_width=True):
                st.session_state.nav_section = "Event Discovery & Timeline"
                st.rerun()
        with act_c2:
            if st.button("Inspect Entity Topology Graph (Module 3)", key="goto_topology_btn", use_container_width=True):
                st.session_state.nav_section = "Threat Hunting & Topology"
                st.rerun()
        with act_c3:
            if st.button("Analyze Clock-Skew Correction (Module 6)", key="goto_skew_btn", use_container_width=True):
                st.session_state.nav_section = "Clock-Skew Synchronization"
                st.rerun()

    st.markdown("---")
    st.markdown("<div style='font-size: 15px; font-weight: 700; color: #0F172A; margin-bottom: 4px;'>Quantitative Benchmark Evaluator Across All 3 Scenarios</div>", unsafe_allow_html=True)
    st.markdown("<div style='font-size: 12px; color: #475569; margin-bottom: 12px;'>Executes the complete ground-truth verification protocol across all three synthetic scenarios in a clean sandbox. Measures parsing coverage, inter-host skew estimation residuals, and temporal ordering concordance (Kendall's tau).</div>", unsafe_allow_html=True)

    if st.button("Execute Quantitative Benchmark Across All 3 Scenarios", type="primary", key="benchmark_eval_btn", use_container_width=True):
        with st.spinner("Executing quantitative ground-truth benchmark across Scenarios 1, 2, and 3..."):
            from src.evaluation.runner import run_evaluation
            eval_reports = run_evaluation(data_dir=DATA_DIR, synthetic_dir=SYNTHETIC_DIR, verbose=False)
            st.session_state["eval_reports"] = eval_reports
        st.toast("Benchmark evaluation completed across all 3 ground-truth scenarios.")

    if "eval_reports" in st.session_state:
        reports = st.session_state["eval_reports"]
        matrix_rows = []
        for rep in reports:
            scen_name = rep.scenario_name
            cov = rep.coverage_stats.parsing_success_rate
            ord_uncorr = rep.ordering_metric_normalized.pairwise_ordering_accuracy_percent
            ord_corr = rep.ordering_metric_corrected.pairwise_ordering_accuracy_percent if rep.ordering_metric_corrected else ord_uncorr
            tau_uncorr = rep.ordering_metric_normalized.kendall_tau
            tau_corr = rep.ordering_metric_corrected.kendall_tau if rep.ordering_metric_corrected else tau_uncorr

            skew_info = "N/A"
            if rep.skew_metrics:
                first_sk = list(rep.skew_metrics.values())[0]
                if first_sk.absolute_estimation_error_sec is not None:
                    skew_info = f"Err: {first_sk.absolute_estimation_error_sec:.2f}s ({first_sk.estimation_status})"
                else:
                    skew_info = f"{first_sk.estimation_status}"

            matrix_rows.append({
                "Scenario": scen_name,
                "Parsing Rate": f"{cov}%",
                "Skew Estimation": skew_info,
                "Uncorrected Concordance": f"{ord_uncorr:.1f}% (τ={tau_uncorr:.3f})",
                "Corrected Concordance": f"{ord_corr:.1f}% (τ={tau_corr:.3f})",
            })
        st.dataframe(pd.DataFrame(matrix_rows), use_container_width=True, hide_index=True)

        bench_json_path = DATA_DIR / "benchmark_evaluation_results.json"
        if bench_json_path.exists():
            st.download_button(
                "Download Benchmark Evaluation JSON",
                data=bench_json_path.read_bytes(),
                file_name="benchmark_evaluation_results.json",
                mime="application/json",
                key="dl_bench_json_btn",
            )


# =================================================================================================
# MODULE 11: WORKSPACE & SYSTEM SPECS
# =================================================================================================
elif nav_section == "Workspace & System Specs":
    mg_c1, mg_c2 = st.columns([1, 1])
    with mg_c1:
        st.markdown("<strong>Create New Investigation Workspace</strong>", unsafe_allow_html=True)
        new_id = st.text_input("Investigation ID", placeholder="case_2026_q4_triage", key="new_case_id_input")
        new_title = st.text_input("Investigation Title", placeholder="Project ChronoShield Triage", key="new_case_title_input")
        new_desc = st.text_area("Description", placeholder="Incident summary, target hosts, scope.", height=70, key="new_case_desc_input")
        new_tz = st.selectbox("Baseline Timezone", ["UTC", "America/New_York", "America/Chicago", "America/Los_Angeles", "Europe/London", "Asia/Kolkata", "Asia/Tokyo"], index=0, key="new_case_tz_select")

        if st.button("Create Case Workspace", type="primary", key="create_case_btn"):
            if new_id and new_title:
                try:
                    repo.create_investigation(
                        investigation_id=new_id,
                        title=new_title,
                        description=new_desc,
                        assigned_timezone=new_tz,
                    )
                    st.session_state.active_investigation_id = new_id
                    if "pipeline_cache" in st.session_state:
                        del st.session_state["pipeline_cache"]
                    st.success(f"Investigation '{new_title}' created.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Creation failed: {e}")
            else:
                st.warning("Please provide both an Investigation ID and Title.")

    with mg_c2:
        st.markdown("<strong>Manage Existing Workspaces</strong>", unsafe_allow_html=True)
        st.markdown(f"Current Active: <strong>{html_lib.escape(str(active_inv.title))}</strong> [<code>{html_lib.escape(str(active_inv.investigation_id))}</code>]", unsafe_allow_html=True)
        if st.button("Delete Active Investigation", key="delete_case_btn"):
            del_id = active_inv.investigation_id
            repo.delete_investigation(del_id)
            remaining = repo.list_investigations()
            if remaining:
                st.session_state.active_investigation_id = remaining[0].investigation_id
            else:
                repo.create_investigation("case_default", "Operation ChronoShield", assigned_timezone="UTC")
                st.session_state.active_investigation_id = "case_default"
            if "pipeline_cache" in st.session_state:
                del st.session_state["pipeline_cache"]
            st.warning(f"Deleted investigation '{del_id}'.")
            st.rerun()

    st.markdown("---")
    st.markdown("<strong>System Architecture & Forensic Defensibility</strong>", unsafe_allow_html=True)
    st.markdown(
        """
        <div style="background: #FFFFFF; border: 1px solid #DCE3EC; border-radius: 4px; padding: 12px; font-size: 12px; color: #475569; line-height: 1.6;">
            <strong>Core Forensic Invariants:</strong><br>
            1. <strong>Original Bitstream Preservation:</strong> Evidence bytes are hashed with SHA-256 before ingestion and stored in read-only local storage.<br>
            2. <strong>Tri-State Temporal Separation:</strong> Pristine raw timestamps, normalized UTC values, and clock-corrected timestamps are maintained as distinct schema fields.<br>
            3. <strong>Tamper-Evident Chain-of-Custody:</strong> Every action, file ingestion, annotation, and export is recorded in an append-only SHA-256 hash-chained audit ledger.<br>
            4. <strong>100% Offline & Air-Gapped:</strong> Zero remote dependencies, external CDNs, or cloud APIs.
        </div>
        """,
        unsafe_allow_html=True,
    )
