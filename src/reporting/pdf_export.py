"""Professional PDF Forensic Incident Report Generator using ReportLab."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from src.diagnostics.gap_analysis import DiagnosticItem, ParsingCoverageStats
from src.evidence.manifest import EvidenceManifest
from src.evidence.verification import InvestigationIntegritySummary
from src.storage.repository import InvestigationMetadata
from src.timeline.clock_skew import ClockSkewEstimate
from src.timeline.schema import Event


def export_pdf_report(
    metadata: InvestigationMetadata,
    manifest: EvidenceManifest,
    events: List[Event],
    diagnostics: List[DiagnosticItem],
    coverage_stats: ParsingCoverageStats,
    skew_estimates: Optional[Dict[str, ClockSkewEstimate]] = None,
    integrity_summary: Optional[InvestigationIntegritySummary] = None,
    output_path: Optional[Union[str, Path]] = None,
) -> bytes:
    """Generate a publication-grade PDF incident report.
    
    Returns raw PDF bytes and optionally writes to output_path.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#1e293b"),
    )
    h2_style = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=10,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )
    table_cell = ParagraphStyle(
        "Cell",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1e293b"),
    )
    table_header = ParagraphStyle(
        "CellHeader",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        fontName="Helvetica-Bold",
        textColor=colors.white,
    )
    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["Italic"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#64748b"),
    )

    elements = []

    # Title & Subtitle
    elements.append(Paragraph("Chronica Forensic Incident Investigation Report", title_style))
    elements.append(Paragraph("AIORI-3 PS-013 Incident Timeline & Evidence Collection Pipeline", body_style))
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=10))

    # Case Summary Table
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    case_info = [
        [Paragraph("<b>Investigation Title:</b>", table_cell), Paragraph(metadata.title, table_cell)],
        [Paragraph("<b>Case ID:</b>", table_cell), Paragraph(f"<code>{metadata.investigation_id}</code>", table_cell)],
        [Paragraph("<b>Created UTC:</b>", table_cell), Paragraph(metadata.created_at_utc, table_cell)],
        [Paragraph("<b>Report Generated:</b>", table_cell), Paragraph(now_utc, table_cell)],
        [Paragraph("<b>Total Evidence Files:</b>", table_cell), Paragraph(str(len(manifest.entries)), table_cell)],
        [Paragraph("<b>Timeline Events:</b>", table_cell), Paragraph(f"{len(events):,} records", table_cell)],
    ]
    t_case = Table(case_info, colWidths=[120, 420])
    t_case.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(t_case)
    elements.append(Spacer(1, 12))

    # Evidence Manifest & Integrity Status
    elements.append(Paragraph("Evidence Preservation & Integrity Audit", h2_style))
    manifest_rows = [[
        Paragraph("Evidence ID", table_header),
        Paragraph("Original Filename", table_header),
        Paragraph("Size (Bytes)", table_header),
        Paragraph("Format", table_header),
        Paragraph("SHA-256 Digest (Truncated)", table_header),
        Paragraph("Integrity", table_header),
    ]]

    # Map verification results by evidence_id
    verif_map = {}
    if integrity_summary:
        for r in integrity_summary.results:
            verif_map[r.evidence_id] = r.status

    for ent in manifest.entries:
        v_status = verif_map.get(ent.evidence_id, "UNVERIFIED")
        status_color = "#16a34a" if v_status == "VERIFIED" else ("#dc2626" if v_status == "MISMATCH" else "#ca8a04")
        manifest_rows.append([
            Paragraph(f"<code>{ent.evidence_id}</code>", table_cell),
            Paragraph(ent.original_filename, table_cell),
            Paragraph(f"{ent.file_size_bytes:,}", table_cell),
            Paragraph(ent.detected_format or "Unknown", table_cell),
            Paragraph(f"<code>{ent.sha256_digest[:16]}...{ent.sha256_digest[-8:]}</code>", table_cell),
            Paragraph(f"<font color='{status_color}'><b>{v_status}</b></font>", table_cell),
        ])

    if len(manifest_rows) > 1:
        t_manifest = Table(manifest_rows, colWidths=[70, 110, 60, 60, 170, 70])
        t_manifest.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        elements.append(t_manifest)
    else:
        elements.append(Paragraph("<i>No evidence files collected.</i>", body_style))
    elements.append(Spacer(1, 10))

    # Coverage Statistics
    elements.append(Paragraph("Parsing Coverage & Quality Statistics", h2_style))
    stats_rows = [
        [Paragraph("<b>Metric</b>", table_header), Paragraph("<b>Count</b>", table_header), Paragraph("<b>Percentage / Denominator</b>", table_header)],
        [Paragraph("Total Records Encountered", table_cell), Paragraph(f"{coverage_stats.total_records_encountered:,}", table_cell), Paragraph("100% (Baseline)", table_cell)],
        [Paragraph("Successfully Parsed Records", table_cell), Paragraph(f"{coverage_stats.successfully_parsed_records:,}", table_cell), Paragraph(f"{coverage_stats.parsing_success_rate}% of total", table_cell)],
        [Paragraph("Failed / Malformed Records", table_cell), Paragraph(f"{coverage_stats.failed_records:,}", table_cell), Paragraph(f"{coverage_stats.parsing_failure_rate}% of total", table_cell)],
        [Paragraph("Usable Timestamps", table_cell), Paragraph(f"{coverage_stats.records_with_usable_timestamps:,}", table_cell), Paragraph(f"{coverage_stats.timestamp_usability_rate}% of parsed", table_cell)],
        [Paragraph("Assumptions Required (TZ/Year)", table_cell), Paragraph(f"{coverage_stats.records_requiring_assumptions:,}", table_cell), Paragraph(f"{coverage_stats.assumption_rate}% of usable", table_cell)],
    ]
    t_stats = Table(stats_rows, colWidths=[200, 100, 240])
    t_stats.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    elements.append(t_stats)
    elements.append(Spacer(1, 10))

    # Clock Skew Analysis Summary
    if skew_estimates:
        elements.append(Paragraph("Clock-Skew Analysis & Offsets", h2_style))
        skew_rows = [[
            Paragraph("Target Source", table_header),
            Paragraph("Reference", table_header),
            Paragraph("Anchors", table_header),
            Paragraph("Offset (s)", table_header),
            Paragraph("MAD Spread", table_header),
            Paragraph("Status", table_header),
        ]]
        for host, est in skew_estimates.items():
            off_str = f"{est.estimated_offset_sec:+.3f}s" if est.estimated_offset_sec is not None else "N/A"
            mad_str = f"±{est.spread_mad_sec:.3f}s" if est.spread_mad_sec is not None else "N/A"
            skew_rows.append([
                Paragraph(host, table_cell),
                Paragraph(est.reference_source, table_cell),
                Paragraph(str(est.anchor_count), table_cell),
                Paragraph(f"<b>{off_str}</b>", table_cell),
                Paragraph(mad_str, table_cell),
                Paragraph(est.status, table_cell),
            ])
        t_skew = Table(skew_rows, colWidths=[110, 110, 50, 70, 70, 130])
        t_skew.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        elements.append(t_skew)
        elements.append(Spacer(1, 10))

    # Timeline Highlights (First 25 events)
    elements.append(Paragraph(f"Chronological Timeline Highlights (Showing {min(len(events), 25)} of {len(events):,} events)", h2_style))
    timeline_rows = [[
        Paragraph("Normalized UTC", table_header),
        Paragraph("Source", table_header),
        Paragraph("Level", table_header),
        Paragraph("Category", table_header),
        Paragraph("Description", table_header),
        Paragraph("Provenance", table_header),
    ]]
    for ev in events[:25]:
        ts = ev.normalized_utc_iso or "UNRESOLVED"
        ts_short = ts.replace("T", " ")[:19] if "T" in ts else ts[:19]
        prov = f"{ev.original_filename}:L{ev.line_number}"
        desc = ev.description[:60] + ("..." if len(ev.description) > 60 else "")
        timeline_rows.append([
            Paragraph(f"<code>{ts_short}</code>", table_cell),
            Paragraph(ev.source_host or ev.source_app or "-", table_cell),
            Paragraph(ev.severity, table_cell),
            Paragraph(ev.category, table_cell),
            Paragraph(desc, table_cell),
            Paragraph(f"<code>{prov}</code>", table_cell),
        ])

    if len(timeline_rows) > 1:
        t_tl = Table(timeline_rows, colWidths=[100, 70, 50, 70, 170, 80])
        t_tl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        elements.append(t_tl)
    elements.append(Spacer(1, 10))

    # Forensic Disclaimer
    elements.append(Paragraph("Forensic Limitations & Methodology Notice", h2_style))
    disclaimer_text = (
        "This report was compiled automatically by Chronica. All SHA-256 digests reflect file contents "
        "at collection time. Clock corrections represent defensible statistical estimations derived from "
        "paired anchor observations and do not constitute physical hardware clock calibration certificates. "
        "Quiet periods between events reflect logging pauses rather than verified log deletion. "
        "Records should be corroborated before submission in judicial proceedings."
    )
    elements.append(Paragraph(disclaimer_text, disclaimer_style))

    doc.build(elements)
    pdf_bytes = buffer.getvalue()

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes
