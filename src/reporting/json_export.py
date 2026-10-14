"""Machine-readable JSON export for forensic investigations."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.diagnostics.gap_analysis import DiagnosticItem, ParsingCoverageStats
from src.evidence.manifest import EvidenceManifest
from src.evidence.verification import InvestigationIntegritySummary
from src.storage.repository import InvestigationMetadata
from src.timeline.clock_skew import ClockSkewEstimate
from src.timeline.schema import Event
from src.timeline.search import FilterCriteria


def export_investigation_json(
    metadata: InvestigationMetadata,
    manifest: EvidenceManifest,
    events: List[Event],
    diagnostics: List[DiagnosticItem],
    coverage_stats: ParsingCoverageStats,
    skew_estimates: Optional[Dict[str, ClockSkewEstimate]] = None,
    integrity_summary: Optional[InvestigationIntegritySummary] = None,
    filter_criteria: Optional[FilterCriteria] = None,
) -> str:
    """Generate a comprehensive JSON representation of the investigation."""
    data: Dict[str, Any] = {
        "export_metadata": {
            "format": "Chronica Forensic Investigation Export",
            "version": "1.0.0",
            "exported_at_utc": datetime.now(timezone.utc).isoformat(),
            "scope": "Filtered View" if (filter_criteria and not filter_criteria.is_empty()) else "Complete Investigation",
            "filter_applied": filter_criteria.__dict__ if filter_criteria else None,
        },
        "investigation": metadata.to_dict(),
        "evidence_manifest": manifest.to_dict(include_digest=True),
        "evidence_integrity": {
            "verified_all": integrity_summary.all_verified if integrity_summary else False,
            "verification_time_utc": integrity_summary.verification_time_utc if integrity_summary else None,
            "summary": {
                "total_files": integrity_summary.total_files if integrity_summary else 0,
                "verified": integrity_summary.verified_files if integrity_summary else 0,
                "mismatched": integrity_summary.mismatched_files if integrity_summary else 0,
                "unavailable": integrity_summary.unavailable_files if integrity_summary else 0,
            } if integrity_summary else None,
            "results": [r.__dict__ for r in integrity_summary.results] if integrity_summary else [],
        },
        "coverage_statistics": coverage_stats.to_dict(),
        "clock_skew_analysis": {
            k: v.to_dict() for k, v in (skew_estimates or {}).items()
        },
        "diagnostics": [d.to_dict() for d in diagnostics],
        "timeline_events_count": len(events),
        "timeline_events": [e.to_dict() for e in events],
        "forensic_disclaimer": (
            "This export contains digital forensic records normalized and correlated "
            "by the Chronica system. Integrity hashes confirm preservation from time of collection. "
            "Timing corrections reflect estimated offsets based on documented anchors and do not represent "
            "physical hardware clock certifications. Uncorrelated or unparsed records are preserved separately."
        ),
    }

    return json.dumps(data, indent=2, default=str)
