"""Machine-readable JSON export and backup restoration for forensic investigations."""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from src.diagnostics.gap_analysis import DiagnosticItem, ParsingCoverageStats
from src.evidence.hashing import calculate_sha256_bytes
from src.evidence.manifest import EvidenceManifest
from src.evidence.verification import InvestigationIntegritySummary
from src.storage.repository import InvestigationMetadata, InvestigationRepository
from src.timeline.clock_skew import ClockSkewEstimate
from src.timeline.schema import Event
from src.timeline.search import FilterCriteria


def export_investigation_json(
    metadata: InvestigationMetadata,
    manifest: EvidenceManifest,
    events: List[Event],
    diagnostics: List[DiagnosticItem],
    coverage_stats: Optional[ParsingCoverageStats] = None,
    skew_estimates: Optional[Dict[str, ClockSkewEstimate]] = None,
    integrity_summary: Optional[InvestigationIntegritySummary] = None,
    filter_criteria: Optional[FilterCriteria] = None,
    audit_entries: Optional[List[Any]] = None,
    include_evidence_bytes: bool = True,
    repo: Optional[InvestigationRepository] = None,
    passphrase: Optional[str] = None,
    auth_file: Optional[Path] = None,
) -> str:
    """Generate a comprehensive JSON representation of the investigation."""
    from src.security.passphrase_gate import check_destructive_action_authorized

    effective_auth = auth_file or (repo.auth_file if repo else None)
    check_destructive_action_authorized("export_investigation", passphrase, effective_auth)
    if coverage_stats is None:
        coverage_stats = ParsingCoverageStats(
            total_records_encountered=len(events),
            successfully_parsed_records=len(events),
            failed_records=0,
            records_with_usable_timestamps=len(events),
            records_requiring_assumptions=0,
            unresolved_records=0,
        )

    # Resolve audit entries if not explicitly provided
    resolved_audit_entries: List[Dict[str, Any]] = []
    if audit_entries is not None:
        for entry in audit_entries:
            if hasattr(entry, "to_dict"):
                resolved_audit_entries.append(entry.to_dict())
            elif isinstance(entry, dict):
                resolved_audit_entries.append(entry)
    elif repo is not None:
        try:
            ledger = repo.get_audit_ledger(metadata.investigation_id)
            resolved_audit_entries = [e.to_dict() for e in ledger.get_entries()]
        except Exception:
            resolved_audit_entries = []

    # Preserve evidence payloads for complete restorable backup
    evidence_files: List[Dict[str, Any]] = []
    if include_evidence_bytes and repo is not None:
        for entry in manifest.entries:
            ev_path = repo.get_evidence_file_path(metadata.investigation_id, entry.evidence_id)
            if ev_path and ev_path.is_file():
                raw_bytes = ev_path.read_bytes()
                evidence_files.append({
                    "evidence_id": entry.evidence_id,
                    "original_filename": entry.original_filename,
                    "stored_filename": getattr(entry, "stored_filename", None) or entry.original_filename,
                    "file_size_bytes": len(raw_bytes),
                    "sha256": calculate_sha256_bytes(raw_bytes),
                    "data_base64": base64.b64encode(raw_bytes).decode("ascii"),
                })

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
        "audit_ledger": resolved_audit_entries,
        "evidence_files": evidence_files,
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


def restore_investigation_from_json(
    json_str_or_data: Union[str, Dict[str, Any]],
    repo: InvestigationRepository,
    passphrase: Optional[str] = None,
    auth_file: Optional[Path] = None,
) -> InvestigationMetadata:
    """Restore an investigation from a full structured JSON backup.

    Reconstructs:
    - Investigation metadata
    - Preserved evidence files with SHA-256 verification and 0444 read-only permissions
    - Manifest with integrity digest verification
    - Database timeline events
    - Audit chain-of-custody ledger with head anchor restoration
    - Appends an audited INVESTIGATION_RESTORED action
    """
    from src.security.passphrase_gate import check_destructive_action_authorized

    effective_auth = auth_file or repo.auth_file
    check_destructive_action_authorized("restore_investigation", passphrase, effective_auth)
    if isinstance(json_str_or_data, str):
        data = json.loads(json_str_or_data)
    else:
        data = json_str_or_data

    inv_data = data.get("investigation")
    if not inv_data or "investigation_id" not in inv_data:
        raise ValueError("Invalid backup structure: missing 'investigation' or 'investigation_id'.")

    inv_id = str(inv_data["investigation_id"])

    # 1. Initialize or load investigation metadata
    inv_dir = repo._get_inv_dir(inv_id)
    inv_dir.mkdir(parents=True, exist_ok=True)
    meta = InvestigationMetadata.from_dict(inv_data)
    with open(inv_dir / "investigation.json", "w", encoding="utf-8") as f:
        json.dump(meta.to_dict(), f, indent=2)
    repo.db.upsert_investigation(meta)

    # 2. Restore preserved evidence files
    ev_dir = repo.get_evidence_dir(inv_id)
    ev_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(ev_dir, 0o700)
    except OSError:
        pass

    for f_info in data.get("evidence_files", []):
        stored_name = f_info.get("stored_filename") or f_info.get("original_filename")
        b64_content = f_info.get("data_base64")
        if not stored_name or not b64_content:
            continue
        raw_bytes = base64.b64decode(b64_content)
        expected_sha = f_info.get("sha256")
        if expected_sha:
            computed_sha = calculate_sha256_bytes(raw_bytes)
            if computed_sha.lower() != expected_sha.lower():
                raise ValueError(
                    f"Evidence payload integrity check failed for '{stored_name}': "
                    f"expected {expected_sha}, computed {computed_sha}"
                )
        dest_file = ev_dir / stored_name
        if dest_file.exists():
            try:
                dest_file.chmod(0o666)
            except OSError:
                pass
        dest_file.write_bytes(raw_bytes)
        try:
            dest_file.chmod(0o444)
        except OSError:
            pass

    # 3. Restore manifest
    manifest_data = data.get("evidence_manifest")
    if manifest_data:
        manifest = EvidenceManifest.from_dict(manifest_data, verify_digest=True)
        repo.save_manifest(inv_id, manifest)

    # 4. Restore normalized timeline events
    events_data = data.get("timeline_events", [])
    if events_data:
        events = [Event.from_dict(ed) for ed in events_data]
        repo.save_events(inv_id, events)

    # 5. Restore audit ledger chain and dual anchors
    ledger = repo.get_audit_ledger(inv_id)
    audit_chain_data = data.get("audit_ledger", [])
    if audit_chain_data:
        with open(ledger.ledger_path, "w", encoding="utf-8") as lf:
            for item in audit_chain_data:
                lf.write(json.dumps(item) + "\n")
        last_block = audit_chain_data[-1]
        ledger._update_anchors(
            seq_id=int(last_block["seq_id"]),
            head_hash=str(last_block["entry_hash"]),
            timestamp_utc=str(last_block.get("timestamp_utc", "")),
        )

    # 6. Log restoral event in audit ledger (Rule 10)
    ledger.append(
        action="INVESTIGATION_RESTORED",
        summary=f"Investigation '{inv_id}' successfully restored from structured backup",
        details={
            "restored_at_utc": datetime.now(timezone.utc).isoformat(),
            "event_count": len(events_data),
            "evidence_files_count": len(data.get("evidence_files", [])),
        },
    )

    return meta
