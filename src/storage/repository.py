"""Investigation lifecycle and file-system repository manager.

Maintains strict separation between distinct investigations, managing evidence directories,
manifest files, SQLite structured storage, and case notes.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.evidence.collector import EvidenceCollector
from src.evidence.manifest import EvidenceFileEntry, EvidenceManifest
from src.storage.database import DatabaseManager
from src.timeline.schema import Event


@dataclass
class InvestigationMetadata:
    """Metadata describing an active or saved investigation."""
    investigation_id: str
    title: str
    description: str
    created_at_utc: str
    last_updated_utc: str
    notes: str = ""
    assigned_timezone: str = "UTC"
    reference_source: Optional[str] = None
    clock_skew_correction_enabled: bool = True
    manual_anchors: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InvestigationMetadata:
        # Handle missing fields for backward compatibility
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known_fields}
        if "manual_anchors" not in filtered:
            filtered["manual_anchors"] = []
        return cls(**filtered)


class InvestigationRepository:
    """Repository handling filesystem and database operations for forensic investigations."""

    def __init__(self, data_root: Union[str, Path]) -> None:
        self.data_root = Path(data_root)
        self.investigations_dir = self.data_root / "investigations"
        self.investigations_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_root / "chronica.db"
        self.db = DatabaseManager(self.db_path)

    @staticmethod
    def sanitize_investigation_id(investigation_id: str) -> str:
        """Validate and sanitize an investigation_id to prevent path traversal.

        Strips whitespace, validates alphanumeric/underscore/hyphen characters,
        and enforces a maximum length of 128 characters.

        Raises:
            ValueError: If the investigation_id is invalid.
        """
        clean_id = investigation_id.strip() if investigation_id else ""
        if not clean_id:
            raise ValueError(
                f"Invalid investigation_id '{investigation_id}': must not be empty or whitespace."
            )
        if not re.match(r"^[a-zA-Z0-9_\-]+$", clean_id):
            raise ValueError(
                f"Invalid investigation_id '{investigation_id}': only alphanumeric characters, "
                f"underscores, and hyphens are allowed."
            )
        if len(clean_id) > 128:
            raise ValueError(
                f"Invalid investigation_id '{investigation_id}': exceeds maximum length of 128 characters."
            )
        return clean_id

    def _get_inv_dir(self, investigation_id: str) -> Path:
        """Get investigation directory with path traversal protection."""
        clean_id = self.sanitize_investigation_id(investigation_id)
        target = (self.investigations_dir / clean_id).resolve()
        base = self.investigations_dir.resolve()
        if not target.is_relative_to(base) or target == base:
            raise ValueError(
                f"Investigation ID '{investigation_id}' resolves outside investigations directory."
            )
        return target

    def list_investigations(self) -> List[InvestigationMetadata]:
        """List all saved investigations ordered by creation time."""
        results: List[InvestigationMetadata] = []
        for inv_path in self.investigations_dir.iterdir():
            if inv_path.is_dir():
                meta_file = inv_path / "investigation.json"
                if meta_file.is_file():
                    try:
                        with open(meta_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            results.append(InvestigationMetadata.from_dict(data))
                    except Exception:
                        pass
        return sorted(results, key=lambda m: m.created_at_utc, reverse=True)

    def create_investigation(
        self,
        investigation_id: str,
        title: str,
        description: str = "",
        notes: str = "",
        assigned_timezone: str = "UTC",
        reference_source: Optional[str] = None,
    ) -> InvestigationMetadata:
        """Create a new isolated investigation container."""
        inv_dir = self._get_inv_dir(investigation_id)
        if inv_dir.exists():
            raise ValueError(f"Investigation with ID '{investigation_id}' already exists.")

        inv_dir.mkdir(parents=True, exist_ok=True)
        evidence_dir = inv_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)

        now_utc = datetime.now(timezone.utc).isoformat()
        meta = InvestigationMetadata(
            investigation_id=investigation_id,
            title=title,
            description=description,
            created_at_utc=now_utc,
            last_updated_utc=now_utc,
            notes=notes,
            assigned_timezone=assigned_timezone,
            reference_source=reference_source,
        )

        # Save metadata JSON
        with open(inv_dir / "investigation.json", "w", encoding="utf-8") as f:
            json.dump(meta.to_dict(), f, indent=2)

        # Initialize empty evidence manifest
        manifest = EvidenceManifest(investigation_id=investigation_id)
        manifest.save_to_file(inv_dir / "manifest.json")

        # Log CASE_CREATED audit entry
        try:
            ledger = self.get_audit_ledger(investigation_id)
            ledger.append(
                action="CASE_CREATED",
                summary=f"Investigation '{title}' created.",
                details={"investigation_id": investigation_id, "title": title},
            )
        except Exception:
            pass  # Non-fatal: audit ledger failure doesn't block case creation

        return meta

    def get_investigation(self, investigation_id: str) -> Optional[InvestigationMetadata]:
        """Load metadata for a specific investigation."""
        meta_file = self._get_inv_dir(investigation_id) / "investigation.json"
        if not meta_file.is_file():
            return None
        with open(meta_file, "r", encoding="utf-8") as f:
            return InvestigationMetadata.from_dict(json.load(f))

    def update_investigation(self, meta: InvestigationMetadata) -> None:
        """Update metadata, settings, or notes for an investigation."""
        inv_dir = self._get_inv_dir(meta.investigation_id)
        if not inv_dir.is_dir():
            raise FileNotFoundError(f"Investigation '{meta.investigation_id}' does not exist.")

        meta.last_updated_utc = datetime.now(timezone.utc).isoformat()
        with open(inv_dir / "investigation.json", "w", encoding="utf-8") as f:
            json.dump(meta.to_dict(), f, indent=2)

    def delete_investigation(self, investigation_id: str, delete_evidence_files: bool = True) -> None:
        """Delete an investigation, its SQLite events, and optionally its evidence files."""
        # 1. Delete events from SQLite
        self.db.delete_investigation_events(investigation_id)

        # 2. Delete filesystem directory
        inv_dir = self._get_inv_dir(investigation_id)
        if inv_dir.is_dir():
            import stat
            for p in inv_dir.rglob("*"):
                try:
                    p.chmod(stat.S_IWRITE)
                except Exception:
                    pass
            shutil.rmtree(inv_dir, ignore_errors=True)

    def get_evidence_collector(self, investigation_id: str) -> EvidenceCollector:
        """Get an EvidenceCollector targeted at this investigation's evidence folder."""
        evidence_dir = self._get_inv_dir(investigation_id) / "evidence"
        return EvidenceCollector(evidence_dir=evidence_dir)

    def get_manifest(self, investigation_id: str) -> EvidenceManifest:
        """Load the evidence manifest for an investigation."""
        manifest_path = self._get_inv_dir(investigation_id) / "manifest.json"
        if manifest_path.is_file():
            return EvidenceManifest.load_from_file(manifest_path)
        return EvidenceManifest(investigation_id=investigation_id)

    def save_manifest(self, investigation_id: str, manifest: EvidenceManifest) -> None:
        """Save the evidence manifest."""
        manifest_path = self._get_inv_dir(investigation_id) / "manifest.json"
        manifest.save_to_file(manifest_path)

    def get_evidence_dir(self, investigation_id: str) -> Path:
        """Return the absolute path to preserved evidence."""
        return self._get_inv_dir(investigation_id) / "evidence"

    def get_evidence_file_path(self, investigation_id: str, evidence_id: str) -> Optional[Path]:
        """Return the path to a specific evidence file on disk."""
        manifest = self.get_manifest(investigation_id)
        entry = manifest.get_entry(evidence_id)
        ev_dir = self.get_evidence_dir(investigation_id)
        inv_dir = self._get_inv_dir(investigation_id)

        if entry:
            stored = getattr(entry, "stored_filename", None) or getattr(entry, "stored_relpath", None)
            if stored:
                p = ev_dir / stored
                if p.is_file():
                    return p
                p2 = inv_dir / stored
                if p2.is_file():
                    return p2
            relpath = getattr(entry, "stored_relpath", None)
            if relpath:
                p_rel = inv_dir / relpath
                if p_rel.is_file():
                    return p_rel
                p_rel2 = ev_dir / relpath
                if p_rel2.is_file():
                    return p_rel2

            if entry.original_filename:
                cand = ev_dir / entry.original_filename
                if cand.is_file():
                    return cand
                cand2 = inv_dir / entry.original_filename
                if cand2.is_file():
                    return cand2

        # Check any file in ev_dir starting with evidence_id_ or matching evidence_id
        if ev_dir.is_dir():
            prefix = f"{evidence_id}_"
            for f in ev_dir.iterdir():
                if f.is_file() and (f.name.startswith(prefix) or f.name == f"{evidence_id}.bin" or f.name == evidence_id):
                    return f

        cand = ev_dir / f"{evidence_id}.bin"
        if cand.is_file():
            return cand
        cand_bare = ev_dir / evidence_id
        if cand_bare.is_file():
            return cand_bare
        return None

    def verify_evidence_integrity(self, investigation_id: str):
        """Verify SHA-256 hashes of all preserved evidence files in the investigation."""
        from src.evidence.verification import verify_evidence_integrity
        ev_dir = self.get_evidence_dir(investigation_id)
        manifest = self.get_manifest(investigation_id)
        return verify_evidence_integrity(ev_dir, manifest)

    def get_audit_ledger(self, investigation_id: str):
        """Get the AuditChainLedger for a specific investigation."""
        from src.evidence.audit_chain import AuditChainLedger
        return AuditChainLedger(self._get_inv_dir(investigation_id))

    def save_events(self, investigation_id: str, events: List[Event]) -> None:
        """Save events to the database and update investigation timestamp."""
        self.db.save_events(investigation_id, events)
        meta = self.get_investigation(investigation_id)
        if meta:
            self.update_investigation(meta)

    def load_events(self, investigation_id: str) -> List[Event]:
        """Load events from the database."""
        return self.db.get_events(investigation_id)

    def annotate_event(
        self,
        investigation_id: str,
        event_id: str,
        bookmarked: Optional[bool] = None,
        tags: Optional[List[str]] = None,
        analyst_note: Optional[str] = None,
    ) -> Optional[Event]:
        """Update investigator annotations (bookmark, tags, note) for an event.

        Annotations are stored inside extra_fields to maintain schema compatibility.
        An EVENT_ANNOTATED audit entry is also logged.

        Returns the updated Event, or None if not found.
        """
        target = self.db.get_event_by_id(investigation_id, event_id)
        if target is None:
            return None

        # Update extra_fields with annotation data
        from src.timeline.schema import Event as EventSchema
        import copy
        ev_dict = target.to_dict()
        ev_clone = EventSchema.from_dict(ev_dict)

        if bookmarked is not None:
            ev_clone.extra_fields["bookmarked"] = bookmarked
        if tags is not None:
            ev_clone.extra_fields["tags"] = tags
        if analyst_note is not None:
            ev_clone.extra_fields["analyst_note"] = analyst_note

        self.db.save_events(investigation_id, [ev_clone])

        # Log audit entry
        try:
            ledger = self.get_audit_ledger(investigation_id)
            changes: Dict[str, Any] = {"event_id": event_id}
            if bookmarked is not None:
                changes["bookmarked"] = bookmarked
            if tags is not None:
                changes["tags"] = tags
            if analyst_note is not None:
                changes["analyst_note_length"] = len(analyst_note)
            ledger.append(
                action="EVENT_ANNOTATED",
                summary=f"Event '{event_id}' annotated.",
                details=changes,
            )
        except Exception:
            pass

        return ev_clone
