"""Investigation lifecycle and file-system repository manager.

Maintains strict separation between distinct investigations, managing evidence directories,
manifest files, SQLite structured storage, and case notes.
"""

from __future__ import annotations

import json
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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InvestigationMetadata:
        return cls(**data)


class InvestigationRepository:
    """Repository handling filesystem and database operations for forensic investigations."""

    def __init__(self, data_root: Union[str, Path]) -> None:
        self.data_root = Path(data_root)
        self.investigations_dir = self.data_root / "investigations"
        self.investigations_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_root / "chronica.db"
        self.db = DatabaseManager(self.db_path)

    def _get_inv_dir(self, investigation_id: str) -> Path:
        return self.investigations_dir / investigation_id

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
        )

        # Save metadata JSON
        with open(inv_dir / "investigation.json", "w", encoding="utf-8") as f:
            json.dump(meta.to_dict(), f, indent=2)

        # Initialize empty evidence manifest
        manifest = EvidenceManifest(investigation_id=investigation_id)
        manifest.save_to_file(inv_dir / "manifest.json")

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

    def save_events(self, investigation_id: str, events: List[Event]) -> None:
        """Save events to the database and update investigation timestamp."""
        self.db.save_events(investigation_id, events)
        meta = self.get_investigation(investigation_id)
        if meta:
            self.update_investigation(meta)

    def load_events(self, investigation_id: str) -> List[Event]:
        """Load events from the database."""
        return self.db.get_events(investigation_id)
