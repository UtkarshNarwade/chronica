"""Digital Evidence Manifest schema, serialization, and integrity tracking.

Records all ingested evidence files with their cryptographic hashes, sizes,
collection timestamps, assigned parsers, and status in a tamper-detectable JSON format.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.evidence.hashing import calculate_sha256_bytes

MANIFEST_VERSION = "1.0.0"


class ManifestIntegrityError(Exception):
    """Raised when an evidence manifest's cryptographic digest does not match its contents."""


@dataclass
class EvidenceFileEntry:
    """Metadata record for a single collected evidence file."""
    evidence_id: str
    original_filename: str
    stored_filename: str
    file_size_bytes: int
    sha256_digest: str
    collection_time_utc: str
    hash_algorithm: str = "sha256"
    detected_format: Optional[str] = None
    selected_parser: Optional[str] = None
    ingestion_status: str = "PRESERVED"  # PRESERVED, PARSED, PARTIAL, ERROR
    record_count: int = 0
    assigned_timezone: Optional[str] = None  # e.g., 'UTC', 'America/New_York'
    notes: str = ""

    @property
    def collection_timestamp_utc(self) -> str:
        return self.collection_time_utc

    @property
    def stored_relpath(self) -> str:
        return self.stored_filename

    def to_dict(self) -> Dict[str, Any]:

        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EvidenceFileEntry:
        import dataclasses
        known_fields = {f.name for f in dataclasses.fields(cls)}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)



@dataclass
class EvidenceManifest:
    """Forensic evidence manifest documenting all items collected in an investigation."""
    investigation_id: str
    manifest_version: str = MANIFEST_VERSION
    created_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_updated_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    entries: List[EvidenceFileEntry] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    manifest_sha256: Optional[str] = None

    def add_entry(self, entry: EvidenceFileEntry) -> None:
        """Add or update an evidence entry in the manifest."""
        # Replace if existing evidence_id
        self.entries = [e for e in self.entries if e.evidence_id != entry.evidence_id]
        self.entries.append(entry)
        self.last_updated_utc = datetime.now(timezone.utc).isoformat()

    def get_entry(self, evidence_id: str) -> Optional[EvidenceFileEntry]:
        """Find an entry by its evidence ID."""
        for e in self.entries:
            if e.evidence_id == evidence_id:
                return e
        return None

    def calculate_manifest_digest(self) -> str:
        """Calculate a SHA-256 digest of the manifest's normalized content.
        
        Useful for external anchoring or recording in an offline logbook.
        """
        raw_bytes = json.dumps(
            self.to_dict(include_digest=False), sort_keys=True, indent=2
        ).encode("utf-8")
        return calculate_sha256_bytes(raw_bytes)

    def to_dict(self, include_digest: bool = True) -> Dict[str, Any]:
        """Convert manifest to a structured dictionary."""
        d = {
            "investigation_id": self.investigation_id,
            "manifest_version": self.manifest_version,
            "created_at_utc": self.created_at_utc,
            "last_updated_utc": self.last_updated_utc,
            "total_files": len(self.entries),
            "total_bytes": sum(e.file_size_bytes for e in self.entries),
            "entries": [e.to_dict() for e in self.entries],
            "metadata": self.metadata,
        }
        if include_digest:
            digest = self.calculate_manifest_digest()
            self.manifest_sha256 = digest
            d["manifest_sha256"] = digest
        return d

    def save_to_file(self, target_path: Union[str, Path]) -> None:
        """Serialize and save the manifest as indented JSON."""
        path = Path(target_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.to_dict(include_digest=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load_from_file(cls, path: Union[str, Path], verify_digest: bool = True) -> EvidenceManifest:
        """Load manifest from an existing JSON file, optionally verifying its internal SHA-256 digest."""
        file_path = Path(path)
        if not file_path.is_file():
            raise FileNotFoundError(f"Manifest not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        entries = [
            EvidenceFileEntry.from_dict(e) for e in data.get("entries", [])
        ]
        recorded_digest = data.get("manifest_sha256")
        manifest = cls(
            investigation_id=data.get("investigation_id", "unknown"),
            manifest_version=data.get("manifest_version", MANIFEST_VERSION),
            created_at_utc=data.get("created_at_utc", ""),
            last_updated_utc=data.get("last_updated_utc", ""),
            entries=entries,
            metadata=data.get("metadata", {}),
            manifest_sha256=recorded_digest,
        )

        if verify_digest and recorded_digest is not None:
            calculated_digest = manifest.calculate_manifest_digest()
            if recorded_digest.lower() != calculated_digest.lower():
                raise ManifestIntegrityError(
                    f"Manifest integrity verification failed for '{file_path}': "
                    f"recorded SHA-256 '{recorded_digest}' does not match computed SHA-256 '{calculated_digest}'."
                )

        return manifest
