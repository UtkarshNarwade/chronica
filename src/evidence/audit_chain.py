"""Tamper-Evident Chain-of-Custody Audit Ledger.

Implements a hash-chained append-only ledger that records all significant
investigator actions, evidence ingestions, and integrity verifications,
providing a cryptographically-linked, tamper-evident chain of custody.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from src.evidence.hashing import calculate_sha256_bytes


@dataclass
class AuditEntry:
    """A single entry in the chain-of-custody audit ledger."""
    seq_id: int
    timestamp_utc: str
    action: str  # CASE_CREATED, EVIDENCE_INGESTED, INTEGRITY_VERIFIED, CLOCK_SKEW_UPDATED,
                 # MANUAL_ANCHOR_ADDED, EVENT_ANNOTATED, REPORT_EXPORTED, TAMPER_SIMULATED
    actor: str
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = "0" * 64
    entry_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuditEntry:
        import dataclasses
        known_fields = {f.name for f in dataclasses.fields(cls)}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)


class AuditChainLedger:
    """Append-only, hash-chained chain-of-custody audit ledger.

    Stores entries in <investigation_dir>/audit_chain.jsonl.
    Each entry's hash is computed over: seq_id, timestamp, action, actor,
    summary, details (JSON), and the previous entry's hash.
    """

    GENESIS_HASH = "0" * 64
    LEDGER_FILENAME = "audit_chain.jsonl"

    def __init__(self, investigation_dir: Union[str, Path]) -> None:
        self.investigation_dir = Path(investigation_dir)
        self.investigation_dir.mkdir(parents=True, exist_ok=True)
        self.ledger_path = self.investigation_dir / self.LEDGER_FILENAME

    def _compute_entry_hash(
        self,
        seq_id: int,
        timestamp_utc: str,
        action: str,
        actor: str,
        summary: str,
        details: Dict[str, Any],
        prev_hash: str,
    ) -> str:
        """Compute the SHA-256 hash for a ledger entry."""
        raw = (
            f"{seq_id}|{timestamp_utc}|{action}|{actor}|{summary}"
            f"|{json.dumps(details, sort_keys=True)}|{prev_hash}"
        )
        return calculate_sha256_bytes(raw.encode("utf-8"))

    def _get_last_entry(self) -> Optional[AuditEntry]:
        """Return the last entry in the ledger, or None if empty."""
        if not self.ledger_path.is_file():
            return None
        last_line = None
        try:
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last_line = line
        except OSError:
            return None
        if last_line is None:
            return None
        try:
            return AuditEntry.from_dict(json.loads(last_line))
        except (json.JSONDecodeError, TypeError):
            return None

    def append(
        self,
        action: str,
        summary: str,
        details: Optional[Dict[str, Any]] = None,
        actor: str = "chronica-analyst",
    ) -> AuditEntry:
        """Append a new entry to the audit ledger.

        Returns the newly created AuditEntry with computed hashes.
        """
        if details is None:
            details = {}

        last = self._get_last_entry()
        seq_id = (last.seq_id + 1) if last else 1
        prev_hash = last.entry_hash if last else self.GENESIS_HASH
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        entry_hash = self._compute_entry_hash(
            seq_id=seq_id,
            timestamp_utc=timestamp_utc,
            action=action,
            actor=actor,
            summary=summary,
            details=details,
            prev_hash=prev_hash,
        )

        entry = AuditEntry(
            seq_id=seq_id,
            timestamp_utc=timestamp_utc,
            action=action,
            actor=actor,
            summary=summary,
            details=details,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")

        return entry

    def list_entries(self) -> List[AuditEntry]:
        """Return all entries in the ledger in chronological order."""
        entries: List[AuditEntry] = []
        if not self.ledger_path.is_file():
            return entries
        try:
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(AuditEntry.from_dict(json.loads(line)))
                        except (json.JSONDecodeError, TypeError):
                            pass
        except OSError:
            pass
        return entries

    def verify_chain(self) -> Tuple[bool, int, Optional[str]]:
        """Verify the cryptographic integrity of the entire chain.

        Returns:
            (is_valid, total_entries, error_message)
            is_valid = True if all entry hashes and prev_hashes are consistent.
            error_message = None if valid, description of first detected violation otherwise.
        """
        entries = self.list_entries()
        total = len(entries)

        if total == 0:
            return True, 0, None

        prev_hash = "0" * 64

        for i, entry in enumerate(entries):
            # Verify prev_hash links
            if entry.prev_hash != prev_hash:
                return (
                    False,
                    total,
                    (
                        f"Chain break at entry seq_id={entry.seq_id}: "
                        f"prev_hash mismatch. Expected '{prev_hash[:12]}...' "
                        f"but got '{entry.prev_hash[:12]}...'."
                    ),
                )

            # Verify entry_hash
            expected_hash = self._compute_entry_hash(
                seq_id=entry.seq_id,
                timestamp_utc=entry.timestamp_utc,
                action=entry.action,
                actor=entry.actor,
                summary=entry.summary,
                details=entry.details,
                prev_hash=entry.prev_hash,
            )
            if entry.entry_hash != expected_hash:
                return (
                    False,
                    total,
                    (
                        f"Entry hash mismatch at seq_id={entry.seq_id}: "
                        f"stored='{entry.entry_hash[:12]}...' "
                        f"expected='{expected_hash[:12]}...' "
                        f"(entry may have been tampered with)."
                    ),
                )

            prev_hash = entry.entry_hash

        return True, total, None

    def get_entries(self) -> List[AuditEntry]:
        """Alias for list_entries."""
        return self.list_entries()

    def append_entry(
        self,
        action: str,
        summary: str,
        metadata: Optional[Dict[str, Any]] = None,
        details: Optional[Dict[str, Any]] = None,
        actor: str = "Local Investigator",
    ) -> AuditEntry:
        """Alias for append supporting metadata/details."""
        payload = details or metadata or {}
        return self.append(action=action, summary=summary, details=payload, actor=actor)

