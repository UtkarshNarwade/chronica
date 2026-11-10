"""Tamper-Evident Chain-of-Custody Audit Ledger.

Implements a hash-chained append-only ledger that records all significant
investigator actions, evidence ingestions, and integrity verifications,
providing a cryptographically-linked, tamper-evident chain of custody.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

from src.evidence.hashing import calculate_sha256_bytes


class AuditChainIntegrityError(Exception):
    """Raised when an audit chain integrity violation or corruption is encountered."""


_LEDGER_LOCK = threading.RLock()


@contextmanager
def _acquire_file_lock(lock_path: Path, timeout: float = 10.0) -> Generator[None, None, None]:
    """Acquire a cross-platform filesystem lock using atomic file creation."""
    start = time.time()
    fd = None
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
            break
        except FileExistsError:
            if time.time() - start > timeout:
                try:
                    if lock_path.is_file() and (time.time() - lock_path.stat().st_mtime > 30.0):
                        lock_path.unlink(missing_ok=True)
                        continue
                except OSError:
                    pass
                raise TimeoutError(f"Could not acquire ledger lock on {lock_path} within {timeout}s")
            time.sleep(0.005)
        except OSError as err:
            raise OSError(f"Failed to access lock file {lock_path}: {err}") from err

    try:
        yield
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                lock_path.unlink(missing_ok=True)
            except OSError:
                pass


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

    Dual-anchored: stores latest seq_id and head_hash in both:
    1. A separate sidecar file (<investigation_dir>/audit_chain.anchor)
    2. A SQLite database table (audit_chain_anchor)
    """

    GENESIS_HASH = "0" * 64
    LEDGER_FILENAME = "audit_chain.jsonl"
    ANCHOR_FILENAME = "audit_chain.anchor"
    LOCK_FILENAME = "audit_chain.lock"

    def __init__(
        self,
        investigation_dir: Union[str, Path],
        db_path: Optional[Union[str, Path]] = None,
    ) -> None:
        self.investigation_dir = Path(investigation_dir)
        self.investigation_dir.mkdir(parents=True, exist_ok=True)
        self.ledger_path = self.investigation_dir / self.LEDGER_FILENAME
        self.anchor_path = self.investigation_dir / self.ANCHOR_FILENAME
        self.lock_path = self.investigation_dir / self.LOCK_FILENAME

        if db_path is not None:
            self.db_path = Path(db_path)
        elif (self.investigation_dir.parent.parent / "chronica.db").is_file():
            self.db_path = self.investigation_dir.parent.parent / "chronica.db"
        else:
            self.db_path = self.investigation_dir / "audit_anchor.db"

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
        """Return the last entry in the ledger, or None if empty.

        Raises AuditChainIntegrityError if the file contains malformed data.
        """
        if not self.ledger_path.is_file():
            return None

        last_line = None
        last_line_num = 0
        try:
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line_s = line.strip()
                    if line_s:
                        last_line = line_s
                        last_line_num = line_num
        except OSError as err:
            raise AuditChainIntegrityError(f"Failed to read audit ledger: {err}") from err

        if last_line is None:
            return None

        try:
            return AuditEntry.from_dict(json.loads(last_line))
        except (json.JSONDecodeError, TypeError) as err:
            raise AuditChainIntegrityError(
                f"Audit ledger corrupted at line {last_line_num}: unable to parse entry ({err}). "
                "Append aborted to prevent chain forking."
            ) from err

    def _update_anchors(self, seq_id: int, head_hash: str, timestamp_utc: str) -> None:
        """Update both sidecar and SQLite anchors with the latest chain head."""
        # 1. Update sidecar anchor atomically
        sidecar_data = {
            "investigation_id": self.investigation_dir.name,
            "seq_id": seq_id,
            "head_hash": head_hash,
            "timestamp_utc": timestamp_utc,
        }
        tmp_anchor = self.anchor_path.with_suffix(".anchor.tmp")
        with open(tmp_anchor, "w", encoding="utf-8") as f:
            json.dump(sidecar_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_anchor, self.anchor_path)

        # 2. Update SQLite anchor
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path), timeout=10.0)
            try:
                with conn:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS audit_chain_anchor (
                            investigation_id TEXT PRIMARY KEY,
                            seq_id INTEGER NOT NULL,
                            head_hash TEXT NOT NULL,
                            updated_at TEXT NOT NULL
                        )
                        """
                    )
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO audit_chain_anchor (investigation_id, seq_id, head_hash, updated_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (self.investigation_dir.name, seq_id, head_hash, timestamp_utc),
                    )
            finally:
                conn.close()
        except sqlite3.Error as err:
            raise AuditChainIntegrityError(f"Failed to persist audit anchor in SQLite: {err}") from err

    def _get_sidecar_anchor(self) -> Optional[Tuple[int, str]]:
        """Return (seq_id, head_hash) from sidecar anchor, or None if missing."""
        if not self.anchor_path.is_file():
            return None
        try:
            with open(self.anchor_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return int(data["seq_id"]), str(data["head_hash"])
        except (json.JSONDecodeError, KeyError, OSError, TypeError):
            return None

    def _get_sqlite_anchor(self) -> Optional[Tuple[int, str]]:
        """Return (seq_id, head_hash) from SQLite anchor table, or None if missing."""
        if not self.db_path.is_file():
            return None
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=5.0)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_chain_anchor'"
                )
                if not cursor.fetchone():
                    return None
                cursor.execute(
                    "SELECT seq_id, head_hash FROM audit_chain_anchor WHERE investigation_id = ?",
                    (self.investigation_dir.name,),
                )
                row = cursor.fetchone()
                if row:
                    return int(row[0]), str(row[1])
                return None
            finally:
                conn.close()
        except sqlite3.Error:
            return None

    def append(
        self,
        action: str,
        summary: str,
        details: Optional[Dict[str, Any]] = None,
        actor: str = "chronica-analyst",
    ) -> AuditEntry:
        """Append a new entry to the audit ledger under lock.

        Returns the newly created AuditEntry with computed hashes.
        """
        if details is None:
            details = {}

        with _LEDGER_LOCK:
            with _acquire_file_lock(self.lock_path):
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
                    f.flush()
                    os.fsync(f.fileno())

                self._update_anchors(seq_id, entry_hash, timestamp_utc)
                return entry

    def list_entries(self) -> List[AuditEntry]:
        """Return all valid entries in the ledger in chronological order."""
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

        Verifies:
        1. Parseability of every JSON line in audit_chain.jsonl
        2. Genesis hash on seq_id=1
        3. Internal prev_hash continuity and entry_hash matches
        4. External anchors (sidecar and SQLite): detects truncation (seq_id < anchor)
           and whole-chain rewrite (head_hash != anchor).

        Returns:
            (is_valid, total_entries, error_message)
        """
        sidecar_anchor = self._get_sidecar_anchor()
        sqlite_anchor = self._get_sqlite_anchor()

        if not self.ledger_path.is_file():
            if (sidecar_anchor and sidecar_anchor[0] > 0) or (sqlite_anchor and sqlite_anchor[0] > 0):
                return False, 0, "Ledger file missing but head anchors exist (ledger deleted)."
            return True, 0, None

        entries: List[AuditEntry] = []
        try:
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line_s = line.strip()
                    if not line_s:
                        continue
                    try:
                        entries.append(AuditEntry.from_dict(json.loads(line_s)))
                    except (json.JSONDecodeError, TypeError) as parse_err:
                        return (
                            False,
                            len(entries),
                            f"Chain corrupted: invalid JSON at line {line_num} ({parse_err}).",
                        )
        except OSError as os_err:
            return False, 0, f"Failed to read audit ledger: {os_err}"

        total = len(entries)
        if total == 0:
            if (sidecar_anchor and sidecar_anchor[0] > 0) or (sqlite_anchor and sqlite_anchor[0] > 0):
                return False, 0, "Ledger empty but external anchors record prior entries (ledger truncated)."
            return True, 0, None

        prev_hash = self.GENESIS_HASH

        for entry in entries:
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

        # Anchor verification: detect truncation and rewrite
        if sidecar_anchor is not None:
            anchor_seq, anchor_hash = sidecar_anchor
            if total < anchor_seq:
                return (
                    False,
                    total,
                    (
                        f"Chain truncation detected: ledger has {total} entries, "
                        f"but sidecar anchor records seq_id={anchor_seq}."
                    ),
                )
            if entries[-1].entry_hash != anchor_hash:
                return (
                    False,
                    total,
                    (
                        f"Chain rewrite/mismatch detected: head entry hash '{entries[-1].entry_hash[:12]}...' "
                        f"does not match sidecar anchor head hash '{anchor_hash[:12]}...'."
                    ),
                )

        if sqlite_anchor is not None:
            db_seq, db_hash = sqlite_anchor
            if total < db_seq:
                return (
                    False,
                    total,
                    (
                        f"Chain truncation detected: ledger has {total} entries, "
                        f"but database anchor records seq_id={db_seq}."
                    ),
                )
            if entries[-1].entry_hash != db_hash:
                return (
                    False,
                    total,
                    (
                        f"Chain rewrite/mismatch detected: head entry hash '{entries[-1].entry_hash[:12]}...' "
                        f"does not match database anchor head hash '{db_hash[:12]}...'."
                    ),
                )

        if sidecar_anchor is not None and sqlite_anchor is not None:
            if sidecar_anchor[0] != sqlite_anchor[0] or sidecar_anchor[1] != sqlite_anchor[1]:
                return (
                    False,
                    total,
                    "Anchor mismatch: sidecar anchor does not match database anchor.",
                )

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


