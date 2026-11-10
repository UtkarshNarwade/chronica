"""Secure evidence collector and preservation manager.

Handles ingesting evidence files, calculating SHA-256 digests prior to parsing,
sanitizing input filenames against path traversal, enforcing file size limits,
and storing bit-for-bit unchanged copies in the investigation's preserved evidence directory.
"""

from __future__ import annotations

import re
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from src.evidence.hashing import calculate_sha256_bytes, calculate_sha256_file

DEFAULT_MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB


class IngestionError(Exception):
    """Raised when an evidence file fails validation or ingestion."""
    pass


class FileSizeExceededError(IngestionError):
    """Raised when an evidence file exceeds the configured size limit."""
    pass


class UnsafeFilenameError(IngestionError):
    """Raised when an evidence file has a dangerous or traversing filename."""
    pass


@dataclass(frozen=True)
class PreservedEvidence:
    """Immutable record of an ingested and preserved piece of evidence."""
    evidence_id: str
    original_filename: str
    stored_filename: str
    stored_path: Path
    file_size_bytes: int
    sha256_digest: str
    collection_time_utc: str
    hash_algorithm: str = "sha256"


WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}
UNICODE_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


class EvidenceCollector:
    """Manages the collection and preservation of digital evidence files."""

    def __init__(
        self,
        evidence_dir: Union[str, Path],
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    ) -> None:
        self.evidence_dir = Path(evidence_dir)
        self.max_file_size_bytes = max_file_size_bytes
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.evidence_dir.chmod(0o700)
        except (PermissionError, OSError):
            pass

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize an untrusted input filename.
        
        Strips path components, prevents directory traversal ('../'), removes null bytes,
        neutralizes Unicode RTL override/control characters, guards against Windows reserved
        device names (CON, AUX, PRN, NUL, COM*, LPT*), and ensures a safe basename is returned.
        """
        if not filename or not filename.strip():
            return "evidence_unnamed.log"

        # Remove null bytes and unicode control/bidi characters
        cleaned = UNICODE_CONTROL_CHARS.sub("", filename)

        # Extract only the final basename (removes both POSIX / and Windows \ separators)
        cleaned = re.split(r"[/\\]", cleaned)[-1].strip()

        # Remove path traversal tokens and dangerous characters
        cleaned = re.sub(r"\.\.+", ".", cleaned)
        cleaned = re.sub(r"[^\w\.\-\_ ]", "_", cleaned).strip(" .")

        if not cleaned:
            return "evidence_unnamed.log"

        # Guard against Windows reserved device names (CON, PRN, AUX, NUL, COM1..9, LPT1..9)
        stem = Path(cleaned).stem.upper()
        if stem in WINDOWS_RESERVED_NAMES:
            cleaned = f"safe_{cleaned}"

        return cleaned

    def collect_from_bytes(
        self,
        data: bytes,
        original_filename: str,
        custom_evidence_id: Optional[str] = None,
        staging: bool = False,
    ) -> PreservedEvidence:
        """Collect and preserve evidence provided as raw bytes (e.g. from UI file upload)."""
        file_size = len(data)
        if file_size > self.max_file_size_bytes:
            raise FileSizeExceededError(
                f"File '{original_filename}' ({file_size} bytes) exceeds maximum limit "
                f"of {self.max_file_size_bytes} bytes."
            )

        sanitized_name = self.sanitize_filename(original_filename)

        # Calculate SHA-256 before writing to disk
        sha256_digest = calculate_sha256_bytes(data)

        # Audit E9: Deterministic evidence ID derived from SHA-256 hash when not custom
        evidence_id = custom_evidence_id or f"ev_{sha256_digest[:12]}"

        # Store with evidence_id prefix to prevent collisions
        stored_filename = f"{evidence_id}_{sanitized_name}"
        
        target_dir = (self.evidence_dir.parent / ".staging") if staging else self.evidence_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        try:
            target_dir.chmod(0o700)
        except (PermissionError, OSError):
            pass

        dest_path = target_dir / stored_filename

        # If already preserved with identical hash, return existing preserved entry
        if dest_path.exists() and not staging:
            try:
                if calculate_sha256_file(dest_path) == sha256_digest:
                    return PreservedEvidence(
                        evidence_id=evidence_id,
                        original_filename=sanitized_name,
                        stored_filename=stored_filename,
                        stored_path=dest_path,
                        file_size_bytes=file_size,
                        sha256_digest=sha256_digest,
                        collection_time_utc=datetime.now(timezone.utc).isoformat(),
                        hash_algorithm="sha256",
                    )
            except Exception:
                pass

        # Write pristine original bytes
        with open(dest_path, "wb") as f:
            f.write(data)

        # Apply read-only permissions where platform supports it (only for non-staged)
        if not staging:
            try:
                dest_path.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
            except (PermissionError, OSError):
                pass

        collection_time_utc = datetime.now(timezone.utc).isoformat()

        return PreservedEvidence(
            evidence_id=evidence_id,
            original_filename=sanitized_name,
            stored_filename=stored_filename,
            stored_path=dest_path,
            file_size_bytes=file_size,
            sha256_digest=sha256_digest,
            collection_time_utc=collection_time_utc,
            hash_algorithm="sha256",
        )

    def commit_preserved(self, preserved: PreservedEvidence) -> PreservedEvidence:
        """Atomically promote a staged preserved evidence file to the evidence directory."""
        import dataclasses
        import shutil
        final_path = self.evidence_dir / preserved.stored_filename
        if preserved.stored_path != final_path and preserved.stored_path.exists():
            shutil.move(str(preserved.stored_path), str(final_path))
        try:
            final_path.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        except (PermissionError, OSError):
            pass
        staging_dir = self.evidence_dir.parent / ".staging"
        try:
            if staging_dir.is_dir() and not any(staging_dir.iterdir()):
                staging_dir.rmdir()
        except OSError:
            pass
        return dataclasses.replace(preserved, stored_path=final_path)

    def rollback_preserved(self, preserved: PreservedEvidence) -> None:
        """Rollback and delete a staged or partially preserved evidence file."""
        try:
            if preserved.stored_path.exists():
                preserved.stored_path.chmod(stat.S_IWRITE)
                preserved.stored_path.unlink()
        except OSError:
            pass
        final_path = self.evidence_dir / preserved.stored_filename
        try:
            if final_path.exists():
                final_path.chmod(stat.S_IWRITE)
                final_path.unlink()
        except OSError:
            pass
        staging_dir = self.evidence_dir.parent / ".staging"
        try:
            if staging_dir.is_dir() and not any(staging_dir.iterdir()):
                staging_dir.rmdir()
        except OSError:
            pass

    def collect_from_path(
        self,
        source_path: Union[str, Path],
        custom_evidence_id: Optional[str] = None,
    ) -> PreservedEvidence:
        """Collect and preserve evidence from an existing local file."""
        src = Path(source_path)
        if not src.is_file():
            raise IngestionError(f"Source file does not exist: {src}")

        file_size = src.stat().st_size
        if file_size > self.max_file_size_bytes:
            raise FileSizeExceededError(
                f"File '{src.name}' ({file_size} bytes) exceeds maximum limit "
                f"of {self.max_file_size_bytes} bytes."
            )

        sanitized_name = self.sanitize_filename(src.name)

        # Stream chunk by chunk while simultaneously hashing into temporary file
        import hashlib
        hasher = hashlib.sha256()
        total_read = 0

        temp_staged = self.evidence_dir / f"tmp_stream_{uuid.uuid4().hex[:12]}"
        with open(src, "rb") as in_f, open(temp_staged, "wb") as out_f:
            while chunk := in_f.read(65536):
                hasher.update(chunk)
                out_f.write(chunk)
                total_read += len(chunk)

        sha256_digest = hasher.hexdigest()
        evidence_id = custom_evidence_id or f"ev_{sha256_digest[:12]}"
        stored_filename = f"{evidence_id}_{sanitized_name}"
        dest_path = self.evidence_dir / stored_filename

        if dest_path.exists():
            try:
                temp_staged.unlink(missing_ok=True)
            except Exception:
                pass
        else:
            temp_staged.rename(dest_path)

        try:
            dest_path.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        except (PermissionError, OSError):
            pass

        collection_time_utc = datetime.now(timezone.utc).isoformat()

        return PreservedEvidence(
            evidence_id=evidence_id,
            original_filename=sanitized_name,
            stored_filename=stored_filename,
            stored_path=dest_path,
            file_size_bytes=total_read,
            sha256_digest=sha256_digest,
            collection_time_utc=collection_time_utc,
            hash_algorithm="sha256",
        )
