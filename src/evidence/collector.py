"""Secure evidence collector and preservation manager.

Handles ingesting evidence files, calculating SHA-256 digests prior to parsing,
sanitizing input filenames against path traversal, enforcing file size limits,
and storing bit-for-bit unchanged copies in the investigation's preserved evidence directory.
"""

from __future__ import annotations

import os
import re
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Optional, Union

from src.evidence.hashing import calculate_sha256_bytes, calculate_sha256_stream

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

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize an untrusted input filename.
        
        Strips path components, prevents directory traversal ('../'), removes null bytes,
        and ensures a safe basename is returned.
        """
        if not filename or not filename.strip():
            return "evidence_unnamed.log"

        # Remove null bytes
        cleaned = filename.replace("\x00", "")

        # Extract only the final basename (removes both POSIX / and Windows \ separators)
        cleaned = re.split(r"[/\\]", cleaned)[-1].strip()

        # Remove path traversal tokens and dangerous characters
        cleaned = re.sub(r"\.\.+", ".", cleaned)
        cleaned = re.sub(r"[^\w\.\-\_ ]", "_", cleaned).strip(" .")

        if not cleaned:
            return "evidence_unnamed.log"
        return cleaned

    def collect_from_bytes(
        self,
        data: bytes,
        original_filename: str,
        custom_evidence_id: Optional[str] = None,
    ) -> PreservedEvidence:
        """Collect and preserve evidence provided as raw bytes (e.g. from UI file upload)."""
        file_size = len(data)
        if file_size > self.max_file_size_bytes:
            raise FileSizeExceededError(
                f"File '{original_filename}' ({file_size} bytes) exceeds maximum limit "
                f"of {self.max_file_size_bytes} bytes."
            )

        sanitized_name = self.sanitize_filename(original_filename)
        evidence_id = custom_evidence_id or f"ev_{uuid.uuid4().hex[:12]}"
        
        # Calculate SHA-256 before writing to disk
        sha256_digest = calculate_sha256_bytes(data)

        # Store with evidence_id prefix to prevent collisions
        stored_filename = f"{evidence_id}_{sanitized_name}"
        dest_path = self.evidence_dir / stored_filename

        # Write pristine original bytes
        with open(dest_path, "wb") as f:
            f.write(data)

        # Apply read-only permissions where platform supports it
        try:
            dest_path.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        except (PermissionError, OSError):
            pass  # Non-fatal if OS doesn't support setting read-only attributes

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
        evidence_id = custom_evidence_id or f"ev_{uuid.uuid4().hex[:12]}"
        stored_filename = f"{evidence_id}_{sanitized_name}"
        dest_path = self.evidence_dir / stored_filename

        # Stream chunk by chunk while simultaneously hashing and writing
        import hashlib
        hasher = hashlib.sha256()
        total_read = 0

        with open(src, "rb") as in_f, open(dest_path, "wb") as out_f:
            while chunk := in_f.read(65536):
                hasher.update(chunk)
                out_f.write(chunk)
                total_read += len(chunk)

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
            sha256_digest=hasher.hexdigest(),
            collection_time_utc=collection_time_utc,
            hash_algorithm="sha256",
        )
