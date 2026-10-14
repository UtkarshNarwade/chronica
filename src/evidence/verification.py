"""Evidence integrity verification engine.

Re-hashes stored evidence files on disk and compares against cryptographic
digests recorded in the manifest, detecting corruption or tampering.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union

from src.evidence.hashing import calculate_sha256_file
from src.evidence.manifest import EvidenceManifest


class IntegrityStatus(str, Enum):
    """Integrity evaluation states."""
    VERIFIED = "VERIFIED"                  # Hash matches recorded manifest digest
    MISMATCH = "MISMATCH"                  # Hash differs: corruption or tampering detected
    UNAVAILABLE = "UNAVAILABLE"            # File missing or permission error
    NOT_YET_VERIFIED = "NOT_YET_VERIFIED"  # Untested


@dataclass
class VerificationResult:
    """Detailed verification record for a single evidence file."""
    evidence_id: str
    original_filename: str
    stored_path: str
    status: IntegrityStatus
    recorded_sha256: str
    calculated_sha256: Optional[str]
    verification_time_utc: str
    details: str
    forensic_limitation_notice: str = (
        "Forensic Limitation: A matching hash proves byte-for-byte integrity since "
        "the time of collection. It does not establish that the log was authentic, "
        "that system clocks were accurate, or that alteration did not occur prior to collection."
    )

    @property
    def is_intact(self) -> bool:
        return self.status == IntegrityStatus.VERIFIED


@dataclass
class InvestigationIntegritySummary:
    """Summary of evidence verification across all files in an investigation."""
    investigation_id: str
    verification_time_utc: str
    total_files: int
    verified_files: int
    mismatched_files: int
    unavailable_files: int
    results: List[VerificationResult]

    @property
    def all_verified(self) -> bool:
        return self.total_files > 0 and self.verified_files == self.total_files


def verify_file_integrity(
    file_path: Union[str, Path],
    recorded_sha256: str,
    evidence_id: str = "unknown",
    original_filename: str = "",
) -> VerificationResult:
    """Verify integrity of a single evidence file against a recorded digest."""
    path = Path(file_path)
    now_utc = datetime.now(timezone.utc).isoformat()

    if not path.is_file():
        return VerificationResult(
            evidence_id=evidence_id,
            original_filename=original_filename or path.name,
            stored_path=str(path),
            status=IntegrityStatus.UNAVAILABLE,
            recorded_sha256=recorded_sha256,
            calculated_sha256=None,
            verification_time_utc=now_utc,
            details=f"Evidence file cannot be found at: {path}",
        )

    try:
        calculated = calculate_sha256_file(path)
    except Exception as exc:
        return VerificationResult(
            evidence_id=evidence_id,
            original_filename=original_filename or path.name,
            stored_path=str(path),
            status=IntegrityStatus.UNAVAILABLE,
            recorded_sha256=recorded_sha256,
            calculated_sha256=None,
            verification_time_utc=now_utc,
            details=f"Error reading evidence file: {exc}",
        )

    if calculated.lower() == recorded_sha256.lower():
        return VerificationResult(
            evidence_id=evidence_id,
            original_filename=original_filename or path.name,
            stored_path=str(path),
            status=IntegrityStatus.VERIFIED,
            recorded_sha256=recorded_sha256,
            calculated_sha256=calculated,
            verification_time_utc=now_utc,
            details="Cryptographic SHA-256 digest matches preserved baseline.",
        )
    else:
        return VerificationResult(
            evidence_id=evidence_id,
            original_filename=original_filename or path.name,
            stored_path=str(path),
            status=IntegrityStatus.MISMATCH,
            recorded_sha256=recorded_sha256,
            calculated_sha256=calculated,
            verification_time_utc=now_utc,
            details=(
                f"INTEGRITY VIOLATION DETECTED! Computed SHA-256 ({calculated}) "
                f"differs from baseline ({recorded_sha256}). File may have been altered."
            ),
        )


def verify_evidence_integrity(
    evidence_dir: Union[str, Path],
    manifest: EvidenceManifest,
) -> InvestigationIntegritySummary:
    """Verify all evidence files recorded in an investigation manifest."""
    base_dir = Path(evidence_dir)
    results: List[VerificationResult] = []
    now_utc = datetime.now(timezone.utc).isoformat()

    for entry in manifest.entries:
        target_path = base_dir / entry.stored_filename
        res = verify_file_integrity(
            file_path=target_path,
            recorded_sha256=entry.sha256_digest,
            evidence_id=entry.evidence_id,
            original_filename=entry.original_filename,
        )
        results.append(res)

    verified = sum(1 for r in results if r.status == IntegrityStatus.VERIFIED)
    mismatched = sum(1 for r in results if r.status == IntegrityStatus.MISMATCH)
    unavailable = sum(1 for r in results if r.status == IntegrityStatus.UNAVAILABLE)

    return InvestigationIntegritySummary(
        investigation_id=manifest.investigation_id,
        verification_time_utc=now_utc,
        total_files=len(manifest.entries),
        verified_files=verified,
        mismatched_files=mismatched,
        unavailable_files=unavailable,
        results=results,
    )
