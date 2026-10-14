"""Evidence management, cryptographic hashing, preservation, and integrity verification."""

from src.evidence.hashing import calculate_sha256_file, calculate_sha256_bytes
from src.evidence.collector import EvidenceCollector, PreservedEvidence
from src.evidence.manifest import EvidenceManifest, EvidenceFileEntry
from src.evidence.verification import verify_evidence_integrity, IntegrityStatus, VerificationResult

__all__ = [
    "calculate_sha256_file",
    "calculate_sha256_bytes",
    "EvidenceCollector",
    "PreservedEvidence",
    "EvidenceManifest",
    "EvidenceFileEntry",
    "verify_evidence_integrity",
    "IntegrityStatus",
    "VerificationResult",
]
