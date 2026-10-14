"""Unit tests for cryptographic hashing, manifest generation, and integrity verification."""

import tempfile
from pathlib import Path
import pytest

from src.evidence.hashing import calculate_sha256_bytes, calculate_sha256_file
from src.evidence.collector import EvidenceCollector, IngestionError, FileSizeExceededError
from src.evidence.manifest import EvidenceManifest, EvidenceFileEntry
from src.evidence.verification import verify_evidence_integrity, verify_file_integrity, IntegrityStatus


def test_sha256_known_bytes():
    # SHA-256 of empty string
    assert calculate_sha256_bytes(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    # SHA-256 of "hello world"
    assert calculate_sha256_bytes(b"hello world") == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"


def test_sha256_file_matches_bytes(tmp_path: Path):
    sample_file = tmp_path / "test.log"
    data = b"Line 1\nLine 2\nLine 3\n"
    sample_file.write_bytes(data)

    assert calculate_sha256_file(sample_file) == calculate_sha256_bytes(data)


def test_sha256_changes_on_single_bit_flip(tmp_path: Path):
    data_orig = b"Evidence record 12345"
    data_tampered = b"Evidence record 12346"  # Single character changed

    hash1 = calculate_sha256_bytes(data_orig)
    hash2 = calculate_sha256_bytes(data_tampered)

    assert hash1 != hash2


def test_evidence_collector_preserves_pristine_copy(tmp_path: Path):
    collector = EvidenceCollector(evidence_dir=tmp_path / "evidence")
    raw_data = b"2026-10-12 10:00:00 System reboot initiated\n"

    preserved = collector.collect_from_bytes(raw_data, original_filename="syslog.log")

    assert preserved.original_filename == "syslog.log"
    assert preserved.file_size_bytes == len(raw_data)
    assert preserved.sha256_digest == calculate_sha256_bytes(raw_data)
    assert preserved.stored_path.is_file()
    assert preserved.stored_path.read_bytes() == raw_data


def test_evidence_collector_sanitizes_unsafe_path(tmp_path: Path):
    collector = EvidenceCollector(evidence_dir=tmp_path / "evidence")
    
    # Path traversal attempt: ../../etc/passwd
    unsafe_name = "../../etc/passwd"
    sanitized = EvidenceCollector.sanitize_filename(unsafe_name)
    assert "/" not in sanitized
    assert "\\" not in sanitized
    assert ".." not in sanitized

    preserved = collector.collect_from_bytes(b"dummy", original_filename=unsafe_name)
    assert ".." not in preserved.stored_filename
    assert (tmp_path / "evidence" / preserved.stored_filename).is_file()


def test_evidence_collector_enforces_size_limit(tmp_path: Path):
    collector = EvidenceCollector(evidence_dir=tmp_path / "evidence", max_file_size_bytes=100)
    large_data = b"A" * 150

    with pytest.raises(FileSizeExceededError):
        collector.collect_from_bytes(large_data, original_filename="large.log")


def test_verification_detects_tampering(tmp_path: Path):
    collector = EvidenceCollector(evidence_dir=tmp_path / "evidence")
    data = b"Pristine authentic log content"
    preserved = collector.collect_from_bytes(data, original_filename="auth.log")

    # Baseline verification
    res_clean = verify_file_integrity(
        file_path=preserved.stored_path,
        recorded_sha256=preserved.sha256_digest,
        original_filename="auth.log",
    )
    assert res_clean.status == IntegrityStatus.VERIFIED
    assert res_clean.is_intact is True

    # Simulate malicious modification (flip 1 byte)
    import os, stat
    os.chmod(preserved.stored_path, stat.S_IWRITE)
    with open(preserved.stored_path, "wb") as f:
        f.write(b"Malicious modified content")

    res_tampered = verify_file_integrity(
        file_path=preserved.stored_path,
        recorded_sha256=preserved.sha256_digest,
        original_filename="auth.log",
    )
    assert res_tampered.status == IntegrityStatus.MISMATCH
    assert res_tampered.is_intact is False


def test_verification_detects_missing_file(tmp_path: Path):
    res_missing = verify_file_integrity(
        file_path=tmp_path / "non_existent.log",
        recorded_sha256="abc123def456",
        original_filename="missing.log",
    )
    assert res_missing.status == IntegrityStatus.UNAVAILABLE
    assert res_missing.is_intact is False
