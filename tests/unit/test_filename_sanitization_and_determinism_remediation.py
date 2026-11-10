"""Tests reproducing and verifying F-24:
1. Windows/NTFS edge name and reserved device name sanitization (CON, PRN, AUX, NUL, COM1-9, LPT1-9).
2. Unicode control characters and RTL override (U+202E) sanitization.
3. Deterministic evidence and event IDs derived from content hash (E9 from audit report).
"""

from __future__ import annotations

from pathlib import Path

from src.evidence.collector import EvidenceCollector
from src.timeline.schema import Event


def test_reproduce_windows_reserved_device_names_sanitized(tmp_path: Path):
    """Filenames matching Windows reserved device names (CON, AUX, PRN, NUL, COM1, LPT1) must be sanitized."""
    collector = EvidenceCollector(evidence_dir=tmp_path)
    
    # These must NOT return raw reserved names on Windows
    reserved = ["CON.log", "aux.txt", "PRN", "nul.json", "COM1.evtx", "lpt3.csv"]
    for name in reserved:
        sanitized = collector.sanitize_filename(name)
        stem = Path(sanitized).stem.upper()
        assert stem not in {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}, (
            f"Filename '{name}' sanitized to reserved Windows device name '{sanitized}'"
        )


def test_reproduce_unicode_rtl_override_sanitized(tmp_path: Path):
    """Right-to-Left Override (U+202E) and bidirectional spoofing characters must be stripped."""
    collector = EvidenceCollector(evidence_dir=tmp_path)
    # Spoofed filename: legitimate.txt\u202Eexe.bat -> displays visually reversed
    spoofed = "legitimate_test\u202Egpj.exe"
    sanitized = collector.sanitize_filename(spoofed)
    assert "\u202E" not in sanitized
    assert not sanitized.endswith(".exe") or "test" in sanitized


def test_reproduce_deterministic_evidence_id(tmp_path: Path):
    """Collecting identical evidence bytes must produce deterministic, reproducible evidence_id (E9)."""
    collector = EvidenceCollector(evidence_dir=tmp_path)
    data = b"2026-10-12T10:00:00Z web-01 service started successfully\n"

    ev1 = collector.collect_from_bytes(data, "service.log")
    ev2 = collector.collect_from_bytes(data, "service.log")

    # Audit report E9: random UUID4 produces different IDs on each ingest, preventing byte-reproducibility
    assert ev1.evidence_id == ev2.evidence_id, "Identical evidence must produce identical deterministic evidence_id"
    assert ev1.stored_filename == ev2.stored_filename


def test_adversarial_ntfs_alternate_data_streams_sanitized(tmp_path: Path):
    """NTFS Alternate Data Stream syntax (file:stream or file::$DATA) must be neutralized."""
    collector = EvidenceCollector(evidence_dir=tmp_path)
    ads_names = ["payload.txt::$DATA", "evidence.log:hidden", "malicious.exe:stream.dll"]
    for ads in ads_names:
        sanitized = collector.sanitize_filename(ads)
        assert ":" not in sanitized, f"Colon retained in sanitized name '{sanitized}'"
        assert not sanitized.startswith(":")


def test_adversarial_deterministic_event_id_generation():
    """Event.create must generate deterministic event IDs based on evidence_id and line_number."""
    ev1 = Event.create(
        investigation_id="inv1",
        evidence_id="ev_123456789abc",
        original_filename="audit.log",
        line_number=42,
        raw_text="sample log line",
        original_timestamp_str="2026-10-12T10:00:00Z",
    )
    ev2 = Event.create(
        investigation_id="inv1",
        evidence_id="ev_123456789abc",
        original_filename="audit.log",
        line_number=42,
        raw_text="sample log line",
        original_timestamp_str="2026-10-12T10:00:00Z",
    )
    assert ev1.event_id == "ev_123456789abc_L42"
    assert ev1.event_id == ev2.event_id

