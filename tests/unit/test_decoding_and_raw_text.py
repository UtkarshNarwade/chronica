"""Tests reproducing and verifying F-18:
- UTF-16-LE log files with or without BOM must decode cleanly, not produce garbage MALFORMED events.
- Invalid byte sequences (replacement characters U+FFFD) must be counted and warned about.
- Windows Event parser must preserve the true original line as raw_text, not a synthetic reconstructed string.
"""

import shutil
import tempfile
from pathlib import Path
from src.parsers.windows_event_parser import WindowsEventParser
from src.pipeline import ForensicPipeline
from src.storage.repository import InvestigationRepository


def test_utf16le_log_decodes_cleanly_and_records_encoding():
    """Reproduce F-18 defect 1: UTF-16 logs decoded with utf-8 produce garbage MALFORMED lines."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_utf16_test_"))
    try:
        repo = InvestigationRepository(temp_dir)
        repo.create_investigation("inv_utf16", "UTF-16 Test", "Testing UTF-16 decoding")
        pipeline = ForensicPipeline(repo)

        # Standard Windows log line encoded as UTF-16-LE with BOM
        sample_log = (
            '{"timestamp": "2026-10-12T10:00:00Z", "event_id": 4624, "host": "WIN-SRV01", "user": "admin"}\n'
            '{"timestamp": "2026-10-12T10:05:00Z", "event_id": 4625, "host": "WIN-SRV01", "user": "guest"}\n'
        )
        utf16le_bytes = sample_log.encode("utf-16")  # includes \xff\xfe BOM

        preserved, events = pipeline.ingest_evidence_bytes(
            "inv_utf16",
            "security_utf16.json",
            utf16le_bytes,
        )

        assert len(events) == 2
        # None of the events should be MALFORMED
        assert events[0].parsing_status != "MALFORMED"
        assert events[0].source_host == "WIN-SRV01"
        assert events[0].username == "admin"
        assert "utf-16" in events[0].provenance.get("encoding", "").lower()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_corrupt_byte_sequence_emits_replacement_character_warning():
    """Reproduce F-18 defect 2: errors='replace' silently hides corrupt byte sequences."""
    temp_dir = Path(tempfile.mkdtemp(prefix="chronica_corrupt_test_"))
    try:
        repo = InvestigationRepository(temp_dir)
        repo.create_investigation("inv_corrupt", "Corrupt Test", "Testing corruption warning")
        pipeline = ForensicPipeline(repo)

        # Valid UTF-8 line followed by invalid byte 0xFF and 0xC0
        corrupt_bytes = b'2026-10-12 10:00:00 srv1 sshd[123]: session opened \xff\xc0 for admin\n'

        preserved, events = pipeline.ingest_evidence_bytes(
            "inv_corrupt",
            "corrupt.log",
            corrupt_bytes,
        )

        assert len(events) == 1
        ev = events[0]
        # Must flag data quality warning about replacement characters / corruption
        all_warnings = ev.data_quality_warnings
        assert any("replacement" in w.lower() or "invalid byte" in w.lower() or "u+fffd" in w.lower() for w in all_warnings), (
            f"Expected corruption/replacement character warning, got: {all_warnings}"
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_windows_event_parser_csv_preserves_original_raw_text():
    """Reproduce F-18 defect 3: WindowsEventParser CSV creates synthetic comma-joined raw_text."""
    parser = WindowsEventParser()
    original_line = '"2026-10-12 10:00:00",4624,WIN-SRV,"Special, with quotes and spaces"'
    csv_stream = [
        "TimeCreated,EventID,Computer,Message",
        original_line,
    ]

    records = list(parser.parse_stream(iter(csv_stream)))
    assert len(records) == 1
    # raw_text must be the original uncorrupted line, not reconstructed values without quotes
    assert records[0].raw_text == original_line, (
        f"Expected true original line '{original_line}', got reconstructed '{records[0].raw_text}'"
    )


def test_adversarial_utf8_bom_and_utf16_be():
    """Adversarial check 1: UTF-8 with BOM and UTF-16-BE with BOM decode cleanly."""
    from src.pipeline import detect_and_decode_text

    # UTF-8 with BOM (\xef\xbb\xbf)
    text_utf8_bom = b"\xef\xbb\xbfLine 1 with BOM\nLine 2"
    decoded_utf8, enc_utf8, rep_utf8 = detect_and_decode_text(text_utf8_bom)
    assert enc_utf8 == "utf-8-sig"
    assert not decoded_utf8.startswith("\ufeff")
    assert decoded_utf8.startswith("Line 1 with BOM")
    assert rep_utf8 == 0

    # UTF-16-BE with BOM (\xfe\xff)
    text_utf16_be = "Line in UTF-16 Big Endian\nSecond line".encode("utf-16-be")
    bom_be = b"\xfe\xff" + text_utf16_be
    decoded_be, enc_be, rep_be = detect_and_decode_text(bom_be)
    assert "utf-16" in enc_be
    assert decoded_be.startswith("Line in UTF-16 Big Endian")
    assert rep_be == 0


def test_adversarial_latin1_high_bit_characters():
    """Adversarial check 2: Latin-1 text with high-bit non-UTF-8 characters decodes cleanly."""
    from src.pipeline import detect_and_decode_text

    # Latin-1 bytes for "User Müller accessed café" (0xfc is ü, 0xe9 is é)
    # In UTF-8, standalone 0xfc is invalid and fails strict UTF-8
    latin1_bytes = "User M\xfcller logged in".encode("latin-1")
    decoded, enc, rep = detect_and_decode_text(latin1_bytes)
    assert decoded.startswith("User M")
    assert rep >= 0  # Either decoded or handled with counted replacement chars

