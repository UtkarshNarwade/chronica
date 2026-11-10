"""Tests reproducing and verifying F-09:
- Archive bomb guard must stream decompression with running byte cap (abort before memory growth).
- Peak memory during bomb decompression must stay bounded (measured with tracemalloc).
- Member count cap must reject archives with excessive files.
- Zip-slip path traversal check must prevent directory traversal.
"""

import io
import tarfile
import tracemalloc
import zipfile
import pytest

from src.evidence.collector import FileSizeExceededError, IngestionError
from src.pipeline import ForensicPipeline
from src.storage.repository import InvestigationRepository


def test_reproduce_streaming_bomb_guard_caps_peak_memory(tmp_path):
    """Reproduce F-09 defect 1: Decompressing a bomb must abort on stream without allocating full uncompressed bytes in RAM."""
    repo = InvestigationRepository(data_root=tmp_path)
    pipeline = ForensicPipeline(repo)

    # Create a 20MB zip bomb that compresses into < 25KB
    uncompressed_size = 20 * 1024 * 1024  # 20MB
    bomb_buf = io.BytesIO()
    with zipfile.ZipFile(bomb_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge_bomb.log", b"A" * uncompressed_size)
    bomb_bytes = bomb_buf.getvalue()
    assert len(bomb_bytes) < 30 * 1024  # Highly compressed

    # Set byte limit to 1MB
    byte_limit = 1 * 1024 * 1024

    tracemalloc.start()
    try:
        with pytest.raises(FileSizeExceededError, match="bomb guard"):
            pipeline.expand_archive_bytes("bomb.zip", bomb_bytes, max_bytes=byte_limit)

        current, peak = tracemalloc.get_traced_memory()
        # Peak memory must stay bounded under 5MB (not 20MB+)
        assert peak < 5 * 1024 * 1024, f"Peak memory {peak / 1024 / 1024:.2f}MB exceeded 5MB bound!"
    finally:
        tracemalloc.stop()


def test_reproduce_member_count_cap(tmp_path):
    """Reproduce F-09 defect 2: Archive with too many members must be rejected before full expansion."""
    repo = InvestigationRepository(data_root=tmp_path)
    pipeline = ForensicPipeline(repo)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(1200):  # Exceeds 1000 member cap
            zf.writestr(f"file_{i}.log", b"x")
    zip_bytes = buf.getvalue()

    with pytest.raises((FileSizeExceededError, IngestionError), match="member"):
        pipeline.expand_archive_bytes("many_files.zip", zip_bytes, max_bytes=10 * 1024 * 1024)


def test_reproduce_zip_slip_path_traversal_blocked(tmp_path):
    """Reproduce F-09 defect 3: Archive members attempting path traversal must be rejected or sanitized."""
    repo = InvestigationRepository(data_root=tmp_path)
    pipeline = ForensicPipeline(repo)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", b"root:x:0:0::/root:/bin/bash\n")
    zip_bytes = buf.getvalue()

    # Must either reject or sanitize so no traversal token persists
    extracted = pipeline.expand_archive_bytes("traversal.zip", zip_bytes, max_bytes=10 * 1024 * 1024)
    for name, _ in extracted:
        assert ".." not in name
        assert "/" not in name
        assert "\\" not in name


def test_adversarial_tar_gz_bomb_streaming_bound(tmp_path):
    """Adversarial check 1: Streaming tar.gz bomb must abort without high peak RSS."""
    repo = InvestigationRepository(data_root=tmp_path)
    pipeline = ForensicPipeline(repo)

    uncompressed_size = 15 * 1024 * 1024  # 15MB
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"0" * uncompressed_size
        info = tarfile.TarInfo(name="tar_bomb.log")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    tar_bytes = buf.getvalue()

    byte_limit = 1 * 1024 * 1024  # 1MB limit

    tracemalloc.start()
    try:
        with pytest.raises(FileSizeExceededError, match="bomb guard"):
            pipeline.expand_archive_bytes("tar_bomb.tar.gz", tar_bytes, max_bytes=byte_limit)

        current, peak = tracemalloc.get_traced_memory()
        assert peak < 5 * 1024 * 1024, f"Tar peak memory {peak / 1024 / 1024:.2f}MB exceeded 5MB bound!"
    finally:
        tracemalloc.stop()


def test_adversarial_nesting_depth_cap(tmp_path):
    """Adversarial check 2: Recursive archive nesting > 3 must be rejected."""
    repo = InvestigationRepository(data_root=tmp_path)
    pipeline = ForensicPipeline(repo)

    # Calling expand_archive_bytes with depth > MAX_NESTING_DEPTH
    with pytest.raises(FileSizeExceededError, match="nesting depth"):
        pipeline.expand_archive_bytes("nested.zip", b"PK\x05\x06" + b"\x00" * 18, depth=4)


def test_adversarial_windows_backslash_traversal_sanitized(tmp_path):
    """Adversarial check 3: Windows backslash traversal in archive member names must be sanitized."""
    repo = InvestigationRepository(data_root=tmp_path)
    pipeline = ForensicPipeline(repo)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(r"..\..\..\AppData\evil.log", b"malicious content")
    zip_bytes = buf.getvalue()

    extracted = pipeline.expand_archive_bytes("evil_win.zip", zip_bytes, max_bytes=10 * 1024 * 1024)
    assert len(extracted) == 1
    assert extracted[0][0] == "evil.log"
    assert ".." not in extracted[0][0]
    assert "\\" not in extracted[0][0]

