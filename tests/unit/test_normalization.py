"""Unit tests for timestamp parsing, UTC normalization, and inference tracking."""

import pytest

from src.timeline.normalization import TimestampNormalizer
from src.timeline.schema import NormalizationStatus


def test_iso_utc_z_normalization():
    normalizer = TimestampNormalizer()
    res = normalizer.normalize("2026-10-12T14:30:00Z")

    assert res.status == NormalizationStatus.NORMALIZED_EXPLICIT_OFFSET
    assert res.normalized_utc_iso.startswith("2026-10-12T14:30:00")
    assert res.year_inferred is False


def test_iso_explicit_offset_normalization():
    normalizer = TimestampNormalizer()
    # 10:30:00 with +05:30 offset is 05:00:00 UTC
    res = normalizer.normalize("2026-10-12T10:30:00+05:30")

    assert res.status == NormalizationStatus.NORMALIZED_EXPLICIT_OFFSET
    assert res.normalized_utc_iso.startswith("2026-10-12T05:00:00")


def test_different_offsets_same_instant_normalize_identically():
    normalizer = TimestampNormalizer()
    # 14:00:00 UTC
    res1 = normalizer.normalize("2026-10-12T14:00:00Z")
    # 10:00:00 EDT (-04:00) -> 14:00:00 UTC
    res2 = normalizer.normalize("2026-10-12T10:00:00-04:00")
    # 19:30:00 IST (+05:30) -> 14:00:00 UTC
    res3 = normalizer.normalize("2026-10-12T19:30:00+05:30")

    assert res1.normalized_utc_iso == res2.normalized_utc_iso == res3.normalized_utc_iso


def test_apache_clf_normalization():
    normalizer = TimestampNormalizer()
    res = normalizer.normalize("12/Oct/2026:10:00:00 -0400")

    assert res.status == NormalizationStatus.NORMALIZED_EXPLICIT_OFFSET
    # 10:00 -0400 is 14:00 UTC
    assert res.normalized_utc_iso.startswith("2026-10-12T14:00:00")


def test_syslog_yearless_timestamp():
    normalizer = TimestampNormalizer(base_year=2026)
    res = normalizer.normalize("Oct 12 10:00:00", configured_timezone="UTC")

    assert res.year_inferred is True
    assert res.status == NormalizationStatus.NORMALIZED_CONFIGURED_TZ
    assert res.normalized_utc_iso.startswith("2026-10-12T10:00:00")
    assert any("Year inferred as 2026" in w for w in res.warnings)


def test_unix_epoch_normalization():
    normalizer = TimestampNormalizer()
    # Epoch 1700000000
    res = normalizer.normalize("1700000000")
    assert res.status == NormalizationStatus.NORMALIZED_EXPLICIT_OFFSET
    assert res.normalized_utc_iso is not None


def test_invalid_and_missing_timestamps():
    normalizer = TimestampNormalizer()

    # Empty string
    res_empty = normalizer.normalize("")
    assert res_empty.status == NormalizationStatus.MISSING_TIMESTAMP
    assert res_empty.normalized_utc_iso is None

    # Impossible date (Month 99)
    res_invalid = normalizer.normalize("2026-99-99T99:99:99Z")
    assert res_invalid.status == NormalizationStatus.INVALID_TIMESTAMP
    assert res_invalid.normalized_utc_iso is None
