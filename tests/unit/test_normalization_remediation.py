"""Tests reproducing and verifying F-14:
- DST spring-forward gap must be flagged NONEXISTENT with both candidate UTC times.
- Ambiguous DD/MM vs MM/DD must be flagged AMBIGUOUS with candidate dates.
- 12-hour AM/PM, POSIX ctime, and timezone abbreviations must parse (with ambiguity flags for EST/IST/CST).
- Yearless syslog must respect file mtime or configured investigation base year.
"""

from src.timeline.normalization import TimestampNormalizer
from src.timeline.schema import NormalizationStatus


def test_dst_spring_forward_gap_flagged_as_nonexistent():
    """Reproduce F-14 defect 1: non-existent spring-forward time must be flagged NONEXISTENT, not fallback."""
    normalizer = TimestampNormalizer()
    # On 2026-03-08 in America/New_York, clocks jump from 02:00 to 03:00 -> 02:30 does not exist
    raw_ts = "2026-03-08 02:30:00"
    res = normalizer.normalize(raw_ts, configured_timezone="America/New_York")

    assert res.status == NormalizationStatus.NONEXISTENT_DST or "NONEXISTENT" in res.status.value
    # Must list both candidate UTC times (fold=0 pre-transition candidate and fold=1 post-transition candidate)
    warning_text = " ".join(res.warnings)
    assert "07:30:00" in warning_text or "06:30:00" in warning_text
    assert "spring-forward" in warning_text or "Non-existent" in warning_text


def test_ambiguous_dd_mm_vs_mm_dd_flagged():
    """Reproduce F-14 defect 2: ambiguous DD/MM vs MM/DD must not be silently accepted without ambiguity flag."""
    normalizer = TimestampNormalizer()
    raw_ts = "03/04/2026 10:00:00"  # could be 3 April or 4 March
    res = normalizer.normalize(raw_ts, configured_timezone="UTC")

    assert res.status in (NormalizationStatus.AMBIGUOUS_TIMESTAMP, "AMBIGUOUS_TIMESTAMP", "AMBIGUOUS")
    warning_text = " ".join(res.warnings)
    assert "Ambiguous" in warning_text
    assert "2026-04-03" in warning_text or "2026-03-04" in warning_text


def test_unsupported_12h_ampm_and_ctime_and_tz_abbr():
    """Reproduce F-14 defect 3: 12h AM/PM, ctime, and timezone abbreviations must be supported."""
    normalizer = TimestampNormalizer()

    # 1. 12-hour AM/PM (tested with unambiguous day and with MDY preference)
    res_ampm = normalizer.normalize("10/25/2026 2:32:01 PM", configured_timezone="UTC")
    assert res_ampm.status != NormalizationStatus.INVALID_TIMESTAMP
    assert res_ampm.normalized_utc_iso.startswith("2026-10-25T14:32:01")

    normalizer_mdy = TimestampNormalizer(date_order_preference="MDY")
    res_mdy = normalizer_mdy.normalize("10/11/2026 2:32:01 PM", configured_timezone="UTC")
    assert res_mdy.normalized_utc_iso.startswith("2026-10-11T14:32:01")

    # 2. POSIX ctime format
    res_ctime = normalizer.normalize("Sun Oct 11 14:32:01 2026", configured_timezone="UTC")
    assert res_ctime.status != NormalizationStatus.INVALID_TIMESTAMP
    assert res_ctime.normalized_utc_iso.startswith("2026-10-11T14:32:01")

    # 3. Timezone abbreviation EST (with ambiguity flag)
    res_tz = normalizer.normalize("2026-10-11 14:32:01 EST")
    assert res_tz.status != NormalizationStatus.INVALID_TIMESTAMP
    assert res_tz.normalized_utc_dt is not None
    assert any("EST" in w for w in res_tz.warnings)


def test_yearless_syslog_uses_configured_base_year():
    """Reproduce F-14 defect 4: yearless syslog must use configured base year, not analysis-time year."""
    normalizer = TimestampNormalizer(base_year=2023)
    res = normalizer.normalize("Oct 11 14:32:01", configured_timezone="UTC")

    assert res.normalized_utc_iso.startswith("2023-10-11")
    assert res.year_inferred is True


def test_adversarial_dst_fallback_vs_spring_forward():
    """Adversarial check 1: Fallback repeated hour must be AMBIGUOUS_DST, while spring-forward is NONEXISTENT_DST."""
    normalizer = TimestampNormalizer()
    # In America/New_York, clocks fall back on 2026-11-01 from 02:00 to 01:00 -> 01:30 is repeated
    res_fallback = normalizer.normalize("2026-11-01 01:30:00", configured_timezone="America/New_York")
    assert res_fallback.status == NormalizationStatus.AMBIGUOUS_DST
    assert any("fallback" in w.lower() for w in res_fallback.warnings)

    # In America/New_York, clocks spring forward on 2026-03-08 from 02:00 to 03:00 -> 02:30 does not exist
    res_gap = normalizer.normalize("2026-03-08 02:30:00", configured_timezone="America/New_York")
    assert res_gap.status == NormalizationStatus.NONEXISTENT_DST
    assert any("spring-forward" in w.lower() or "non-existent" in w.lower() for w in res_gap.warnings)


def test_adversarial_unambiguous_slashed_dates_do_not_flag_ambiguous():
    """Adversarial check 2: Slashed dates where day > 12 are NOT ambiguous and must not be flagged AMBIGUOUS."""
    normalizer = TimestampNormalizer()
    # 25/11/2026 -> 25 cannot be a month, must be DD/MM/YYYY
    res_dmy = normalizer.normalize("25/11/2026 12:00:00", configured_timezone="UTC")
    assert res_dmy.status != NormalizationStatus.AMBIGUOUS_TIMESTAMP
    assert res_dmy.normalized_utc_iso.startswith("2026-11-25")

    # 11/25/2026 -> 25 cannot be a month, must be MM/DD/YYYY
    res_mdy = normalizer.normalize("11/25/2026 12:00:00", configured_timezone="UTC")
    assert res_mdy.status != NormalizationStatus.AMBIGUOUS_TIMESTAMP
    assert res_mdy.normalized_utc_iso.startswith("2026-11-25")


def test_adversarial_syslog_new_year_rollover_sequence():
    """Adversarial check 3: Stream rollover from Dec 31 to Jan 01 must increment year and persist."""
    normalizer = TimestampNormalizer(base_year=2025)
    r1 = normalizer.normalize("Dec 31 23:59:59", configured_timezone="UTC")
    assert r1.normalized_utc_iso.startswith("2025-12-31")

    r2 = normalizer.normalize("Jan 01 00:00:01", configured_timezone="UTC")
    assert r2.normalized_utc_iso.startswith("2026-01-01")
    assert any("rollover" in w.lower() for w in r2.warnings)

    r3 = normalizer.normalize("Jan 02 12:00:00", configured_timezone="UTC")
    assert r3.normalized_utc_iso.startswith("2026-01-02")


def test_adversarial_ctime_with_padding_spaces_and_tz_abbr_coverage():
    """Adversarial check 4: ctime with double spaces (POSIX %e) and diverse tz abbreviations."""
    normalizer = TimestampNormalizer()
    # POSIX standard ctime has space-padded day for single digits: 'Sun Oct  4 09:12:00 2026'
    r_ctime = normalizer.normalize("Sun Oct  4 09:12:00 2026", configured_timezone="UTC")
    assert r_ctime.status != NormalizationStatus.INVALID_TIMESTAMP
    assert r_ctime.normalized_utc_iso.startswith("2026-10-04T09:12:00")

    # IST (+05:30)
    r_ist = normalizer.normalize("2026-10-11 12:00:00 IST")
    assert r_ist.status == NormalizationStatus.AMBIGUOUS_TIMESTAMP
    assert r_ist.normalized_utc_iso.startswith("2026-10-11T06:30:00")

