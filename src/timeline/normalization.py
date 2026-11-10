"""Robust timestamp parser and UTC normalizer.

Normalizes ISO 8601, RFC 3339, Apache/Nginx CLF, BSD Syslog, and epoch timestamps to UTC,
preserving the original string and transparently tracking time-zone and year inferences.
Also detects ambiguous DST fallback transitions and New Year rollovers in BSD Syslog streams.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from src.timeline.schema import NormalizationStatus

# Regex patterns for fast dispatch
CLF_PATTERN = re.compile(
    r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})$"
)
SYSLOG_BSD_PATTERN = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$"
)
CTIME_PATTERN = re.compile(
    r"^([A-Za-z]{3})\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$"
)
EPOCH_PATTERN = re.compile(r"^\d{10}(?:\.\d+)?$")
EPOCH_MS_PATTERN = re.compile(r"^\d{13}$")

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

# Documented timezone abbreviations with UTC offsets and ambiguity flags
# Documented per RFC 822 / POSIX / tz database standards:
# - EST: UTC-5 (US Eastern) vs UTC+10 (Australian Eastern) -> AMBIGUOUS
# - CST: UTC-6 (US Central) vs UTC+8 (China Standard) vs UTC-5 (Cuba) -> AMBIGUOUS
# - IST: UTC+5:30 (India Standard) vs UTC+1 (Irish Summer) vs UTC+2 (Israel Standard) -> AMBIGUOUS
# - BST: UTC+1 (British Summer Time) -> AMBIGUOUS
TZ_ABBREVIATIONS: Dict[str, Tuple[timezone, bool, str]] = {
    "UTC": (timezone.utc, False, "Coordinated Universal Time (UTC+00:00)"),
    "GMT": (timezone.utc, False, "Greenwich Mean Time (UTC+00:00)"),
    "EST": (timezone(timedelta(hours=-5)), True, "Eastern Standard Time (UTC-05:00); ambiguous with Australian EST (UTC+10:00)"),
    "EDT": (timezone(timedelta(hours=-4)), False, "Eastern Daylight Time (UTC-04:00)"),
    "CST": (timezone(timedelta(hours=-6)), True, "Central Standard Time (UTC-06:00); ambiguous with China ST (UTC+08:00) and Cuba ST (UTC-05:00)"),
    "CDT": (timezone(timedelta(hours=-5)), False, "Central Daylight Time (UTC-05:00)"),
    "MST": (timezone(timedelta(hours=-7)), False, "Mountain Standard Time (UTC-07:00)"),
    "MDT": (timezone(timedelta(hours=-6)), False, "Mountain Daylight Time (UTC-06:00)"),
    "PST": (timezone(timedelta(hours=-8)), False, "Pacific Standard Time (UTC-08:00)"),
    "PDT": (timezone(timedelta(hours=-7)), False, "Pacific Daylight Time (UTC-07:00)"),
    "IST": (timezone(timedelta(hours=5, minutes=30)), True, "India Standard Time (UTC+05:30); ambiguous with Irish ST (UTC+01:00) and Israel ST (UTC+02:00)"),
    "BST": (timezone(timedelta(hours=1)), True, "British Summer Time (UTC+01:00)"),
}


@dataclass
class NormalizedTimestampResult:
    """Outcome of a timestamp normalization attempt."""
    raw_str: Optional[str]
    normalized_utc_dt: Optional[datetime]
    normalized_utc_iso: Optional[str]
    status: NormalizationStatus
    timezone_used: Optional[str]
    year_inferred: bool
    warnings: List[str]


def parse_tz_offset(offset_str: str) -> timezone:
    """Parse '+0530' or '-04:00' or 'Z' into a datetime.timezone."""
    clean = offset_str.strip()
    if clean.upper() == "Z":
        return timezone.utc
    clean = clean.replace(":", "")
    sign = -1 if clean.startswith("-") else 1
    hours = int(clean[1:3])
    minutes = int(clean[3:5]) if len(clean) >= 5 else 0
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def _localize_and_check_dst(
    dt_naive: datetime,
    src_tz: Any,
    tz_name: str,
    base_status: NormalizationStatus,
    warnings: List[str],
) -> Tuple[datetime, NormalizationStatus]:
    """Localize a naive datetime and check for DST fold ambiguity and non-existent gap.

    Returns:
        (utc_datetime, status) where status is:
        - NONEXISTENT_DST if the local time falls within a spring-forward transition gap.
        - AMBIGUOUS_DST if the local time falls within a repeated fall-back transition hour.
        - base_status otherwise.
    """
    try:
        dt0 = dt_naive.replace(tzinfo=src_tz, fold=0).astimezone(timezone.utc)
        dt1 = dt_naive.replace(tzinfo=src_tz, fold=1).astimezone(timezone.utc)

        if dt0 != dt1:
            # Check if this naive datetime exists in the target timezone by round-tripping dt0
            dt0_back = dt0.astimezone(src_tz).replace(tzinfo=None)
            is_nonexistent_gap = abs((dt0_back - dt_naive).total_seconds()) > 1

            if is_nonexistent_gap:
                warnings.append(
                    f"Non-existent DST spring-forward transition timestamp detected in '{tz_name}'. "
                    f"Candidate UTC timestamps: fold=0 ({dt0.strftime('%Y-%m-%dT%H:%M:%SZ')}) or fold=1 ({dt1.strftime('%Y-%m-%dT%H:%M:%SZ')})."
                )
                return dt0, NormalizationStatus.NONEXISTENT_DST
            else:
                warnings.append(
                    f"Ambiguous Daylight Saving Time (DST) fallback transition hour detected in '{tz_name}'; "
                    f"defaulted to first occurrence fold=0 ({dt0.strftime('%Y-%m-%dT%H:%M:%SZ')}). "
                    f"Alternate candidate: fold=1 ({dt1.strftime('%Y-%m-%dT%H:%M:%SZ')})."
                )
                return dt0, NormalizationStatus.AMBIGUOUS_DST

        # Also check gap when dt0 == dt1
        dt0_back = dt0.astimezone(src_tz).replace(tzinfo=None)
        if abs((dt0_back - dt_naive).total_seconds()) > 1:
            warnings.append(
                f"Non-existent DST spring-forward transition timestamp detected in '{tz_name}'. "
                f"Candidate UTC timestamp: {dt0.strftime('%Y-%m-%dT%H:%M:%SZ')}."
            )
            return dt0, NormalizationStatus.NONEXISTENT_DST

        return dt0, base_status

    except Exception:
        dt_loc = dt_naive.replace(tzinfo=src_tz)
        return dt_loc.astimezone(timezone.utc), base_status


class TimestampNormalizer:
    """Normalizes raw timestamp strings to UTC according to documented rules."""

    def __init__(
        self,
        default_timezone: str = "UTC",
        base_year: Optional[int] = None,
        date_order_preference: str = "DMY",
    ) -> None:
        self.default_timezone = default_timezone
        self.base_year = base_year or datetime.now(timezone.utc).year
        self.current_syslog_year: int = self.base_year
        self.last_syslog_month: Optional[int] = None
        self.date_order_preference: str = date_order_preference.upper()

    def normalize(
        self,
        raw_ts: Optional[str],
        configured_timezone: Optional[str] = None,
        override_year: Optional[int] = None,
    ) -> NormalizedTimestampResult:
        """Parse raw timestamp string and convert to UTC.
        
        Args:
            raw_ts: Original timestamp string from the log.
            configured_timezone: Investigator-specified source timezone (e.g. 'America/New_York').
            override_year: Explicit year to use for yearless syslog timestamps (for rollover detection).
        """
        if not raw_ts or not raw_ts.strip():
            return NormalizedTimestampResult(
                raw_str=raw_ts,
                normalized_utc_dt=None,
                normalized_utc_iso=None,
                status=NormalizationStatus.MISSING_TIMESTAMP,
                timezone_used=None,
                year_inferred=False,
                warnings=["Record contains no timestamp string."],
            )

        ts = raw_ts.strip()
        warnings: List[str] = []

        # 1. Try Apache / Nginx CLF: "10/Oct/2026:13:55:36 -0700"
        m_clf = CLF_PATTERN.match(ts)
        if m_clf:
            day, month_str, year, hour, minute, second, offset_str = m_clf.groups()
            month = MONTH_MAP.get(month_str.capitalize())
            if not month:
                return self._invalid_result(ts, f"Invalid month abbreviation '{month_str}' in CLF timestamp.")
            try:
                tz = parse_tz_offset(offset_str)
                dt = datetime(int(year), month, int(day), int(hour), int(minute), int(second), tzinfo=tz)
                utc_dt = dt.astimezone(timezone.utc)
                return NormalizedTimestampResult(
                    raw_str=ts,
                    normalized_utc_dt=utc_dt,
                    normalized_utc_iso=utc_dt.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
                    status=NormalizationStatus.NORMALIZED_EXPLICIT_OFFSET,
                    timezone_used=offset_str,
                    year_inferred=False,
                    warnings=warnings,
                )
            except ValueError as err:
                return self._invalid_result(ts, f"Impossible date/time values: {err}")

        # 2. Try BSD Syslog: "Oct 11 14:32:01" (Yearless)
        m_syslog = SYSLOG_BSD_PATTERN.match(ts)
        if m_syslog:
            month_str, day, hour, minute, second = m_syslog.groups()
            month = MONTH_MAP.get(month_str.capitalize())
            if not month:
                return self._invalid_result(ts, f"Invalid month abbreviation '{month_str}' in syslog timestamp.")

            if override_year is not None:
                target_year = override_year
                self.current_syslog_year = override_year
                self.last_syslog_month = month
            else:
                if self.last_syslog_month == 12 and month == 1:
                    self.current_syslog_year += 1
                    warnings.append("New Year rollover (Dec -> Jan) detected in stream; year incremented.")
                self.last_syslog_month = month
                target_year = self.current_syslog_year

            tz_name = configured_timezone or self.default_timezone
            try:
                src_tz = ZoneInfo(tz_name)
            except ZoneInfoNotFoundError:
                src_tz = timezone.utc
                warnings.append(f"Specified timezone '{tz_name}' not found; defaulted to UTC.")
                tz_name = "UTC"

            try:
                dt_naive = datetime(
                    target_year, month, int(day), int(hour), int(minute), int(second)
                )
            except ValueError as err:
                return self._invalid_result(ts, f"Invalid syslog date/time: {err}")

            base_status = (
                NormalizationStatus.NORMALIZED_CONFIGURED_TZ
                if configured_timezone
                else NormalizationStatus.NORMALIZED_ASSUMED_TZ
            )

            # Check DST ambiguity
            utc_dt, status = _localize_and_check_dst(dt_naive, src_tz, tz_name, base_status, warnings)

            warnings.append(
                f"Year inferred as {target_year} based on investigation baseline. "
                f"Timezone assumed as '{tz_name}'."
            )

            return NormalizedTimestampResult(
                raw_str=ts,
                normalized_utc_dt=utc_dt,
                normalized_utc_iso=utc_dt.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
                status=status,
                timezone_used=tz_name,
                year_inferred=True,
                warnings=warnings,
            )

        # 3. Try POSIX ctime format: "Sun Oct 11 14:32:01 2026"
        m_ctime = CTIME_PATTERN.match(ts)
        if m_ctime:
            _wday, month_str, day, hour, minute, second, year = m_ctime.groups()
            month = MONTH_MAP.get(month_str.capitalize())
            if month:
                try:
                    dt_naive = datetime(int(year), month, int(day), int(hour), int(minute), int(second))
                    tz_name = configured_timezone or self.default_timezone
                    try:
                        src_tz = ZoneInfo(tz_name)
                    except ZoneInfoNotFoundError:
                        src_tz = timezone.utc
                        tz_name = "UTC"

                    base_status = (
                        NormalizationStatus.NORMALIZED_CONFIGURED_TZ
                        if configured_timezone
                        else NormalizationStatus.NORMALIZED_ASSUMED_TZ
                    )
                    utc_dt, status = _localize_and_check_dst(dt_naive, src_tz, tz_name, base_status, warnings)
                    warnings.append(f"POSIX ctime format parsed. Assumed timezone '{tz_name}'.")
                    return NormalizedTimestampResult(
                        raw_str=ts,
                        normalized_utc_dt=utc_dt,
                        normalized_utc_iso=utc_dt.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
                        status=status,
                        timezone_used=tz_name,
                        year_inferred=False,
                        warnings=warnings,
                    )
                except ValueError as err:
                    return self._invalid_result(ts, f"Invalid ctime date/time: {err}")

        # 4. Try Unix Epoch timestamp (seconds or milliseconds)
        if EPOCH_PATTERN.match(ts):
            sec = float(ts)
            utc_dt = datetime.fromtimestamp(sec, tz=timezone.utc)
            return NormalizedTimestampResult(
                raw_str=ts,
                normalized_utc_dt=utc_dt,
                normalized_utc_iso=utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                status=NormalizationStatus.NORMALIZED_EXPLICIT_OFFSET,
                timezone_used="UTC (Epoch)",
                year_inferred=False,
                warnings=warnings,
            )

        if EPOCH_MS_PATTERN.match(ts):
            sec = int(ts) / 1000.0
            utc_dt = datetime.fromtimestamp(sec, tz=timezone.utc)
            return NormalizedTimestampResult(
                raw_str=ts,
                normalized_utc_dt=utc_dt,
                normalized_utc_iso=utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                status=NormalizationStatus.NORMALIZED_EXPLICIT_OFFSET,
                timezone_used="UTC (Epoch ms)",
                year_inferred=False,
                warnings=warnings,
            )

        # 5. Try timezone abbreviation suffix: e.g. "2026-10-11 14:32:01 EST"
        m_abbr = re.match(r"^(.*?)\s+([A-Za-z]{2,4})$", ts)
        if m_abbr:
            candidate_abbr = m_abbr.group(2).upper()
            if candidate_abbr in TZ_ABBREVIATIONS:
                sub_ts = m_abbr.group(1).strip()
                sub_res = self.normalize(sub_ts, configured_timezone="UTC")
                if sub_res.normalized_utc_dt is not None:
                    tz_obj, is_ambig, desc = TZ_ABBREVIATIONS[candidate_abbr]
                    naive_part = sub_res.normalized_utc_dt.replace(tzinfo=None)
                    localized = naive_part.replace(tzinfo=tz_obj)
                    utc_dt = localized.astimezone(timezone.utc)
                    if is_ambig:
                        status = NormalizationStatus.AMBIGUOUS_TIMESTAMP
                        warnings.append(
                            f"Timezone abbreviation '{candidate_abbr}' is ambiguous: {desc}. Resolved as {tz_obj}."
                        )
                    else:
                        status = NormalizationStatus.NORMALIZED_EXPLICIT_OFFSET
                    return NormalizedTimestampResult(
                        raw_str=ts,
                        normalized_utc_dt=utc_dt,
                        normalized_utc_iso=utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                        status=status,
                        timezone_used=candidate_abbr,
                        year_inferred=False,
                        warnings=warnings,
                    )

        # 6. Slashed date DD/MM vs MM/DD ambiguity check
        m_slash = re.match(
            r"^(\d{1,2})/(\d{1,2})/(\d{4})(?:[\sT](\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s*(AM|PM))?)?$",
            ts,
            re.IGNORECASE,
        )
        if m_slash:
            p1, p2, yr, hr, mn, sc, ampm = m_slash.groups()
            num1, num2, year = int(p1), int(p2), int(yr)
            hour = int(hr) if hr else 0
            minute = int(mn) if mn else 0
            second = int(sc) if sc else 0
            if ampm:
                ampm_u = ampm.upper()
                if ampm_u == "PM" and hour < 12:
                    hour += 12
                elif ampm_u == "AM" and hour == 12:
                    hour = 0

            if 1 <= num1 <= 12 and 1 <= num2 <= 12 and num1 != num2:
                # Ambiguous day/month ordering
                try:
                    dt_dmy = datetime(year, num2, num1, hour, minute, second)
                    dt_mdy = datetime(year, num1, num2, hour, minute, second)
                    chosen_dt = dt_mdy if self.date_order_preference == "MDY" else dt_dmy
                    warnings.append(
                        f"Ambiguous date format '{ts}': could be interpreted as DD/MM/YYYY ({dt_dmy.strftime('%Y-%m-%d')}) "
                        f"or MM/DD/YYYY ({dt_mdy.strftime('%Y-%m-%d')}). Applied investigation preference '{self.date_order_preference}'."
                    )
                    tz_name = configured_timezone or self.default_timezone
                    try:
                        src_tz = ZoneInfo(tz_name)
                    except ZoneInfoNotFoundError:
                        src_tz = timezone.utc
                        tz_name = "UTC"

                    utc_dt, _ = _localize_and_check_dst(
                        chosen_dt, src_tz, tz_name, NormalizationStatus.AMBIGUOUS_TIMESTAMP, warnings
                    )
                    return NormalizedTimestampResult(
                        raw_str=ts,
                        normalized_utc_dt=utc_dt,
                        normalized_utc_iso=utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                        status=NormalizationStatus.AMBIGUOUS_TIMESTAMP,
                        timezone_used=tz_name,
                        year_inferred=False,
                        warnings=warnings,
                    )
                except ValueError:
                    pass

        # 7. Try standard ISO 8601 / RFC 3339 via datetime.fromisoformat
        iso_candidate = ts
        if iso_candidate.endswith("Z"):
            iso_candidate = iso_candidate[:-1] + "+00:00"

        try:
            dt = datetime.fromisoformat(iso_candidate)
            if dt.tzinfo is not None:
                utc_dt = dt.astimezone(timezone.utc)
                return NormalizedTimestampResult(
                    raw_str=ts,
                    normalized_utc_dt=utc_dt,
                    normalized_utc_iso=utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    status=NormalizationStatus.NORMALIZED_EXPLICIT_OFFSET,
                    timezone_used=str(dt.tzinfo),
                    year_inferred=False,
                    warnings=warnings,
                )
            else:
                # Naive ISO timestamp (no timezone offset provided)
                tz_name = configured_timezone or self.default_timezone
                try:
                    src_tz = ZoneInfo(tz_name)
                except ZoneInfoNotFoundError:
                    src_tz = timezone.utc
                    warnings.append(f"Timezone '{tz_name}' not found; defaulted to UTC.")
                    tz_name = "UTC"

                base_status = (
                    NormalizationStatus.NORMALIZED_CONFIGURED_TZ
                    if configured_timezone
                    else NormalizationStatus.NORMALIZED_ASSUMED_TZ
                )

                utc_dt, status = _localize_and_check_dst(dt, src_tz, tz_name, base_status, warnings)
                warnings.append(f"Naive ISO timestamp: source timezone assumed as '{tz_name}'.")

                return NormalizedTimestampResult(
                    raw_str=ts,
                    normalized_utc_dt=utc_dt,
                    normalized_utc_iso=utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    status=status,
                    timezone_used=tz_name,
                    year_inferred=False,
                    warnings=warnings,
                )
        except ValueError:
            pass

        # 8. Try standard strptime formats (common 12-hour AM/PM and 24-hour variants)
        common_formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%Y-%m-%d %I:%M:%S %p",
            "%Y/%m/%d %I:%M:%S %p",
            "%d/%m/%Y %I:%M:%S %p",
            "%m/%d/%Y %I:%M:%S %p",
            "%d/%m/%Y %I:%M %p",
            "%m/%d/%Y %I:%M %p",
            "%Y-%m-%d %I:%M %p",
            "%Y-%m-%d %H:%M:%S,%f",  # Java / Python logging
            "%Y-%m-%d %H:%M:%S.%f",
        ]

        for fmt in common_formats:
            try:
                dt = datetime.strptime(ts, fmt)
                tz_name = configured_timezone or self.default_timezone
                try:
                    src_tz = ZoneInfo(tz_name)
                except ZoneInfoNotFoundError:
                    src_tz = timezone.utc
                    tz_name = "UTC"

                base_status = (
                    NormalizationStatus.NORMALIZED_CONFIGURED_TZ
                    if configured_timezone
                    else NormalizationStatus.NORMALIZED_ASSUMED_TZ
                )

                utc_dt, status = _localize_and_check_dst(dt, src_tz, tz_name, base_status, warnings)
                warnings.append(f"Format parsed as '{fmt}'. Assumed timezone '{tz_name}'.")

                return NormalizedTimestampResult(
                    raw_str=ts,
                    normalized_utc_dt=utc_dt,
                    normalized_utc_iso=utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    status=status,
                    timezone_used=tz_name,
                    year_inferred=False,
                    warnings=warnings,
                )
            except ValueError:
                continue

        # If all strategies fail
        return self._invalid_result(ts, f"Unable to parse timestamp '{ts}' into any supported format.")

    def _invalid_result(self, raw_ts: str, reason: str) -> NormalizedTimestampResult:
        return NormalizedTimestampResult(
            raw_str=raw_ts,
            normalized_utc_dt=None,
            normalized_utc_iso=None,
            status=NormalizationStatus.INVALID_TIMESTAMP,
            timezone_used=None,
            year_inferred=False,
            warnings=[reason],
        )
