"""Robust timestamp parser and UTC normalizer.

Normalizes ISO 8601, RFC 3339, Apache/Nginx CLF, BSD Syslog, and epoch timestamps to UTC,
preserving the original string and transparently tracking time-zone and year inferences.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from src.timeline.schema import NormalizationStatus

# Regex patterns for fast dispatch
CLF_PATTERN = re.compile(
    r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})$"
)
SYSLOG_BSD_PATTERN = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$"
)
EPOCH_PATTERN = re.compile(r"^\d{10}(?:\.\d+)?$")
EPOCH_MS_PATTERN = re.compile(r"^\d{13}$")

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
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
    from datetime import timedelta
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


class TimestampNormalizer:
    """Normalizes raw timestamp strings to UTC according to documented rules."""

    def __init__(
        self,
        default_timezone: str = "UTC",
        base_year: Optional[int] = None,
    ) -> None:
        self.default_timezone = default_timezone
        self.base_year = base_year or datetime.now(timezone.utc).year

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
            override_year: Explicit year to use for yearless syslog timestamps.
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
        target_year = override_year or self.base_year

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

            tz_name = configured_timezone or self.default_timezone
            try:
                src_tz = ZoneInfo(tz_name)
            except ZoneInfoNotFoundError:
                src_tz = timezone.utc
                warnings.append(f"Specified timezone '{tz_name}' not found; defaulted to UTC.")
                tz_name = "UTC"

            try:
                dt_local = datetime(
                    target_year, month, int(day), int(hour), int(minute), int(second), tzinfo=src_tz
                )
                utc_dt = dt_local.astimezone(timezone.utc)
            except ValueError as err:
                return self._invalid_result(ts, f"Invalid syslog date/time: {err}")

            status = (
                NormalizationStatus.NORMALIZED_CONFIGURED_TZ
                if configured_timezone
                else NormalizationStatus.NORMALIZED_ASSUMED_TZ
            )
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

        # 3. Try Unix Epoch timestamp (seconds or milliseconds)
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

        # 4. Try standard ISO 8601 / RFC 3339 via datetime.fromisoformat
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

                dt_localized = dt.replace(tzinfo=src_tz)
                utc_dt = dt_localized.astimezone(timezone.utc)

                status = (
                    NormalizationStatus.NORMALIZED_CONFIGURED_TZ
                    if configured_timezone
                    else NormalizationStatus.NORMALIZED_ASSUMED_TZ
                )
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

        # 5. Try standard strptime formats (common date-time variants)
        common_formats = [
            ("%Y-%m-%d %H:%M:%S", False),
            ("%Y/%m/%d %H:%M:%S", False),
            ("%d/%m/%Y %H:%M:%S", False),
            ("%m/%d/%Y %H:%M:%S", False),
            ("%Y-%m-%d %H:%M:%S,%f", False),  # Java / Python logging
        ]

        for fmt, has_tz in common_formats:
            try:
                dt = datetime.strptime(ts, fmt)
                tz_name = configured_timezone or self.default_timezone
                try:
                    src_tz = ZoneInfo(tz_name)
                except ZoneInfoNotFoundError:
                    src_tz = timezone.utc
                    tz_name = "UTC"

                dt_localized = dt.replace(tzinfo=src_tz)
                utc_dt = dt_localized.astimezone(timezone.utc)
                status = (
                    NormalizationStatus.NORMALIZED_CONFIGURED_TZ
                    if configured_timezone
                    else NormalizationStatus.NORMALIZED_ASSUMED_TZ
                )
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
