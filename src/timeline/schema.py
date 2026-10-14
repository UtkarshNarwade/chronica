"""Unified forensic event schema and status definitions."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class NormalizationStatus(str, Enum):
    """Timestamp normalization classification."""
    NORMALIZED_EXPLICIT_OFFSET = "NORMALIZED_EXPLICIT_OFFSET"  # E.g. '2026-10-11T14:30:00+00:00' or '...Z'
    NORMALIZED_CONFIGURED_TZ = "NORMALIZED_CONFIGURED_TZ"      # Investigator supplied source timezone
    NORMALIZED_ASSUMED_TZ = "NORMALIZED_ASSUMED_TZ"            # Default assumption used (documented)
    NORMALIZED_YEAR_INFERRED = "NORMALIZED_YEAR_INFERRED"      # Syslog yearless timestamp inferred
    AMBIGUOUS_DST = "AMBIGUOUS_DST"                            # Falls within daylight saving fallback hour
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"                    # Non-existent or unparseable date/time
    MISSING_TIMESTAMP = "MISSING_TIMESTAMP"                    # Record had no timestamp


class CorrectionStatus(str, Enum):
    """Clock-skew correction status for an event."""
    UNCORRECTED = "UNCORRECTED"                                # No correction applied
    CORRECTED = "CORRECTED"                                    # Offset subtracted based on confirmed anchors
    INCONCLUSIVE_INSUFFICIENT_ANCHORS = "INCONCLUSIVE_INSUFFICIENT_ANCHORS"
    INCONCLUSIVE_CONFLICTING_ANCHORS = "INCONCLUSIVE_CONFLICTING_ANCHORS"
    CORRECTION_DISABLED = "CORRECTION_DISABLED"


@dataclass
class Event:
    """A standardized forensic event record retaining complete original provenance."""
    event_id: str
    investigation_id: str
    evidence_id: str
    original_filename: str
    line_number: int
    raw_text: str
    original_timestamp_str: Optional[str]
    parsed_dt_iso: Optional[str] = None
    normalized_utc_iso: Optional[str] = None
    corrected_utc_iso: Optional[str] = None
    normalization_status: str = NormalizationStatus.MISSING_TIMESTAMP.value
    timezone_assumed: Optional[str] = None
    year_inferred: bool = False
    estimated_clock_offset_sec: Optional[float] = None
    correction_uncertainty_sec: Optional[float] = None
    correction_status: str = CorrectionStatus.UNCORRECTED.value
    source_host: Optional[str] = None
    source_app: Optional[str] = None
    severity: str = "INFO"
    category: str = "SYSTEM"
    username: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    description: str = ""
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    parsing_status: str = "SUCCESS"
    data_quality_warnings: List[str] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
    extra_fields: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        investigation_id: str,
        evidence_id: str,
        original_filename: str,
        line_number: int,
        raw_text: str,
        original_timestamp_str: Optional[str],
        **kwargs: Any,
    ) -> Event:
        event_id = kwargs.pop("event_id", f"evt_{uuid.uuid4().hex[:12]}")
        if "normalization_status" not in kwargs:
            if kwargs.get("normalized_utc_iso"):
                kwargs["normalization_status"] = NormalizationStatus.NORMALIZED_EXPLICIT_OFFSET.value
            elif original_timestamp_str is None:
                kwargs["normalization_status"] = NormalizationStatus.MISSING_TIMESTAMP.value
        return cls(
            event_id=event_id,
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            original_filename=original_filename,
            line_number=line_number,
            raw_text=raw_text,
            original_timestamp_str=original_timestamp_str,
            **kwargs,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Event:
        return cls(**data)
