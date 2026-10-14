"""Clock-skew analysis, offset estimation, and timeline correction.

Implements defensible clock offset estimation using confirmed anchor pairs
(shared request IDs, session tokens, or investigator-verified synchronizations),
robust statistics (median, median absolute deviation), explicit sign conventions,
and honest reporting of inconclusive scenarios.
"""

from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.timeline.schema import CorrectionStatus, Event

SIGN_CONVENTION_DOC = (
    "Sign Convention: offset = target_clock - reference_clock. "
    "A positive offset (+s) indicates the target source clock was running ahead of the reference clock. "
    "To normalize target events into the reference timeline: corrected_time = target_time - offset."
)


@dataclass
class AnchorPair:
    """A pair of events from different sources representing the same physical instant."""
    anchor_id: str
    target_event_id: str
    target_source: str  # host or file name
    target_utc_iso: str
    target_utc_epoch: float
    reference_event_id: str
    reference_source: str
    reference_utc_iso: str
    reference_utc_epoch: float
    anchor_type: str  # REQUEST_ID, SESSION_ID, CORRELATED_EVENT, INVESTIGATOR_CONFIRMED
    anchor_key: str  # e.g., 'req-alpha-001'
    raw_offset_sec: float  # target_epoch - reference_epoch
    is_confirmed: bool = True
    confidence_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ClockSkewEstimate:
    """Calculated clock offset estimate and uncertainty metrics for a target source."""
    target_source: str
    reference_source: str
    anchor_count: int
    estimated_offset_sec: Optional[float]
    offset_sign_convention: str = SIGN_CONVENTION_DOC
    spread_mad_sec: Optional[float] = None  # Median Absolute Deviation
    min_offset_sec: Optional[float] = None
    max_offset_sec: Optional[float] = None
    estimation_method: str = "Median of confirmed anchor observations"
    status: str = "ESTIMATED"  # ESTIMATED, INCONCLUSIVE_INSUFFICIENT_ANCHORS, INCONCLUSIVE_CONFLICTING_ANCHORS, DISABLED
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ClockSkewAnalyzer:
    """Performs anchor discovery, statistical offset estimation, and timeline adjustment."""

    def __init__(
        self,
        min_anchors_required: int = 2,
        max_conflict_spread_sec: float = 30.0,
    ) -> None:
        self.min_anchors_required = min_anchors_required
        self.max_conflict_spread_sec = max_conflict_spread_sec

    def discover_anchors(
        self,
        events: List[Event],
        reference_source: str,
        target_source: str,
    ) -> List[AnchorPair]:
        """Automatically identify candidate anchor pairs sharing identical request_ids or session_ids."""
        ref_events_by_req: Dict[str, List[Event]] = {}
        target_events_by_req: Dict[str, List[Event]] = {}

        for ev in events:
            if not ev.normalized_utc_iso:
                continue

            # Identify source identifier (source_host or original_filename)
            ev_source = ev.source_host or ev.original_filename

            if ev.request_id:
                req = ev.request_id.strip()
                if ev_source == reference_source:
                    ref_events_by_req.setdefault(req, []).append(ev)
                elif ev_source == target_source:
                    target_events_by_req.setdefault(req, []).append(ev)

        anchors: List[AnchorPair] = []
        shared_keys = set(ref_events_by_req.keys()).intersection(target_events_by_req.keys())

        for key in sorted(shared_keys):
            refs = ref_events_by_req[key]
            targets = target_events_by_req[key]

            # Pair corresponding events (first with first)
            for i in range(min(len(refs), len(targets))):
                ref_ev = refs[i]
                tar_ev = targets[i]

                ref_dt = datetime.fromisoformat(ref_ev.normalized_utc_iso.replace("Z", "+00:00"))
                tar_dt = datetime.fromisoformat(tar_ev.normalized_utc_iso.replace("Z", "+00:00"))

                ref_epoch = ref_dt.timestamp()
                tar_epoch = tar_dt.timestamp()

                raw_offset = tar_epoch - ref_epoch  # target - reference

                anchor = AnchorPair(
                    anchor_id=f"anc_{key}_{i}",
                    target_event_id=tar_ev.event_id,
                    target_source=target_source,
                    target_utc_iso=tar_ev.normalized_utc_iso,
                    target_utc_epoch=tar_epoch,
                    reference_event_id=ref_ev.event_id,
                    reference_source=reference_source,
                    reference_utc_iso=ref_ev.normalized_utc_iso,
                    reference_utc_epoch=ref_epoch,
                    anchor_type="REQUEST_ID",
                    anchor_key=key,
                    raw_offset_sec=round(raw_offset, 3),
                    is_confirmed=True,
                    confidence_notes=f"Linked by shared Request ID '{key}'.",
                )
                anchors.append(anchor)

        return anchors

    def estimate_skew(
        self,
        anchors: List[AnchorPair],
        target_source: str,
        reference_source: str,
    ) -> ClockSkewEstimate:
        """Estimate clock offset using robust median statistics across confirmed anchors."""
        confirmed = [a for a in anchors if a.is_confirmed and a.target_source == target_source and a.reference_source == reference_source]
        count = len(confirmed)

        if count < self.min_anchors_required:
            return ClockSkewEstimate(
                target_source=target_source,
                reference_source=reference_source,
                anchor_count=count,
                estimated_offset_sec=None,
                status="INCONCLUSIVE_INSUFFICIENT_ANCHORS",
                explanation=(
                    f"Only {count} anchor(s) found between '{target_source}' and '{reference_source}'. "
                    f"A minimum of {self.min_anchors_required} independent confirmed anchors is required "
                    f"to avoid basing forensic adjustments on isolated or potentially delayed logs."
                ),
            )

        offsets = [a.raw_offset_sec for a in confirmed]
        median_offset = round(statistics.median(offsets), 3)

        # Median Absolute Deviation (MAD)
        deviations = [abs(x - median_offset) for x in offsets]
        mad = round(statistics.median(deviations), 3)
        min_offset = min(offsets)
        max_offset = max(offsets)
        spread = max_offset - min_offset

        if spread > self.max_conflict_spread_sec:
            return ClockSkewEstimate(
                target_source=target_source,
                reference_source=reference_source,
                anchor_count=count,
                estimated_offset_sec=None,
                spread_mad_sec=mad,
                min_offset_sec=min_offset,
                max_offset_sec=max_offset,
                status="INCONCLUSIVE_CONFLICTING_ANCHORS",
                explanation=(
                    f"Anchors exhibit conflicting offsets spanning {spread:.2f}s "
                    f"(exceeds acceptable spread threshold {self.max_conflict_spread_sec:.2f}s). "
                    f"Offsets observed: {offsets}. May indicate variable logging lag or unstable drift."
                ),
            )

        return ClockSkewEstimate(
            target_source=target_source,
            reference_source=reference_source,
            anchor_count=count,
            estimated_offset_sec=median_offset,
            spread_mad_sec=mad,
            min_offset_sec=min_offset,
            max_offset_sec=max_offset,
            status="ESTIMATED",
            explanation=(
                f"Clock offset robustly estimated at {median_offset:+.3f}s from {count} confirmed anchors "
                f"(MAD spread: ±{mad:.3f}s, range: [{min_offset:.2f}s, {max_offset:.2f}s])."
            ),
        )

    def apply_corrections(
        self,
        events: List[Event],
        estimates: Dict[str, ClockSkewEstimate],
        enabled: bool = True,
    ) -> List[Event]:
        """Apply clock skew adjustments to events, preserving original and normalized timestamps."""
        updated: List[Event] = []

        for ev in events:
            # Create a clone
            ev_dict = ev.to_dict()
            ev_clone = Event.from_dict(ev_dict)

            source_id = ev.source_host or ev.original_filename
            estimate = estimates.get(source_id)

            if not enabled:
                ev_clone.corrected_utc_iso = ev.normalized_utc_iso
                ev_clone.estimated_clock_offset_sec = None
                ev_clone.correction_uncertainty_sec = None
                ev_clone.correction_status = CorrectionStatus.CORRECTION_DISABLED.value
                updated.append(ev_clone)
                continue

            if not estimate or estimate.status != "ESTIMATED" or estimate.estimated_offset_sec is None:
                ev_clone.corrected_utc_iso = ev.normalized_utc_iso
                ev_clone.estimated_clock_offset_sec = None
                ev_clone.correction_uncertainty_sec = None
                if estimate and estimate.status.startswith("INCONCLUSIVE"):
                    ev_clone.correction_status = estimate.status
                else:
                    ev_clone.correction_status = CorrectionStatus.UNCORRECTED.value
                updated.append(ev_clone)
                continue

            # Apply correction: corrected_time = target_time - offset
            if ev.normalized_utc_iso:
                try:
                    dt = datetime.fromisoformat(ev.normalized_utc_iso.replace("Z", "+00:00"))
                    corrected_dt = dt - timedelta(seconds=estimate.estimated_offset_sec)
                    ev_clone.corrected_utc_iso = corrected_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    ev_clone.estimated_clock_offset_sec = estimate.estimated_offset_sec
                    ev_clone.correction_uncertainty_sec = estimate.spread_mad_sec
                    ev_clone.correction_status = CorrectionStatus.CORRECTED.value
                except Exception as err:
                    ev_clone.data_quality_warnings.append(f"Correction application error: {err}")
                    ev_clone.corrected_utc_iso = ev.normalized_utc_iso

            updated.append(ev_clone)

        return updated
