"""Clock-skew analysis, offset estimation, and timeline correction.

Implements defensible clock offset estimation using confirmed anchor pairs
(shared request IDs, session tokens, or investigator-verified synchronizations),
robust statistics (median, median absolute deviation), explicit sign conventions,
Theil-Sen linear drift estimation, a latency tolerance guard, and honest reporting
of inconclusive scenarios.
"""

from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

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
    uncertainty_sec: Optional[float] = None  # Defensible uncertainty bound (F-15: latency bound + sample penalty + floor)
    min_offset_sec: Optional[float] = None
    max_offset_sec: Optional[float] = None
    estimation_method: str = "Median of confirmed anchor observations"
    status: str = "ESTIMATED"  # ESTIMATED, INCONCLUSIVE_INSUFFICIENT_ANCHORS, INCONCLUSIVE_CONFLICTING_ANCHORS, DISABLED
    explanation: str = ""
    drift_rate_ppm: Optional[float] = None  # Parts per million drift rate (µs/s)
    drift_base_epoch: Optional[float] = None  # Reference epoch t0 for applying linear drift
    drift_applied: bool = False  # True if linear drift was applied to timeline events
    probable_tz_misconfiguration: bool = False  # True if offset matches whole/half hour multiples
    within_latency_tolerance: bool = False  # True if offset is within latency_tolerance_sec

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ClockSkewAnalyzer:
    """Performs anchor discovery, statistical offset estimation, and timeline adjustment."""

    def __init__(
        self,
        min_anchors_required: int = 2,
        max_conflict_spread_sec: float = 30.0,
        latency_tolerance_sec: float = 2.0,
        uncertainty_floor_sec: float = 0.5,
        min_anchors_for_zero_uncertainty: int = 30,
        significant_drift_ppm_threshold: float = 10.0,
    ) -> None:
        """Initialize the clock skew analyzer.

        Args:
            min_anchors_required: Minimum anchor pairs needed for a reliable estimate.
            max_conflict_spread_sec: Max anchor offset spread before flagging as conflicting.
            latency_tolerance_sec: Observed offsets within ±this value are treated as normal
                network/execution latency and NOT subtracted (preserving causal ordering).
                Default 2.0s handles sub-2s execution delays without false clock corrections.
            uncertainty_floor_sec: Absolute resolution floor below which uncertainty cannot fall (0.5s).
            min_anchors_for_zero_uncertainty: Threshold below which uncertainty cannot be ±0 (N=30).
            significant_drift_ppm_threshold: Minimum ppm drift rate to apply linear drift correction (10.0 ppm).
        """
        self.min_anchors_required = min_anchors_required
        self.max_conflict_spread_sec = max_conflict_spread_sec
        self.latency_tolerance_sec = latency_tolerance_sec
        self.uncertainty_floor_sec = uncertainty_floor_sec
        self.min_anchors_for_zero_uncertainty = min_anchors_for_zero_uncertainty
        self.significant_drift_ppm_threshold = significant_drift_ppm_threshold

    @staticmethod
    def is_anchor_eligible(key: str) -> bool:
        """Evaluate if an identifier is eligible for cross-host clock synchronization (F-02).

        Host-local sequence numbers such as audit daemon serials ('audit-12345'),
        numeric response metrics, or process IDs are local counters that collide
        across unrelated systems. Only true distributed trace, request, or session
        identifiers qualify as cross-source synchronization anchors.
        """
        if not key or not isinstance(key, str):
            return False
        cleaned = key.strip()
        if not cleaned:
            return False
        # Exclude per-host auditd serial IDs
        if cleaned.lower().startswith("audit-"):
            return False
        # Exclude pure numeric values (e.g. status codes, response sizes, PIDs)
        cleaned_no_dot = cleaned.replace(".", "", 1)
        if cleaned_no_dot.isdigit():
            return False
        return True

    def discover_anchors(
        self,
        events: List[Event],
        reference_source: str,
        target_source: str,
        manual_anchors: Optional[List[AnchorPair]] = None,
    ) -> List[AnchorPair]:
        """Automatically identify candidate anchor pairs via request_id, session_id, or manual links.

        Discovery order:
        1. Shared request_id values (REQUEST_ID anchors)
        2. Shared session_id values not already paired via request_id (SESSION_ID anchors)
        3. Any manual INVESTIGATOR_CONFIRMED anchors provided

        Args:
            events: All events in the investigation.
            reference_source: Trusted reference clock source identifier.
            target_source: Target source to estimate skew for.
            manual_anchors: Optional investigator-confirmed anchor pairs.

        Returns:
            List of AnchorPair objects.
        """
        ref_events_by_req: Dict[str, List[Event]] = {}
        target_events_by_req: Dict[str, List[Event]] = {}
        ref_events_by_sess: Dict[str, List[Event]] = {}
        target_events_by_sess: Dict[str, List[Event]] = {}

        for ev in events:
            if not ev.normalized_utc_iso:
                continue

            ev_source = ev.source_host or ev.original_filename

            if ev_source == reference_source:
                if ev.request_id:
                    ref_events_by_req.setdefault(ev.request_id.strip(), []).append(ev)
                if ev.session_id:
                    ref_events_by_sess.setdefault(ev.session_id.strip(), []).append(ev)
            elif ev_source == target_source:
                if ev.request_id:
                    target_events_by_req.setdefault(ev.request_id.strip(), []).append(ev)
                if ev.session_id:
                    target_events_by_sess.setdefault(ev.session_id.strip(), []).append(ev)

        anchors: List[AnchorPair] = []
        paired_ref_event_ids: set = set()
        paired_target_event_ids: set = set()

        # 1. REQUEST_ID anchors
        shared_req_keys = set(ref_events_by_req.keys()).intersection(target_events_by_req.keys())
        for key in sorted(shared_req_keys):
            if not self.is_anchor_eligible(key):
                continue
            refs = ref_events_by_req[key]
            targets = target_events_by_req[key]
            for i in range(min(len(refs), len(targets))):
                ref_ev = refs[i]
                tar_ev = targets[i]
                ref_dt = datetime.fromisoformat(ref_ev.normalized_utc_iso.replace("Z", "+00:00"))
                tar_dt = datetime.fromisoformat(tar_ev.normalized_utc_iso.replace("Z", "+00:00"))
                ref_epoch = ref_dt.timestamp()
                tar_epoch = tar_dt.timestamp()
                raw_offset = tar_epoch - ref_epoch
                anchor = AnchorPair(
                    anchor_id=f"anc_req_{key}_{i}",
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
                paired_ref_event_ids.add(ref_ev.event_id)
                paired_target_event_ids.add(tar_ev.event_id)

        # 2. SESSION_ID anchors (only for events not already paired via request_id)
        shared_sess_keys = set(ref_events_by_sess.keys()).intersection(target_events_by_sess.keys())
        for key in sorted(shared_sess_keys):
            if not self.is_anchor_eligible(key):
                continue
            refs = [ev for ev in ref_events_by_sess[key] if ev.event_id not in paired_ref_event_ids]
            targets = [ev for ev in target_events_by_sess[key] if ev.event_id not in paired_target_event_ids]
            if not refs or not targets:
                continue

            # Pair earliest events of each session per source
            refs_sorted = sorted(refs, key=lambda e: e.normalized_utc_iso or "")
            targets_sorted = sorted(targets, key=lambda e: e.normalized_utc_iso or "")
            ref_ev = refs_sorted[0]
            tar_ev = targets_sorted[0]

            ref_dt = datetime.fromisoformat(ref_ev.normalized_utc_iso.replace("Z", "+00:00"))
            tar_dt = datetime.fromisoformat(tar_ev.normalized_utc_iso.replace("Z", "+00:00"))
            ref_epoch = ref_dt.timestamp()
            tar_epoch = tar_dt.timestamp()
            raw_offset = tar_epoch - ref_epoch

            anchor = AnchorPair(
                anchor_id=f"anc_sess_{key}_0",
                target_event_id=tar_ev.event_id,
                target_source=target_source,
                target_utc_iso=tar_ev.normalized_utc_iso,
                target_utc_epoch=tar_epoch,
                reference_event_id=ref_ev.event_id,
                reference_source=reference_source,
                reference_utc_iso=ref_ev.normalized_utc_iso,
                reference_utc_epoch=ref_epoch,
                anchor_type="SESSION_ID",
                anchor_key=key,
                raw_offset_sec=round(raw_offset, 3),
                is_confirmed=True,
                confidence_notes=f"Linked by earliest event in shared Session ID '{key}'.",
            )
            anchors.append(anchor)
            paired_ref_event_ids.add(ref_ev.event_id)
            paired_target_event_ids.add(tar_ev.event_id)

        # 3. Manual INVESTIGATOR_CONFIRMED anchors
        if manual_anchors:
            for ma in manual_anchors:
                if (ma.reference_source == reference_source and ma.target_source == target_source
                        and ma.anchor_type == "INVESTIGATOR_CONFIRMED"):
                    anchors.append(ma)

        return anchors

    def estimate_skew(
        self,
        anchors: List[AnchorPair],
        target_source: str,
        reference_source: str,
    ) -> ClockSkewEstimate:
        """Estimate clock offset using robust median statistics across confirmed anchors.

        Also computes Theil-Sen linear drift rate (ppm) and applies latency tolerance guard
        to prevent false corrections on sub-tolerance execution latencies.
        """
        confirmed = [
            a for a in anchors
            if a.is_confirmed and a.target_source == target_source and a.reference_source == reference_source
        ]
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
            sample_penalty = self.latency_tolerance_sec / (count ** 0.5)
            unc = round(max(mad + sample_penalty, self.uncertainty_floor_sec), 3)
            return ClockSkewEstimate(
                target_source=target_source,
                reference_source=reference_source,
                anchor_count=count,
                estimated_offset_sec=None,
                spread_mad_sec=mad,
                uncertainty_sec=unc,
                min_offset_sec=min_offset,
                max_offset_sec=max_offset,
                status="INCONCLUSIVE_CONFLICTING_ANCHORS",
                explanation=(
                    f"Anchors exhibit conflicting offsets spanning {spread:.2f}s "
                    f"(exceeds acceptable spread threshold {self.max_conflict_spread_sec:.2f}s). "
                    f"Offsets observed: {offsets}. May indicate variable logging lag or unstable drift."
                ),
            )

        # Theil-Sen linear drift estimation
        drift_rate_ppm: Optional[float] = None
        drift_base_epoch: Optional[float] = None
        drift_applied: bool = False
        drift_slope: float = 0.0
        residual_spread: float = mad

        if count >= 3:
            slopes = []
            for i in range(len(confirmed)):
                for j in range(i + 1, len(confirmed)):
                    a_i = confirmed[i]
                    a_j = confirmed[j]
                    dt_ij = a_j.reference_utc_epoch - a_i.reference_utc_epoch
                    if abs(dt_ij) >= 10.0:
                        slope = (a_j.raw_offset_sec - a_i.raw_offset_sec) / dt_ij
                        slopes.append(slope)
            if slopes:
                median_slope = statistics.median(slopes)
                drift_rate_ppm = round(median_slope * 1_000_000, 2)
                drift_slope = median_slope

                if abs(drift_rate_ppm) >= self.significant_drift_ppm_threshold:
                    drift_applied = True
                    drift_base_epoch = confirmed[0].reference_utc_epoch
                    base_offsets = [
                        a.raw_offset_sec - (drift_slope * (a.reference_utc_epoch - drift_base_epoch))
                        for a in confirmed
                    ]
                    median_offset = round(statistics.median(base_offsets), 3)
                    residuals = [
                        abs(a.raw_offset_sec - (median_offset + drift_slope * (a.reference_utc_epoch - drift_base_epoch)))
                        for a in confirmed
                    ]
                    residual_spread = statistics.median(residuals)
                else:
                    drift_applied = False
                    residual_spread = mad

        # Forensic uncertainty model (F-15):
        # Incorporates latency bound and sample-size penalty.
        # When anchor count < N (default N=30), uncertainty is bounded away from zero.
        sample_penalty = self.latency_tolerance_sec / (count ** 0.5)
        if count < self.min_anchors_for_zero_uncertainty:
            uncertainty_sec = round(max(residual_spread + sample_penalty, self.uncertainty_floor_sec), 3)
        else:
            uncertainty_sec = round(max(residual_spread, self.uncertainty_floor_sec), 3)

        # Detect probable timezone misconfiguration (e.g., offsets within 60s of multiple of 30 mins)
        probable_tz = False
        if abs(median_offset) >= 1740.0:
            rem_30m = abs(median_offset) % 1800.0
            dist_to_30m = min(rem_30m, 1800.0 - rem_30m)
            if dist_to_30m <= 60.0:
                probable_tz = True

        # Latency tolerance guard
        within_latency_tolerance = (
            self.latency_tolerance_sec > 0
            and abs(median_offset) <= self.latency_tolerance_sec
        )

        if within_latency_tolerance:
            explanation = (
                f"Observed offset of {median_offset:+.3f}s is within the normal network/execution "
                f"latency tolerance of ±{self.latency_tolerance_sec:.2f}s. "
                f"The offset will NOT be subtracted to preserve causal event ordering. "
                f"({count} anchors, uncertainty: ±{uncertainty_sec:.3f}s, MAD: ±{mad:.3f}s)"
            )
        else:
            explanation = (
                f"Clock offset robustly estimated at {median_offset:+.3f}s from {count} confirmed anchors "
                f"(uncertainty: ±{uncertainty_sec:.3f}s, MAD: ±{mad:.3f}s, range: [{min_offset:.2f}s, {max_offset:.2f}s])."
            )
            if drift_rate_ppm is not None:
                if drift_applied:
                    explanation += f" Linear drift of {drift_rate_ppm:+.2f} ppm applied."
                else:
                    explanation += f" Linear drift of {drift_rate_ppm:+.2f} ppm was considered insignificant (<{self.significant_drift_ppm_threshold} ppm) and ignored."
            if probable_tz:
                explanation += " Probable timezone misconfiguration: offset is within 60s of a 30-minute multiple."

        return ClockSkewEstimate(
            target_source=target_source,
            reference_source=reference_source,
            anchor_count=count,
            estimated_offset_sec=median_offset,
            spread_mad_sec=mad,
            uncertainty_sec=uncertainty_sec,
            min_offset_sec=min_offset,
            max_offset_sec=max_offset,
            status="ESTIMATED",
            explanation=explanation,
            drift_rate_ppm=drift_rate_ppm,
            drift_base_epoch=drift_base_epoch,
            drift_applied=drift_applied,
            probable_tz_misconfiguration=probable_tz,
            within_latency_tolerance=within_latency_tolerance,
        )

    def apply_corrections(
        self,
        events: List[Event],
        estimates: Dict[str, ClockSkewEstimate],
        enabled: bool = True,
    ) -> List[Event]:
        """Apply clock skew adjustments to events, preserving original and normalized timestamps.

        If an estimate's within_latency_tolerance is True, the event is left uncorrected
        to preserve causal ordering (sub-tolerance execution delays are not clock skew).
        """
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

            effective_uncertainty = estimate.uncertainty_sec if estimate.uncertainty_sec is not None else estimate.spread_mad_sec

            # Causal guard: if offset is within latency tolerance, do NOT apply correction
            if estimate.within_latency_tolerance:
                ev_clone.corrected_utc_iso = ev.normalized_utc_iso
                ev_clone.estimated_clock_offset_sec = 0.0
                ev_clone.correction_uncertainty_sec = effective_uncertainty
                ev_clone.correction_status = CorrectionStatus.UNCORRECTED.value
                updated.append(ev_clone)
                continue

            # Apply correction: corrected_time = target_time - offset
            if ev.normalized_utc_iso:
                try:
                    dt = datetime.fromisoformat(ev.normalized_utc_iso.replace("Z", "+00:00"))
                    target_epoch = dt.timestamp()

                    # Apply linear drift if active
                    if (
                        estimate.drift_applied
                        and estimate.drift_rate_ppm is not None
                        and estimate.drift_base_epoch is not None
                    ):
                        drift_slope = estimate.drift_rate_ppm / 1_000_000.0
                        # Exact transformation: T_target = (1 + m)*T_ref + const
                        target_base = estimate.drift_base_epoch + estimate.estimated_offset_sec
                        delta_target = target_epoch - target_base
                        ref_epoch = estimate.drift_base_epoch + (delta_target / (1.0 + drift_slope))
                        offset_to_apply = target_epoch - ref_epoch
                    else:
                        offset_to_apply = estimate.estimated_offset_sec

                    corrected_dt = dt - timedelta(seconds=offset_to_apply)
                    ev_clone.corrected_utc_iso = corrected_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    ev_clone.estimated_clock_offset_sec = round(offset_to_apply, 3)
                    ev_clone.correction_uncertainty_sec = effective_uncertainty
                    ev_clone.correction_status = CorrectionStatus.CORRECTED.value
                except Exception as err:
                    ev_clone.data_quality_warnings.append(f"Correction application error: {err}")
                    ev_clone.corrected_utc_iso = ev.normalized_utc_iso

            updated.append(ev_clone)

        return updated
