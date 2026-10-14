"""Timeline assembler and multi-source chronological aggregator.

Merges events from multiple evidence files, supports sorting by normalized UTC,
corrected UTC, or original line sequence, and maintains deterministic tie-breaking.
"""

from __future__ import annotations

from typing import List, Tuple

from src.timeline.schema import Event, NormalizationStatus


class TimelineAssembler:
    """Aggregates parsed and normalized events into a unified timeline."""

    @staticmethod
    def sort_timeline(
        events: List[Event],
        sort_by: str = "normalized_utc",  # 'normalized_utc', 'corrected_utc', 'original_order'
        ascending: bool = True,
    ) -> Tuple[List[Event], List[Event]]:
        """Sort timeline events while preserving deterministic secondary order.
        
        Returns:
            Tuple of:
            1. Valid chronological events (sorted).
            2. Unresolved / invalid timestamp events (segregated).
        """
        valid_events: List[Event] = []
        unresolved_events: List[Event] = []

        for ev in events:
            if ev.normalization_status in (
                NormalizationStatus.INVALID_TIMESTAMP.value,
                NormalizationStatus.MISSING_TIMESTAMP.value,
            ) or not ev.normalized_utc_iso:
                unresolved_events.append(ev)
            else:
                valid_events.append(ev)

        # Sort valid events
        if sort_by == "corrected_utc":
            def sort_key(e: Event):
                ts = e.corrected_utc_iso or e.normalized_utc_iso or ""
                return (ts, e.evidence_id, e.line_number, e.event_id)
        elif sort_by == "original_order":
            def sort_key(e: Event):
                return (e.evidence_id, e.line_number, e.event_id)
        else:  # Default: normalized_utc
            def sort_key(e: Event):
                ts = e.normalized_utc_iso or ""
                return (ts, e.evidence_id, e.line_number, e.event_id)

        sorted_valid = sorted(valid_events, key=sort_key, reverse=not ascending)

        # Secondary sort on unresolved events by evidence file and line number
        sorted_unresolved = sorted(
            unresolved_events,
            key=lambda e: (e.evidence_id, e.line_number, e.event_id),
        )

        return sorted_valid, sorted_unresolved
