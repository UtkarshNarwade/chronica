"""Timeline search and multi-facet filtering engine.

Provides full-text keyword querying and combined filtering across hosts,
evidence files, time ranges, accounts, IPs, severities, and data-quality states.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Set

from src.timeline.schema import Event


@dataclass
class FilterCriteria:
    """Filter parameters for timeline exploration."""
    keyword: Optional[str] = None
    source_host: Optional[str] = None
    evidence_id: Optional[str] = None
    original_filename: Optional[str] = None
    start_time_iso: Optional[str] = None
    end_time_iso: Optional[str] = None
    username: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    parsing_status: Optional[str] = None
    correction_status: Optional[str] = None
    has_warnings_only: bool = False

    def is_empty(self) -> bool:
        return not any([
            self.keyword,
            self.source_host,
            self.evidence_id,
            self.original_filename,
            self.start_time_iso,
            self.end_time_iso,
            self.username,
            self.src_ip,
            self.dst_ip,
            self.severity,
            self.category,
            self.parsing_status,
            self.correction_status,
            self.has_warnings_only,
        ])


@dataclass
class SearchResult:
    """Outcome of a filtered search operation."""
    total_events: int
    filtered_events: int
    events: List[Event]
    criteria: FilterCriteria
    unique_hosts: List[str] = field(default_factory=list)
    unique_users: List[str] = field(default_factory=list)
    unique_ips: List[str] = field(default_factory=list)


class TimelineSearchEngine:
    """In-memory search and multi-facet filtering engine for timeline events."""

    @staticmethod
    def filter_events(events: List[Event], criteria: FilterCriteria) -> SearchResult:
        """Apply all specified filter criteria using boolean conjunction (AND)."""
        total = len(events)
        if criteria.is_empty():
            return SearchResult(
                total_events=total,
                filtered_events=total,
                events=events,
                criteria=criteria,
                unique_hosts=sorted(list({e.source_host for e in events if e.source_host})),
                unique_users=sorted(list({e.username for e in events if e.username})),
                unique_ips=sorted(list({e.src_ip for e in events if e.src_ip})),
            )

        filtered: List[Event] = []
        kw_lower = criteria.keyword.strip().lower() if criteria.keyword else None

        for ev in events:
            # 1. Full-text keyword match
            if kw_lower:
                text_to_search = (
                    f"{ev.raw_text} {ev.description} {ev.message if hasattr(ev, 'message') else ''} "
                    f"{ev.username or ''} {ev.src_ip or ''} {ev.dst_ip or ''} {ev.request_id or ''} "
                    f"{ev.source_host or ''} {ev.source_app or ''}"
                ).lower()
                if kw_lower not in text_to_search:
                    continue

            # 2. Host filter
            if criteria.source_host and ev.source_host != criteria.source_host:
                continue

            # 3. Evidence file filter
            if criteria.evidence_id and ev.evidence_id != criteria.evidence_id:
                continue
            if criteria.original_filename and ev.original_filename != criteria.original_filename:
                continue

            # 4. Username filter
            if criteria.username and (not ev.username or criteria.username.lower() not in ev.username.lower()):
                continue

            # 5. IP filter
            if criteria.src_ip and ev.src_ip != criteria.src_ip:
                continue
            if criteria.dst_ip and ev.dst_ip != criteria.dst_ip:
                continue

            # 6. Severity and Category
            if criteria.severity and ev.severity.upper() != criteria.severity.upper():
                continue
            if criteria.category and ev.category.upper() != criteria.category.upper():
                continue

            # 7. Parsing status
            if criteria.parsing_status and ev.parsing_status != criteria.parsing_status:
                continue

            # 8. Correction status
            if criteria.correction_status and ev.correction_status != criteria.correction_status:
                continue

            # 9. Warnings only
            if criteria.has_warnings_only and not ev.data_quality_warnings:
                continue

            # 10. Time range (comparing ISO strings lexicographically for ISO 8601 UTC)
            ts = ev.corrected_utc_iso or ev.normalized_utc_iso
            if criteria.start_time_iso:
                if not ts or ts < criteria.start_time_iso:
                    continue
            if criteria.end_time_iso:
                if not ts or ts > criteria.end_time_iso:
                    continue

            filtered.append(ev)

        return SearchResult(
            total_events=total,
            filtered_events=len(filtered),
            events=filtered,
            criteria=criteria,
            unique_hosts=sorted(list({e.source_host for e in filtered if e.source_host})),
            unique_users=sorted(list({e.username for e in filtered if e.username})),
            unique_ips=sorted(list({e.src_ip for e in filtered if e.src_ip})),
        )
