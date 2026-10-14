"""Cross-source event correlation and link discovery.

Discovers logical relationships across disparate log sources based on shared
identifiers (Request IDs, Session tokens, IP/User associations) without
assuming causal relationships.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from src.timeline.schema import Event


@dataclass
class CorrelationCluster:
    """Group of correlated events linked by a common entity or transaction identifier."""
    cluster_id: str
    cluster_type: str  # REQUEST_ID, SESSION_ID, USER_ACTIVITY, IP_ACTIVITY
    common_value: str
    event_ids: List[str] = field(default_factory=list)
    sources_involved: List[str] = field(default_factory=list)
    start_time_utc: Optional[str] = None
    end_time_utc: Optional[str] = None
    notes: str = ""


class EventCorrelator:
    """Discovers cross-source correlation links among timeline events."""

    def correlate(self, events: List[Event]) -> List[CorrelationCluster]:
        """Group events into correlation clusters based on shared identifiers."""
        req_clusters: Dict[str, List[Event]] = {}
        sess_clusters: Dict[str, List[Event]] = {}

        for ev in events:
            if ev.request_id:
                req_clusters.setdefault(ev.request_id.strip(), []).append(ev)
            if ev.session_id:
                sess_clusters.setdefault(ev.session_id.strip(), []).append(ev)

        clusters: List[CorrelationCluster] = []

        # Request ID Clusters
        for req_id, group in req_clusters.items():
            if len(group) >= 2:
                sources = sorted(list({ev.source_host or ev.original_filename for ev in group}))
                times = [ev.normalized_utc_iso for ev in group if ev.normalized_utc_iso]
                start_time = min(times) if times else None
                end_time = max(times) if times else None

                cluster = CorrelationCluster(
                    cluster_id=f"cluster_req_{req_id}",
                    cluster_type="REQUEST_ID",
                    common_value=req_id,
                    event_ids=[ev.event_id for ev in group],
                    sources_involved=sources,
                    start_time_utc=start_time,
                    end_time_utc=end_time,
                    notes=(
                        f"Found {len(group)} events across {len(sources)} source(s) "
                        f"sharing Request ID '{req_id}'."
                    ),
                )
                clusters.append(cluster)

        # Session ID Clusters
        for sess_id, group in sess_clusters.items():
            if len(group) >= 2:
                sources = sorted(list({ev.source_host or ev.original_filename for ev in group}))
                times = [ev.normalized_utc_iso for ev in group if ev.normalized_utc_iso]
                start_time = min(times) if times else None
                end_time = max(times) if times else None

                cluster = CorrelationCluster(
                    cluster_id=f"cluster_sess_{sess_id}",
                    cluster_type="SESSION_ID",
                    common_value=sess_id,
                    event_ids=[ev.event_id for ev in group],
                    sources_involved=sources,
                    start_time_utc=start_time,
                    end_time_utc=end_time,
                    notes=(
                        f"Found {len(group)} events sharing Session ID '{sess_id}'."
                    ),
                )
                clusters.append(cluster)

        return clusters
