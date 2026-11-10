"""Cross-source event correlation and link discovery.

Discovers logical relationships across disparate log sources based on shared
identifiers (Request IDs, Session tokens, IP/User associations) using corrected time
and neutral forensic attribution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from src.timeline.schema import Event


def _effective_time(ev: Event) -> Optional[str]:
    """Retrieve the forensically most defensible timestamp (corrected time prioritized over normalized time)."""
    return ev.corrected_utc_iso or ev.normalized_utc_iso


def _effective_epoch(ev: Event) -> Optional[float]:
    """Parse effective timestamp to epoch seconds."""
    ts = _effective_time(ev)
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def _detect_ordered_hop(events_group: List[Event], window_sec: float) -> Optional[Tuple[str, str, float]]:
    """Check if an ordered transition between distinct sources occurred within the time window.

    Returns (source_A, source_B, delta_sec) if a valid hop pattern is found, else None.
    """
    valid_events = []
    for ev in events_group:
        epoch = _effective_epoch(ev)
        src = ev.source_host or ev.original_filename
        if epoch is not None and src:
            valid_events.append((epoch, src))

    if len(valid_events) < 2:
        return None

    valid_events.sort(key=lambda x: x[0])

    for i in range(len(valid_events) - 1):
        epoch1, src1 = valid_events[i]
        for j in range(i + 1, len(valid_events)):
            epoch2, src2 = valid_events[j]
            dt = epoch2 - epoch1
            if dt > window_sec:
                break
            if src1 != src2:
                return (src1, src2, dt)
    return None


@dataclass
class CorrelationCluster:
    """Group of correlated events linked by a common entity or transaction identifier."""
    cluster_id: str
    cluster_type: str  # REQUEST_ID, SESSION_ID, SHARED_USER, SHARED_IP, LATERAL_MOVEMENT_USER, LATERAL_MOVEMENT_IP
    common_value: str
    event_ids: List[str] = field(default_factory=list)
    sources_involved: List[str] = field(default_factory=list)
    start_time_utc: Optional[str] = None
    end_time_utc: Optional[str] = None
    notes: str = ""


class EventCorrelator:
    """Discovers cross-source correlation links among timeline events."""

    def __init__(self, lateral_movement_window_sec: float = 3600.0) -> None:
        """Initialize the event correlator.

        Args:
            lateral_movement_window_sec: Maximum time delta (seconds) between sequential activity
                across distinct hosts to qualify as an ordered lateral movement hop (default: 3600s / 1 hr).
                Activities outside this window are neutrally classified as shared identity across sources.
        """
        self.lateral_movement_window_sec = lateral_movement_window_sec

    def correlate(self, events: List[Event]) -> List[CorrelationCluster]:
        """Group events into correlation clusters based on shared identifiers.

        Discovers:
        - REQUEST_ID: Events sharing the same request/transaction ID
        - SESSION_ID: Events sharing the same session token
        - SHARED_USER / LATERAL_MOVEMENT_USER: Same username active on >= 2 distinct sources
        - SHARED_IP / LATERAL_MOVEMENT_IP: Same source IP active on >= 2 distinct sources
        """
        req_clusters: Dict[str, List[Event]] = {}
        sess_clusters: Dict[str, List[Event]] = {}
        user_clusters: Dict[str, List[Event]] = {}
        ip_clusters: Dict[str, List[Event]] = {}

        for ev in events:
            if ev.request_id:
                req_clusters.setdefault(ev.request_id.strip(), []).append(ev)
            if ev.session_id:
                sess_clusters.setdefault(ev.session_id.strip(), []).append(ev)
            if ev.username:
                user_clusters.setdefault(ev.username.strip(), []).append(ev)
            if ev.src_ip:
                ip_clusters.setdefault(ev.src_ip.strip(), []).append(ev)

        clusters: List[CorrelationCluster] = []

        # Request ID Clusters
        for req_id, group in req_clusters.items():
            if len(group) >= 2:
                sources = sorted(list({ev.source_host or ev.original_filename for ev in group}))
                times = [_effective_time(ev) for ev in group if _effective_time(ev)]
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
                times = [_effective_time(ev) for ev in group if _effective_time(ev)]
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

        # User Clusters: SHARED_USER vs LATERAL_MOVEMENT_USER
        for username, group in user_clusters.items():
            distinct_sources = sorted(list({ev.source_host or ev.original_filename for ev in group}))
            if len(distinct_sources) >= 2:
                times = [_effective_time(ev) for ev in group if _effective_time(ev)]
                start_time = min(times) if times else None
                end_time = max(times) if times else None

                hop = _detect_ordered_hop(group, self.lateral_movement_window_sec)
                if hop:
                    src_a, src_b, dt = hop
                    c_type = "LATERAL_MOVEMENT_USER"
                    notes = (
                        f"User '{username}' observed moving between sources within {dt:.1f}s "
                        f"({src_a} -> {src_b}). Ordered lateral movement pattern across {len(distinct_sources)} sources."
                    )
                else:
                    c_type = "SHARED_USER"
                    notes = (
                        f"User '{username}' active across {len(distinct_sources)} distinct sources: "
                        f"{', '.join(distinct_sources[:5])}{'...' if len(distinct_sources) > 5 else ''}. "
                        f"Shared identity across sources."
                    )

                cluster = CorrelationCluster(
                    cluster_id=f"cluster_user_{username.replace(' ', '_')}",
                    cluster_type=c_type,
                    common_value=username,
                    event_ids=[ev.event_id for ev in group],
                    sources_involved=distinct_sources,
                    start_time_utc=start_time,
                    end_time_utc=end_time,
                    notes=notes,
                )
                clusters.append(cluster)

        # IP Clusters: SHARED_IP vs LATERAL_MOVEMENT_IP
        for src_ip, group in ip_clusters.items():
            distinct_sources = sorted(list({ev.source_host or ev.original_filename for ev in group}))
            if len(distinct_sources) >= 2:
                times = [_effective_time(ev) for ev in group if _effective_time(ev)]
                start_time = min(times) if times else None
                end_time = max(times) if times else None

                hop = _detect_ordered_hop(group, self.lateral_movement_window_sec)
                if hop:
                    src_a, src_b, dt = hop
                    c_type = "LATERAL_MOVEMENT_IP"
                    notes = (
                        f"Source IP '{src_ip}' observed connecting across sources within {dt:.1f}s "
                        f"({src_a} -> {src_b}). Ordered lateral movement or scanning pattern across {len(distinct_sources)} sources."
                    )
                else:
                    c_type = "SHARED_IP"
                    notes = (
                        f"Source IP '{src_ip}' active across {len(distinct_sources)} distinct sources: "
                        f"{', '.join(distinct_sources[:5])}{'...' if len(distinct_sources) > 5 else ''}. "
                        f"Shared IP address across sources."
                    )

                cluster = CorrelationCluster(
                    cluster_id=f"cluster_ip_{src_ip.replace('.', '_').replace(':', '_')}",
                    cluster_type=c_type,
                    common_value=src_ip,
                    event_ids=[ev.event_id for ev in group],
                    sources_involved=distinct_sources,
                    start_time_utc=start_time,
                    end_time_utc=end_time,
                    notes=notes,
                )
                clusters.append(cluster)

        return clusters
