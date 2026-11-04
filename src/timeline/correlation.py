"""Cross-source event correlation and link discovery.

Discovers logical relationships across disparate log sources based on shared
identifiers (Request IDs, Session tokens, IP/User associations) without
assuming causal relationships.

Enhanced with LATERAL_USER and LATERAL_IP cluster detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from src.timeline.schema import Event


@dataclass
class CorrelationCluster:
    """Group of correlated events linked by a common entity or transaction identifier."""
    cluster_id: str
    cluster_type: str  # REQUEST_ID, SESSION_ID, LATERAL_USER, LATERAL_IP
    common_value: str
    event_ids: List[str] = field(default_factory=list)
    sources_involved: List[str] = field(default_factory=list)
    start_time_utc: Optional[str] = None
    end_time_utc: Optional[str] = None
    notes: str = ""


class EventCorrelator:
    """Discovers cross-source correlation links among timeline events."""

    def correlate(self, events: List[Event]) -> List[CorrelationCluster]:
        """Group events into correlation clusters based on shared identifiers.

        Discovers:
        - REQUEST_ID: Events sharing the same request/transaction ID
        - SESSION_ID: Events sharing the same session token
        - LATERAL_USER: Same username active on >= 2 distinct hosts/sources
        - LATERAL_IP: Same source IP active on >= 2 distinct hosts/sources
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

        # LATERAL_USER: Same username active on >= 2 distinct hosts/sources
        for username, group in user_clusters.items():
            distinct_sources = sorted(list({ev.source_host or ev.original_filename for ev in group}))
            if len(distinct_sources) >= 2:
                times = [ev.normalized_utc_iso for ev in group if ev.normalized_utc_iso]
                start_time = min(times) if times else None
                end_time = max(times) if times else None

                cluster = CorrelationCluster(
                    cluster_id=f"cluster_user_{username.replace(' ', '_')}",
                    cluster_type="LATERAL_USER",
                    common_value=username,
                    event_ids=[ev.event_id for ev in group],
                    sources_involved=distinct_sources,
                    start_time_utc=start_time,
                    end_time_utc=end_time,
                    notes=(
                        f"User '{username}' active across {len(distinct_sources)} distinct sources: "
                        f"{', '.join(distinct_sources[:5])}{'...' if len(distinct_sources) > 5 else ''}. "
                        f"Possible lateral movement indicator."
                    ),
                )
                clusters.append(cluster)

        # LATERAL_IP: Same source IP active on >= 2 distinct hosts/sources
        for src_ip, group in ip_clusters.items():
            distinct_sources = sorted(list({ev.source_host or ev.original_filename for ev in group}))
            if len(distinct_sources) >= 2:
                times = [ev.normalized_utc_iso for ev in group if ev.normalized_utc_iso]
                start_time = min(times) if times else None
                end_time = max(times) if times else None

                cluster = CorrelationCluster(
                    cluster_id=f"cluster_ip_{src_ip.replace('.', '_').replace(':', '_')}",
                    cluster_type="LATERAL_IP",
                    common_value=src_ip,
                    event_ids=[ev.event_id for ev in group],
                    sources_involved=distinct_sources,
                    start_time_utc=start_time,
                    end_time_utc=end_time,
                    notes=(
                        f"Source IP '{src_ip}' active across {len(distinct_sources)} distinct sources: "
                        f"{', '.join(distinct_sources[:5])}{'...' if len(distinct_sources) > 5 else ''}. "
                        f"Possible lateral movement or scanning indicator."
                    ),
                )
                clusters.append(cluster)

        return clusters
