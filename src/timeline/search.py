"""Timeline search and multi-facet filtering engine.

Provides full-text keyword querying and combined filtering across hosts,
evidence files, time ranges, accounts, IPs, severities, and data-quality states.

Enhanced with regex search, exclude keyword, IP/CIDR subnet filter,
bookmark filter, and tag filter.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set

from src.timeline.schema import Event


@dataclass
class StructuredPredicates:
    """Parsed structured tokens from a Chronica CQL query string."""
    hosts: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    severities: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    request_ids: List[str] = field(default_factory=list)
    session_ids: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    statuses: List[str] = field(default_factory=list)
    not_terms: List[str] = field(default_factory=list)
    free_terms: List[str] = field(default_factory=list)

    @property
    def is_structured(self) -> bool:
        return bool(
            self.hosts
            or self.users
            or self.ips
            or self.severities
            or self.categories
            or self.request_ids
            or self.session_ids
            or self.files
            or self.statuses
            or self.not_terms
        )


def parse_cql_query(query: str) -> StructuredPredicates:
    """Parse structured key:value tokens and NOT modifiers from a CQL string."""
    preds = StructuredPredicates()
    if not query or not query.strip():
        return preds

    import shlex
    try:
        raw_tokens = shlex.split(query)
    except Exception:
        raw_tokens = query.split()

    i = 0
    while i < len(raw_tokens):
        token = raw_tokens[i].strip()
        if not token or token.upper() == "AND":
            i += 1
            continue

        is_not = False
        if token.upper() == "NOT":
            is_not = True
            i += 1
            if i >= len(raw_tokens):
                break
            token = raw_tokens[i].strip()
        elif token.startswith("-") and len(token) > 1:
            is_not = True
            token = token[1:]

        if ":" in token:
            key, val = token.split(":", 1)
            key = key.lower()
            val = val.strip("\"'")
            if is_not:
                preds.not_terms.append(val.lower())
            else:
                if key in ("host", "hostname", "source_host"):
                    preds.hosts.append(val.lower())
                elif key in ("user", "username", "actor"):
                    preds.users.append(val.lower())
                elif key in ("ip", "src_ip", "dst_ip"):
                    preds.ips.append(val.lower())
                elif key in ("sev", "severity", "level"):
                    preds.severities.append(val.upper())
                elif key in ("cat", "category"):
                    preds.categories.append(val.upper())
                elif key in ("req", "request_id", "correlation_id"):
                    preds.request_ids.append(val.lower())
                elif key in ("session", "session_id", "sess"):
                    preds.session_ids.append(val.lower())
                elif key in ("file", "source", "evidence", "original_filename"):
                    preds.files.append(val.lower())
                elif key in ("status", "parsing_status", "correction_status"):
                    preds.statuses.append(val.upper())
                else:
                    preds.free_terms.append(token.lower())
        else:
            clean_term = token.strip("\"'")
            if is_not:
                preds.not_terms.append(clean_term.lower())
            else:
                preds.free_terms.append(clean_term.lower())
        i += 1

    return preds


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
    # New fields (all optional with safe defaults for backward compatibility)
    use_regex: bool = False                     # Compile keyword as case-insensitive regex
    exclude_keyword: Optional[str] = None       # Negative filter: exclude events matching this term
    ip_subnet_cidr: Optional[str] = None        # CIDR subnet filter (e.g., '192.168.1.0/24')
    bookmarked_only: bool = False               # Only return bookmarked events
    tag_filter: Optional[str] = None           # Filter by tag in extra_fields["tags"]
    host: Optional[str] = None                 # Alias for source_host
    severities: Optional[List[str]] = None      # Multi-select severity list
    categories: Optional[List[str]] = None      # Multi-select category list

    def __post_init__(self) -> None:
        if self.host and not self.source_host:
            self.source_host = self.host

    def is_empty(self) -> bool:
        return not any([
            self.keyword,
            self.source_host,
            self.host,
            self.evidence_id,
            self.original_filename,
            self.start_time_iso,
            self.end_time_iso,
            self.username,
            self.src_ip,
            self.dst_ip,
            self.severity,
            self.category,
            self.severities,
            self.categories,
            self.parsing_status,
            self.correction_status,
            self.has_warnings_only,
            self.use_regex,
            self.exclude_keyword,
            self.ip_subnet_cidr,
            self.bookmarked_only,
            self.tag_filter,
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

        # Pre-compile regex or parse structured CQL predicates
        kw_regex: Optional[re.Pattern] = None
        kw_lower: Optional[str] = None
        cql_preds: Optional[StructuredPredicates] = None
        if criteria.keyword:
            if criteria.use_regex:
                try:
                    kw_regex = re.compile(criteria.keyword, re.IGNORECASE)
                except re.error:
                    kw_lower = criteria.keyword.strip().lower()
            else:
                cql_preds = parse_cql_query(criteria.keyword)
                kw_lower = criteria.keyword.strip().lower()

        # Pre-compile exclude keyword
        excl_lower: Optional[str] = None
        if criteria.exclude_keyword:
            excl_lower = criteria.exclude_keyword.strip().lower()

        # Pre-parse CIDR subnet
        subnet: Optional[ipaddress.IPv4Network | ipaddress.IPv6Network] = None
        if criteria.ip_subnet_cidr:
            try:
                subnet = ipaddress.ip_network(criteria.ip_subnet_cidr.strip(), strict=False)
            except ValueError:
                pass  # Invalid CIDR — skip subnet filtering

        filtered: List[Event] = []

        for ev in events:
            # Build text corpus for keyword search
            text_corpus = (
                f"{ev.raw_text} {ev.description} "
                f"{ev.username or ''} {ev.src_ip or ''} {ev.dst_ip or ''} {ev.request_id or ''} "
                f"{ev.source_host or ''} {ev.source_app or ''}"
            )

            # 1. Full-text keyword match (structured CQL predicates, regex, or substring)
            if kw_regex is not None:
                if not kw_regex.search(text_corpus):
                    continue
            elif cql_preds and cql_preds.is_structured:
                # Structured CQL predicates evaluation
                ev_host_lower = (ev.source_host or "").lower()
                if any(h not in ev_host_lower for h in cql_preds.hosts):
                    continue

                ev_user_lower = (ev.username or "").lower()
                if any(u not in ev_user_lower for u in cql_preds.users):
                    continue

                ev_ips_lower = f"{ev.src_ip or ''} {ev.dst_ip or ''}".lower()
                if any(ip not in ev_ips_lower for ip in cql_preds.ips):
                    continue

                ev_sev_upper = (ev.severity or "").upper()
                if any(s != ev_sev_upper for s in cql_preds.severities):
                    continue

                ev_cat_upper = (ev.category or "").upper()
                if any(c != ev_cat_upper for c in cql_preds.categories):
                    continue

                ev_req_lower = f"{ev.request_id or ''} {ev.extra_fields.get('request_id', '')} {ev.extra_fields.get('correlation_id', '')}".lower()
                if any(r not in ev_req_lower for r in cql_preds.request_ids):
                    continue

                ev_sess_lower = f"{ev.session_id or ''} {ev.extra_fields.get('session_id', '')} {ev.raw_text}".lower()
                if any(s not in ev_sess_lower for s in cql_preds.session_ids):
                    continue

                ev_file_lower = f"{ev.original_filename or ''} {ev.evidence_id or ''}".lower()
                if any(f not in ev_file_lower for f in cql_preds.files):
                    continue

                ev_stat_upper = f"{ev.parsing_status or ''} {ev.correction_status or ''}".upper()
                if any(st not in ev_stat_upper for st in cql_preds.statuses):
                    continue

                tc_lower = text_corpus.lower()
                if any(not_t in tc_lower for not_t in cql_preds.not_terms):
                    continue

                if any(free_t not in tc_lower for free_t in cql_preds.free_terms):
                    continue
            elif kw_lower:
                if kw_lower not in text_corpus.lower():
                    continue

            # 2. Exclude keyword (negative filter)
            if excl_lower:
                if excl_lower in text_corpus.lower():
                    continue

            # 3. Host filter
            if criteria.source_host and ev.source_host != criteria.source_host:
                continue

            # 4. Evidence file filter
            if criteria.evidence_id and ev.evidence_id != criteria.evidence_id:
                continue
            if criteria.original_filename and ev.original_filename != criteria.original_filename:
                continue

            # 5. Username filter
            if criteria.username and (not ev.username or criteria.username.lower() not in ev.username.lower()):
                continue

            # 6. IP filter (exact)
            if criteria.src_ip and ev.src_ip != criteria.src_ip:
                continue
            if criteria.dst_ip and ev.dst_ip != criteria.dst_ip:
                continue

            # 7. CIDR subnet filter
            if subnet is not None:
                ev_ips = [ip for ip in (ev.src_ip, ev.dst_ip) if ip]
                if not ev_ips:
                    continue
                in_subnet = False
                for ip_str in ev_ips:
                    try:
                        ip_obj = ipaddress.ip_address(ip_str.strip())
                        if ip_obj in subnet:
                            in_subnet = True
                            break
                    except ValueError:
                        pass
                if not in_subnet:
                    continue

            # 8. Severity and Category
            if criteria.severities:
                sev_set = {s.upper() for s in criteria.severities}
                if ev.severity.upper() not in sev_set:
                    continue
            elif criteria.severity and ev.severity.upper() != criteria.severity.upper():
                continue

            if criteria.categories:
                cat_set = {c.upper() for c in criteria.categories}
                if ev.category.upper() not in cat_set:
                    continue
            elif criteria.category and ev.category.upper() != criteria.category.upper():
                continue


            # 9. Parsing status
            if criteria.parsing_status and ev.parsing_status != criteria.parsing_status:
                continue

            # 10. Correction status
            if criteria.correction_status and ev.correction_status != criteria.correction_status:
                continue

            # 11. Warnings only
            if criteria.has_warnings_only and not ev.data_quality_warnings:
                continue

            # 12. Time range (comparing ISO strings lexicographically for ISO 8601 UTC)
            ts = ev.corrected_utc_iso or ev.normalized_utc_iso
            if criteria.start_time_iso:
                if not ts or ts < criteria.start_time_iso:
                    continue
            if criteria.end_time_iso:
                if not ts or ts > criteria.end_time_iso:
                    continue

            # 13. Bookmarked only
            if criteria.bookmarked_only:
                if ev.extra_fields.get("bookmarked") is not True:
                    continue

            # 14. Tag filter
            if criteria.tag_filter:
                event_tags = ev.extra_fields.get("tags", [])
                if criteria.tag_filter not in event_tags:
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

    @classmethod
    def search(cls, events: List[Event], criteria: FilterCriteria) -> List[Event]:
        """Convenience method returning filtered Event list directly."""
        return cls.filter_events(events, criteria).events
