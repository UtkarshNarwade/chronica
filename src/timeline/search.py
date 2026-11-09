"""Timeline search and multi-facet filtering engine.

Provides full-text keyword querying and combined filtering across hosts,
evidence files, time ranges, accounts, IPs, severities, and data-quality states.

Enhanced with regex search, exclude keyword, IP/CIDR subnet filter,
bookmark filter, and tag filter.
"""

from __future__ import annotations

import concurrent.futures
import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from src.timeline.schema import Event

MAX_REGEX_LEN = 256
REGEX_TIMEOUT_SEC = 0.2

_REGEX_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="cql_regex")


_REDOS_PATTERNS = [
    re.compile(r"\([^)]*[+*{][^)]*\)[+*{]"),  # Nested quantifiers like (a+)+ or (.*)*
    re.compile(r"[+*]\s*[+*]"),               # Consecutive quantifiers
]


def is_suspect_redos(pattern: str) -> bool:
    """Detect common catastrophic backtracking (ReDoS) patterns upfront (F-16)."""
    if not pattern:
        return False
    return any(p.search(pattern) for p in _REDOS_PATTERNS)


def safe_regex_search(pattern: re.Pattern, text: str, timeout: float = REGEX_TIMEOUT_SEC) -> bool:
    """Execute regex search safely with timeout and bounded pattern length to prevent ReDoS (F-16)."""
    future = _REGEX_POOL.submit(pattern.search, text)
    try:
        match = future.result(timeout=timeout)
        return match is not None
    except concurrent.futures.TimeoutError:
        return False
    except Exception:
        return False


class CQLNode:
    """Base class for parsed CQL Abstract Syntax Tree nodes."""

    def evaluate(self, ev: Event, text_corpus: str) -> bool:
        raise NotImplementedError


class FreeTextNode(CQLNode):
    """Matches a phrase or keyword in the full text corpus."""

    def __init__(self, term: str) -> None:
        self.term = term.lower()

    def evaluate(self, ev: Event, text_corpus: str) -> bool:
        if not self.term:
            return True
        return self.term in text_corpus.lower()


class FieldMatchNode(CQLNode):
    """Matches specific fields with exact semantics or explicit wildcards (*)."""

    def __init__(self, key: str, values: List[str]) -> None:
        self.key = key.lower()
        self.values = [v.strip() for v in values if v.strip()]

    def evaluate(self, ev: Event, text_corpus: str) -> bool:
        if not self.values:
            return True

        extracted: List[str] = []
        if self.key in ("host", "hostname", "source_host"):
            extracted = [ev.source_host or ""]
        elif self.key in ("user", "username", "actor"):
            extracted = [ev.username or ""]
        elif self.key in ("ip", "src_ip", "dst_ip"):
            extracted = [ip for ip in (ev.src_ip, ev.dst_ip) if ip]
        elif self.key in ("sev", "severity", "level"):
            extracted = [(ev.severity or "").upper()]
        elif self.key in ("cat", "category"):
            extracted = [(ev.category or "").upper()]
        elif self.key in ("req", "request_id", "correlation_id"):
            extracted = [
                r for r in (
                    ev.request_id,
                    str(ev.extra_fields.get("request_id", "")),
                    str(ev.extra_fields.get("correlation_id", "")),
                ) if r
            ]
        elif self.key in ("sess", "session", "session_id"):
            extracted = [
                s for s in (
                    ev.session_id,
                    str(ev.extra_fields.get("session_id", "")),
                ) if s
            ]
        elif self.key in ("file", "source", "evidence", "original_filename"):
            extracted = [f for f in (ev.original_filename, ev.evidence_id) if f]
        elif self.key in ("status", "parsing_status", "correction_status"):
            extracted = [st.upper() for st in (ev.parsing_status, ev.correction_status) if st]
        else:
            val = ev.extra_fields.get(self.key)
            if val is not None:
                extracted = [str(val)]

        if not extracted:
            return False

        for target_pat in self.values:
            pat_lower = target_pat.lower()
            if self.key in ("sev", "severity", "level", "cat", "category", "status"):
                if any(ev_val == target_pat.upper() for ev_val in extracted):
                    return True
            elif self.key in ("ip", "src_ip", "dst_ip"):
                for ev_ip in extracted:
                    if ev_ip.lower() == pat_lower:
                        return True
                    if "/" in target_pat:
                        try:
                            net = ipaddress.ip_network(target_pat, strict=False)
                            if ipaddress.ip_address(ev_ip) in net:
                                return True
                        except ValueError:
                            pass
            else:
                if pat_lower.endswith("*"):
                    prefix = pat_lower[:-1]
                    if any(ev_val.lower().startswith(prefix) for ev_val in extracted):
                        return True
                elif "*" in pat_lower or "?" in pat_lower:
                    if any(fnmatch.fnmatchcase(ev_val.lower(), pat_lower) for ev_val in extracted):
                        return True
                else:
                    if any(ev_val.lower() == pat_lower for ev_val in extracted):
                        return True
        return False


class TimeBoundNode(CQLNode):
    """Evaluates time boundaries (after / before), supporting inclusive full-day semantics."""

    def __init__(self, bound_type: str, iso_str: str) -> None:
        self.bound_type = bound_type
        self.iso_str = iso_str

    def evaluate(self, ev: Event, text_corpus: str) -> bool:
        ev_ts = ev.corrected_utc_iso or ev.normalized_utc_iso or ""
        if not ev_ts:
            return False
        if self.bound_type == "after":
            return ev_ts >= self.iso_str
        elif self.bound_type == "before":
            return ev_ts <= self.iso_str
        return True


class AndNode(CQLNode):
    """Conjunction of CQL sub-expressions."""

    def __init__(self, children: List[CQLNode]) -> None:
        self.children = children

    def evaluate(self, ev: Event, text_corpus: str) -> bool:
        return all(c.evaluate(ev, text_corpus) for c in self.children)


class OrNode(CQLNode):
    """Disjunction of CQL sub-expressions."""

    def __init__(self, children: List[CQLNode]) -> None:
        self.children = children

    def evaluate(self, ev: Event, text_corpus: str) -> bool:
        return any(c.evaluate(ev, text_corpus) for c in self.children)


class NotNode(CQLNode):
    """Negation of a CQL sub-expression."""

    def __init__(self, child: CQLNode) -> None:
        self.child = child

    def evaluate(self, ev: Event, text_corpus: str) -> bool:
        return not self.child.evaluate(ev, text_corpus)


@dataclass
class StructuredPredicates:
    """Parsed structured tokens from a Chronica CQL query string."""
    hosts: List[List[str]] = field(default_factory=list)
    users: List[List[str]] = field(default_factory=list)
    ips: List[List[str]] = field(default_factory=list)
    severities: List[List[str]] = field(default_factory=list)
    categories: List[List[str]] = field(default_factory=list)
    request_ids: List[List[str]] = field(default_factory=list)
    session_ids: List[List[str]] = field(default_factory=list)
    files: List[List[str]] = field(default_factory=list)
    statuses: List[List[str]] = field(default_factory=list)
    not_terms: List[str] = field(default_factory=list)
    free_terms: List[str] = field(default_factory=list)
    after_iso: Optional[str] = None
    before_iso: Optional[str] = None
    ast_root: Optional[CQLNode] = None

    @property
    def is_structured(self) -> bool:
        return bool(
            self.ast_root is not None
            or self.hosts
            or self.users
            or self.ips
            or self.severities
            or self.categories
            or self.request_ids
            or self.session_ids
            or self.files
            or self.statuses
            or self.not_terms
            or self.free_terms
            or self.after_iso
            or self.before_iso
        )

    def evaluate(self, ev: Event, text_corpus: str) -> bool:
        if self.ast_root is not None:
            return self.ast_root.evaluate(ev, text_corpus)
        return True


def tokenize_cql(query: str) -> List[Tuple[str, str]]:
    """Tokenize a CQL query string into (TOKEN_TYPE, VALUE) pairs."""
    tokens: List[Tuple[str, str]] = []
    i = 0
    n = len(query)
    while i < n:
        c = query[i]
        if c.isspace():
            i += 1
            continue
        if c == "(":
            tokens.append(("LPAREN", "("))
            i += 1
        elif c == ")":
            tokens.append(("RPAREN", ")"))
            i += 1
        elif c in ('"', "'"):
            quote = c
            i += 1
            start = i
            while i < n and query[i] != quote:
                if query[i] == "\\" and i + 1 < n:
                    i += 2
                else:
                    i += 1
            phrase = query[start:i]
            if i < n and query[i] == quote:
                i += 1
            clean_phrase = phrase.replace('\\"', '"').replace("\\'", "'").replace('\\\\', '\\')
            tokens.append(("TERM", clean_phrase))
        else:
            start = i
            while i < n and not query[i].isspace() and query[i] not in "()":
                if query[i] in ('"', "'"):
                    quote = query[i]
                    i += 1
                    while i < n and query[i] != quote:
                        if query[i] == "\\" and i + 1 < n:
                            i += 2
                        else:
                            i += 1
                    if i < n and query[i] == quote:
                        i += 1
                else:
                    i += 1
            word = query[start:i]
            upper_word = word.upper()
            if upper_word == "AND":
                tokens.append(("AND", "AND"))
            elif upper_word == "OR":
                tokens.append(("OR", "OR"))
            elif upper_word == "NOT":
                tokens.append(("NOT", "NOT"))
            elif word.startswith("-") and len(word) > 1:
                tokens.append(("NOT", "NOT"))
                rem = word[1:]
                if ":" in rem:
                    tokens.append(("FIELD", rem))
                else:
                    tokens.append(("TERM", rem))
            elif ":" in word:
                key, rval = word.split(":", 1)
                clean_rval = rval.replace('\\"', '"').replace("\\'", "'").replace('\\\\', '\\')
                tokens.append(("FIELD", f"{key}:{clean_rval}"))
            else:
                tokens.append(("TERM", word))
    return tokens


class _CQLParser:
    def __init__(self, tokens: List[Tuple[str, str]]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Optional[Tuple[str, str]]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def advance(self) -> Tuple[str, str]:
        t = self.tokens[self.pos]
        self.pos += 1
        return t

    def parse(self) -> Optional[CQLNode]:
        if not self.tokens:
            return None
        return self.parse_or()

    def parse_or(self) -> CQLNode:
        left = self.parse_and()
        while self.peek() and self.peek()[0] == "OR":
            self.advance()
            right = self.parse_and()
            left = OrNode([left, right])
        return left

    def parse_and(self) -> CQLNode:
        children = [self.parse_unary()]
        while self.peek() and self.peek()[0] not in ("OR", "RPAREN"):
            if self.peek()[0] == "AND":
                self.advance()
            children.append(self.parse_unary())
        if len(children) == 1:
            return children[0]
        return AndNode(children)

    def parse_unary(self) -> CQLNode:
        if self.peek() and self.peek()[0] == "NOT":
            self.advance()
            operand = self.parse_unary()
            return NotNode(operand)
        return self.parse_primary()

    def parse_primary(self) -> CQLNode:
        token = self.peek()
        if not token:
            return FreeTextNode("")
        ttype, val = token
        if ttype == "LPAREN":
            self.advance()
            node = self.parse_or()
            if self.peek() and self.peek()[0] == "RPAREN":
                self.advance()
            return node
        elif ttype == "FIELD":
            self.advance()
            key, raw_val = val.split(":", 1)
            raw_val = raw_val.strip("\"'")
            key_clean = key.lower()
            if key_clean in ("after", "since"):
                if re.match(r"^\d{4}-\d{2}-\d{2}$", raw_val):
                    iso = f"{raw_val}T00:00:00.000000Z"
                else:
                    iso = raw_val
                return TimeBoundNode("after", iso)
            elif key_clean in ("before", "until"):
                if re.match(r"^\d{4}-\d{2}-\d{2}$", raw_val):
                    iso = f"{raw_val}T23:59:59.999999Z"
                else:
                    iso = raw_val
                return TimeBoundNode("before", iso)
            else:
                parts = [p.strip().strip("\"'") for p in raw_val.split(",") if p.strip()]
                return FieldMatchNode(key_clean, parts if parts else [raw_val])
        elif ttype == "TERM":
            self.advance()
            return FreeTextNode(val)
        else:
            self.advance()
            return FreeTextNode(val)


def parse_cql_query(query: str) -> StructuredPredicates:
    """Parse structured key:value tokens, comma-separated OR lists, NOT modifiers, and boolean logic."""
    preds = StructuredPredicates()
    if not query or not query.strip():
        return preds

    tokens = tokenize_cql(query)
    parser = _CQLParser(tokens)
    preds.ast_root = parser.parse()

    # Populate legacy fields for full backward compatibility
    for ttype, val in tokens:
        if ttype == "FIELD":
            if ":" in val:
                key, rval = val.split(":", 1)
                rval = rval.strip("\"'")
                parts = [p.strip().strip("\"'") for p in rval.split(",") if p.strip()] or [rval]
                k = key.lower()
                if k in ("host", "hostname", "source_host"):
                    preds.hosts.append([p.lower() for p in parts])
                elif k in ("user", "username", "actor"):
                    preds.users.append([p.lower() for p in parts])
                elif k in ("ip", "src_ip", "dst_ip"):
                    preds.ips.append([p.lower() for p in parts])
                elif k in ("sev", "severity", "level"):
                    preds.severities.append([p.upper() for p in parts])
                elif k in ("cat", "category"):
                    preds.categories.append([p.upper() for p in parts])
                elif k in ("req", "request_id", "correlation_id"):
                    preds.request_ids.append([p.lower() for p in parts])
                elif k in ("session", "session_id", "sess"):
                    preds.session_ids.append([p.lower() for p in parts])
                elif k in ("file", "source", "evidence", "original_filename"):
                    preds.files.append([p.lower() for p in parts])
                elif k in ("status", "parsing_status", "correction_status"):
                    preds.statuses.append([p.upper() for p in parts])
                elif k in ("after", "since"):
                    preds.after_iso = f"{rval}T00:00:00.000000Z" if re.match(r"^\d{4}-\d{2}-\d{2}$", rval) else rval
                elif k in ("before", "until"):
                    preds.before_iso = f"{rval}T23:59:59.999999Z" if re.match(r"^\d{4}-\d{2}-\d{2}$", rval) else rval
        elif ttype == "TERM":
            preds.free_terms.append(val.lower())

    # Populate not_terms for legacy checks
    i = 0
    while i < len(tokens):
        if tokens[i][0] == "NOT" and i + 1 < len(tokens):
            next_t = tokens[i + 1]
            if next_t[0] == "TERM":
                preds.not_terms.append(next_t[1].lower())
            elif next_t[0] == "FIELD" and ":" in next_t[1]:
                preds.not_terms.append(next_t[1].split(":", 1)[1].strip("\"'").lower())
            i += 2
        else:
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
                if len(criteria.keyword) <= MAX_REGEX_LEN and not is_suspect_redos(criteria.keyword):
                    try:
                        kw_regex = re.compile(criteria.keyword, re.IGNORECASE)
                    except re.error:
                        kw_lower = criteria.keyword.strip().lower()
                else:
                    # Unsafe or oversized pattern: avoid catastrophic backtracking (F-16)
                    kw_regex = None
                    kw_lower = criteria.keyword.strip().lower() if not is_suspect_redos(criteria.keyword) else None
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
            # Build full text corpus for keyword search without truncation (F-16)
            text_corpus = (
                f"{ev.raw_text} {ev.description} "
                f"{ev.username or ''} {ev.src_ip or ''} {ev.dst_ip or ''} {ev.request_id or ''} "
                f"{ev.source_host or ''} {ev.source_app or ''}"
            )

            # 1. Full-text keyword match (structured CQL predicates, safe regex with timeout, or substring)
            if kw_regex is not None:
                if not safe_regex_search(kw_regex, text_corpus):
                    continue
            elif cql_preds and cql_preds.is_structured:
                if not cql_preds.evaluate(ev, text_corpus):
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
