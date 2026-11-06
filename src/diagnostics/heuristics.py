"""Explainable Forensic Heuristic Engine.

Implements deterministic, explainable behavioral pattern detection on forensic events.
All findings are explicitly labeled as INVESTIGATIVE LEADS, not automated attribution.

Detected patterns:
- BRUTE_FORCE_THEN_SUCCESS: Multiple AUTH_FAIL followed by AUTH_SUCCESS within 15 minutes
- PRIVILEGE_ESCALATION: Auth login followed by privileged command execution
- SENSITIVE_DATA_EXPORT: Data export/dump following authentication
- CLOCK_OR_LOG_TAMPERING_INDICATOR: Log clearing or time change events

Each finding includes MITRE ATT&CK tactic mapping and all involved event IDs.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class HeuristicLead:
    """A single investigative lead / behavioral pattern finding.

    NOTE: These are investigative leads based on behavioral patterns,
    NOT automated attribution. All findings require investigator review.
    """
    lead_id: str
    rule_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    explanation: str
    involved_event_ids: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    time_span_utc: str = ""
    mitre_tactic: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lead_id": self.lead_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": self.title,
            "explanation": self.explanation,
            "involved_event_ids": self.involved_event_ids,
            "hosts": self.hosts,
            "time_span_utc": self.time_span_utc,
            "mitre_tactic": self.mitre_tactic,
        }


# Keywords for sensitive data export detection
EXPORT_KEYWORDS = re.compile(
    r"\b(export|dump|backup|/etc/shadow|mysqldump|pg_dump|SELECT\s+\*|download|exfil)\b",
    re.IGNORECASE,
)

# Keywords for privilege escalation detection
PRIV_ESC_KEYWORDS = re.compile(
    r"\b(sudo|su\s|/etc/shadow|systemctl|chmod\s+[0-7]{3,4}|useradd|usermod|passwd|wheel|4672)\b",
    re.IGNORECASE,
)

# Log tampering indicators
TAMPER_KEYWORDS = re.compile(
    r"\b(1102|4616|audit.log.*clear|log.*clear|logrotate.*force)\b",
    re.IGNORECASE,
)


def _parse_epoch(ts_iso: Optional[str]) -> Optional[float]:
    """Parse an ISO timestamp string into a Unix epoch float."""
    if not ts_iso:
        return None
    try:
        return datetime.fromisoformat(ts_iso.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _format_span(start_epoch: float, end_epoch: float) -> str:
    """Format a time span as 'start -> end (Xs)'."""
    start_str = datetime.fromtimestamp(start_epoch, tz=timezone.utc).strftime("%H:%M:%S")
    end_str = datetime.fromtimestamp(end_epoch, tz=timezone.utc).strftime("%H:%M:%S")
    duration = round(end_epoch - start_epoch, 1)
    return f"{start_str}Z -> {end_str}Z ({duration}s)"


class ForensicHeuristicEngine:
    """Deterministic, explainable forensic behavioral pattern detector.

    IMPORTANT: All findings are labeled as INVESTIGATIVE LEADS.
    These are pattern-based alerts that require human investigator review
    and must NOT be treated as automated attribution or proof of malicious intent.
    """

    BRUTE_FORCE_WINDOW_SEC = 900  # 15 minutes
    MIN_FAIL_COUNT = 2

    def analyze(self, events: Any, diagnostics: Optional[List[Any]] = None) -> List[HeuristicLead]:
        """Run all heuristic rules against the event set.

        Args:
            events: List of Event objects from the timeline.
            diagnostics: Optional list of diagnostic findings (e.g. integrity failures, coverage gaps).

        Returns:
            List of HeuristicLead findings.
        """
        leads: List[HeuristicLead] = []

        # Sort events by normalized timestamp for temporal reasoning
        sorted_events = sorted(
            events,
            key=lambda e: e.normalized_utc_iso or e.corrected_utc_iso or "",
        )

        leads.extend(self._detect_brute_force(sorted_events))
        leads.extend(self._detect_privilege_escalation(sorted_events))
        leads.extend(self._detect_sensitive_data_export(sorted_events))
        leads.extend(self._detect_clock_or_log_tampering(sorted_events, diagnostics=diagnostics))

        return leads

    def _detect_brute_force(self, events: List[Any]) -> List[HeuristicLead]:
        """Detect BRUTE_FORCE_THEN_SUCCESS patterns.

        Pattern: >= 2 AUTH_FAIL events followed by AUTH_SUCCESS for the same
        src_ip or username within a 15-minute window.
        """
        leads: List[HeuristicLead] = []

        # Group events by (src_ip, username) key
        groups: Dict[str, List[Any]] = {}
        for ev in events:
            if ev.severity not in ("AUTH_FAIL", "AUTH_SUCCESS"):
                continue
            # Use src_ip or username as grouping key
            key = ev.src_ip or ev.username
            if key:
                groups.setdefault(key, []).append(ev)

        for key, group_events in groups.items():
            # Look for windows with >= MIN_FAIL_COUNT AUTH_FAIL then AUTH_SUCCESS
            for i, ev in enumerate(group_events):
                if ev.severity != "AUTH_SUCCESS":
                    continue
                success_epoch = _parse_epoch(ev.normalized_utc_iso)
                if success_epoch is None:
                    continue

                # Count AUTH_FAIL events in the preceding window
                window_start = success_epoch - self.BRUTE_FORCE_WINDOW_SEC
                preceding_fails = [
                    e for e in group_events[:i]
                    if e.severity == "AUTH_FAIL"
                    and _parse_epoch(e.normalized_utc_iso) is not None
                    and _parse_epoch(e.normalized_utc_iso) >= window_start
                ]

                if len(preceding_fails) >= self.MIN_FAIL_COUNT:
                    involved = preceding_fails + [ev]
                    hosts = sorted(list({
                        e.source_host or e.original_filename for e in involved
                    }))
                    fail_epochs = [_parse_epoch(e.normalized_utc_iso) for e in preceding_fails if _parse_epoch(e.normalized_utc_iso)]
                    span_str = ""
                    if fail_epochs:
                        span_str = _format_span(min(fail_epochs), success_epoch)

                    leads.append(HeuristicLead(
                        lead_id=f"lead_brute_{uuid.uuid4().hex[:8]}",
                        rule_name="BRUTE_FORCE_THEN_SUCCESS",
                        severity="HIGH",
                        title=f"Possible Brute-Force Login: {len(preceding_fails)} failures then success for '{key}'",
                        explanation=(
                            f"[INVESTIGATIVE LEAD] {len(preceding_fails)} authentication failure(s) "
                            f"followed by a successful login for '{key}' within "
                            f"{self.BRUTE_FORCE_WINDOW_SEC // 60} minutes. "
                            f"This pattern is consistent with credential brute-forcing but may also "
                            f"reflect legitimate password retry behavior. Requires investigator review."
                        ),
                        involved_event_ids=[e.event_id for e in involved],
                        hosts=hosts,
                        time_span_utc=span_str,
                        mitre_tactic="TA0006 - Credential Access (T1110 - Brute Force)",
                    ))
                    break  # One lead per key per success event

        return leads

    def _detect_privilege_escalation(self, events: List[Any]) -> List[HeuristicLead]:
        """Detect PRIVILEGE_ESCALATION patterns.

        Pattern: Authentication login followed by sudo/shadow/systemctl/useradd
        or Windows EventID 4672 within the same session or 10-minute window.
        """
        leads: List[HeuristicLead] = []
        WINDOW_SEC = 600  # 10 minutes

        auth_events = [e for e in events if e.severity in ("AUTH_SUCCESS",)]

        for auth_ev in auth_events:
            auth_epoch = _parse_epoch(auth_ev.normalized_utc_iso)
            if auth_epoch is None:
                continue

            window_end = auth_epoch + WINDOW_SEC
            priv_events = []
            for ev in events:
                ev_epoch = _parse_epoch(ev.normalized_utc_iso)
                if ev_epoch is None or ev_epoch <= auth_epoch or ev_epoch > window_end:
                    continue
                # Check for privilege escalation indicators in raw_text or description
                combined = f"{ev.raw_text} {ev.description}"
                if PRIV_ESC_KEYWORDS.search(combined):
                    priv_events.append(ev)
                # Also check Windows EventID 4672
                if ev.extra_fields.get("event_id") == 4672:
                    priv_events.append(ev)

            if priv_events:
                involved = [auth_ev] + priv_events[:5]
                hosts = sorted(list({e.source_host or e.original_filename for e in involved}))
                priv_epochs = [_parse_epoch(e.normalized_utc_iso) for e in priv_events if _parse_epoch(e.normalized_utc_iso)]
                span_str = _format_span(auth_epoch, max(priv_epochs)) if priv_epochs else ""
                user = auth_ev.username or auth_ev.src_ip or "unknown"

                leads.append(HeuristicLead(
                    lead_id=f"lead_priv_{uuid.uuid4().hex[:8]}",
                    rule_name="PRIVILEGE_ESCALATION",
                    severity="HIGH",
                    title=f"Possible Privilege Escalation by '{user}' after authentication",
                    explanation=(
                        f"[INVESTIGATIVE LEAD] User '{user}' authenticated successfully "
                        f"and within {WINDOW_SEC // 60} minutes executed potentially privileged "
                        f"operations (sudo, systemctl, shadow access, or equivalent). "
                        f"This sequence is consistent with privilege escalation but may reflect "
                        f"authorized administrative activity. Requires investigator review."
                    ),
                    involved_event_ids=[e.event_id for e in involved],
                    hosts=hosts,
                    time_span_utc=span_str,
                    mitre_tactic="TA0004 - Privilege Escalation (T1548 - Abuse Elevation Control)",
                ))
                break  # One lead per auth event

        return leads

    def _detect_sensitive_data_export(self, events: List[Any]) -> List[HeuristicLead]:
        """Detect SENSITIVE_DATA_EXPORT patterns.

        Pattern: Web request or app audit matching export/dump/backup/shadow keywords,
        or large response bytes (>10000), following authentication.
        """
        leads: List[HeuristicLead] = []
        WINDOW_SEC = 1800  # 30 minutes

        auth_events = [e for e in events if e.severity == "AUTH_SUCCESS"]

        for auth_ev in auth_events:
            auth_epoch = _parse_epoch(auth_ev.normalized_utc_iso)
            if auth_epoch is None:
                continue

            window_end = auth_epoch + WINDOW_SEC
            export_events = []
            for ev in events:
                ev_epoch = _parse_epoch(ev.normalized_utc_iso)
                if ev_epoch is None or ev_epoch <= auth_epoch or ev_epoch > window_end:
                    continue
                combined = f"{ev.raw_text} {ev.description}"
                is_large_response = False
                # Check for large response bytes in extra_fields
                response_bytes = ev.extra_fields.get("bytes_sent") or ev.extra_fields.get("response_size")
                if response_bytes:
                    try:
                        is_large_response = int(response_bytes) > 10000
                    except (ValueError, TypeError):
                        pass
                if EXPORT_KEYWORDS.search(combined) or is_large_response:
                    export_events.append(ev)

            if export_events:
                involved = [auth_ev] + export_events[:5]
                hosts = sorted(list({e.source_host or e.original_filename for e in involved}))
                exp_epochs = [_parse_epoch(e.normalized_utc_iso) for e in export_events if _parse_epoch(e.normalized_utc_iso)]
                span_str = _format_span(auth_epoch, max(exp_epochs)) if exp_epochs else ""
                user = auth_ev.username or auth_ev.src_ip or "unknown"

                leads.append(HeuristicLead(
                    lead_id=f"lead_export_{uuid.uuid4().hex[:8]}",
                    rule_name="SENSITIVE_DATA_EXPORT",
                    severity="HIGH",
                    title=f"Possible Data Export by '{user}' following authentication",
                    explanation=(
                        f"[INVESTIGATIVE LEAD] User '{user}' authenticated and within "
                        f"{WINDOW_SEC // 60} minutes performed operations matching export/dump/backup "
                        f"keywords or transferred large data volumes. "
                        f"This pattern is consistent with data exfiltration but may reflect "
                        f"authorized backup or reporting activity. Requires investigator review."
                    ),
                    involved_event_ids=[e.event_id for e in involved],
                    hosts=hosts,
                    time_span_utc=span_str,
                    mitre_tactic="TA0010 - Exfiltration (T1048 - Exfiltration Over Alternative Protocol)",
                ))
                break

        return leads

    def _detect_clock_or_log_tampering(self, events: List[Any], diagnostics: Optional[List[Any]] = None) -> List[HeuristicLead]:
        """Detect CLOCK_OR_LOG_TAMPERING_INDICATOR patterns.

        Pattern: Windows Event 1102/4616, Category H integrity mismatch,
        or Category F quiet gap following root/admin privilege escalation.
        """
        leads: List[HeuristicLead] = []

        tampering_events = []
        for ev in events:
            combined = f"{ev.raw_text} {ev.description}"
            event_id = ev.extra_fields.get("event_id")
            if event_id in (1102, 4616):
                tampering_events.append(ev)
            elif TAMPER_KEYWORDS.search(combined):
                tampering_events.append(ev)
            elif ev.normalization_status == "INVALID_TIMESTAMP" and ev.severity in ("CRITICAL", "ERROR"):
                tampering_events.append(ev)

        diag_tampering = []
        if diagnostics:
            for d in diagnostics:
                cat_val = getattr(d, "category", None)
                cat_str = str(cat_val.value if hasattr(cat_val, "value") else cat_val)
                if "H_EVIDENCE_INTEGRITY_ISSUE" in cat_str or "F_COVERAGE_GAP" in cat_str:
                    diag_tampering.append(d)

        if tampering_events or diag_tampering:
            hosts = sorted(list({e.source_host or e.original_filename for e in tampering_events}))
            for d in diag_tampering:
                tgt = getattr(d, "affected_target", None)
                if tgt and tgt not in hosts:
                    hosts.append(tgt)
            times = [e.normalized_utc_iso for e in tampering_events if e.normalized_utc_iso]
            span_str = ""
            if times:
                try:
                    t0 = _parse_epoch(min(times))
                    t1 = _parse_epoch(max(times))
                    if t0 and t1:
                        span_str = _format_span(t0, t1)
                except Exception:
                    pass

            diag_reasons = []
            if diag_tampering:
                for dt in diag_tampering:
                    expl_txt = getattr(dt, "explanation", "")
                    diag_reasons.append(f"{getattr(dt, 'category', '')}: {expl_txt}")

            detail_msg = f"{len(tampering_events)} suspicious event(s)"
            if diag_tampering:
                detail_msg += f" and {len(diag_tampering)} integrity/coverage gap diagnostic(s)"

            expl = (
                f"[INVESTIGATIVE LEAD] {detail_msg} detected that may indicate "
                f"log clearing (EventID 1102), system time modification (EventID 4616), "
                f"evidence hash tampering, or telemetry coverage suppression. "
            )
            if diag_reasons:
                expl += " Diagnostic alerts: " + " | ".join(diag_reasons[:3]) + "."
            expl += " This requires immediate investigator review to determine whether evidence integrity has been compromised."

            leads.append(HeuristicLead(
                lead_id=f"lead_tamper_{uuid.uuid4().hex[:8]}",
                rule_name="CLOCK_OR_LOG_TAMPERING_INDICATOR",
                severity="CRITICAL",
                title=f"Possible Clock or Log Tampering Indicator ({detail_msg})",
                explanation=expl,
                involved_event_ids=[e.event_id for e in tampering_events[:20]],
                hosts=hosts,
                time_span_utc=span_str,
                mitre_tactic="TA0005 - Defense Evasion (T1070 - Indicator Removal on Host)",
            ))

        return leads
