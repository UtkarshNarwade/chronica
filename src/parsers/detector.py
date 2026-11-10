"""Explainable format detection and parser registry.

Evaluates sample lines from uploaded files across candidate parsers,
calculating confidence scores and generating transparent explanations
of why a format was selected or why autodetection was inconclusive.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from src.parsers.base import BaseParser
from src.parsers.auditd_parser import AuditdParser
from src.parsers.csv_firewall_parser import CsvFirewallParser
from src.parsers.custom_regex_parser import CustomRegexParser
from src.parsers.jsonl_parser import JsonlParser
from src.parsers.syslog_parser import SyslogParser
from src.parsers.web_access_parser import WebAccessParser
from src.parsers.windows_event_parser import WindowsEventParser

CONFIDENCE_THRESHOLD = 0.50  # Must be >= 0.5 to autodetect without investigator prompt


@dataclass
class DetectionResult:
    """Outcome of an explainable format autodetection attempt."""
    detected_format: Optional[str]
    confidence: float
    explanation: str
    is_confident: bool
    candidate_scores: Dict[str, float]
    suggested_action: str


class ParserRegistry:
    """Registry of log parsers with format autodetection support."""

    def __init__(self) -> None:
        self._parsers: Dict[str, BaseParser] = {
            "syslog": SyslogParser(),
            "jsonl": JsonlParser(),
            "web_access": WebAccessParser(),
            "csv_firewall": CsvFirewallParser(),
            "auditd": AuditdParser(),
            "windows_event": WindowsEventParser(),
            "custom_regex": CustomRegexParser(),  # Never auto-selected (score=0.0)
        }

    def get_parser(self, format_name: str) -> Optional[BaseParser]:
        """Retrieve parser instance by its registered key."""
        return self._parsers.get(format_name.lower())

    def register_parser(self, format_name: str, parser: BaseParser) -> None:
        """Register a new parser instance."""
        self._parsers[format_name.lower()] = parser

    def list_formats(self) -> Dict[str, str]:
        """List registered formats and descriptions."""
        return {name: p.description for name, p in self._parsers.items()}

    def detect_format(self, sample_lines: List[str]) -> DetectionResult:
        """Autodetect log format using explainable heuristics.
        
        Args:
            sample_lines: First 10-30 lines of the file.
            
        Returns:
            DetectionResult detailing the highest-scoring parser and confidence.

        Note: custom_regex always scores 0.0 and is excluded from autodetection.
        """
        # Filter non-empty lines
        non_empty = [ln.strip() for ln in sample_lines if ln.strip()]
        if not non_empty:
            return DetectionResult(
                detected_format=None,
                confidence=0.0,
                explanation="File is empty or contains only whitespace.",
                is_confident=False,
                candidate_scores={},
                suggested_action="Verify file content. If empty, discard from investigation.",
            )

        scores: Dict[str, float] = {}
        explanations: Dict[str, str] = {}

        # Exclude custom_regex from autodetection (always 0.0)
        for name, parser in self._parsers.items():
            if name == "custom_regex":
                scores[name] = 0.0
                explanations[name] = "custom_regex is never auto-detected."
                continue
            score, expl = parser.score_confidence(non_empty)
            scores[name] = score
            explanations[name] = expl

        # Find candidate with highest score (excluding custom_regex)
        autodetect_scores = {k: v for k, v in scores.items() if k != "custom_regex"}
        best_format, best_score = max(autodetect_scores.items(), key=lambda item: item[1])

        if best_score >= CONFIDENCE_THRESHOLD:
            return DetectionResult(
                detected_format=best_format,
                confidence=round(best_score, 3),
                explanation=explanations[best_format],
                is_confident=True,
                candidate_scores=scores,
                suggested_action=f"Confirmed format '{best_format}'. Ready for ingestion.",
            )
        else:
            return DetectionResult(
                detected_format=None,
                confidence=round(best_score, 3),
                explanation=(
                    f"Autodetection inconclusive. Highest candidate was '{best_format}' "
                    f"with confidence {best_score:.2f} (below required threshold {CONFIDENCE_THRESHOLD:.2f}). "
                    f"Evaluations: {'; '.join(f'{k}: {v:.2f}' for k, v in autodetect_scores.items())}"
                ),
                is_confident=False,
                candidate_scores=scores,
                suggested_action="Please manually select the appropriate parser before importing.",
            )
