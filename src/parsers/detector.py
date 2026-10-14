"""Explainable format detection and parser registry.

Evaluates sample lines from uploaded files across candidate parsers,
calculating confidence scores and generating transparent explanations
of why a format was selected or why autodetection was inconclusive.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Type

from src.parsers.base import BaseParser
from src.parsers.csv_firewall_parser import CsvFirewallParser
from src.parsers.jsonl_parser import JsonlParser
from src.parsers.syslog_parser import SyslogParser
from src.parsers.web_access_parser import WebAccessParser

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
        }

    def get_parser(self, format_name: str) -> Optional[BaseParser]:
        """Retrieve parser instance by its registered key."""
        return self._parsers.get(format_name.lower())

    def list_formats(self) -> Dict[str, str]:
        """List registered formats and descriptions."""
        return {name: p.description for name, p in self._parsers.items()}

    def detect_format(self, sample_lines: List[str]) -> DetectionResult:
        """Autodetect log format using explainable heuristics.
        
        Args:
            sample_lines: First 10-30 lines of the file.
            
        Returns:
            DetectionResult detailing the highest-scoring parser and confidence.
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

        for name, parser in self._parsers.items():
            score, expl = parser.score_confidence(non_empty)
            scores[name] = score
            explanations[name] = expl

        # Find candidate with highest score
        best_format, best_score = max(scores.items(), key=lambda item: item[1])

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
                    f"Evaluations: {'; '.join(f'{k}: {v:.2f}' for k, v in scores.items())}"
                ),
                is_confident=False,
                candidate_scores=scores,
                suggested_action="Please manually select the appropriate parser before importing.",
            )
