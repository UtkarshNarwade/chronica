"""Base parser interface and normalized parsed record representation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional


@dataclass
class ParsedRecord:
    """Intermediate representation of a log record extracted by a parser."""
    line_number: int
    raw_text: str
    original_timestamp_str: Optional[str]
    source_host: Optional[str] = None
    source_app: Optional[str] = None
    severity: str = "INFO"  # INFO, WARNING, ERROR, CRITICAL, AUTH_SUCCESS, AUTH_FAIL, NETWORK, etc.
    category: str = "SYSTEM"  # AUTHENTICATION, WEB_REQUEST, SYSTEM, NETWORK, APPLICATION, DATA_ACCESS
    username: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    message: str = ""
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    extra_fields: Dict[str, Any] = field(default_factory=dict)
    parse_status: str = "SUCCESS"  # SUCCESS, PARTIAL, MALFORMED, UNSUPPORTED
    warnings: List[str] = field(default_factory=list)


class BaseParser(ABC):
    """Abstract base class for all log format parsers."""

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Human-readable name of the format (e.g. 'syslog', 'jsonl', 'web_access')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief description of the parser and supported log types."""
        pass

    @abstractmethod
    def parse_line(self, line: str, line_number: int, context: Optional[Dict[str, Any]] = None) -> ParsedRecord:
        """Parse an individual line of log text."""
        pass

    def parse_stream(
        self,
        lines: Iterator[str],
        context: Optional[Dict[str, Any]] = None,
    ) -> Iterator[ParsedRecord]:
        """Parse a stream of log lines, yielding ParsedRecord objects."""
        for idx, line in enumerate(lines, start=1):
            stripped = line.rstrip("\r\n")
            if not stripped:
                continue
            yield self.parse_line(stripped, idx, context=context)

    @abstractmethod
    def score_confidence(self, sample_lines: List[str]) -> tuple[float, str]:
        """Evaluate how confident this parser is that sample_lines match its format.
        
        Returns:
            Tuple of (confidence_score: float [0.0 - 1.0], explanation: str)
        """
        pass
