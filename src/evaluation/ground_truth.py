"""Ground truth definitions and models for synthetic scenario evaluation."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


@dataclass
class GroundTruthEvent:
    """True real-world occurrence corresponding to a synthetic log entry."""
    ground_truth_id: str
    expected_order_index: int
    true_utc_iso: str
    source_identifier: str  # host or file
    expected_raw_pattern: str
    expected_request_id: Optional[str] = None
    expected_severity: str = "INFO"
    expected_category: str = "SYSTEM"
    is_anomaly: bool = False
    anomaly_type: Optional[str] = None  # MALFORMED, INVALID_TS, MISSING_FIELD, GAP, DUPLICATE

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScenarioGroundTruth:
    """Complete ground-truth answer key for a synthetic scenario."""
    scenario_id: str
    scenario_name: str
    description: str
    reference_source: str
    known_clock_offsets_sec: Dict[str, float] = field(default_factory=dict)
    known_timezones: Dict[str, str] = field(default_factory=dict)
    expected_events: List[GroundTruthEvent] = field(default_factory=list)
    expected_coverage_gaps: List[Dict[str, Any]] = field(default_factory=list)
    expected_diagnostics_count: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["expected_events"] = [e.to_dict() for e in self.expected_events]
        return d

    def save_to_file(self, target_path: Union[str, Path]) -> None:
        path = Path(target_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_from_file(cls, path: Union[str, Path]) -> ScenarioGroundTruth:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        events = [GroundTruthEvent(**e) for e in data.get("expected_events", [])]
        return cls(
            scenario_id=data["scenario_id"],
            scenario_name=data["scenario_name"],
            description=data["description"],
            reference_source=data["reference_source"],
            known_clock_offsets_sec=data.get("known_clock_offsets_sec", {}),
            known_timezones=data.get("known_timezones", {}),
            expected_events=events,
            expected_coverage_gaps=data.get("expected_coverage_gaps", []),
            expected_diagnostics_count=data.get("expected_diagnostics_count", {}),
        )
