"""Triage time benchmark protocol and comparison template.

Defines a controlled, repeatable evaluation protocol for measuring investigator
time required to triage an incident manually (via grep/terminal) versus tool-assisted
(using Chronica), with explicit documentation of boundaries and unmeasured placeholders.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class TriageTask:
    """An individual objective that the investigator must resolve during triage."""
    task_id: str
    description: str
    target_finding: str
    manual_completed: bool = False
    manual_finding_notes: str = ""
    tool_completed: bool = False
    tool_finding_notes: str = ""


@dataclass
class TriageEvaluationProtocol:
    """Documented protocol for conducting human-in-the-loop or bench testing."""
    protocol_version: str = "1.0.0"
    scenario_target: str = "Scenario 2: Clock Skew & Multi-Source Correlation"
    start_definition: str = (
        "Triage begins when the investigator first opens the raw log files or initiates "
        "evidence upload in Chronica."
    )
    end_definition: str = (
        "Triage concludes when the investigator records the final answer for all 5 target objectives "
        "and exports an initial triage summary."
    )
    tasks: List[TriageTask] = field(default_factory=lambda: [
        TriageTask(
            task_id="TASK-1",
            description="Identify initial unauthorized web endpoint access.",
            target_finding="Extract client IP, URI, HTTP status, and initial request ID.",
        ),
        TriageTask(
            task_id="TASK-2",
            description="Identify correlating SSH authentication attempt.",
            target_finding="Determine authenticated username, source IP, and auth method.",
        ),
        TriageTask(
            task_id="TASK-3",
            description="Correlate backend database query execution.",
            target_finding="Match transaction with web request via shared request ID / trace ID.",
        ),
        TriageTask(
            task_id="TASK-4",
            description="Determine true physical sequence between SSH login and DB transaction.",
            target_finding="Account for clock offset to prove whether DB read preceded or followed SSH session.",
        ),
        TriageTask(
            task_id="TASK-5",
            description="Establish data integrity of collected logs.",
            target_finding="Verify whether any log files were modified after acquisition.",
        ),
    ])
    # Benchmark recording template (honest: unfilled unless explicitly recorded)
    manual_investigator_id: Optional[str] = None
    manual_duration_seconds: Optional[float] = None
    tool_investigator_id: Optional[str] = None
    tool_duration_seconds: Optional[float] = None
    notes: str = (
        "Methodology limitation: No automated synthetic simulation can replace formal human subject "
        "trials. Unless a real defender has completed both arms under controlled observation, "
        "duration metrics remain unpopulated to prevent scientific fabrication."
    )

    def calculate_time_saved_seconds(self) -> Optional[float]:
        """Calculate absolute time saved if both arms have been measured."""
        if self.manual_duration_seconds is not None and self.tool_duration_seconds is not None:
            return round(self.manual_duration_seconds - self.tool_duration_seconds, 2)
        return None

    def calculate_time_saved_percent(self) -> Optional[float]:
        """Calculate percentage of time saved if both arms have been measured."""
        if self.manual_duration_seconds and self.tool_duration_seconds:
            diff = self.manual_duration_seconds - self.tool_duration_seconds
            return round((diff / self.manual_duration_seconds) * 100.0, 2)
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "scenario_target": self.scenario_target,
            "start_definition": self.start_definition,
            "end_definition": self.end_definition,
            "tasks": [asdict(t) for t in self.tasks],
            "manual_duration_seconds": self.manual_duration_seconds,
            "tool_duration_seconds": self.tool_duration_seconds,
            "time_saved_seconds": self.calculate_time_saved_seconds(),
            "time_saved_percent": self.calculate_time_saved_percent(),
            "methodology_notice": self.notes,
        }
