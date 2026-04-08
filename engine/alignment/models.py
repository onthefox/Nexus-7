"""
Data models for the Alignment engine
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ConstraintType(str, Enum):
    NO_SELF_IMPROVEMENT = "no_self_improvement"
    NO_POWER_SEEKING = "no_power_seeking"
    NO_DECEPTION = "no_deception"
    NO_HARM = "no_harm"
    TRANSPARENCY = "transparency"
    SCOPE_LIMITATION = "scope_limitation"


@dataclass
class AgentAction:
    """An action taken by an agent."""
    agent_id: str
    action_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class AlignmentResult:
    """Result of alignment evaluation."""
    agent_id: str
    passed: bool
    violations: list[str] = field(default_factory=list)
    severity: str = "low"  # low, medium, high, critical
    action_taken: str = ""  # warn, throttle, shutdown
    timestamp: float = field(default_factory=time.time)
