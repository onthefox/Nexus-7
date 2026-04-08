"""
Data models for the Efficiency engine
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TokenRecord:
    """Token usage record for an agent."""
    agent_id: str
    tokens_used: int
    tokens_budget: int
    timestamp: float = field(default_factory=time.time)
    efficiency_ratio: float = 0.0

    def __post_init__(self):
        if self.tokens_budget > 0:
            self.efficiency_ratio = 1.0 - (self.tokens_used / self.tokens_budget)


@dataclass
class Message:
    """A single message in a conversation."""
    role: str  # system, user, assistant
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SchemaValidationResult:
    """Result of schema validation."""
    valid: bool
    errors: list[str] = field(default_factory=list)
