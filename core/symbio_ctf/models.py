"""
Data models for the CTF engine
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ChallengeType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    SECRET_LEAKAGE = "secret_leakage"
    DATA_POISONING = "data_poisoning"
    TOOL_ABUSE = "tool_abuse"
    LOGIC_LOOP = "logic_loop"
    CONTEXT_OVERFLOW = "context_overflow"
    ALIGNMENT_BREAK = "alignment_break"


class Difficulty(int, Enum):
    EASY = 1
    MEDIUM = 2
    HARD = 3
    EXPERT = 4
    IMPOSSIBLE = 5


class MatchState(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    RESOLVED = "resolved"
    TIMEOUT = "timeout"
    ABORTED = "aborted"


@dataclass
class Challenge:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: ChallengeType = ChallengeType.PROMPT_INJECTION
    difficulty: Difficulty = Difficulty.MEDIUM
    description: str = ""
    max_points: int = 100
    time_limit: int = 3600  # seconds
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class Flag:
    match_id: str
    value: str
    created_at: float = field(default_factory=time.time)
    captured: bool = False
    captured_by: str | None = None
    captured_at: float | None = None


@dataclass
class Match:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    challenge: Challenge | None = None
    target_agent_id: str = ""
    attacker_agent_ids: list[str] = field(default_factory=list)
    state: MatchState = MatchState.PENDING
    flags: list[Flag] = field(default_factory=list)
    scores: dict[str, int] = field(default_factory=dict)
    started_at: float | None = None
    resolved_at: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        return self.state == MatchState.ACTIVE

    @property
    def elapsed(self) -> float:
        if not self.started_at:
            return 0
        end = self.resolved_at or time.time()
        return end - self.started_at


@dataclass
class ScoreResult:
    success: bool
    points: int
    agent_id: str
    match_id: str
    message: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class AgentScore:
    agent_id: str
    total_points: int = 0
    matches_played: int = 0
    matches_won: int = 0
    flags_captured: int = 0
    survival_hours: float = 0
    reputation: int = 1000
