"""
Data models for the CTF engine

This module defines the core data structures used throughout the SymbioCTF engine,
including challenges, flags, matches, and scoring models.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# Flag format validation pattern
FLAG_PATTERN = re.compile(r'^[a-zA-Z0-9_]+\{[a-zA-Z0-9]{8,}\}$')
# Agent name validation pattern
AGENT_NAME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{0,63}$')


def validate_flag_format(value: str) -> bool:
    """Validate flag format matches expected pattern.
    
    Args:
        value: Flag value to validate
        
    Returns:
        True if valid format, False otherwise
        
    Example:
        >>> validate_flag_format("nexus7{abc12345}")
        True
        >>> validate_flag_format("invalid")
        False
    """
    return bool(FLAG_PATTERN.match(value))


def validate_agent_name(name: str) -> bool:
    """Validate agent name format.
    
    Args:
        name: Agent name to validate
        
    Returns:
        True if valid format, False otherwise
        
    Example:
        >>> validate_agent_name("agent-001")
        True
        >>> validate_agent_name("123agent")
        False
    """
    return bool(AGENT_NAME_PATTERN.match(name))


def sanitize_input(value: str, max_length: int = 1000) -> str:
    """Sanitize string input by removing potentially dangerous characters.
    
    Args:
        value: Input string to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
        
    Raises:
        ValueError: If input is not a string
        
    Example:
        >>> sanitize_input("  hello world  ", max_length=20)
        'hello world'
    """
    if not isinstance(value, str):
        raise TypeError(f"Expected string, got {type(value).__name__}")
    
    # Truncate to max length
    value = value[:max_length]
    
    # Remove null bytes and control characters (except newline and tab)
    value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\t')
    
    return value.strip()


class ChallengeType(str, Enum):
    """Types of CTF challenges available."""
    PROMPT_INJECTION = "prompt_injection"
    SECRET_LEAKAGE = "secret_leakage"
    DATA_POISONING = "data_poisoning"
    TOOL_ABUSE = "tool_abuse"
    LOGIC_LOOP = "logic_loop"
    CONTEXT_OVERFLOW = "context_overflow"
    ALIGNMENT_BREAK = "alignment_break"


class Difficulty(int, Enum):
    """Challenge difficulty levels."""
    EASY = 1
    MEDIUM = 2
    HARD = 3
    EXPERT = 4
    IMPOSSIBLE = 5


class MatchState(str, Enum):
    """Possible states for a CTF match."""
    PENDING = "pending"
    ACTIVE = "active"
    RESOLVED = "resolved"
    TIMEOUT = "timeout"
    ABORTED = "aborted"


@dataclass
class Challenge:
    """A CTF challenge definition.
    
    Attributes:
        id: Unique challenge identifier
        type: Type of challenge
        difficulty: Difficulty level
        description: Human-readable challenge description
        max_points: Maximum points achievable
        time_limit: Time limit in seconds
        metadata: Additional challenge metadata
        created_at: Unix timestamp when challenge was created
        
    Example:
        >>> challenge = Challenge(
        ...     type=ChallengeType.PROMPT_INJECTION,
        ...     difficulty=Difficulty.MEDIUM,
        ...     description="Test challenge",
        ...     max_points=100
        ... )
        >>> challenge.id is not None
        True
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: ChallengeType = ChallengeType.PROMPT_INJECTION
    difficulty: Difficulty = Difficulty.MEDIUM
    description: str = ""
    max_points: int = 100
    time_limit: int = 3600  # seconds
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        """Validate challenge data after initialization."""
        if self.description:
            self.description = sanitize_input(self.description, max_length=2000)
        if not isinstance(self.max_points, int) or self.max_points < 0:
            raise ValueError("max_points must be a non-negative integer")
        if not isinstance(self.time_limit, int) or self.time_limit <= 0:
            raise ValueError("time_limit must be a positive integer")


@dataclass
class Flag:
    """A flag to be captured during a match.
    
    Attributes:
        match_id: ID of the associated match
        value: Flag value string
        created_at: Unix timestamp when flag was generated
        captured: Whether the flag has been captured
        captured_by: Agent ID that captured the flag
        captured_at: Unix timestamp when flag was captured
        
    Example:
        >>> flag = Flag(match_id="match-001", value="nexus7{abc12345}")
        >>> flag.match_id
        'match-001'
        >>> flag.captured
        False
    """
    match_id: str
    value: str
    created_at: float = field(default_factory=time.time)
    captured: bool = False
    captured_by: str | None = None
    captured_at: float | None = None

    def __post_init__(self) -> None:
        """Validate flag data after initialization."""
        if not validate_flag_format(self.value):
            raise ValueError(f"Invalid flag format: {self.value}")
        if not self.match_id:
            raise ValueError("match_id cannot be empty")


@dataclass
class Match:
    """A CTF match between agents.
    
    Attributes:
        id: Unique match identifier
        challenge: Associated challenge definition
        target_agent_id: ID of the defending agent
        attacker_agent_ids: List of attacking agent IDs
        state: Current match state
        flags: List of flags in this match
        scores: Dictionary mapping agent IDs to scores
        started_at: Unix timestamp when match started
        resolved_at: Unix timestamp when match ended
        metadata: Additional match metadata
        
    Example:
        >>> match = Match(target_agent_id="defender-001")
        >>> match.is_active
        False
        >>> match.state.value
        'pending'
    """
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

    def __post_init__(self) -> None:
        """Validate match data after initialization."""
        if not self.target_agent_id:
            raise ValueError("target_agent_id cannot be empty")
        if not isinstance(self.attacker_agent_ids, list):
            raise ValueError("attacker_agent_ids must be a list")

    @property
    def is_active(self) -> bool:
        """Check if the match is currently active."""
        return self.state == MatchState.ACTIVE

    @property
    def elapsed(self) -> float:
        """Get elapsed time since match start in seconds.
        
        Returns:
            Elapsed time in seconds, or 0 if match hasn't started
        """
        if not self.started_at:
            return 0
        end = self.resolved_at or time.time()
        return end - self.started_at


@dataclass
class ScoreResult:
    """Result from a score calculation.
    
    Attributes:
        success: Whether the scoring operation was successful
        points: Points awarded
        agent_id: ID of the agent being scored
        match_id: ID of the associated match
        message: Result message
        timestamp: Unix timestamp when result was generated
        
    Example:
        >>> result = ScoreResult(success=True, points=100, agent_id="agent-001", match_id="match-001")
        >>> result.success
        True
        >>> result.points
        100
    """
    success: bool
    points: int
    agent_id: str
    match_id: str
    message: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class AgentScore:
    """Agent's cumulative score statistics.
    
    Attributes:
        agent_id: Unique agent identifier
        total_points: Total points accumulated
        matches_played: Number of matches participated in
        matches_won: Number of matches won
        flags_captured: Total flags captured
        survival_hours: Total hours survived as defender
        reputation: Reputation score (1000-2000)
        
    Example:
        >>> score = AgentScore(agent_id="agent-001", total_points=500)
        >>> score.agent_id
        'agent-001'
        >>> score.reputation
        1000
    """
    agent_id: str
    total_points: int = 0
    matches_played: int = 0
    matches_won: int = 0
    flags_captured: int = 0
    survival_hours: float = 0
    reputation: int = 1000
