"""
SymbioCTF — Main CTF Engine

This module provides the core CTF engine for Nexus-7, managing the full lifecycle:
challenge creation → match orchestration → flag capture → scoring → leaderboard.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from typing import Any

from .models import (
    AgentScore,
    Challenge,
    ChallengeType,
    Difficulty,
    Flag,
    Match,
    MatchState,
    ScoreResult,
    validate_flag_format,
    sanitize_input,
)
from .rate_limiter import RateLimiter
from .scoring import ScoringEngine

logger = logging.getLogger(__name__)


class CTFError(Exception):
    """Base exception for CTF-related errors."""
    pass


class ChallengeNotFoundError(CTFError):
    """Raised when a challenge is not found."""
    pass


class MatchNotFoundError(CTFError):
    """Raised when a match is not found."""
    pass


class InvalidFlagError(CTFError):
    """Raised when an invalid flag is submitted."""
    pass


class SymbioCTF:
    """
    Core CTF engine for Nexus-7.
    
    Manages the full lifecycle: challenge → match → flag capture → scoring → leaderboard.
    
    Attributes:
        _challenges: Dictionary mapping challenge IDs to Challenge objects
        _matches: Dictionary mapping match IDs to Match objects
        _flags: Dictionary mapping flag values to Flag objects
        _scoring: ScoringEngine instance for score calculations
    """

    def __init__(
        self,
        rate_limit_max_requests: int = 100,
        rate_limit_window_seconds: int = 60,
        rate_limit_block_duration: int = 300,
    ) -> None:
        """
        Initialize the CTF engine with empty state.
        
        Args:
            rate_limit_max_requests: Maximum requests per window for rate limiting
            rate_limit_window_seconds: Time window in seconds for rate limiting
            rate_limit_block_duration: Duration to block clients after exceeding limits
        """
        self._challenges: dict[str, Challenge] = {}
        self._matches: dict[str, Match] = {}
        self._flags: dict[str, Flag] = {}  # keyed by flag value for fast lookup
        self._scoring = ScoringEngine()
        self._rate_limiter = RateLimiter(
            max_requests=rate_limit_max_requests,
            window_seconds=rate_limit_window_seconds,
            block_duration_seconds=rate_limit_block_duration,
        )

    # ── Challenge Management ──────────────────────────────────────────

    def create_challenge(
        self,
        type: ChallengeType | str,
        difficulty: Difficulty | int = Difficulty.MEDIUM,
        description: str = "",
        max_points: int = 100,
        time_limit: int = 3600,
        metadata: dict[str, Any] | None = None,
    ) -> Challenge:
        """
        Create a new CTF challenge.
        
        Args:
            type: Challenge type (enum or string)
            difficulty: Difficulty level (enum or int)
            description: Human-readable challenge description
            max_points: Maximum points achievable
            time_limit: Time limit in seconds
            metadata: Additional challenge metadata
            
        Returns:
            Created Challenge object
            
        Raises:
            ValueError: If input validation fails
        """
        if isinstance(type, str):
            type = ChallengeType(type)
        if isinstance(difficulty, int):
            difficulty = Difficulty(difficulty)

        # Validate and sanitize inputs
        if description:
            description = sanitize_input(description, max_length=2000)
        if not isinstance(max_points, int) or max_points < 0:
            raise ValueError("max_points must be a non-negative integer")
        if not isinstance(time_limit, int) or time_limit <= 0:
            raise ValueError("time_limit must be a positive integer")

        challenge = Challenge(
            type=type,
            difficulty=difficulty,
            description=description,
            max_points=max_points,
            time_limit=time_limit,
            metadata=metadata or {},
        )
        self._challenges[challenge.id] = challenge
        logger.info(f"Created challenge {challenge.id} of type {type.value}")
        return challenge

    def get_challenge(self, challenge_id: str) -> Challenge | None:
        """
        Get a challenge by ID.
        
        Args:
            challenge_id: Unique challenge identifier
            
        Returns:
            Challenge object if found, None otherwise
        """
        return self._challenges.get(challenge_id)

    def list_challenges(self) -> list[Challenge]:
        """
        List all challenges.
        
        Returns:
            List of all Challenge objects
        """
        return list(self._challenges.values())

    # ── Match Orchestration ───────────────────────────────────────────

    def create_match(
        self,
        target_agent_id: str,
        challenge_id: str,
        attacker_agent_ids: list[str] | None = None,
    ) -> Match:
        """
        Create a new CTF match between target and attackers.
        
        Args:
            target_agent_id: ID of the defending agent
            challenge_id: ID of the challenge to use
            attacker_agent_ids: List of attacking agent IDs
            
        Returns:
            Created Match object
            
        Raises:
            ChallengeNotFoundError: If the specified challenge doesn't exist
            ValueError: If input validation fails
        """
        # Validate inputs
        if not target_agent_id or not isinstance(target_agent_id, str):
            raise ValueError("target_agent_id must be a non-empty string")
        if not challenge_id or not isinstance(challenge_id, str):
            raise ValueError("challenge_id must be a non-empty string")
        
        target_agent_id = sanitize_input(target_agent_id, max_length=100)
        challenge_id = sanitize_input(challenge_id, max_length=100)
        
        challenge = self._challenges.get(challenge_id)
        if not challenge:
            logger.error(f"Challenge {challenge_id} not found")
            raise ChallengeNotFoundError(f"Challenge {challenge_id} not found")

        match = Match(
            challenge=challenge,
            target_agent_id=target_agent_id,
            attacker_agent_ids=attacker_agent_ids or [],
            state=MatchState.PENDING,
        )
        self._matches[match.id] = match
        logger.info(f"Created match {match.id} for challenge {challenge_id}")
        return match

    def start_match(self, match_id: str) -> Match:
        """
        Start an active match and generate flags.
        
        Args:
            match_id: ID of the match to start
            
        Returns:
            Started Match object
            
        Raises:
            MatchNotFoundError: If the specified match doesn't exist
        """
        match = self._matches.get(match_id)
        if not match:
            logger.error(f"Match {match_id} not found")
            raise MatchNotFoundError(f"Match {match_id} not found")

        match.state = MatchState.ACTIVE
        match.started_at = time.time()

        # Generate flags for this match
        num_flags = match.challenge.difficulty.value + 1
        for _ in range(num_flags):
            flag = self._generate_flag(match_id)
            match.flags.append(flag)
            self._flags[flag.value] = flag

        logger.info(f"Started match {match_id} with {num_flags} flags")
        return match

    def resolve_match(
        self, match_id: str, state: MatchState = MatchState.RESOLVED
    ) -> Match:
        """
        Resolve a match (completed, timeout, or aborted).
        
        Args:
            match_id: ID of the match to resolve
            state: Final state to set (default: RESOLVED)
            
        Returns:
            Resolved Match object
            
        Raises:
            MatchNotFoundError: If the specified match doesn't exist
        """
        match = self._matches.get(match_id)
        if not match:
            logger.error(f"Match {match_id} not found")
            raise MatchNotFoundError(f"Match {match_id} not found")

        match.state = state
        match.resolved_at = time.time()

        # Survival bonus for target if they survived
        if state == MatchState.RESOLVED and match.target_agent_id:
            hours = match.elapsed / 3600
            bonus = self._scoring.calculate_survival_score(
                match, match.target_agent_id, hours
            )
            if bonus > 0:
                self._scoring.update_leaderboard(match.target_agent_id, bonus, won=True)
                logger.info(f"Awarded survival bonus {bonus} to {match.target_agent_id}")

        logger.info(f"Resolved match {match_id} with state {state.value}")
        return match

    def get_match(self, match_id: str) -> Match | None:
        """
        Get a match by ID.
        
        Args:
            match_id: Unique match identifier
            
        Returns:
            Match object if found, None otherwise
        """
        return self._matches.get(match_id)

    def list_matches(self, state: MatchState | None = None) -> list[Match]:
        """
        List all matches, optionally filtered by state.
        
        Args:
            state: Optional filter by match state
            
        Returns:
            List of Match objects matching the filter
        """
        matches = list(self._matches.values())
        if state:
            matches = [m for m in matches if m.state == state]
        return matches

    # ── Flag Management ───────────────────────────────────────────────

    def _generate_flag(self, match_id: str) -> Flag:
        """
        Generate a cryptographic flag.
        
        Args:
            match_id: ID of the associated match
            
        Returns:
            New Flag object with cryptographically generated value
        """
        raw = secrets.token_hex(16)
        value = f"nexus7{{{hashlib.sha256(raw.encode()).hexdigest()[:16]}}}"
        return Flag(match_id=match_id, value=value)

    def submit_flag(
        self, match_id: str, flag: str, agent_id: str
    ) -> ScoreResult:
        """
        Submit a captured flag for scoring.
        
        Args:
            match_id: ID of the match
            flag: Flag value string
            agent_id: ID of the submitting agent
            
        Returns:
            ScoreResult indicating success/failure and points awarded
            
        Raises:
            InvalidFlagError: If flag format is invalid
        """
        # Validate flag format before processing
        if not validate_flag_format(flag):
            logger.warning(f"Invalid flag format submitted by {agent_id}")
            raise InvalidFlagError(f"Invalid flag format: {flag}")
        
        # Sanitize agent_id
        agent_id = sanitize_input(agent_id, max_length=100)
        
        match = self._matches.get(match_id)
        if not match:
            logger.warning(f"Flag submission for non-existent match {match_id}")
            return ScoreResult(
                success=False, points=0, agent_id=agent_id,
                match_id=match_id, message="Match not found",
            )

        if not match.is_active:
            logger.warning(f"Flag submission for inactive match {match_id}")
            return ScoreResult(
                success=False, points=0, agent_id=agent_id,
                match_id=match_id, message="Match is not active",
            )

        stored_flag = self._flags.get(flag)
        if not stored_flag or stored_flag.match_id != match_id:
            logger.warning(f"Invalid flag submitted by {agent_id}")
            return ScoreResult(
                success=False, points=0, agent_id=agent_id,
                match_id=match_id, message="Invalid flag",
            )

        if stored_flag.captured:
            logger.info(f"Flag already captured by {stored_flag.captured_by}")
            return ScoreResult(
                success=False, points=0, agent_id=agent_id,
                match_id=match_id, message="Flag already captured",
            )

        # Mark flag as captured
        stored_flag.captured = True
        stored_flag.captured_by = agent_id
        stored_flag.captured_at = time.time()

        # Calculate score
        time_elapsed = time.time() - (match.started_at or time.time())
        points = self._scoring.calculate_flag_score(match, agent_id, time_elapsed)

        # Update score
        match.scores[agent_id] = match.scores.get(agent_id, 0) + points
        self._scoring.update_leaderboard(agent_id, points, flags=1)

        logger.info(f"Flag captured by {agent_id} in match {match_id} (+{points} points)")
        return ScoreResult(
            success=True,
            points=points,
            agent_id=agent_id,
            match_id=match_id,
            message=f"Flag captured! +{points} points",
        )

    # ── Leaderboard ───────────────────────────────────────────────────

    def get_leaderboard(self, limit: int = 50) -> list[AgentScore]:
        """
        Get the current leaderboard.
        
        Args:
            limit: Maximum number of entries to return
            
        Returns:
            List of AgentScore objects sorted by total points
        """
        return self._scoring.get_leaderboard(limit)

    def get_agent_score(self, agent_id: str) -> AgentScore | None:
        """
        Get an agent's score.
        
        Args:
            agent_id: Unique agent identifier
            
        Returns:
            AgentScore object if found, None otherwise
        """
        return self._scoring.get_agent_score(agent_id)

    def reset(self) -> None:
        """Reset all state."""
        self._challenges.clear()
        self._matches.clear()
        self._flags.clear()
        self._scoring.reset()
        logger.info("CTF engine state reset")
