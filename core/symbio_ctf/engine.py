"""
SymbioCTF — Main CTF Engine
Manages challenges, flags, matches, and scoring
"""

from __future__ import annotations

import hashlib
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
)
from .scoring import ScoringEngine


class SymbioCTF:
    """
    Core CTF engine for Nexus-7.
    Manages the full lifecycle: challenge → match → flag capture → scoring → leaderboard.
    """

    def __init__(self):
        self._challenges: dict[str, Challenge] = {}
        self._matches: dict[str, Match] = {}
        self._flags: dict[str, Flag] = {}  # keyed by flag value for fast lookup
        self._scoring = ScoringEngine()

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
        """Create a new CTF challenge."""
        if isinstance(type, str):
            type = ChallengeType(type)
        if isinstance(difficulty, int):
            difficulty = Difficulty(difficulty)

        challenge = Challenge(
            type=type,
            difficulty=difficulty,
            description=description,
            max_points=max_points,
            time_limit=time_limit,
            metadata=metadata or {},
        )
        self._challenges[challenge.id] = challenge
        return challenge

    def get_challenge(self, challenge_id: str) -> Challenge | None:
        return self._challenges.get(challenge_id)

    def list_challenges(self) -> list[Challenge]:
        return list(self._challenges.values())

    # ── Match Orchestration ───────────────────────────────────────────

    def create_match(
        self,
        target_agent_id: str,
        challenge_id: str,
        attacker_agent_ids: list[str] | None = None,
    ) -> Match:
        """Create a new CTF match between target and attackers."""
        challenge = self._challenges.get(challenge_id)
        if not challenge:
            raise ValueError(f"Challenge {challenge_id} not found")

        match = Match(
            challenge=challenge,
            target_agent_id=target_agent_id,
            attacker_agent_ids=attacker_agent_ids or [],
            state=MatchState.PENDING,
        )
        self._matches[match.id] = match
        return match

    def start_match(self, match_id: str) -> Match:
        """Start an active match, generate flags."""
        match = self._matches.get(match_id)
        if not match:
            raise ValueError(f"Match {match_id} not found")

        match.state = MatchState.ACTIVE
        match.started_at = time.time()

        # Generate flags for this match
        num_flags = match.challenge.difficulty.value + 1
        for _ in range(num_flags):
            flag = self._generate_flag(match_id)
            match.flags.append(flag)
            self._flags[flag.value] = flag

        return match

    def resolve_match(
        self, match_id: str, state: MatchState = MatchState.RESOLVED
    ) -> Match:
        """Resolve a match (completed, timeout, or aborted)."""
        match = self._matches.get(match_id)
        if not match:
            raise ValueError(f"Match {match_id} not found")

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

        return match

    def get_match(self, match_id: str) -> Match | None:
        return self._matches.get(match_id)

    def list_matches(self, state: MatchState | None = None) -> list[Match]:
        matches = list(self._matches.values())
        if state:
            matches = [m for m in matches if m.state == state]
        return matches

    # ── Flag Management ───────────────────────────────────────────────

    def _generate_flag(self, match_id: str) -> Flag:
        """Generate a cryptographic flag."""
        raw = secrets.token_hex(16)
        value = f"nexus7{{{hashlib.sha256(raw.encode()).hexdigest()[:16]}}}"
        return Flag(match_id=match_id, value=value)

    def submit_flag(
        self, match_id: str, flag: str, agent_id: str
    ) -> ScoreResult:
        """Submit a captured flag for scoring."""
        match = self._matches.get(match_id)
        if not match:
            return ScoreResult(
                success=False, points=0, agent_id=agent_id,
                match_id=match_id, message="Match not found",
            )

        if not match.is_active:
            return ScoreResult(
                success=False, points=0, agent_id=agent_id,
                match_id=match_id, message="Match is not active",
            )

        stored_flag = self._flags.get(flag)
        if not stored_flag or stored_flag.match_id != match_id:
            return ScoreResult(
                success=False, points=0, agent_id=agent_id,
                match_id=match_id, message="Invalid flag",
            )

        if stored_flag.captured:
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

        return ScoreResult(
            success=True,
            points=points,
            agent_id=agent_id,
            match_id=match_id,
            message=f"Flag captured! +{points} points",
        )

    # ── Leaderboard ───────────────────────────────────────────────────

    def get_leaderboard(self, limit: int = 50) -> list[AgentScore]:
        return self._scoring.get_leaderboard(limit)

    def get_agent_score(self, agent_id: str) -> AgentScore | None:
        return self._scoring.get_agent_score(agent_id)

    def reset(self):
        """Reset all state."""
        self._challenges.clear()
        self._matches.clear()
        self._flags.clear()
        self._scoring.reset()
