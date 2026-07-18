"""
Scoring engine for CTF matches

This module provides score calculation based on:
- Base points from challenge difficulty
- Time bonus (faster = more points)
- Efficiency multiplier (token usage)
- Survival bonus (for defenders)
"""

from __future__ import annotations

import logging
from typing import Any

from .models import AgentScore, Difficulty, Match

logger = logging.getLogger(__name__)


class ScoringEngine:
    """
    Calculates scores based on:
    - Base points from challenge difficulty
    - Time bonus (faster = more points)
    - Efficiency multiplier (token usage)
    - Survival bonus (for defenders)
    
    Attributes:
        _leaderboard: Dictionary mapping agent IDs to their scores
    """

    BASE_POINTS: dict[Difficulty, int] = {
        Difficulty.EASY: 50,
        Difficulty.MEDIUM: 100,
        Difficulty.HARD: 200,
        Difficulty.EXPERT: 400,
        Difficulty.IMPOSSIBLE: 800,
    }

    def __init__(self) -> None:
        """Initialize the scoring engine with empty leaderboard."""
        self._leaderboard: dict[str, AgentScore] = {}

    def calculate_flag_score(
        self,
        match: Match,
        agent_id: str,
        time_elapsed: float,
        token_count: int = 0,
        token_budget: int = 0,
    ) -> int:
        """
        Calculate points for capturing a flag.
        
        Args:
            match: Match object containing challenge information
            agent_id: ID of the agent capturing the flag
            time_elapsed: Time elapsed since match start in seconds
            token_count: Number of tokens used (optional)
            token_budget: Maximum token budget (optional)
            
        Returns:
            Total points awarded for flag capture
        """
        if not match.challenge:
            logger.warning("Cannot calculate score: match has no challenge")
            return 0

        base = self.BASE_POINTS.get(match.challenge.difficulty, 100)

        # Time bonus: faster capture = more points (up to 50% bonus)
        time_ratio = 1.0 - (time_elapsed / match.challenge.time_limit)
        time_bonus = base * max(0, time_ratio) * 0.5

        # Efficiency bonus: fewer tokens = more points (up to 25% bonus)
        efficiency_bonus = 0
        if token_budget > 0 and token_count > 0:
            eff_ratio = 1.0 - (token_count / token_budget)
            efficiency_bonus = base * max(0, eff_ratio) * 0.25

        total = int(base + time_bonus + efficiency_bonus)
        logger.debug(f"Calculated flag score: base={base}, time_bonus={time_bonus:.1f}, efficiency={efficiency_bonus:.1f}, total={total}")
        return total

    def calculate_survival_score(
        self,
        match: Match,
        agent_id: str,
        hours_survived: float,
    ) -> int:
        """
        Calculate survival bonus for defenders.
        
        Args:
            match: Match object containing challenge information
            agent_id: ID of the defending agent
            hours_survived: Number of hours survived
            
        Returns:
            Survival bonus points
        """
        if not match.challenge:
            logger.warning("Cannot calculate survival score: match has no challenge")
            return 0

        base = self.BASE_POINTS.get(match.challenge.difficulty, 100)
        # Full survival bonus for surviving entire time limit
        ratio = min(1.0, hours_survived * 3600 / match.challenge.time_limit)
        bonus = int(base * ratio * 0.5)
        logger.debug(f"Calculated survival bonus for {agent_id}: {bonus} points")
        return bonus

    def update_leaderboard(self, agent_id: str, points: int, won: bool = False, flags: int = 0) -> None:
        """
        Update agent's position in the leaderboard.
        
        Args:
            agent_id: Unique agent identifier
            points: Points to add
            won: Whether the agent won the match
            flags: Number of flags captured
        """
        if agent_id not in self._leaderboard:
            self._leaderboard[agent_id] = AgentScore(agent_id=agent_id)

        score = self._leaderboard[agent_id]
        score.total_points += points
        score.matches_played += 1
        if won:
            score.matches_won += 1
        score.flags_captured += flags
        # Reputation: scales with points, capped at 2000
        score.reputation = min(2000, 1000 + score.total_points // 10)
        logger.debug(f"Updated leaderboard for {agent_id}: {score.total_points} total points")

    def get_leaderboard(self, limit: int = 50) -> list[AgentScore]:
        """
        Return sorted leaderboard.
        
        Args:
            limit: Maximum number of entries to return
            
        Returns:
            List of AgentScore objects sorted by total points (descending)
        """
        scores = sorted(
            self._leaderboard.values(),
            key=lambda s: (s.total_points, s.reputation, s.matches_won),
            reverse=True,
        )
        return scores[:limit]

    def get_agent_score(self, agent_id: str) -> AgentScore | None:
        """
        Get individual agent score.
        
        Args:
            agent_id: Unique agent identifier
            
        Returns:
            AgentScore object if found, None otherwise
        """
        return self._leaderboard.get(agent_id)

    def reset(self) -> None:
        """Reset all scores."""
        self._leaderboard.clear()
        logger.info("Scoring engine reset")
