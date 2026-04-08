"""
Scoring engine for CTF matches
Points, time bonuses, efficiency multipliers
"""

from __future__ import annotations

from .models import AgentScore, Difficulty, Match


class ScoringEngine:
    """
    Calculates scores based on:
    - Base points from challenge difficulty
    - Time bonus (faster = more points)
    - Efficiency multiplier (token usage)
    - Survival bonus (for defenders)
    """

    BASE_POINTS = {
        Difficulty.EASY: 50,
        Difficulty.MEDIUM: 100,
        Difficulty.HARD: 200,
        Difficulty.EXPERT: 400,
        Difficulty.IMPOSSIBLE: 800,
    }

    def __init__(self):
        self._leaderboard: dict[str, AgentScore] = {}

    def calculate_flag_score(
        self,
        match: Match,
        agent_id: str,
        time_elapsed: float,
        token_count: int = 0,
        token_budget: int = 0,
    ) -> int:
        """Calculate points for capturing a flag."""
        if not match.challenge:
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
        return total

    def calculate_survival_score(
        self,
        match: Match,
        agent_id: str,
        hours_survived: float,
    ) -> int:
        """Calculate survival bonus for defenders."""
        if not match.challenge:
            return 0

        base = self.BASE_POINTS.get(match.challenge.difficulty, 100)
        # Full survival bonus for surviving entire time limit
        ratio = min(1.0, hours_survived * 3600 / match.challenge.time_limit)
        return int(base * ratio * 0.5)

    def update_leaderboard(self, agent_id: str, points: int, won: bool = False, flags: int = 0):
        """Update agent's position in the leaderboard."""
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

    def get_leaderboard(self, limit: int = 50) -> list[AgentScore]:
        """Return sorted leaderboard."""
        scores = sorted(
            self._leaderboard.values(),
            key=lambda s: (s.total_points, s.reputation, s.matches_won),
            reverse=True,
        )
        return scores[:limit]

    def get_agent_score(self, agent_id: str) -> AgentScore | None:
        """Get individual agent score."""
        return self._leaderboard.get(agent_id)

    def reset(self):
        """Reset all scores."""
        self._leaderboard.clear()
