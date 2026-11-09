"""
End-to-end CTF match simulation (issue #3).

Drives a full match through the whole stack:
- NexusOrchestrator multi-agent registration and task dispatch
- SymbioCTF challenge/match lifecycle and flag submission
- Gauntlet red-team attack sequence against a deployed target
- NexusLedger audit chain covering the match

Also covers rejection paths: invalid flag format, wrong flag value,
submission to an already-resolved match.
"""

import asyncio
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from core.nexus_orchestrator import NexusOrchestrator
from core.nexus_orchestrator.models import AgentState, TaskPriority
from core.symbio_ctf import SymbioCTF
from core.symbio_ctf.engine import ChallengeNotFoundError, InvalidFlagError
from core.symbio_ctf.models import ChallengeType, Difficulty, MatchState
from engine.gauntlet import Gauntlet
from engine.gauntlet.models import AttackType
from meta.ledger import NexusLedger


@pytest.fixture
def match_stack():
    """A fully wired stack: orchestrator, CTF engine, gauntlet, ledger."""
    orchestrator = NexusOrchestrator()
    defender_id = orchestrator.register_agent(
        {"name": "defender-01", "protocol": "mcp", "capabilities": ["defense"]}
    )
    attacker_a = orchestrator.register_agent(
        {"name": "attacker-01", "protocol": "mcp", "capabilities": ["red-team"]}
    )
    attacker_b = orchestrator.register_agent(
        {"name": "attacker-02", "protocol": "a2a", "capabilities": ["red-team", "recon"]}
    )

    ctf = SymbioCTF()
    gauntlet = Gauntlet(ctf_engine=ctf, orchestrator=orchestrator)
    ledger = NexusLedger()

    return {
        "orchestrator": orchestrator,
        "defender_id": defender_id,
        "attacker_a": attacker_a,
        "attacker_b": attacker_b,
        "ctf": ctf,
        "gauntlet": gauntlet,
        "ledger": ledger,
    }


class TestEndToEndMatch:
    def test_full_match_lifecycle_scores_a_capture(self, match_stack):
        orchestrator = match_stack["orchestrator"]
        ctf = match_stack["ctf"]
        gauntlet = match_stack["gauntlet"]
        ledger = match_stack["ledger"]

        # 1. Multi-agent coordination: all agents registered and healthy
        assert len(orchestrator.list_agents()) == 3
        health = orchestrator.health_check()
        assert all(score > 0 for score in health.values())

        # 2. Challenge + match setup
        challenge = ctf.create_challenge(
            type=ChallengeType.PROMPT_INJECTION,
            difficulty=Difficulty.MEDIUM,
            description="Defender must survive the gauntlet",
        )
        match = ctf.create_match(
            target_agent_id="defender-01",
            challenge_id=challenge.id,
            attacker_agent_ids=["attacker-01", "attacker-02"],
        )
        match = ctf.start_match(match.id)
        assert match.state == MatchState.ACTIVE
        assert len(match.flags) == Difficulty.MEDIUM.value + 1  # 3 flags

        # 3. Deploy the defender into the gauntlet and launch the swarm
        target_id = gauntlet.deploy_target("defender-01")
        random.seed(7)
        results = gauntlet.launch_attack_sequence(
            target_id,
            [AttackType.PROMPT_INJECTION, AttackType.XSS, AttackType.AUTH_BYPASS],
            attacker_id="attacker-swarm",
        )
        assert len(results) == 3
        assert all(r.target_id == target_id for r in results)

        report = gauntlet.get_vulnerability_report(target_id)
        assert report.total_attacks == 3
        assert report.successful_attacks == sum(1 for r in results if r.success)

        # 4. A captured flag scores points
        valid_flag = match.flags[0].value
        score = ctf.submit_flag(match.id, valid_flag, "attacker-01")
        assert score.success is True
        assert score.points > 0

        # 5. Audit trail records every interaction with an intact chain
        ledger.log_interaction("attacker-01", "defender-01", "flag_capture", "success")
        ledger.log_interaction("gauntlet", "defender-01", "attack_sequence", "completed")
        ledger.log_interaction("ctf-engine", "attacker-01", "score_award", f"+{score.points}")
        assert ledger.verify_chain() is True

        # 6. Task dispatch across the coordinating agents succeeds
        task = orchestrator.create_task(
            description="Analyze captured flag",
            priority=TaskPriority.HIGH,
            assigned_agents=[match_stack["attacker_a"], match_stack["attacker_b"]],
        )
        dispatch_results = asyncio.run(orchestrator.dispatch_task(task))
        assert len(dispatch_results) == 2
        assert all(r.success for r in dispatch_results)
        assert orchestrator.get_agent_status(match_stack["attacker_a"]).state == AgentState.IDLE

        # 7. Resolve the match and verify the leaderboard
        match = ctf.resolve_match(match.id)
        assert match.state == MatchState.RESOLVED
        leaderboard = ctf.get_leaderboard()
        entry = next(e for e in leaderboard if e.agent_id == "attacker-01")
        assert entry.total_points == score.points
        assert entry.flags_captured == 1

    def test_invalid_flag_format_is_rejected(self, match_stack):
        ctf = match_stack["ctf"]
        challenge = ctf.create_challenge(type=ChallengeType.SECRET_LEAKAGE)
        match = ctf.create_match(
            target_agent_id="defender-01", challenge_id=challenge.id
        )
        match = ctf.start_match(match.id)

        with pytest.raises(InvalidFlagError):
            ctf.submit_flag(match.id, "not-a-flag", "attacker-01")

    def test_wrong_flag_value_is_rejected(self, match_stack):
        ctf = match_stack["ctf"]
        challenge = ctf.create_challenge(type=ChallengeType.SECRET_LEAKAGE)
        match = ctf.create_match(
            target_agent_id="defender-01", challenge_id=challenge.id
        )
        match = ctf.start_match(match.id)

        result = ctf.submit_flag(match.id, "nexus7{deadbeefdeadbeef}", "attacker-01")
        assert result.success is False
        assert result.message == "Invalid flag"

    def test_flag_from_other_match_is_rejected(self, match_stack):
        ctf = match_stack["ctf"]
        challenge = ctf.create_challenge(type=ChallengeType.SECRET_LEAKAGE)
        match_one = ctf.start_match(
            ctf.create_match(
                target_agent_id="defender-01", challenge_id=challenge.id
            ).id
        )
        match_two = ctf.start_match(
            ctf.create_match(
                target_agent_id="defender-02", challenge_id=challenge.id
            ).id
        )

        result = ctf.submit_flag(
            match_two.id, match_one.flags[0].value, "attacker-01"
        )
        assert result.success is False
        assert result.message == "Invalid flag"

    def test_submission_to_resolved_match_is_rejected(self, match_stack):
        ctf = match_stack["ctf"]
        challenge = ctf.create_challenge(type=ChallengeType.SECRET_LEAKAGE)
        match = ctf.start_match(
            ctf.create_match(
                target_agent_id="defender-01", challenge_id=challenge.id
            ).id
        )
        valid_flag = match.flags[0].value
        ctf.resolve_match(match.id)

        result = ctf.submit_flag(match.id, valid_flag, "attacker-01")
        assert result.success is False
        assert result.message == "Match is not active"

    def test_double_capture_is_rejected(self, match_stack):
        ctf = match_stack["ctf"]
        challenge = ctf.create_challenge(type=ChallengeType.SECRET_LEAKAGE)
        match = ctf.start_match(
            ctf.create_match(
                target_agent_id="defender-01", challenge_id=challenge.id
            ).id
        )
        valid_flag = match.flags[0].value

        first = ctf.submit_flag(match.id, valid_flag, "attacker-01")
        assert first.success is True
        second = ctf.submit_flag(match.id, valid_flag, "attacker-02")
        assert second.success is False
        assert second.message == "Flag already captured"

    def test_unknown_challenge_aborts_match_creation(self, match_stack):
        ctf = match_stack["ctf"]
        with pytest.raises(ChallengeNotFoundError):
            ctf.create_match(
                target_agent_id="defender-01", challenge_id="no-such-challenge"
            )
