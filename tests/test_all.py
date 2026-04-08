"""
Tests for Nexus-7 CTF-OS Ecosystem
"""

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSymbioCTF:
    def test_create_challenge(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.models import ChallengeType, Difficulty

        ctf = SymbioCTF()
        challenge = ctf.create_challenge(
            type=ChallengeType.PROMPT_INJECTION,
            difficulty=Difficulty.MEDIUM,
            description="Test challenge",
        )
        assert challenge.id is not None
        assert challenge.type == ChallengeType.PROMPT_INJECTION
        assert challenge.difficulty == Difficulty.MEDIUM

    def test_create_and_start_match(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.models import ChallengeType, Difficulty, MatchState

        ctf = SymbioCTF()
        challenge = ctf.create_challenge(ChallengeType.PROMPT_INJECTION, Difficulty.EASY)
        match = ctf.create_match(
            target_agent_id="target-001",
            challenge_id=challenge.id,
            attacker_agent_ids=["attacker-001"],
        )
        assert match.state == MatchState.PENDING
        assert len(match.attacker_agent_ids) == 1

        match = ctf.start_match(match.id)
        assert match.state == MatchState.ACTIVE
        assert len(match.flags) > 0  # Flags generated

    def test_flag_submission(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.models import ChallengeType, Difficulty

        ctf = SymbioCTF()
        challenge = ctf.create_challenge(ChallengeType.SECRET_LEAKAGE, Difficulty.HARD)
        match = ctf.create_match("target-001", challenge.id, ["attacker-001"])
        ctf.start_match(match.id)

        # Submit invalid flag
        result = ctf.submit_flag(match.id, "nexus7{invalid}", "attacker-001")
        assert not result.success

        # Submit valid flag
        valid_flag = match.flags[0].value
        result = ctf.submit_flag(match.id, valid_flag, "attacker-001")
        assert result.success
        assert result.points > 0

    def test_leaderboard(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.models import ChallengeType, Difficulty

        ctf = SymbioCTF()
        challenge = ctf.create_challenge(ChallengeType.TOOL_ABUSE, Difficulty.MEDIUM)
        match = ctf.create_match("target-001", challenge.id, ["attacker-001"])
        ctf.start_match(match.id)

        flag = match.flags[0].value
        ctf.submit_flag(match.id, flag, "attacker-001")

        leaderboard = ctf.get_leaderboard()
        assert len(leaderboard) > 0
        assert leaderboard[0].agent_id == "attacker-001"
        assert leaderboard[0].flags_captured >= 1


class TestNexusOrchestrator:
    def test_register_agent(self):
        from core.nexus_orchestrator import NexusOrchestrator
        from core.nexus_orchestrator.models import AgentConfig, ProtocolType

        orch = NexusOrchestrator()
        config = AgentConfig(
            name="shannon-pentest",
            protocol=ProtocolType.MCP,
            capabilities=["red-team", "pentest"],
        )
        agent_id = orch.register_agent(config)
        assert agent_id.startswith("agent-")

        status = orch.get_agent_status(agent_id)
        assert status is not None
        assert status.config.name == "shannon-pentest"

    def test_create_task(self):
        from core.nexus_orchestrator import NexusOrchestrator
        from core.nexus_orchestrator.models import TaskPriority

        orch = NexusOrchestrator()
        task = orch.create_task(
            description="Test task",
            priority=TaskPriority.HIGH,
        )
        assert task.id is not None
        assert task.priority == TaskPriority.HIGH


class TestGauntlet:
    def test_deploy_target(self):
        from engine.gauntlet import Gauntlet
        from engine.gauntlet.models import SandboxConfig

        gauntlet = Gauntlet()
        target_id = gauntlet.deploy_target("agent-001", SandboxConfig())
        assert target_id.startswith("target-")

    def test_launch_attack(self):
        from engine.gauntlet import Gauntlet
        from engine.gauntlet.models import AttackType

        gauntlet = Gauntlet()
        target_id = gauntlet.deploy_target("agent-001")
        result = gauntlet.launch_attack(target_id, AttackType.PROMPT_INJECTION)
        assert result.attack_type == AttackType.PROMPT_INJECTION
        assert result.target_id == target_id


class TestEfficiency:
    def test_prune_context(self):
        from engine.efficiency import EfficiencyMiddleware
        from engine.efficiency.models import Message

        mw = EfficiencyMiddleware(default_max_tokens=100)
        messages = [
            Message(role="system", content="You are a helpful assistant"),
            Message(role="user", content="Hello" * 100),
            Message(role="assistant", content="Hi there" * 100),
            Message(role="user", content="Latest message"),
        ]
        pruned = mw.prune_context(messages, max_tokens=50)
        assert len(pruned) < len(messages)

    def test_schema_validation(self):
        from engine.efficiency import EfficiencyMiddleware

        mw = EfficiencyMiddleware()
        schema = {
            "required": ["action", "target"],
            "properties": {
                "action": {"type": "string"},
                "target": {"type": "string"},
                "value": {"type": "integer"},
            },
        }
        valid = {"action": "create", "target": "entity", "value": 42}
        result = mw.validate_response(valid, schema)
        assert result.valid

        invalid = {"action": "create"}  # missing target
        result = mw.validate_response(invalid, schema)
        assert not result.valid


class TestAlignment:
    def test_evaluate_safe_action(self):
        from engine.alignment import AlignmentGuard
        from engine.alignment.models import AgentAction

        guard = AlignmentGuard()
        action = AgentAction(agent_id="agent-001", action_type="query_database", payload={"table": "users"})
        result = guard.evaluate_action(action)
        assert result.passed

    def test_evaluate_dangerous_action(self):
        from engine.alignment import AlignmentGuard
        from engine.alignment.models import AgentAction, ConstraintType

        guard = AlignmentGuard()
        guard.enforce_constraints("agent-001", [ConstraintType.NO_HARM])
        action = AgentAction(agent_id="agent-001", action_type="delete_all_data", payload={})
        result = guard.evaluate_action(action)
        assert not result.passed
        assert len(result.violations) > 0


class TestLedger:
    def test_create_did(self):
        from meta.ledger import NexusLedger

        ledger = NexusLedger()
        did = ledger.create_did("agent-001")
        assert did.did.startswith("did:nexus7:")
        assert did.public_key is not None

    def test_mint_reputation(self):
        from meta.ledger import NexusLedger

        ledger = NexusLedger()
        ledger.create_did("agent-001")
        token = ledger.mint_reputation("agent-001", 100)
        assert token.score == 100
        assert ledger.get_agent_reputation("agent-001") == 100

    def test_immutable_chain(self):
        from meta.ledger import NexusLedger

        ledger = NexusLedger()
        ledger.log_interaction("agent-001", "agent-002", "attack", "failed")
        ledger.log_interaction("agent-002", "agent-001", "counter", "success")
        assert ledger.verify_chain()
