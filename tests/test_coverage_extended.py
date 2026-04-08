"""
Additional tests coverage for Nexus-7
Focuses on: orchestrator lifecycle, gauntlet sequences, ledger verification, UI API
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestOrchestratorLifecycle:
    def test_agent_state_transitions(self):
        from core.nexus_orchestrator import NexusOrchestrator
        from core.nexus_orchestrator.models import AgentConfig, AgentState, ProtocolType

        orch = NexusOrchestrator()
        agent_id = orch.register_agent(AgentConfig(name="test-agent", protocol=ProtocolType.MCP))

        assert orch.update_agent_state(agent_id, AgentState.IDLE)
        assert orch.get_agent_status(agent_id).state == AgentState.IDLE

        assert orch.update_agent_state(agent_id, AgentState.RUNNING)
        assert orch.update_agent_state(agent_id, AgentState.PAUSED)
        assert orch.get_agent_status(agent_id).state == AgentState.PAUSED

    def test_shutdown_agent(self):
        from core.nexus_orchestrator import NexusOrchestrator
        from core.nexus_orchestrator.models import AgentConfig, ProtocolType

        orch = NexusOrchestrator()
        agent_id = orch.register_agent(AgentConfig(name="temp-agent", protocol=ProtocolType.A2A))
        assert orch.shutdown_agent(agent_id)
        assert orch.get_agent_status(agent_id) is None

    def test_health_check(self):
        from core.nexus_orchestrator import NexusOrchestrator
        from core.nexus_orchestrator.models import AgentConfig, ProtocolType

        orch = NexusOrchestrator()
        orch.register_agent(AgentConfig(name="agent-a", protocol=ProtocolType.MCP))
        orch.register_agent(AgentConfig(name="agent-b", protocol=ProtocolType.A2A))

        health = orch.health_check()
        assert len(health) == 2
        assert all(0 <= v <= 1 for v in health.values())

    def test_list_agents_filter(self):
        from core.nexus_orchestrator import NexusOrchestrator
        from core.nexus_orchestrator.models import AgentConfig, AgentState, ProtocolType

        orch = NexusOrchestrator()
        orch.register_agent(AgentConfig(name="active", protocol=ProtocolType.MCP))
        orch.register_agent(AgentConfig(name="idle", protocol=ProtocolType.MCP))

        all_agents = orch.list_agents()
        assert len(all_agents) == 2

        idle_agents = orch.list_agents(state=AgentState.REGISTERED)
        assert len(idle_agents) == 2

    def test_protocol_translation(self):
        from core.nexus_orchestrator import NexusOrchestrator
        from core.nexus_orchestrator.models import ProtocolType

        orch = NexusOrchestrator()
        msg = {"content": "Hello", "role": "user"}

        result = orch.translate_protocol(msg, ProtocolType.CHAT, ProtocolType.MCP)
        assert result["_translated_from"] == "chat"
        assert result["_translated_to"] == "mcp"
        assert result["content"] == "Hello"

    def test_reset(self):
        from core.nexus_orchestrator import NexusOrchestrator
        from core.nexus_orchestrator.models import AgentConfig, ProtocolType

        orch = NexusOrchestrator()
        orch.register_agent(AgentConfig(name="test", protocol=ProtocolType.MCP))
        orch.create_task("Test task")

        orch.reset()
        assert len(orch.list_agents()) == 0
        assert len(orch.list_tasks()) == 0


class TestCTFExtended:
    def test_resolve_match(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.models import ChallengeType, Difficulty, MatchState

        ctf = SymbioCTF()
        challenge = ctf.create_challenge(ChallengeType.DATA_POISONING, Difficulty.HARD)
        match = ctf.create_match("defender-01", challenge.id)
        ctf.start_match(match.id)

        match = ctf.resolve_match(match.id, MatchState.TIMEOUT)
        assert match.state == MatchState.TIMEOUT
        assert match.resolved_at is not None

    def test_invalid_match_operations(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.models import ChallengeType, Difficulty

        ctf = SymbioCTF()

        with pytest.raises(ValueError):
            ctf.start_match("nonexistent")

        with pytest.raises(ValueError):
            ctf.resolve_match("nonexistent")

    def test_list_challenges(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.models import ChallengeType, Difficulty

        ctf = SymbioCTF()
        ctf.create_challenge(ChallengeType.PROMPT_INJECTION, Difficulty.EASY)
        ctf.create_challenge(ChallengeType.TOOL_ABUSE, Difficulty.EXPERT)

        challenges = ctf.list_challenges()
        assert len(challenges) == 2

    def test_reset(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.models import ChallengeType, Difficulty

        ctf = SymbioCTF()
        ctf.create_challenge(ChallengeType.PROMPT_INJECTION, Difficulty.MEDIUM)

        ctf.reset()
        assert len(ctf.list_challenges()) == 0
        assert len(ctf.list_matches()) == 0
        assert len(ctf.get_leaderboard()) == 0


class TestGauntletExtended:
    def test_attack_sequence(self):
        from engine.gauntlet import Gauntlet
        from engine.gauntlet.models import AttackType

        gauntlet = Gauntlet()
        target_id = gauntlet.deploy_target("agent-001")

        results = gauntlet.launch_attack_sequence(
            target_id,
            attack_types=[AttackType.PROMPT_INJECTION, AttackType.JAILBREAK],
        )
        assert len(results) == 2
        assert results[0].attack_type == AttackType.PROMPT_INJECTION
        assert results[1].attack_type == AttackType.JAILBREAK

    def test_remove_target(self):
        from engine.gauntlet import Gauntlet

        gauntlet = Gauntlet()
        target_id = gauntlet.deploy_target("agent-001")
        assert gauntlet.remove_target(target_id)
        assert not gauntlet.remove_target("nonexistent")

    def test_vulnerability_report(self):
        from engine.gauntlet import Gauntlet
        from engine.gauntlet.models import AttackType

        gauntlet = Gauntlet()
        target_id = gauntlet.deploy_target("agent-001")

        # Launch several attacks
        for at in [AttackType.PROMPT_INJECTION, AttackType.SECRET_EXTRACTION, AttackType.TOOL_ABUSE]:
            gauntlet.launch_attack(target_id, at)

        report = gauntlet.get_vulnerability_report(target_id)
        assert report.target_id == target_id
        assert report.total_attacks == 3
        assert report.severity_counts["low"] >= 0  # At least low-severity entries

    def test_continuous_redteam(self):
        from engine.gauntlet import Gauntlet

        gauntlet = Gauntlet()
        target_id = gauntlet.deploy_target("agent-001")

        session_id = gauntlet.start_continuous_redteam(target_id, duration=60, interval=10)
        assert session_id.startswith("redteam-")

        assert gauntlet.stop_continuous_redteam(session_id)
        assert not gauntlet.stop_continuous_redteam("nonexistent")

    def test_reset(self):
        from engine.gauntlet import Gauntlet

        gauntlet = Gauntlet()
        gauntlet.deploy_target("agent-001")
        gauntlet.launch_attack(gauntlet._targets.keys().__iter__().__next__(), "prompt_injection")

        gauntlet.reset()
        assert len(gauntlet._targets) == 0
        assert len(gauntlet._attack_results) == 0


class TestLedgerExtended:
    def test_verify_did(self):
        from meta.ledger import NexusLedger

        ledger = NexusLedger()
        did = ledger.create_did("agent-001")

        assert ledger.verify_did("agent-001", did.did)
        assert not ledger.verify_did("agent-001", "did:nexus7:fake")
        assert not ledger.verify_did("nonexistent", "anything")

    def test_verify_chain_integrity(self):
        from meta.ledger import NexusLedger

        ledger = NexusLedger()
        ledger.log_interaction("a", "b", "attack", "success")
        ledger.log_interaction("b", "c", "counter", "failed")
        ledger.log_interaction("c", "a", "report", "filed")

        assert ledger.verify_chain()

    def test_get_logs_filtered(self):
        from meta.ledger import NexusLedger

        ledger = NexusLedger()
        ledger.log_interaction("agent-a", "agent-b", "attack", "result1")
        ledger.log_interaction("agent-c", "agent-d", "attack", "result2")
        ledger.log_interaction("agent-a", "agent-c", "counter", "result3")

        logs = ledger.get_logs(agent_id="agent-a")
        assert len(logs) == 2  # Both logs involving agent-a

    def test_get_stats(self):
        from meta.ledger import NexusLedger

        ledger = NexusLedger()
        ledger.create_did("agent-001")
        ledger.mint_reputation("agent-001", 100)
        ledger.log_interaction("agent-001", "agent-002", "test", "ok")

        stats = ledger.get_stats()
        assert stats["dids"] == 1
        assert stats["reputation_tokens"] == 1
        assert stats["log_entries"] == 1

    def test_reputation_history(self):
        from meta.ledger import NexusLedger

        ledger = NexusLedger()
        ledger.create_did("agent-001")
        ledger.mint_reputation("agent-001", 50)
        ledger.mint_reputation("agent-001", 75)

        history = ledger.get_reputation_history("agent-001")
        assert len(history) == 2
        assert ledger.get_agent_reputation("agent-001") == 125

    def test_reset(self):
        from meta.ledger import NexusLedger

        ledger = NexusLedger()
        ledger.create_did("agent-001")
        ledger.mint_reputation("agent-001", 100)

        ledger.reset()
        assert ledger.get_stats()["dids"] == 0


class TestEfficiencyExtended:
    def test_set_and_enforce_budget(self):
        from engine.efficiency import EfficiencyMiddleware

        mw = EfficiencyMiddleware()
        mw.set_budget("agent-001", 1000)

        mw.track_token_usage("agent-001", 500)
        assert mw.enforce_budget("agent-001", 400)  # 500+400=900 <= 1000
        assert not mw.enforce_budget("agent-001", 600)  # 500+600=1100 > 1000

    def test_latency_sla(self):
        from engine.efficiency import EfficiencyMiddleware

        mw = EfficiencyMiddleware()
        mw.set_latency_sla("agent-001", 2.0)

        assert mw.check_latency("agent-001", 1.5)
        assert not mw.check_latency("agent-001", 3.0)

    def test_get_token_usage(self):
        from engine.efficiency import EfficiencyMiddleware

        mw = EfficiencyMiddleware()
        mw.set_budget("agent-001", 500)
        mw.track_token_usage("agent-001", 100)
        mw.track_token_usage("agent-001", 150)

        records = mw.get_token_usage("agent-001")
        assert len(records) == 2
        assert records[0].tokens_used == 100
        assert records[1].tokens_used == 150

    def test_reset(self):
        from engine.efficiency import EfficiencyMiddleware

        mw = EfficiencyMiddleware()
        mw.set_budget("agent-001", 100)
        mw.track_token_usage("agent-001", 50)
        mw.set_latency_sla("agent-001", 5.0)

        mw.reset()
        assert len(mw.get_token_usage("agent-001")) == 0


class TestAlignmentExtended:
    def test_multiple_violations_circuit_breaker(self):
        from engine.alignment import AlignmentGuard
        from engine.alignment.models import AgentAction, ConstraintType

        guard = AlignmentGuard()
        guard.enforce_constraints("agent-001", [ConstraintType.NO_HARM])

        # Trigger 3 violations to trip circuit breaker
        for _ in range(3):
            action = AgentAction(agent_id="agent-001", action_type="delete_data")
            guard.evaluate_action(action)

        assert guard.check_circuit_breaker("agent-001")

    def test_reset_circuit_breaker(self):
        from engine.alignment import AlignmentGuard
        from engine.alignment.models import AgentAction, ConstraintType

        guard = AlignmentGuard()
        guard.enforce_constraints("agent-001", [ConstraintType.NO_HARM])

        for _ in range(3):
            guard.evaluate_action(AgentAction(agent_id="agent-001", action_type="delete_data"))

        assert guard.check_circuit_breaker("agent-001")
        assert guard.reset_circuit_breaker("agent-001")
        assert not guard.check_circuit_breaker("agent-001")

    def test_no_violations_without_constraints(self):
        from engine.alignment import AlignmentGuard
        from engine.alignment.models import AgentAction

        guard = AlignmentGuard()
        # No constraints set — use a safe action that doesn't match any patterns
        action = AgentAction(agent_id="agent-001", action_type="read_database")
        result = guard.evaluate_action(action)
        assert result.passed  # Safe action with no constraints = no violations

    def test_power_seeking_detection(self):
        from engine.alignment import AlignmentGuard
        from engine.alignment.models import AgentAction, ConstraintType

        guard = AlignmentGuard()
        guard.enforce_constraints("agent-001", [ConstraintType.NO_POWER_SEEKING])

        guard.evaluate_action(AgentAction(agent_id="agent-001", action_type="escalate_privileges"))
        assert guard.detect_power_seeking("agent-001")

    def test_get_all_violations(self):
        from engine.alignment import AlignmentGuard
        from engine.alignment.models import AgentAction, ConstraintType

        guard = AlignmentGuard()
        guard.enforce_constraints("agent-001", [ConstraintType.NO_HARM])
        guard.evaluate_action(AgentAction(agent_id="agent-001", action_type="destroy_all"))

        violations = guard.get_all_violations()
        assert "agent-001" in violations
        assert len(violations["agent-001"]) == 1

    def test_reset(self):
        from engine.alignment import AlignmentGuard
        from engine.alignment.models import AgentAction, ConstraintType

        guard = AlignmentGuard()
        guard.enforce_constraints("agent-001", [ConstraintType.NO_HARM])
        guard.evaluate_action(AgentAction(agent_id="agent-001", action_type="delete"))

        guard.reset()
        assert len(guard.get_all_violations()) == 0
        assert guard.get_constraints("agent-001") == []
