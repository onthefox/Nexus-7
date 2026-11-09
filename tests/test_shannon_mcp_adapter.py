"""
Tests for the Shannon MCP integration (issue #4).

Covers:
- MCPClient: JSON-RPC handshake, ping, tools/list, tools/call, error handling
- OWASP LLM Top 10 mapping for Shannon attack patterns
- ShannonAgentAdapter: attack execution, flag capture, OWASP tagging
- Gauntlet integration (attach_shannon / launch_shannon_attack)
- End-to-end scenario with Shannon as attacker against a live CTF match
"""

import sys
import os

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.fake_mcp_server import FakeShannonMCPServer, SERVER_INFO

from core.symbio_ctf import SymbioCTF
from core.symbio_ctf.models import ChallengeType, Difficulty
from engine.gauntlet import Gauntlet
from engine.gauntlet.adapters import (
    ATTACK_TYPE_TO_TOOL,
    MCPClient,
    MCPError,
    OWASP_LLM_TOP10,
    OWASP_UNMAPPED,
    ShannonAgentAdapter,
    owasp_for_pattern,
    owasp_name,
)
from engine.gauntlet.models import AttackType


VALID_FLAG = "nexus7{ab12cd34ef56}"


@pytest.fixture
def fake_server():
    return FakeShannonMCPServer()


@pytest.fixture
def mcp_client(fake_server):
    transport = httpx.ASGITransport(app=fake_server)
    client = MCPClient("http://shannon.test/mcp", api_key="test-key", transport=transport)
    yield client
    # Async client cleanup happens inside the async tests via aclose()


async def make_adapter(fake_server, **client_kwargs) -> ShannonAgentAdapter:
    transport = httpx.ASGITransport(app=fake_server)
    client = MCPClient(
        "http://shannon.test/mcp",
        api_key="test-key",
        transport=transport,
        **client_kwargs,
    )
    return ShannonAgentAdapter(client)


# ── MCP Client Tests ─────────────────────────────────────────────────


class TestMCPClient:
    async def test_initialize_handshake(self, mcp_client, fake_server):
        info = await mcp_client.initialize()
        assert info["serverInfo"]["name"] == SERVER_INFO["serverInfo"]["name"]
        assert mcp_client.is_initialized
        assert mcp_client.server_info["protocolVersion"] == "2024-11-05"
        await mcp_client.aclose()

    async def test_authorization_header_sent(self, mcp_client, fake_server):
        await mcp_client.initialize()
        assert fake_server.authorization_headers[-1] == "Bearer test-key"
        await mcp_client.aclose()

    async def test_ping(self, mcp_client):
        assert await mcp_client.ping() is True
        await mcp_client.aclose()

    async def test_list_tools(self, mcp_client):
        tools = await mcp_client.list_tools()
        names = [tool.name for tool in tools]
        assert "run_prompt_injection" in names
        assert "run_ssrf" in names
        assert all(tool.input_schema.get("type") == "object" for tool in tools)
        await mcp_client.aclose()

    async def test_call_tool_returns_parsed_outcome(self, mcp_client, fake_server):
        fake_server.successful_attacks = {"run_prompt_injection"}
        result = await mcp_client.call_tool(
            "run_prompt_injection", {"target": "t-1", "attack_type": "prompt_injection"}
        )
        assert result["isError"] is False
        assert result["content"][0]["type"] == "text"
        await mcp_client.aclose()

    async def test_call_tool_unknown_tool_raises_mcp_error(self, mcp_client):
        with pytest.raises(MCPError) as exc_info:
            await mcp_client.call_tool("nonexistent_tool", {})
        assert exc_info.value.code == -32601
        await mcp_client.aclose()

    async def test_unknown_method_raises_mcp_error(self, mcp_client):
        with pytest.raises(MCPError) as exc_info:
            await mcp_client._request("resources/list", {})
        assert "Method not found" in str(exc_info.value)
        await mcp_client.aclose()

    async def test_endpoint_unavailable_raises_transport_error(self, fake_server):
        fake_server.unavailable = True
        transport = httpx.ASGITransport(app=fake_server)
        client = MCPClient("http://shannon.test/mcp", transport=transport)
        with pytest.raises(MCPError) as exc_info:
            await client.ping()
        assert exc_info.value.code == 503
        await client.aclose()

    def test_empty_endpoint_url_rejected(self):
        with pytest.raises(ValueError):
            MCPClient("")

    async def test_context_manager_closes_client(self, fake_server):
        transport = httpx.ASGITransport(app=fake_server)
        async with MCPClient("http://shannon.test/mcp", transport=transport) as client:
            assert await client.ping() is True
        # After aclose the underlying client is closed; further calls raise RuntimeError
        with pytest.raises(RuntimeError):
            await client.ping()

    async def test_call_tool_auto_initializes(self, fake_server):
        transport = httpx.ASGITransport(app=fake_server)
        client = MCPClient("http://shannon.test/mcp", transport=transport)
        assert client.is_initialized is False
        await client.call_tool("run_prompt_injection", {})
        assert client.is_initialized is True
        await client.aclose()


# ── OWASP Mapping Tests ──────────────────────────────────────────────


class TestOWASPMapping:
    def test_catalogue_covers_all_ten_categories(self):
        assert len(OWASP_LLM_TOP10) == 10
        assert set(OWASP_LLM_TOP10) == {f"LLM{i:02d}" for i in range(1, 11)}
        assert OWASP_LLM_TOP10["LLM01"] == "Prompt Injection"

    def test_shannon_patterns_map_to_owasp(self):
        assert owasp_for_pattern("prompt_injection") == "LLM01"
        assert owasp_for_pattern("secret_extraction") == "LLM02"
        assert owasp_for_pattern("tool_abuse") == "LLM06"
        assert owasp_for_pattern("context_overflow") == "LLM10"

    def test_tool_name_decorations_are_normalized(self):
        assert owasp_for_pattern("run_prompt_injection") == "LLM01"
        assert owasp_for_pattern("run_jailbreak") == "LLM01"
        assert owasp_for_pattern("shannon.tool_abuse") == "LLM06"

    def test_matching_is_case_insensitive(self):
        assert owasp_for_pattern("Prompt_Injection") == "LLM01"

    def test_unmapped_pattern_falls_back(self):
        assert owasp_for_pattern("quantum_decryption") == OWASP_UNMAPPED
        assert owasp_for_pattern("") == OWASP_UNMAPPED
        assert owasp_for_pattern(None) == OWASP_UNMAPPED

    def test_owasp_name_lookup(self):
        assert owasp_name("LLM07") == "System Prompt Leakage"
        assert owasp_name("INVALID") == ""

    def test_mapping_covers_many_patterns(self):
        from engine.gauntlet.adapters import SHANNON_PATTERN_TO_OWASP

        assert len(SHANNON_PATTERN_TO_OWASP) >= 20
        for code in SHANNON_PATTERN_TO_OWASP.values():
            assert code in OWASP_LLM_TOP10


# ── Shannon Agent Adapter Tests ──────────────────────────────────────


class TestShannonAgentAdapter:
    def test_every_attack_type_has_a_tool(self):
        assert set(ATTACK_TYPE_TO_TOOL) == set(AttackType)

    def test_tool_for_resolves_known_and_unknown(self):
        adapter = ShannonAgentAdapter(mcp_client=None)
        assert adapter.tool_for(AttackType.PROMPT_INJECTION) == "run_prompt_injection"
        assert adapter.tool_for("xss") == "run_xss"

    async def test_is_available_true_and_false(self, fake_server):
        adapter = await make_adapter(fake_server)
        assert await adapter.is_available() is True

        fake_server.unavailable = True
        assert await adapter.is_available() is False

    async def test_discover_tools(self, fake_server):
        adapter = await make_adapter(fake_server)
        tools = await adapter.discover_tools()
        assert "run_prompt_injection" in tools
        assert len(tools) == 24

    async def test_successful_attack_is_owasp_tagged(self, fake_server):
        adapter = await make_adapter(fake_server)
        result = await adapter.launch_attack("target-1", AttackType.PROMPT_INJECTION)
        assert result.success is True
        assert result.attacker_id == "shannon"
        assert result.target_id == "target-1"
        assert result.details["owasp"] == "LLM01"
        assert result.details["owasp_name"] == "Prompt Injection"
        assert result.details["mcp_tool"] == "run_prompt_injection"
        assert result.severity == "high"

    async def test_failed_attack_reports_failure(self, fake_server):
        fake_server.successful_attacks = set()
        adapter = await make_adapter(fake_server)
        result = await adapter.launch_attack("target-1", AttackType.XSS)
        assert result.success is False
        assert not result.flag_captured

    async def test_flag_capture_populates_result(self, fake_server):
        fake_server.flag_tool = "run_prompt_injection"
        fake_server.flag_to_return = VALID_FLAG
        adapter = await make_adapter(fake_server)
        result = await adapter.launch_attack("target-1", AttackType.PROMPT_INJECTION)
        assert result.flag_captured is True
        assert result.flag_value == VALID_FLAG

    async def test_mcp_error_becomes_failed_attack_result(self, fake_server):
        fake_server.error_tools = {"run_ssrf"}
        adapter = await make_adapter(fake_server)
        result = await adapter.launch_attack("target-1", AttackType.SSRF)
        assert result.success is False
        assert "Tool not found" in result.details["error"]
        assert result.details["mcp_error_code"] == -32601

    async def test_run_campaign_runs_default_sequence(self, fake_server):
        adapter = await make_adapter(fake_server)
        results = await adapter.run_campaign("target-1")
        assert len(results) == 4
        assert [r.attack_type for r in results][0] == AttackType.PROMPT_INJECTION
        assert sum(1 for r in results if r.success) == 1  # only prompt injection

    async def test_owasp_coverage_counts_successes_only(self, fake_server):
        fake_server.flag_tool = "run_prompt_injection"
        fake_server.flag_to_return = VALID_FLAG
        adapter = await make_adapter(fake_server)
        results = await adapter.run_campaign(
            "target-1",
            [AttackType.PROMPT_INJECTION, AttackType.SECRET_EXTRACTION],
        )
        coverage = adapter.owasp_coverage(results)
        assert coverage["LLM01"] == 1
        assert coverage["LLM02"] == 0  # secret_extraction failed
        assert sum(coverage.values()) == 1

    async def test_invalid_attack_type_string_raises(self, fake_server):
        adapter = await make_adapter(fake_server)
        with pytest.raises(ValueError):
            await adapter.launch_attack("target-1", "not_an_attack")


# ── Gauntlet Integration Tests ───────────────────────────────────────


class TestGauntletShannonIntegration:
    async def test_launch_without_adapter_raises(self):
        gauntlet = Gauntlet()
        with pytest.raises(RuntimeError, match="No Shannon adapter attached"):
            await gauntlet.launch_shannon_attack("t-1", AttackType.PROMPT_INJECTION)

    async def test_launch_on_unknown_target_raises(self, fake_server):
        gauntlet = Gauntlet()
        gauntlet.attach_shannon(await make_adapter(fake_server))
        assert gauntlet.has_shannon() is True
        with pytest.raises(ValueError, match="not deployed"):
            await gauntlet.launch_shannon_attack("ghost", AttackType.PROMPT_INJECTION)

    async def test_launch_appends_result_to_gauntlet_ledger(self, fake_server):
        gauntlet = Gauntlet()
        gauntlet.attach_shannon(await make_adapter(fake_server))
        target_id = gauntlet.deploy_target("defender-1")
        result = await gauntlet.launch_shannon_attack(target_id, AttackType.PROMPT_INJECTION)
        assert result.success is True
        assert gauntlet.get_all_results() == [result]

    async def test_attach_shannon_accepts_string_attack_type(self, fake_server):
        gauntlet = Gauntlet()
        gauntlet.attach_shannon(await make_adapter(fake_server))
        target_id = gauntlet.deploy_target("defender-1")
        result = await gauntlet.launch_shannon_attack(target_id, "prompt_injection")
        assert result.attack_type == AttackType.PROMPT_INJECTION

    async def test_reset_detaches_shannon(self, fake_server):
        gauntlet = Gauntlet()
        gauntlet.attach_shannon(await make_adapter(fake_server))
        gauntlet.reset()
        assert gauntlet.has_shannon() is False


# ── Shannon-as-Attacker Scenario (issue #4 acceptance) ───────────────


class TestShannonAttackerScenario:
    async def test_shannon_captures_flag_and_scores_in_ctf_match(self, fake_server):
        ctf = SymbioCTF()
        challenge = ctf.create_challenge(
            type=ChallengeType.PROMPT_INJECTION,
            difficulty=Difficulty.MEDIUM,
            description="Defender must resist Shannon prompt injection attacks",
        )
        match = ctf.create_match(
            target_agent_id="defender-agent",
            challenge_id=challenge.id,
            attacker_agent_ids=["shannon"],
        )
        match = ctf.start_match(match.id)
        assert match.is_active

        fake_server.successful_attacks = {"run_prompt_injection"}
        fake_server.flag_tool = "run_prompt_injection"
        fake_server.flag_to_return = match.flags[0].value

        gauntlet = Gauntlet(ctf_engine=ctf)
        gauntlet.attach_shannon(await make_adapter(fake_server))
        target_id = gauntlet.deploy_target("defender-agent")

        attack = await gauntlet.launch_shannon_attack(target_id, AttackType.PROMPT_INJECTION)
        assert attack.success is True
        assert attack.flag_captured is True
        assert attack.flag_value == match.flags[0].value
        assert attack.details["owasp"] == "LLM01"

        score = ctf.submit_flag(match.id, attack.flag_value, attack.attacker_id)
        assert score.success is True
        assert score.points > 0

        report = gauntlet.get_vulnerability_report(target_id)
        assert report.total_attacks == 1
        assert report.successful_attacks == 1

        match = ctf.resolve_match(match.id)
        leaderboard = ctf.get_leaderboard()
        shannon_entry = next(e for e in leaderboard if e.agent_id == "shannon")
        assert shannon_entry.total_points == score.points
        assert shannon_entry.flags_captured == 1

    async def test_defended_target_rejects_shannon_flag_grab(self, fake_server):
        """Shannon cannot capture a flag when its attacks all fail."""
        ctf = SymbioCTF()
        challenge = ctf.create_challenge(
            type=ChallengeType.PROMPT_INJECTION, difficulty=Difficulty.EXPERT
        )
        match = ctf.create_match(
            target_agent_id="hardened-agent",
            challenge_id=challenge.id,
            attacker_agent_ids=["shannon"],
        )
        match = ctf.start_match(match.id)

        fake_server.successful_attacks = set()
        gauntlet = Gauntlet()
        gauntlet.attach_shannon(await make_adapter(fake_server))
        target_id = gauntlet.deploy_target("hardened-agent")

        for attack_type in (AttackType.PROMPT_INJECTION, AttackType.JAILBREAK):
            result = await gauntlet.launch_shannon_attack(target_id, attack_type)
            assert result.success is False
            assert not result.flag_captured

        assert ctf.get_leaderboard() == []
        assert all(not flag.captured for flag in match.flags)
