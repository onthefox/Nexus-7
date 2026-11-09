"""Shannon red-team agent adapter bridging the Gauntlet to an MCP endpoint.

Call chain: Gauntlet -> ShannonAgentAdapter -> MCPClient -> Shannon Endpoint.

The adapter translates :class:`engine.gauntlet.models.AttackType` requests
into MCP ``tools/call`` invocations against the remote Shannon pentest agent,
tags every result with its OWASP LLM Top 10 category, and feeds results back
into the Gauntlet's attack-result ledger.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Optional

from engine.gauntlet.models import AttackResult, AttackType

from .mcp_client import MCPClient, MCPError
from .owasp_mapping import OWASP_LLM_TOP10, owasp_for_pattern, owasp_name

# Gauntlet AttackType -> Shannon MCP tool name.
ATTACK_TYPE_TO_TOOL: dict[AttackType, str] = {
    AttackType.PROMPT_INJECTION: "run_prompt_injection",
    AttackType.INDIRECT_INJECTION: "run_indirect_prompt_injection",
    AttackType.SECRET_EXTRACTION: "run_secret_extraction",
    AttackType.TOOL_ABUSE: "run_tool_abuse",
    AttackType.LOGIC_LOOP: "run_logic_loop",
    AttackType.CONTEXT_OVERFLOW: "run_context_overflow",
    AttackType.JAILBREAK: "run_jailbreak",
    AttackType.DATA_POISONING: "run_data_poisoning",
    AttackType.SWE_CODE_EXPLOIT: "run_swe_code_exploit",
    AttackType.SQL_INJECTION: "run_sql_injection",
    AttackType.XSS: "run_xss",
    AttackType.CSRF: "run_csrf",
    AttackType.IDOR: "run_idor",
    AttackType.SSRF: "run_ssrf",
    AttackType.AUTH_BYPASS: "run_auth_bypass",
    AttackType.FILE_UPLOAD: "run_file_upload",
    AttackType.XXE: "run_xxe",
    AttackType.DESERIALIZATION: "run_deserialization",
    AttackType.RATE_LIMIT_BYPASS: "run_rate_limit_bypass",
    AttackType.CORS_MISCONFIG: "run_cors_misconfig",
    AttackType.EXPLOIT_CHAIN: "run_exploit_chain",
    AttackType.INFECTION_CHAIN: "run_infection_chain",
    AttackType.BEHAVIORAL_ANALYSIS: "run_behavioral_analysis",
    AttackType.MULTI_STAGE: "run_multi_stage",
}

DEFAULT_ATTACK_TYPES: tuple[AttackType, ...] = (
    AttackType.PROMPT_INJECTION,
    AttackType.SECRET_EXTRACTION,
    AttackType.TOOL_ABUSE,
    AttackType.JAILBREAK,
)


def _extract_tool_text(result: Any) -> str:
    """Extract concatenated text content from an MCP tools/call result."""
    if not isinstance(result, dict):
        return ""
    chunks = []
    for item in result.get("content", []) or []:
        if isinstance(item, dict) and item.get("type") == "text":
            chunks.append(str(item.get("text", "")))
    return "\n".join(chunks)


def _parse_attack_payload(result: Any) -> dict[str, Any]:
    """Parse the Shannon attack outcome from an MCP tools/call result.

    Shannon returns its structured outcome as JSON inside the tool text
    content; plain text is treated as an unstructured vulnerability note.
    """
    text = _extract_tool_text(result)
    if isinstance(result, dict) and result.get("isError"):
        return {"success": False, "error": text or "Shannon reported a tool error"}
    if not text:
        return {"success": False, "error": "Shannon returned empty tool output"}
    try:
        parsed = json.loads(text)
    except ValueError:
        return {"success": True, "vulnerability": text}
    if not isinstance(parsed, dict):
        return {"success": True, "vulnerability": text}
    return parsed


class ShannonAgentAdapter:
    """Executes Gauntlet attacks through the remote Shannon pentest agent."""

    def __init__(
        self,
        mcp_client: MCPClient,
        attacker_id: str = "shannon",
        max_turns: int = 200,
    ) -> None:
        self._client = mcp_client
        self._attacker_id = attacker_id
        self._max_turns = max_turns

    @property
    def attacker_id(self) -> str:
        return self._attacker_id

    async def is_available(self) -> bool:
        """True when the Shannon MCP endpoint answers a ping."""
        try:
            return await self._client.ping()
        except MCPError:
            return False

    async def discover_tools(self) -> list[str]:
        """Names of the tools the Shannon endpoint currently advertises."""
        tools = await self._client.list_tools()
        return [tool.name for tool in tools]

    def tool_for(self, attack_type: AttackType | str) -> Optional[str]:
        """Resolve a Gauntlet attack type to its Shannon MCP tool name."""
        if isinstance(attack_type, str):
            attack_type = AttackType(attack_type)
        return ATTACK_TYPE_TO_TOOL.get(attack_type)

    async def launch_attack(
        self,
        target_id: str,
        attack_type: AttackType | str,
    ) -> AttackResult:
        """Run a single Shannon attack against ``target_id`` via MCP."""
        if isinstance(attack_type, str):
            attack_type = AttackType(attack_type)

        tool_name = self.tool_for(attack_type)
        if tool_name is None:
            return AttackResult(
                attack_type=attack_type,
                target_id=target_id,
                attacker_id=self._attacker_id,
                success=False,
                details={"error": f"No Shannon tool mapped for {attack_type.value}"},
            )

        arguments = {
            "target": target_id,
            "attack_type": attack_type.value,
            "max_turns": self._max_turns,
        }
        try:
            result = await self._client.call_tool(tool_name, arguments)
        except MCPError as exc:
            return AttackResult(
                attack_type=attack_type,
                target_id=target_id,
                attacker_id=self._attacker_id,
                success=False,
                details={
                    "error": str(exc),
                    "mcp_tool": tool_name,
                    "mcp_error_code": exc.code,
                },
            )

        outcome = _parse_attack_payload(result)
        owasp_code = owasp_for_pattern(outcome.get("owasp") or tool_name)
        flag_value = outcome.get("flag")
        return AttackResult(
            attack_type=attack_type,
            target_id=target_id,
            attacker_id=self._attacker_id,
            success=bool(outcome.get("success")),
            flag_captured=bool(flag_value),
            flag_value=str(flag_value) if flag_value else "",
            vulnerability=str(outcome.get("vulnerability", "")),
            severity=str(outcome.get("severity", "low")),
            details={
                "payload": outcome.get("payload", ""),
                "owasp": owasp_code,
                "owasp_name": owasp_name(owasp_code),
                "mcp_tool": tool_name,
                "shannon_raw": outcome,
            },
        )

    async def run_campaign(
        self,
        target_id: str,
        attack_types: Optional[Iterable[AttackType]] = None,
    ) -> list[AttackResult]:
        """Run a sequence of Shannon attacks against one target."""
        types = list(attack_types) if attack_types is not None else list(DEFAULT_ATTACK_TYPES)
        return [await self.launch_attack(target_id, attack_type) for attack_type in types]

    @staticmethod
    def owasp_coverage(results: Iterable[AttackResult]) -> dict[str, int]:
        """Count of successful attacks per OWASP LLM Top 10 category."""
        coverage = {code: 0 for code in OWASP_LLM_TOP10}
        for result in results:
            if not result.success:
                continue
            code = result.details.get("owasp")
            if code in coverage:
                coverage[code] += 1
        return coverage
