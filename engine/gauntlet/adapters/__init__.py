"""Nexus-7 — Gauntlet adapters.

Bridges the Gauntlet red-teaming engine to external attack agents over the
Model Context Protocol (MCP). The Shannon adapter implements:

Gauntlet → ShannonAgentAdapter → MCPClient → Shannon Endpoint
"""

from .mcp_client import MCPClient, MCPError, MCPTool
from .owasp_mapping import (
    OWASP_LLM_TOP10,
    OWASP_UNMAPPED,
    SHANNON_PATTERN_TO_OWASP,
    owasp_for_pattern,
    owasp_name,
)
from .shannon_agent import ATTACK_TYPE_TO_TOOL, ShannonAgentAdapter

__all__ = [
    "MCPClient",
    "MCPError",
    "MCPTool",
    "OWASP_LLM_TOP10",
    "OWASP_UNMAPPED",
    "SHANNON_PATTERN_TO_OWASP",
    "owasp_for_pattern",
    "owasp_name",
    "ATTACK_TYPE_TO_TOOL",
    "ShannonAgentAdapter",
]
