"""Minimal Model Context Protocol (MCP) client.

Speaks JSON-RPC 2.0 over HTTP to a remote MCP server (e.g. the Shannon pentest
agent endpoint). Implements the MCP core methods needed by the Gauntlet:

- ``initialize`` — protocol handshake
- ``ping`` — liveness check
- ``tools/list`` — tool discovery
- ``tools/call`` — tool invocation

The endpoint URL is fully configurable; no network traffic happens until a
method is awaited, and an ``httpx.AsyncTransport`` can be injected for testing
(production code never fabricates one itself).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

MCP_PROTOCOL_VERSION = "2024-11-05"
MCP_CLIENT_NAME = "nexus7-gauntlet"
MCP_CLIENT_VERSION = "1.0.0"


class MCPError(Exception):
    """Raised when an MCP request fails at the transport or protocol level."""

    def __init__(self, message: str, code: Optional[int] = None) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class MCPTool:
    """A tool advertised by the remote MCP server."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)


class MCPClient:
    """Async JSON-RPC 2.0 client for an MCP server over HTTP.

    Args:
        endpoint_url: Absolute URL of the MCP endpoint
            (e.g. ``http://shannon.internal:9900/mcp``).
        api_key: Optional bearer token sent as ``Authorization`` header.
        timeout: Per-request timeout in seconds.
        transport: Optional ``httpx.AsyncTransport`` injection point
            (used by the test suite to mount a fake MCP server).
    """

    def __init__(
        self,
        endpoint_url: str,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        transport: Optional[httpx.AsyncTransport] = None,
    ) -> None:
        if not endpoint_url:
            raise ValueError("endpoint_url must be a non-empty URL")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._endpoint_url = endpoint_url
        self._client = httpx.AsyncClient(
            base_url=endpoint_url,
            timeout=timeout,
            headers=headers,
            transport=transport,
        )
        self._next_id = 0
        self._initialized = False
        self._server_info: dict[str, Any] = {}

    # ── JSON-RPC plumbing ─────────────────────────────────────────────

    async def _request(self, method: str, params: Optional[dict[str, Any]] = None) -> Any:
        self._next_id += 1
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self._next_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params

        try:
            response = await self._client.post("/", json=payload)
        except httpx.HTTPError as exc:
            raise MCPError(f"Transport error calling MCP endpoint: {exc}") from exc

        if response.status_code >= 400:
            raise MCPError(
                f"MCP endpoint returned HTTP {response.status_code}",
                code=response.status_code,
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise MCPError("MCP endpoint returned a non-JSON response") from exc

        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
            raise MCPError("MCP response is not a valid JSON-RPC 2.0 object")
        if body.get("id") != self._next_id:
            raise MCPError("MCP response id does not match request id")

        if "error" in body:
            error = body["error"] or {}
            raise MCPError(
                str(error.get("message", "Unknown MCP error")),
                code=error.get("code"),
            )
        return body.get("result")

    # ── MCP methods ───────────────────────────────────────────────────

    async def initialize(self) -> dict[str, Any]:
        """Perform the MCP protocol handshake and return server info."""
        result = await self._request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "clientInfo": {"name": MCP_CLIENT_NAME, "version": MCP_CLIENT_VERSION},
            },
        )
        if not isinstance(result, dict):
            raise MCPError("MCP initialize returned no server info")
        self._server_info = result
        self._initialized = True
        return result

    @property
    def server_info(self) -> dict[str, Any]:
        """Server info captured during ``initialize`` (empty before it)."""
        return dict(self._server_info)

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    async def ping(self) -> bool:
        """Return True when the endpoint answers a ping."""
        await self._request("ping")
        return True

    async def list_tools(self) -> list[MCPTool]:
        """List tools advertised by the remote server."""
        result = await self._request("tools/list", {})
        raw_tools = result.get("tools", []) if isinstance(result, dict) else []
        tools = []
        for raw in raw_tools:
            if not isinstance(raw, dict) or "name" not in raw:
                continue
            tools.append(
                MCPTool(
                    name=str(raw["name"]),
                    description=str(raw.get("description", "")),
                    input_schema=raw.get("inputSchema") or {},
                )
            )
        return tools

    async def call_tool(self, name: str, arguments: Optional[dict[str, Any]] = None) -> Any:
        """Invoke a remote tool and return its raw MCP result object."""
        if not self._initialized:
            # Best-effort handshake so callers do not need to remember it.
            await self.initialize()
        result = await self._request(
            "tools/call",
            {"name": name, "arguments": arguments or {}},
        )
        return result

    async def aclose(self) -> None:
        """Release the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> "MCPClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()
