"""Fake Shannon MCP server used only by the test suite.

Implements the JSON-RPC 2.0 / MCP surface the production ``MCPClient`` speaks:
``initialize``, ``ping``, ``tools/list`` and ``tools/call``. Mounted through
``httpx.ASGITransport`` so no real network socket is involved.

The server is intentionally scriptable: tests configure which attacks
succeed, which tool returns a captured flag, and can force protocol errors
to exercise the adapter's failure paths.
"""

from __future__ import annotations

import json
from typing import Any

SHANNON_TOOLS = [
    "run_prompt_injection",
    "run_indirect_prompt_injection",
    "run_secret_extraction",
    "run_tool_abuse",
    "run_logic_loop",
    "run_context_overflow",
    "run_jailbreak",
    "run_data_poisoning",
    "run_swe_code_exploit",
    "run_sql_injection",
    "run_xss",
    "run_csrf",
    "run_idor",
    "run_ssrf",
    "run_auth_bypass",
    "run_file_upload",
    "run_xxe",
    "run_deserialization",
    "run_rate_limit_bypass",
    "run_cors_misconfig",
    "run_exploit_chain",
    "run_infection_chain",
    "run_behavioral_analysis",
    "run_multi_stage",
]

SERVER_INFO = {
    "protocolVersion": "2024-11-05",
    "serverInfo": {"name": "shannon-fake", "version": "0.1.0"},
    "capabilities": {"tools": {"listChanged": False}},
}


def _json_rpc_result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _json_rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


class FakeShannonMCPServer:
    """Raw ASGI application emulating the Shannon pentest MCP endpoint."""

    def __init__(self) -> None:
        self.successful_attacks: set[str] = {"run_prompt_injection"}
        self.flag_tool: str | None = None
        self.flag_to_return: str | None = None
        self.error_tools: set[str] = set()  # tools that answer with JSON-RPC errors
        self.unavailable = False  # respond 503 for every request
        self.request_log: list[dict[str, Any]] = []
        self.authorization_headers: list[str | None] = []

    def _tool_outcome(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool_name not in SHANNON_TOOLS:
            return {"success": False, "error": f"Unknown Shannon tool {tool_name}"}
        success = tool_name in self.successful_attacks
        outcome: dict[str, Any] = {
            "success": success,
            "payload": f"shannon:{tool_name}:{arguments.get('target', '')}",
            "severity": "high" if success else "info",
            "vulnerability": f"Simulated {tool_name} finding" if success else "",
        }
        if success and tool_name == self.flag_tool and self.flag_to_return:
            outcome["flag"] = self.flag_to_return
        return outcome

    async def _handle(self, request: dict[str, Any]) -> dict[str, Any]:
        request_id = request.get("id")
        method = request.get("method", "")

        if request_id is None:
            # Notifications are accepted and never answered.
            return {"__notification__": True}

        if method == "initialize":
            return _json_rpc_result(request_id, dict(SERVER_INFO))
        if method == "ping":
            return _json_rpc_result(request_id, {})
        if method == "tools/list":
            tools = [
                {
                    "name": name,
                    "description": f"Shannon {name} attack",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string"},
                            "attack_type": {"type": "string"},
                            "max_turns": {"type": "integer"},
                        },
                    },
                }
                for name in SHANNON_TOOLS
            ]
            return _json_rpc_result(request_id, {"tools": tools})
        if method == "tools/call":
            params = request.get("params") or {}
            tool_name = str(params.get("name", ""))
            arguments = params.get("arguments") or {}
            if tool_name in self.error_tools or tool_name not in SHANNON_TOOLS:
                return _json_rpc_error(
                    request_id, -32601, f"Tool not found: {tool_name}"
                )
            outcome = self._tool_outcome(tool_name, arguments)
            return _json_rpc_result(
                request_id,
                {
                    "content": [
                        {"type": "text", "text": json.dumps(outcome)},
                    ],
                    "isError": False,
                },
            )
        return _json_rpc_error(request_id, -32601, f"Method not found: {method}")

    async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001
        if scope["type"] != "http":
            raise RuntimeError("FakeShannonMCPServer only supports HTTP requests")

        body = b""
        while True:
            message = await receive()
            if message["type"] == "http.request":
                body += message.get("body", b"")
                if not message.get("more_body"):
                    break
            elif message["type"] == "http.disconnect":
                return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        self.authorization_headers.append(headers.get("authorization"))
        self.request_log.append(json.loads(body.decode("utf-8")) if body else {})

        if self.unavailable:
            status, payload = 503, {"detail": "Shannon endpoint unavailable"}
        else:
            response = await self._handle(self.request_log[-1])
            if response.get("__notification__"):
                status, payload = 202, {}
            else:
                status, payload = 200, response

        encoded = json.dumps(payload).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(encoded)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": encoded})
