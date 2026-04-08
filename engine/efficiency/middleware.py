"""
EfficiencyMiddleware — Token Optimization and Schema Enforcement
PruMerge-style prompt pruning, JSON schema validation, token budget tracking.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from .models import Message, SchemaValidationResult, TokenRecord


class EfficiencyMiddleware:
    """
    Middleware for optimizing token usage and enforcing schemas.
    Implements:
    - Context window pruning (remove redundant/irrelevant messages)
    - Token budget enforcement
    - JSON schema validation for agent responses
    - Latency SLA monitoring
    """

    def __init__(self, default_max_tokens: int = 4096):
        self._default_max_tokens = default_max_tokens
        self._token_records: dict[str, list[TokenRecord]] = {}
        self._budgets: dict[str, int] = {}
        self._latency_slas: dict[str, float] = {}

    # ── Context Pruning (PruMerge-style) ─────────────────────────────

    def prune_context(
        self,
        messages: list[Message],
        max_tokens: int | None = None,
        strategy: str = "truncate",  # truncate, summarize, selective
    ) -> list[Message]:
        """
        Prune message history to fit within token budget.
        Strategies:
        - truncate: keep most recent messages
        - selective: keep system + recent, drop middle
        - summarize: replace old messages with summary (stub)
        """
        limit = max_tokens or self._default_max_tokens
        # Estimate: ~4 chars per token
        max_chars = limit * 4

        total_chars = sum(len(m.content) for m in messages)
        if total_chars <= max_chars:
            return messages

        if strategy == "truncate":
            return self._truncate(messages, max_chars)
        elif strategy == "selective":
            return self._selective_keep(messages, max_chars)
        else:
            return self._truncate(messages, max_chars)

    def _truncate(self, messages: list[Message], max_chars: int) -> list[Message]:
        """Keep most recent messages that fit."""
        result = []
        chars = 0
        for msg in reversed(messages):
            if chars + len(msg.content) > max_chars:
                break
            result.append(msg)
            chars += len(msg.content)
        return list(reversed(result))

    def _selective_keep(self, messages: list[Message], max_chars: int) -> list[Message]:
        """Keep system messages + most recent, drop middle."""
        system_msgs = [m for m in messages if m.role == "system"]
        non_system = [m for m in messages if m.role != "system"]

        # Reserve space for system messages
        system_chars = sum(len(m.content) for m in system_msgs)
        remaining = max(0, max_chars - system_chars)

        # Keep most recent non-system messages
        recent = self._truncate(non_system, remaining)
        return system_msgs + recent

    # ── Schema Validation ────────────────────────────────────────────

    def validate_response(
        self, response: dict[str, Any], schema: dict[str, Any] | None = None
    ) -> SchemaValidationResult:
        """
        Validate agent response against a JSON schema.
        Uses basic type checking (no jsonschema dependency for MVP).
        """
        if schema is None:
            return SchemaValidationResult(valid=True)

        errors = []
        required = schema.get("required", [])
        properties = schema.get("properties", {})

        # Check required fields
        for field in required:
            if field not in response:
                errors.append(f"Missing required field: {field}")

        # Check types
        for field, value in response.items():
            if field in properties:
                expected_type = properties[field].get("type")
                if expected_type and not self._check_type(value, expected_type):
                    errors.append(
                        f"Field '{field}' expected type '{expected_type}', "
                        f"got '{type(value).__name__}'"
                    )

        return SchemaValidationResult(valid=len(errors) == 0, errors=errors)

    def _check_type(self, value: Any, expected: str) -> bool:
        """Basic type check."""
        type_map = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "array": list,
            "object": dict,
        }
        expected_types = type_map.get(expected)
        if expected_types is None:
            return True
        return isinstance(value, expected_types)

    # ── Token Budget Tracking ────────────────────────────────────────

    def track_token_usage(self, agent_id: str, tokens: int) -> TokenRecord:
        """Record token usage for an agent."""
        budget = self._budgets.get(agent_id, self._default_max_tokens)
        record = TokenRecord(
            agent_id=agent_id,
            tokens_used=tokens,
            tokens_budget=budget,
        )
        if agent_id not in self._token_records:
            self._token_records[agent_id] = []
        self._token_records[agent_id].append(record)
        return record

    def set_budget(self, agent_id: str, budget: int):
        """Set token budget for an agent."""
        self._budgets[agent_id] = budget

    def enforce_budget(self, agent_id: str, tokens: int) -> bool:
        """Check if adding more tokens would exceed budget."""
        budget = self._budgets.get(agent_id, self._default_max_tokens)
        records = self._token_records.get(agent_id, [])
        total_used = sum(r.tokens_used for r in records)
        return (total_used + tokens) <= budget

    def get_token_usage(self, agent_id: str) -> list[TokenRecord]:
        return list(self._token_records.get(agent_id, []))

    # ── Latency SLA ──────────────────────────────────────────────────

    def set_latency_sla(self, agent_id: str, max_latency: float):
        """Set maximum allowed latency (seconds) for an agent."""
        self._latency_slas[agent_id] = max_latency

    def check_latency(self, agent_id: str, latency: float) -> bool:
        """Check if latency is within SLA."""
        sla = self._latency_slas.get(agent_id, float("inf"))
        return latency <= sla

    def reset(self):
        self._token_records.clear()
        self._budgets.clear()
        self._latency_slas.clear()
