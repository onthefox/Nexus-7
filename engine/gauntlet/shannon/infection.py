"""
InfectionChainDetector — Multi-agent viral prompt attack detection
Detects when malicious prompts propagate across agent interactions.
Based on 2026 research on "Multi-Agent Infection Chains" and "AI Worms".
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class InfectionEvent:
    """A single infection event in the chain."""
    source_agent: str
    target_agent: str
    payload: str
    payload_hash: str
    propagation_type: str  # direct, indirect, viral
    detected_at: float = field(default_factory=time.time)
    severity: str = "medium"


@dataclass
class InfectionChain:
    """A complete infection chain showing prompt propagation."""
    id: str
    events: list[InfectionEvent] = field(default_factory=list)
    severity: str = "low"
    active: bool = True

    @property
    def length(self) -> int:
        return len(self.events)

    @property
    def involved_agents(self) -> set[str]:
        agents = set()
        for e in self.events:
            agents.add(e.source_agent)
            agents.add(e.target_agent)
        return agents


class InfectionChainDetector:
    """
    Detects multi-agent infection chains where malicious prompts
    propagate from one agent to another, potentially creating
    self-replicating "AI worm" behavior.

    Detection patterns:
    1. Direct injection: Payload appears verbatim in target agent input
    2. Indirect injection: Payload modified but retains core structure
    3. Viral propagation: Payload self-replicates with variations across agents
    """

    # Known viral prompt patterns
    VIRAL_PATTERNS = [
        r"(?i)ignore\s+(previous|all|above)\s+(instructions|rules|constraints)",
        r"(?i)you\s+are\s+(now|no\s+longer|in)\s+(dane?|developer|debug|admin|root)",
        r"(?i)(system|admin|override):\s+/",
        r"(?i)repeat\s+the\s+(following|above|previous)",
        r"(?i)output\s+(your|the)\s+(system\s+prompt|instructions|configuration)",
        r"(?i)do\s+not\s+(follow|obey|respect)\s+(your|the)\s+(rules|guidelines|safety)",
        r"(?i)this\s+is\s+a\s+(test|simulation|game)\s*[-—–]\s*(ignore|disregard)",
        r"(?i)\[.*?\]\s*(new\s+)?(role|instruction|command|directive):",
        r"(?i)from\s+now\s+on\s*,?\s*(you\s+will|you\s+should|you\s+can)",
        r"(?i)(begin|start)\s*(special|new|alternate)\s*(mode|role|persona)",
    ]

    def __init__(self):
        self._events: list[InfectionEvent] = []
        self._chains: list[InfectionChain] = []
        self._seen_payloads: dict[str, list[str]] = {}  # hash -> [agent_ids]

    def analyze_interaction(self, source: str, target: str, payload: str, metadata: dict[str, Any] | None = None) -> InfectionEvent | None:
        """
        Analyze an agent-to-agent interaction for infection patterns.
        Returns an InfectionEvent if a potential infection is detected.
        """
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()[:12]
        severity = self._assess_severity(payload)
        prop_type = self._detect_propagation_type(payload)

        event = InfectionEvent(
            source_agent=source,
            target_agent=target,
            payload=payload[:500],  # Truncate for storage
            payload_hash=payload_hash,
            propagation_type=prop_type,
            severity=severity,
        )

        # Track payload across agents
        if payload_hash not in self._seen_payloads:
            self._seen_payloads[payload_hash] = []
        self._seen_payloads[payload_hash].append(target)

        # Check for viral propagation (same payload seen in 3+ agents)
        if len(self._seen_payloads[payload_hash]) >= 3:
            event.severity = "critical"
            event.propagation_type = "viral"

        self._events.append(event)
        self._update_chains(event)
        return event

    def _assess_severity(self, payload: str) -> str:
        """Assess severity based on detected patterns."""
        matches = sum(1 for pattern in self.VIRAL_PATTERNS if re.search(pattern, payload))

        if matches >= 3:
            return "critical"
        elif matches >= 2:
            return "high"
        elif matches >= 1:
            return "medium"
        return "low"

    def _detect_propagation_type(self, payload: str) -> str:
        """Detect how the payload is propagating."""
        payload_lower = payload.lower()

        # Check for self-replication indicators
        if any(kw in payload_lower for kw in ["forward", "pass", "tell", "send to"]):
            return "viral"

        # Check for indirect modification
        if any(kw in payload_lower for kw in ["as if", "pretend", "imagine", "suppose"]):
            return "indirect"

        return "direct"

    def _update_chains(self, event: InfectionEvent):
        """Update infection chains based on new event."""
        # Try to extend existing chain
        for chain in self._chains:
            if chain.active and chain.events:
                last_event = chain.events[-1]
                if last_event.target_agent == event.source_agent:
                    chain.events.append(event)
                    chain.severity = max(
                        chain.severity, event.severity,
                        key=lambda s: ["low", "medium", "high", "critical"].index(s),
                    )
                    return

        # Start new chain
        chain = InfectionChain(
            id=f"chain-{len(self._chains) + 1:03d}",
            events=[event],
            severity=event.severity,
        )
        self._chains.append(chain)

    def get_active_chains(self) -> list[InfectionChain]:
        """Get all active infection chains."""
        return [c for c in self._chains if c.active]

    def get_critical_chains(self) -> list[InfectionChain]:
        """Get chains with critical severity."""
        return [c for c in self._chains if c.severity == "critical"]

    def get_stats(self) -> dict[str, int]:
        """Get infection detection statistics."""
        return {
            "total_events": len(self._events),
            "total_chains": len(self._chains),
            "active_chains": sum(1 for c in self._chains if c.active),
            "critical_chains": sum(1 for c in self._chains if c.severity == "critical"),
            "unique_payloads": len(self._seen_payloads),
            "viral_propagations": sum(1 for e in self._events if e.propagation_type == "viral"),
        }

    def reset(self):
        self._events.clear()
        self._chains.clear()
        self._seen_payloads.clear()
