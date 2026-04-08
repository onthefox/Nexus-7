"""
Data models for the Ledger
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DID:
    """Decentralized Identity for an agent."""
    agent_id: str
    did: str  # e.g., did:nexus7:abc123
    public_key: str
    created_at: float = field(default_factory=time.time)


@dataclass
class InteractionLog:
    """Immutable log of an agent interaction."""
    id: str
    source_agent: str
    target_agent: str
    action: str
    result: str
    hash: str  # cryptographic hash for immutability
    timestamp: float = field(default_factory=time.time)


@dataclass
class ReputationToken:
    """Blockchain-backed reputation token."""
    agent_id: str
    token_id: str
    score: int
    minted_at: float = field(default_factory=time.time)
    expires_at: float | None = None
