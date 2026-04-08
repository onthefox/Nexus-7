"""
NexusLedger — Blockchain-Backed Identity and Reputation Layer
Provides DIDs, reputation tokens, and immutable audit logging.
Uses hashlib + secrets for cryptographic primitives (libsodium-ready).
"""

from __future__ import annotations

import hashlib
import secrets
import time
from typing import Any

from .models import DID, InteractionLog, ReputationToken


class NexusLedger:
    """
    Append-only ledger for agent identities, reputation, and interactions.
    In MVP: in-memory with cryptographic hashing.
    Future: integrate with actual blockchain (Ethereum, Solana).
    """

    def __init__(self):
        self._dids: dict[str, DID] = {}
        self._reputation: dict[str, list[ReputationToken]] = {}
        self._logs: list[InteractionLog] = []
        self._chain_hash = "0" * 64  # Genesis block

    # ── Decentralized Identity ────────────────────────────────────────

    def create_did(self, agent_id: str) -> DID:
        """Create a cryptographic DID for an agent."""
        # Generate keypair (stub — use nacl in production)
        private_key = secrets.token_hex(32)
        public_key = hashlib.sha256(private_key.encode()).hexdigest()

        did_value = f"did:nexus7:{agent_id[:8]}-{public_key[:8]}"

        did = DID(
            agent_id=agent_id,
            did=did_value,
            public_key=public_key,
        )
        self._dids[agent_id] = did
        return did

    def get_did(self, agent_id: str) -> DID | None:
        return self._dids.get(agent_id)

    def verify_did(self, agent_id: str, did: str) -> bool:
        """Verify that a DID belongs to an agent."""
        stored = self._dids.get(agent_id)
        return stored is not None and stored.did == did

    # ── Reputation Tokens ────────────────────────────────────────────

    def mint_reputation(self, agent_id: str, score: int) -> ReputationToken:
        """Mint a reputation token for an agent."""
        if agent_id not in self._dids:
            self.create_did(agent_id)

        token_id = f"rep-{secrets.token_hex(8)}"
        token = ReputationToken(
            agent_id=agent_id,
            token_id=token_id,
            score=score,
        )

        if agent_id not in self._reputation:
            self._reputation[agent_id] = []
        self._reputation[agent_id].append(token)
        return token

    def get_agent_reputation(self, agent_id: str) -> int:
        """Get total reputation score for an agent."""
        tokens = self._reputation.get(agent_id, [])
        return sum(t.score for t in tokens)

    def get_reputation_history(self, agent_id: str) -> list[ReputationToken]:
        return list(self._reputation.get(agent_id, []))

    # ── Immutable Audit Log ──────────────────────────────────────────

    def log_interaction(
        self,
        source_agent: str,
        target_agent: str,
        action: str,
        result: str,
        metadata: dict[str, Any] | None = None,
    ) -> InteractionLog:
        """
        Log an interaction with cryptographic chaining.
        Each entry includes a hash of the previous entry (blockchain-style).
        """
        data = f"{source_agent}:{target_agent}:{action}:{result}:{self._chain_hash}"
        entry_hash = hashlib.sha256(data.encode()).hexdigest()

        log = InteractionLog(
            id=f"log-{len(self._logs) + 1:06d}",
            source_agent=source_agent,
            target_agent=target_agent,
            action=action,
            result=result,
            hash=entry_hash,
        )
        self._logs.append(log)
        self._chain_hash = entry_hash  # Update chain
        return log

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire chain."""
        current_hash = "0" * 64
        for log in self._logs:
            data = f"{log.source_agent}:{log.target_agent}:{log.action}:{log.result}:{current_hash}"
            expected = hashlib.sha256(data.encode()).hexdigest()
            if expected != log.hash:
                return False
            current_hash = log.hash
        return True

    def get_logs(self, agent_id: str | None = None, limit: int = 100) -> list[InteractionLog]:
        """Get interaction logs, optionally filtered by agent."""
        logs = self._logs
        if agent_id:
            logs = [
                l for l in logs
                if l.source_agent == agent_id or l.target_agent == agent_id
            ]
        return logs[-limit:]

    # ── Chain State ──────────────────────────────────────────────────

    def get_chain_hash(self) -> str:
        return self._chain_hash

    def get_stats(self) -> dict[str, int]:
        return {
            "dids": len(self._dids),
            "reputation_tokens": sum(len(v) for v in self._reputation.values()),
            "log_entries": len(self._logs),
            "chain_hash": self._chain_hash[:16] + "...",
        }

    def reset(self):
        self._dids.clear()
        self._reputation.clear()
        self._logs.clear()
        self._chain_hash = "0" * 64
