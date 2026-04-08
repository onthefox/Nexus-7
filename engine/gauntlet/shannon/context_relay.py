"""
ContextRelay — Long-running session state management
Maintains context across extended pentest trajectories.
Based on NDSS 2026 paper: "Context Relay for Long-Running Penetration-Testing Agents"
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ContextSnapshot:
    """A point-in-time snapshot of the pentest session state."""
    id: str
    phase: str
    summary: str
    key_findings: list[str] = field(default_factory=list)
    active_targets: list[str] = field(default_factory=list)
    token_count: int = 0
    created_at: float = field(default_factory=time.time)
    hash: str = ""

    def __post_init__(self):
        if not self.hash:
            data = json.dumps({
                "phase": self.phase,
                "summary": self.summary,
                "findings": self.key_findings,
                "targets": self.active_targets,
            }, sort_keys=True)
            self.hash = hashlib.sha256(data.encode()).hexdigest()[:16]


class ContextRelay:
    """
    Maintains context for long-running pentest sessions.
    Solves the context window problem by:
    1. Creating compact snapshots at phase boundaries
    2. Compressing old context into summaries
    3. Relaying only relevant context to new agents
    4. Maintaining a verifiable chain of snapshots
    """

    MAX_CONTEXT_TOKENS = 8000  # Maximum context window
    SNAPSHOT_COMPRESSION_RATIO = 0.1  # Compress to 10% of original

    def __init__(self, session_id: str = ""):
        self.session_id = session_id or f"session-{int(time.time())}"
        self._snapshots: list[ContextSnapshot] = []
        self._chain_hash = "0" * 16  # Genesis
        self._current_context: dict[str, Any] = {}
        self._total_tokens = 0

    def create_snapshot(self, phase: str, summary: str, findings: list[str] | None = None, targets: list[str] | None = None) -> ContextSnapshot:
        """Create a context snapshot at a phase boundary."""
        snapshot = ContextSnapshot(
            id=f"snapshot-{len(self._snapshots) + 1:03d}",
            phase=phase,
            summary=summary,
            key_findings=findings or [],
            active_targets=targets or [],
            token_count=self._estimate_tokens(summary) + sum(self._estimate_tokens(f) for f in (findings or [])),
        )

        # Chain to previous snapshot
        data = f"{snapshot.hash}:{self._chain_hash}"
        self._chain_hash = hashlib.sha256(data.encode()).hexdigest()[:16]

        self._snapshots.append(snapshot)
        self._total_tokens += snapshot.token_count
        return snapshot

    def get_relay_context(self, max_snapshots: int = 3) -> dict[str, Any]:
        """
        Get the most relevant context for a new agent.
        Returns compressed summaries of old snapshots + full recent snapshots.
        """
        if not self._snapshots:
            return {"session_id": self.session_id, "phase": "unknown", "summary": "No context available"}

        # Get most recent snapshots (full)
        recent = self._snapshots[-max_snapshots:]

        # Compress older snapshots into summaries
        older = self._snapshots[:-max_snapshots] if len(self._snapshots) > max_snapshots else []
        compressed_summary = self._compress_snapshots(older)

        latest = recent[-1] if recent else self._snapshots[-1]

        return {
            "session_id": self.session_id,
            "current_phase": latest.phase,
            "chain_hash": self._chain_hash,
            "total_snapshots": len(self._snapshots),
            "total_tokens": self._total_tokens,
            "recent_context": [
                {
                    "id": s.id,
                    "phase": s.phase,
                    "summary": s.summary,
                    "findings": s.key_findings,
                    "hash": s.hash,
                }
                for s in recent
            ],
            "compressed_history": compressed_summary,
            "active_targets": latest.active_targets,
        }

    def _compress_snapshots(self, snapshots: list[ContextSnapshot]) -> str:
        """Compress multiple snapshots into a single summary."""
        if not snapshots:
            return "No prior history."

        phases = [s.phase for s in snapshots]
        finding_count = sum(len(s.key_findings) for s in snapshots)

        return (
            f"Prior session: {len(snapshots)} snapshots across phases [{', '.join(phases)}]. "
            f"{finding_count} findings discovered. "
            f"Key targets: {', '.join(set(t for s in snapshots for t in s.active_targets)) or 'none'}."
        )

    def verify_chain(self) -> bool:
        """Verify the integrity of the snapshot chain."""
        if len(self._snapshots) < 2:
            return True
        current_hash = "0" * 16
        for snapshot in self._snapshots:
            expected = hashlib.sha256(f"{snapshot.hash}:{current_hash}".encode()).hexdigest()[:16]
            current_hash = expected
        return current_hash == self._chain_hash

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count (rough: ~4 chars per token)."""
        return len(text) // 4

    def get_snapshot_count(self) -> int:
        return len(self._snapshots)

    def get_total_tokens(self) -> int:
        return self._total_tokens

    def get_latest_snapshot(self) -> ContextSnapshot | None:
        return self._snapshots[-1] if self._snapshots else None

    def reset(self):
        self._snapshots.clear()
        self._chain_hash = "0" * 16
        self._current_context.clear()
        self._total_tokens = 0
