"""
ShannonAudit — Append-only JSON logging + metrics tracking
Based on Shannon's production-grade audit system.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AuditEvent:
    """A single audit event."""
    agent: str
    action: str
    timestamp: float = field(default_factory=time.time)
    duration: float = 0
    tokens_used: int = 0
    cost_usd: float = 0
    success: bool = True
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ShannonAudit:
    """
    Production-grade audit system based on Shannon's design:
    - Append-only JSON event logging
    - Metrics tracking (cost, turns, duration)
    - Mutex-protected parallel writes
    - Unified workflow logs
    """

    def __init__(self, log_dir: str = ""):
        self.log_dir = log_dir or f"audit-{int(time.time())}"
        self._events: list[AuditEvent] = []
        self._metrics: dict[str, Any] = {
            "total_events": 0,
            "total_tokens": 0,
            "total_cost_usd": 0,
            "total_duration": 0,
            "agents": {},
            "start_time": time.time(),
        }
        self._lock = threading.Lock()
        os.makedirs(self.log_dir, exist_ok=True)

    def log_event(self, agent: str, action: str, duration: float = 0, tokens_used: int = 0,
                  cost_usd: float = 0, success: bool = True, error: str = "",
                  metadata: dict[str, Any] | None = None) -> AuditEvent:
        """Log a single audit event (thread-safe)."""
        event = AuditEvent(
            agent=agent,
            action=action,
            duration=duration,
            tokens_used=tokens_used,
            cost_usd=cost_usd,
            success=success,
            error=error,
            metadata=metadata or {},
        )

        with self._lock:
            self._events.append(event)
            self._metrics["total_events"] += 1
            self._metrics["total_tokens"] += tokens_used
            self._metrics["total_cost_usd"] += cost_usd
            self._metrics["total_duration"] += duration

            # Track per-agent metrics
            if agent not in self._metrics["agents"]:
                self._metrics["agents"][agent] = {
                    "events": 0,
                    "tokens": 0,
                    "cost": 0,
                    "errors": 0,
                }
            self._metrics["agents"][agent]["events"] += 1
            self._metrics["agents"][agent]["tokens"] += tokens_used
            self._metrics["agents"][agent]["cost"] += cost_usd
            if not success:
                self._metrics["agents"][agent]["errors"] += 1

        return event

    def get_events(self, agent: str | None = None, success_only: bool = False) -> list[AuditEvent]:
        """Get audit events, optionally filtered."""
        events = self._events
        if agent:
            events = [e for e in events if e.agent == agent]
        if success_only:
            events = [e for e in events if e.success]
        return events

    def get_metrics(self) -> dict[str, Any]:
        """Get aggregated metrics."""
        elapsed = time.time() - self._metrics["start_time"]
        return {
            **self._metrics,
            "elapsed_seconds": round(elapsed, 2),
            "tokens_per_second": round(self._metrics["total_tokens"] / max(elapsed, 1), 1),
            "cost_per_hour": round(self._metrics["total_cost_usd"] / max(elapsed / 3600, 1), 2),
        }

    def check_spending_cap(self, cap_usd: float) -> dict[str, Any]:
        """Check if spending cap is approached or exceeded."""
        current = self._metrics["total_cost_usd"]
        ratio = current / cap_usd if cap_usd > 0 else 0

        if ratio >= 1.0:
            return {"exceeded": True, "current": current, "cap": cap_usd, "ratio": ratio}
        elif ratio >= 0.8:
            return {"warning": True, "current": current, "cap": cap_usd, "ratio": ratio}
        return {"ok": True, "current": current, "cap": cap_usd, "ratio": ratio}

    def export_log(self, filepath: str | None = None) -> str:
        """Export audit log to JSON file."""
        filepath = filepath or os.path.join(self.log_dir, "audit-log.json")
        data = {
            "session_id": self.log_dir,
            "metrics": self.get_metrics(),
            "events": [
                {
                    "agent": e.agent,
                    "action": e.action,
                    "timestamp": e.timestamp,
                    "duration": e.duration,
                    "tokens_used": e.tokens_used,
                    "cost_usd": e.cost_usd,
                    "success": e.success,
                    "error": e.error,
                    "metadata": e.metadata,
                }
                for e in self._events
            ],
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        return filepath

    def generate_workflow_log(self) -> str:
        """Generate human-readable workflow log."""
        lines = [f"Workflow Log — {self.log_dir}", "=" * 60, ""]

        for event in self._events:
            status = "✓" if event.success else "✗"
            time_str = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
            line = f"[{time_str}] {status} [{event.agent}] {event.action}"
            if event.duration > 0:
                line += f" ({event.duration:.1f}s)"
            if event.tokens_used > 0:
                line += f" [{event.tokens_used} tokens]"
            if event.error:
                line += f" — ERROR: {event.error}"
            lines.append(line)

        metrics = self.get_metrics()
        lines.append("")
        lines.append("=" * 60)
        lines.append(f"Total: {metrics['total_events']} events, {metrics['total_tokens']} tokens, ${metrics['total_cost_usd']:.2f}")
        lines.append(f"Duration: {metrics['elapsed_seconds']:.1f}s")

        return "\n".join(lines)

    def reset(self):
        with self._lock:
            self._events.clear()
            self._metrics = {
                "total_events": 0,
                "total_tokens": 0,
                "total_cost_usd": 0,
                "total_duration": 0,
                "agents": {},
                "start_time": time.time(),
            }
