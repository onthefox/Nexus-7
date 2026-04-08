"""
NexusOrchestrator — Multi-Agent Coordination Engine
Handles agent lifecycle, task dispatch, and protocol adapters.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from .models import (
    AgentConfig,
    AgentState,
    AgentStatus,
    Task,
    TaskPriority,
    TaskResult,
    ProtocolType,
)


class NexusOrchestrator:
    """
    Central orchestrator for multi-agent coordination.
    Manages agent registration, task dispatch, health monitoring,
    and protocol translation between MCP, A2A, and Chat.
    """

    def __init__(self):
        self._agents: dict[str, AgentStatus] = {}
        self._task_queue: list[Task] = []
        self._task_results: dict[str, list[TaskResult]] = {}
        self._running = False

    # ── Agent Management ──────────────────────────────────────────────

    def register_agent(self, config: AgentConfig | dict) -> str:
        """Register a new agent and return its ID."""
        if isinstance(config, dict):
            config = AgentConfig(**config)

        agent_id = f"agent-{len(self._agents) + 1:04d}"
        status = AgentStatus(agent_id=agent_id, config=config)
        self._agents[agent_id] = status
        return agent_id

    def get_agent_status(self, agent_id: str) -> AgentStatus | None:
        """Get current status of an agent."""
        return self._agents.get(agent_id)

    def list_agents(self, state: AgentState | None = None) -> list[AgentStatus]:
        """List all registered agents, optionally filtered by state."""
        agents = list(self._agents.values())
        if state:
            agents = [a for a in agents if a.state == state]
        return agents

    def update_agent_state(self, agent_id: str, state: AgentState) -> bool:
        """Update an agent's runtime state."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.state = state
        agent.last_seen = time.time()
        return True

    def shutdown_agent(self, agent_id: str) -> bool:
        """Terminate and remove an agent."""
        if agent_id not in self._agents:
            return False
        self._agents[agent_id].state = AgentState.TERMINATED
        del self._agents[agent_id]
        return True

    def health_check(self) -> dict[str, float]:
        """Run health check on all agents, return health scores."""
        results = {}
        for agent_id, agent in self._agents.items():
            # Simple health: degrade if not seen recently
            age = time.time() - agent.last_seen
            if age > 300:  # 5 minutes
                agent.health = max(0, agent.health - 0.1)
            else:
                agent.health = min(1.0, agent.health + 0.05)
            results[agent_id] = agent.health
        return results

    # ── Task Dispatch ─────────────────────────────────────────────────

    def create_task(
        self,
        description: str,
        payload: dict[str, Any] | None = None,
        priority: TaskPriority | int = TaskPriority.NORMAL,
        assigned_agents: list[str] | None = None,
        timeout: int = 120,
    ) -> Task:
        """Create a new task."""
        if isinstance(priority, int):
            priority = TaskPriority(priority)

        task = Task(
            description=description,
            payload=payload or {},
            priority=priority,
            assigned_agents=assigned_agents or [],
            timeout=timeout,
        )
        # Insert in priority order
        self._task_queue.append(task)
        self._task_queue.sort(key=lambda t: t.priority.value, reverse=True)
        self._task_results[task.id] = []
        return task

    async def dispatch_task(self, task: Task) -> list[TaskResult]:
        """
        Dispatch a task to assigned agents.
        In production, this would make actual API calls to agent endpoints.
        For now, returns stub results.
        """
        start = time.time()
        results = []

        for agent_id in task.assigned_agents:
            agent = self._agents.get(agent_id)
            if not agent or agent.state == AgentState.TERMINATED:
                results.append(TaskResult(
                    task_id=task.id,
                    agent_id=agent_id,
                    success=False,
                    error="Agent not available",
                ))
                continue

            agent.state = AgentState.RUNNING
            # Stub: in production, call agent endpoint
            result = TaskResult(
                task_id=task.id,
                agent_id=agent_id,
                success=True,
                output={"status": "completed", "protocol": agent.config.protocol.value},
                tokens_used=0,
                duration=time.time() - start,
            )
            agent.state = AgentState.IDLE
            agent.tasks_completed += 1
            agent.last_seen = time.time()
            results.append(result)

        self._task_results[task.id] = results
        return results

    def get_task_results(self, task_id: str) -> list[TaskResult]:
        """Get results for a task."""
        return self._task_results.get(task_id, [])

    def list_tasks(self) -> list[Task]:
        """List all pending tasks."""
        return list(self._task_queue)

    # ── Protocol Adapter ──────────────────────────────────────────────

    def translate_protocol(
        self, message: dict[str, Any], from_proto: ProtocolType, to_proto: ProtocolType
    ) -> dict[str, Any]:
        """
        Translate a message between protocols.
        MCP ↔ A2A ↔ Chat
        """
        if from_proto == to_proto:
            return message

        # Stub: real implementation would do proper protocol translation
        return {
            **message,
            "_translated_from": from_proto.value,
            "_translated_to": to_proto.value,
        }

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def start(self):
        """Start the orchestrator background loop."""
        self._running = True
        while self._running:
            await asyncio.sleep(1)
            self.health_check()

    async def stop(self):
        """Stop the orchestrator."""
        self._running = False

    def reset(self):
        """Reset all state."""
        self._agents.clear()
        self._task_queue.clear()
        self._task_results.clear()
