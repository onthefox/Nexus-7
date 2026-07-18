"""
NexusOrchestrator — Multi-Agent Coordination Engine

This module provides the central orchestrator for multi-agent coordination,
handling agent lifecycle management, task dispatch, health monitoring,
and protocol translation between MCP, A2A, and Chat protocols.
"""

from __future__ import annotations

import asyncio
import logging
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
    sanitize_input,
)

logger = logging.getLogger(__name__)


class OrchestratorError(Exception):
    """Base exception for orchestrator errors."""
    pass


class AgentNotFoundError(OrchestratorError):
    """Raised when an agent is not found."""
    pass


class TaskDispatchError(OrchestratorError):
    """Raised when task dispatch fails."""
    pass


class NexusOrchestrator:
    """
    Central orchestrator for multi-agent coordination.
    
    Manages agent registration, task dispatch, health monitoring,
    and protocol translation between MCP, A2A, and Chat.
    
    Attributes:
        _agents: Dictionary mapping agent IDs to their status
        _task_queue: List of pending tasks sorted by priority
        _task_results: Dictionary mapping task IDs to their results
        _running: Flag indicating if orchestrator is running
    """

    def __init__(self) -> None:
        """Initialize the orchestrator with empty state."""
        self._agents: dict[str, AgentStatus] = {}
        self._task_queue: list[Task] = []
        self._task_results: dict[str, list[TaskResult]] = {}
        self._running = False

    # ── Agent Management ──────────────────────────────────────────────

    def register_agent(self, config: AgentConfig | dict) -> str:
        """
        Register a new agent and return its ID.
        
        Args:
            config: Agent configuration object or dictionary
            
        Returns:
            Unique agent identifier string
            
        Raises:
            ValueError: If config is invalid
        """
        if isinstance(config, dict):
            # Sanitize string inputs before creating AgentConfig
            if 'name' in config:
                config['name'] = sanitize_input(str(config.get('name', '')), max_length=64)
            if 'endpoint' in config:
                config['endpoint'] = sanitize_input(str(config.get('endpoint', '')), max_length=500)
            try:
                config = AgentConfig(**config)
            except (TypeError, KeyError, ValueError) as e:
                logger.error(f"Invalid agent configuration: {e}")
                raise ValueError(f"Invalid agent configuration: {e}")

        agent_id = f"agent-{len(self._agents) + 1:04d}"
        status = AgentStatus(agent_id=agent_id, config=config)
        self._agents[agent_id] = status
        logger.info(f"Registered agent {agent_id} with name '{config.name}'")
        return agent_id

    def get_agent_status(self, agent_id: str) -> AgentStatus | None:
        """
        Get current status of an agent.
        
        Args:
            agent_id: Unique identifier of the agent
            
        Returns:
            AgentStatus object if found, None otherwise
        """
        return self._agents.get(agent_id)

    def list_agents(self, state: AgentState | None = None) -> list[AgentStatus]:
        """
        List all registered agents, optionally filtered by state.
        
        Args:
            state: Optional filter by agent state
            
        Returns:
            List of AgentStatus objects matching the filter
        """
        agents = list(self._agents.values())
        if state:
            agents = [a for a in agents if a.state == state]
        return agents

    def update_agent_state(self, agent_id: str, state: AgentState) -> bool:
        """
        Update an agent's runtime state.
        
        Args:
            agent_id: Unique identifier of the agent
            state: New state to set
            
        Returns:
            True if successful, False if agent not found
        """
        agent = self._agents.get(agent_id)
        if not agent:
            logger.warning(f"Attempted to update state of non-existent agent {agent_id}")
            return False
        agent.state = state
        agent.last_seen = time.time()
        logger.debug(f"Updated agent {agent_id} state to {state.value}")
        return True

    def shutdown_agent(self, agent_id: str) -> bool:
        """
        Terminate and remove an agent.
        
        Args:
            agent_id: Unique identifier of the agent
            
        Returns:
            True if successful, False if agent not found
        """
        if agent_id not in self._agents:
            logger.warning(f"Attempted to shutdown non-existent agent {agent_id}")
            return False
        self._agents[agent_id].state = AgentState.TERMINATED
        del self._agents[agent_id]
        logger.info(f"Shutdown agent {agent_id}")
        return True

    def health_check(self) -> dict[str, float]:
        """
        Run health check on all agents, return health scores.
        
        Returns:
            Dictionary mapping agent IDs to health scores (0.0-1.0)
        """
        results = {}
        for agent_id, agent in self._agents.items():
            # Simple health: degrade if not seen recently
            age = time.time() - agent.last_seen
            if age > 300:  # 5 minutes
                agent.health = max(0, agent.health - 0.1)
                logger.debug(f"Agent {agent_id} health degraded due to inactivity")
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
        """
        Create a new task.
        
        Args:
            description: Human-readable task description
            payload: Task-specific data payload
            priority: Task priority level or integer value
            assigned_agents: List of agent IDs to assign
            timeout: Task timeout in seconds
            
        Returns:
            Created Task object
        """
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
        logger.info(f"Created task {task.id} with priority {priority.name}")
        return task

    async def dispatch_task(self, task: Task) -> list[TaskResult]:
        """
        Dispatch a task to assigned agents.
        
        In production, this would make actual API calls to agent endpoints.
        For now, returns stub results.
        
        Args:
            task: Task object to dispatch
            
        Returns:
            List of TaskResult objects from each agent
        """
        start = time.time()
        results = []

        for agent_id in task.assigned_agents:
            agent = self._agents.get(agent_id)
            if not agent or agent.state == AgentState.TERMINATED:
                logger.warning(f"Agent {agent_id} not available for task {task.id}")
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
        logger.info(f"Dispatched task {task.id} to {len(results)} agents")
        return results

    def get_task_results(self, task_id: str) -> list[TaskResult]:
        """
        Get results for a task.
        
        Args:
            task_id: ID of the task
            
        Returns:
            List of TaskResult objects, empty list if not found
        """
        return self._task_results.get(task_id, [])

    def list_tasks(self) -> list[Task]:
        """
        List all pending tasks.
        
        Returns:
            List of pending Task objects
        """
        return list(self._task_queue)

    # ── Protocol Adapter ──────────────────────────────────────────────

    def translate_protocol(
        self, message: dict[str, Any], from_proto: ProtocolType, to_proto: ProtocolType
    ) -> dict[str, Any]:
        """
        Translate a message between protocols.
        
        Args:
            message: Message dictionary to translate
            from_proto: Source protocol type
            to_proto: Target protocol type
            
        Returns:
            Translated message dictionary
        """
        if from_proto == to_proto:
            return message

        # Stub: real implementation would do proper protocol translation
        logger.debug(f"Translating message from {from_proto.value} to {to_proto.value}")
        return {
            **message,
            "_translated_from": from_proto.value,
            "_translated_to": to_proto.value,
        }

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the orchestrator background loop."""
        self._running = True
        logger.info("Orchestrator started")
        while self._running:
            await asyncio.sleep(1)
            self.health_check()

    async def stop(self) -> None:
        """Stop the orchestrator."""
        self._running = False
        logger.info("Orchestrator stopped")

    def reset(self) -> None:
        """Reset all state."""
        self._agents.clear()
        self._task_queue.clear()
        self._task_results.clear()
        logger.info("Orchestrator state reset")
