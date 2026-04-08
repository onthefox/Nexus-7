"""
Data models for the Nexus Orchestrator
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProtocolType(str, Enum):
    MCP = "mcp"  # Model Context Protocol
    A2A = "a2a"  # Agent-to-Agent
    CHAT = "chat"  # Human-to-Agent chat


class AgentState(str, Enum):
    REGISTERED = "registered"
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"
    TERMINATED = "terminated"


class TaskPriority(int, Enum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class AgentConfig:
    """Configuration for registering an agent."""
    name: str
    protocol: ProtocolType = ProtocolType.MCP
    endpoint: str = ""
    capabilities: list[str] = field(default_factory=list)
    max_tokens: int = 4096
    timeout: int = 120
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentStatus:
    """Runtime status of a registered agent."""
    agent_id: str
    config: AgentConfig
    state: AgentState = AgentState.REGISTERED
    health: float = 1.0  # 0.0 - 1.0
    tasks_completed: int = 0
    tasks_failed: int = 0
    last_seen: float = field(default_factory=time.time)
    token_usage: int = 0


@dataclass
class Task:
    """A task to be dispatched to agents."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    description: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    assigned_agents: list[str] = field(default_factory=list)
    timeout: int = 120
    created_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskResult:
    """Result from task execution."""
    task_id: str
    agent_id: str
    success: bool
    output: Any = None
    error: str = ""
    tokens_used: int = 0
    duration: float = 0
    timestamp: float = field(default_factory=time.time)
