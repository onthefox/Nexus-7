"""
Data models for the Nexus Orchestrator

This module defines the core data structures used throughout the Nexus Orchestrator,
including agent configurations, task definitions, and execution results.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# Agent name validation pattern
AGENT_NAME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{0,63}$')


def sanitize_input(value: str, max_length: int = 1000) -> str:
    """Sanitize string input by removing potentially dangerous characters.
    
    Args:
        value: Input string to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
        
    Raises:
        TypeError: If input is not a string
        
    Example:
        >>> sanitize_input("  hello world  ", max_length=20)
        'hello world'
    """
    if not isinstance(value, str):
        raise TypeError(f"Expected string, got {type(value).__name__}")
    
    # Truncate to max length
    value = value[:max_length]
    
    # Remove null bytes and control characters (except newline and tab)
    value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\t')
    
    return value.strip()


def validate_agent_name(name: str) -> bool:
    """Validate agent name format.
    
    Args:
        name: Agent name to validate
        
    Returns:
        True if valid format, False otherwise
        
    Example:
        >>> validate_agent_name("agent-001")
        True
        >>> validate_agent_name("123agent")
        False
    """
    return bool(AGENT_NAME_PATTERN.match(name))


class ProtocolType(str, Enum):
    """Supported communication protocols for agent interaction."""
    MCP = "mcp"  # Model Context Protocol
    A2A = "a2a"  # Agent-to-Agent
    CHAT = "chat"  # Human-to-Agent chat


class AgentState(str, Enum):
    """Possible runtime states for an agent."""
    REGISTERED = "registered"
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"
    TERMINATED = "terminated"


class TaskPriority(int, Enum):
    """Task priority levels for scheduling."""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class AgentConfig:
    """Configuration for registering an agent.
    
    Attributes:
        name: Human-readable name for the agent
        protocol: Communication protocol to use (default: MCP)
        endpoint: Network endpoint for the agent
        capabilities: List of capability identifiers
        max_tokens: Maximum token budget for the agent
        timeout: Request timeout in seconds
        metadata: Additional configuration metadata
        
    Example:
        >>> config = AgentConfig(name="test-agent", protocol=ProtocolType.MCP)
        >>> config.name
        'test-agent'
        >>> config.max_tokens
        4096
    """
    name: str
    protocol: ProtocolType = ProtocolType.MCP
    endpoint: str = ""
    capabilities: list[str] = field(default_factory=list)
    max_tokens: int = 4096
    timeout: int = 120
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate agent configuration after initialization."""
        if not validate_agent_name(self.name):
            raise ValueError(
                f"Invalid agent name '{self.name}'. "
                "Must start with letter and contain only alphanumeric, underscore, or hyphen."
            )
        if self.endpoint and not isinstance(self.endpoint, str):
            raise ValueError("endpoint must be a string")
        if not isinstance(self.max_tokens, int) or self.max_tokens <= 0:
            raise ValueError("max_tokens must be a positive integer")
        if not isinstance(self.timeout, int) or self.timeout <= 0:
            raise ValueError("timeout must be a positive integer")
        
        # Sanitize strings
        self.name = sanitize_input(self.name, max_length=64)
        self.endpoint = sanitize_input(self.endpoint, max_length=500)


@dataclass
class AgentStatus:
    """Runtime status of a registered agent.
    
    Attributes:
        agent_id: Unique identifier for the agent
        config: Agent configuration
        state: Current runtime state
        health: Health score from 0.0 to 1.0
        tasks_completed: Number of successfully completed tasks
        tasks_failed: Number of failed tasks
        last_seen: Unix timestamp of last activity
        token_usage: Total tokens consumed by this agent
        
    Example:
        >>> from .models import AgentConfig, ProtocolType
        >>> config = AgentConfig(name="test-agent")
        >>> status = AgentStatus(agent_id="agent-001", config=config)
        >>> status.health
        1.0
        >>> status.state.value
        'registered'
    """
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
    """A task to be dispatched to agents.
    
    Attributes:
        id: Unique task identifier
        description: Human-readable task description
        payload: Task-specific data payload
        priority: Task priority level
        assigned_agents: List of agent IDs assigned to this task
        timeout: Task timeout in seconds
        created_at: Unix timestamp when task was created
        metadata: Additional task metadata
        
    Example:
        >>> task = Task(description="Test task", priority=TaskPriority.HIGH)
        >>> task.id is not None
        True
        >>> task.priority.value
        2
    """
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
    """Result from task execution.
    
    Attributes:
        task_id: ID of the executed task
        agent_id: ID of the agent that executed the task
        success: Whether execution was successful
        output: Result output data
        error: Error message if execution failed
        tokens_used: Number of tokens consumed during execution
        duration: Execution duration in seconds
        timestamp: Unix timestamp when result was generated
        
    Example:
        >>> result = TaskResult(task_id="task-001", agent_id="agent-001", success=True)
        >>> result.success
        True
        >>> result.tokens_used
        0
    """
    task_id: str
    agent_id: str
    success: bool
    output: Any = None
    error: str = ""
    tokens_used: int = 0
    duration: float = 0
    timestamp: float = field(default_factory=time.time)
