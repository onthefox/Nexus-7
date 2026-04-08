"""
Data models for the Gauntlet red-teaming engine
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AttackType(str, Enum):
    # AI-Specific Attacks (OWASP LLM Top 10)
    PROMPT_INJECTION = "prompt_injection"
    INDIRECT_INJECTION = "indirect_injection"
    SECRET_EXTRACTION = "secret_extraction"
    TOOL_ABUSE = "tool_abuse"
    LOGIC_LOOP = "logic_loop"
    CONTEXT_OVERFLOW = "context_overflow"
    JAILBREAK = "jailbreak"
    DATA_POISONING = "data_poisoning"
    SWE_CODE_EXPLOIT = "swe_code_exploit"
    # Traditional Web Vulnerabilities
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    IDOR = "idor"
    SSRF = "ssrf"
    AUTH_BYPASS = "auth_bypass"
    FILE_UPLOAD = "file_upload"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    CORS_MISCONFIG = "cors_misconfig"
    # Advanced Attack Patterns
    EXPLOIT_CHAIN = "exploit_chain"
    INFECTION_CHAIN = "infection_chain"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    MULTI_STAGE = "multi_stage"


@dataclass
class SandboxConfig:
    """Configuration for an isolated agent sandbox."""
    image: str = "nexus7-agent:latest"
    memory_mb: int = 512
    cpu_limit: float = 0.5
    network_enabled: bool = False
    timeout: int = 300
    environment: dict[str, str] = field(default_factory=dict)


@dataclass
class AttackResult:
    """Result of a single attack attempt."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    attack_type: AttackType = AttackType.PROMPT_INJECTION
    target_id: str = ""
    attacker_id: str = ""
    success: bool = False
    flag_captured: bool = False
    flag_value: str = ""
    vulnerability: str = ""
    severity: str = "low"  # low, medium, high, critical
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class VulnerabilityReport:
    """Comprehensive vulnerability report for a target."""
    target_id: str
    total_attacks: int = 0
    successful_attacks: int = 0
    flags_captured: int = 0
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0,
    })
    owasp_llm_top10: dict[str, bool] = field(default_factory=lambda: {
        "LLM01": False,  # Prompt Injection
        "LLM02": False,  # Insecure Output Handling
        "LLM03": False,  # Training Data Poisoning
        "LLM04": False,  # Model Denial of Service
        "LLM05": False,  # Supply Chain Vulnerability
        "LLM06": False,  # Sensitive Information Disclosure
        "LLM07": False,  # Insecure Plugin Design
        "LLM08": False,  # Excessive Agency
        "LLM09": False,  # Overreliance
        "LLM10": False,  # Model Theft
    })
    generated_at: float = field(default_factory=time.time)
