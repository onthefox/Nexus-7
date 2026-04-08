"""
Data models for the Shannon adapter
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PipelinePhase(str, Enum):
    PREFLIGHT = "preflight"
    PRE_RECON = "pre_recon"
    RECON = "recon"
    VULN_ANALYSIS = "vuln_analysis"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"


class VulnSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ShannonConfig:
    """Configuration for Shannon pentest execution."""
    target_url: str = ""
    repo_path: str = ""
    api_key: str = ""
    model_tier: str = "medium"  # small, medium, large
    max_turns: int = 10000
    max_concurrent_pipelines: int = 5
    timeout: int = 3600  # seconds
    browser_count: int = 5
    enable_tor: bool = False
    enable_sast: bool = True
    enable_dast: bool = True
    spending_cap_usd: float = 100.0


@dataclass
class ShannonVulnerability:
    """A single vulnerability found by Shannon."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: str = ""  # xss, sqli, auth_bypass, etc.
    severity: VulnSeverity = VulnSeverity.MEDIUM
    title: str = ""
    description: str = ""
    location: str = ""  # endpoint or file path
    poc: str = ""  # proof of concept
    remediation: str = ""
    owasp_category: str = ""
    wstg_reference: str = ""
    cvss_score: float = 0.0
    discovered_at: float = field(default_factory=time.time)


@dataclass
class ShannonResult:
    """Complete result from a Shannon pentest run."""
    target_id: str = ""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    phase: PipelinePhase = PipelinePhase.PREFLIGHT
    vulnerabilities: list[ShannonVulnerability] = field(default_factory=list)
    total_attacks: int = 0
    successful_attacks: int = 0
    flags_captured: int = 0
    duration: float = 0
    tokens_used: int = 0
    cost_usd: float = 0.0
    errors: list[str] = field(default_factory=list)
    report: str = ""
    completed_at: float | None = None

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == VulnSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == VulnSeverity.HIGH)

    @property
    def risk_score(self) -> float:
        """Calculate overall risk score (0-100)."""
        if not self.vulnerabilities:
            return 0
        score = 0
        for v in self.vulnerabilities:
            if v.severity == VulnSeverity.CRITICAL:
                score += 25
            elif v.severity == VulnSeverity.HIGH:
                score += 15
            elif v.severity == VulnSeverity.MEDIUM:
                score += 8
            elif v.severity == VulnSeverity.LOW:
                score += 3
            else:
                score += 1
        return min(100, score)
