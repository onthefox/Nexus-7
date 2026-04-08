"""
Nexus-7 — Gauntlet: Autonomous Red-Teaming Engine
Shannon + SWE-Agent + ChatGPT integration for continuous security testing
"""

from .gauntlet import Gauntlet
from .models import AttackResult, AttackType, SandboxConfig, VulnerabilityReport

__all__ = [
    "Gauntlet",
    "AttackResult",
    "AttackType",
    "SandboxConfig",
    "VulnerabilityReport",
]
