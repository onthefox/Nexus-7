"""
Nexus-7 — Shannon Adapter: Real Temporal Activity Wrapper
Integrates Shannon's 5-phase pentest pipeline as a Gauntlet attack source.
"""

from .shannon_adapter import ShannonAdapter
from .models import ShannonConfig, ShannonResult, PipelinePhase
from .preflight import PreflightValidator
from .exploit_chain import ExploitChainEngine
from .behavioral import BehavioralReasoner
from .context_relay import ContextRelay
from .audit import ShannonAudit
from .infection import InfectionChainDetector
from .sast_dast import SASTDASTPipeline

__all__ = [
    "ShannonAdapter",
    "ShannonConfig",
    "ShannonResult",
    "PipelinePhase",
    "PreflightValidator",
    "ExploitChainEngine",
    "BehavioralReasoner",
    "ContextRelay",
    "ShannonAudit",
    "InfectionChainDetector",
    "SASTDASTPipeline",
]
