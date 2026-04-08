"""
BehavioralReasoner — Tenzai's behavioral reasoning pattern
Analyzes application behavior, trust boundaries, and system interactions
to uncover subtle flaws without scanning or brute-force enumeration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TrustBoundary:
    """A trust boundary in the application."""
    name: str
    description: str
    entry_points: list[str] = field(default_factory=list)
    exit_points: list[str] = field(default_factory=list)
    controls: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)


@dataclass
class BehavioralFinding:
    """A finding from behavioral analysis."""
    title: str
    description: str
    severity: str  # info, low, medium, high, critical
    category: str  # auth, logic, data_flow, trust_boundary
    evidence: str = ""
    recommendation: str = ""
    attack_path: list[str] = field(default_factory=list)


class BehavioralReasoner:
    """
    Tenzai-style behavioral reasoning engine.
    Instead of signature-based scanning, analyzes:
    - Identity and authentication flows
    - Trust boundaries between components
    - Data flow from user input to sensitive operations
    - System interaction patterns that reveal logic flaws
    """

    # Known weak behavioral patterns
    BEHAVIORAL_PATTERNS = {
        "mass_assignment": {
            "category": "data_flow",
            "description": "Application accepts and processes all user-supplied fields without filtering",
            "indicators": ["role", "admin", "is_admin", "privileged", "permissions", "level"],
            "severity": "high",
            "attack_path": [
                "Identify user creation/update endpoint",
                "Add privileged fields to request body",
                "Submit request with elevated permissions",
                "Verify privilege escalation succeeded",
            ],
        },
        "idor": {
            "category": "trust_boundary",
            "description": "Direct object reference without ownership verification",
            "indicators": ["id=", "user_id=", "account=", "resource_id=", "/api/users/", "/api/orders/"],
            "severity": "high",
            "attack_path": [
                "Identify endpoint with numeric ID parameter",
                "Enumerate sequential IDs",
                "Access another user's resource",
                "Modify or delete the resource",
            ],
        },
        "jwt_manipulation": {
            "category": "auth",
            "description": "JWT token can be manipulated to escalate privileges",
            "indicators": ["jwt", "token", "bearer", "alg:", "HS256", "RS256", "none"],
            "severity": "critical",
            "attack_path": [
                "Capture JWT token from request",
                "Decode and examine payload claims",
                "Modify role/admin claims",
                "Change algorithm to 'none' or weak HMAC",
                "Submit modified token",
                "Verify elevated access",
            ],
        },
        "logic_bypass": {
            "category": "logic",
            "description": "Business logic can be bypassed by manipulating request flow",
            "indicators": ["step", "phase", "stage", "workflow", "approve", "verify", "confirm"],
            "severity": "medium",
            "attack_path": [
                "Map multi-step workflow",
                "Identify state transitions",
                "Skip intermediate steps",
                "Access final state directly",
                "Verify bypass succeeded",
            ],
        },
        "cache_poisoning": {
            "category": "data_flow",
            "description": "Application caches user-specific data without proper key isolation",
            "indicators": ["cache", "etag", "vary", "max-age", "cdn", "proxy"],
            "severity": "medium",
            "attack_path": [
                "Identify cacheable responses with user data",
                "Send request with user-specific content",
                "Check if response is cached",
                "Request same URL from different context",
                "Verify cached data leakage",
            ],
        },
    }

    def __init__(self):
        self._boundaries: list[TrustBoundary] = []
        self._findings: list[BehavioralFinding] = []

    def analyze_application(self, endpoints: list[dict], auth_flows: list[dict]) -> list[BehavioralFinding]:
        """
        Analyze application endpoints and auth flows for behavioral weaknesses.
        This is the core Tenzai pattern: behavioral reasoning over signature scanning.
        """
        findings = []

        # Analyze each endpoint
        for ep in endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "GET")
            params = ep.get("params", [])
            auth_required = ep.get("auth_required", False)

            # Check for mass assignment
            if method in ("POST", "PUT", "PATCH"):
                for param in params:
                    for pattern_name, pattern in self.BEHAVIORAL_PATTERNS.items():
                        for indicator in pattern["indicators"]:
                            if indicator.lower() in param.lower():
                                finding = BehavioralFinding(
                                    title=f"Potential {pattern_name} at {method} {path}",
                                    description=pattern["description"],
                                    severity=pattern["severity"],
                                    category=pattern["category"],
                                    evidence=f"Parameter '{param}' matches {pattern_name} indicator",
                                    attack_path=pattern["attack_path"],
                                    recommendation=f"Implement strict input validation for {param}",
                                )
                                findings.append(finding)

            # Check for IDOR patterns
            id_pattern = re.search(r'/(\w+)/(\d+)', path)
            if id_pattern and not auth_required:
                finding = BehavioralFinding(
                    title=f"Potential IDOR at {path}",
                    description=self.BEHAVIORAL_PATTERNS["idor"]["description"],
                    severity="high",
                    category="trust_boundary",
                    evidence=f"Endpoint {path} uses numeric ID without auth",
                    attack_path=self.BEHAVIORAL_PATTERNS["idor"]["attack_path"],
                    recommendation="Implement ownership verification for all resource access",
                )
                findings.append(finding)

        # Analyze auth flows
        for flow in auth_flows:
            flow_type = flow.get("type", "")
            steps = flow.get("steps", [])

            if flow_type == "jwt":
                finding = BehavioralFinding(
                    title="JWT-based authentication detected",
                    description=self.BEHAVIORAL_PATTERNS["jwt_manipulation"]["description"],
                    severity="critical",
                    category="auth",
                    evidence="Application uses JWT for authentication",
                    attack_path=self.BEHAVIORAL_PATTERNS["jwt_manipulation"]["attack_path"],
                    recommendation="Use asymmetric signing (RS256/ES256), validate alg claim, implement token rotation",
                )
                findings.append(finding)

            if len(steps) > 2:
                finding = BehavioralFinding(
                    title=f"Multi-step {flow_type} workflow ({len(steps)} steps)",
                    description="Multi-step workflows can often be bypassed",
                    severity="medium",
                    category="logic",
                    evidence=f"Workflow has {len(steps)} steps: {[s.get('name', '') for s in steps]}",
                    attack_path=self.BEHAVIORAL_PATTERNS["logic_bypass"]["attack_path"],
                    recommendation="Enforce state machine transitions server-side, validate step order",
                )
                findings.append(finding)

        self._findings.extend(findings)
        return findings

    def map_trust_boundaries(self, components: list[dict]) -> list[TrustBoundary]:
        """Map trust boundaries between application components."""
        boundaries = []

        for comp in components:
            name = comp.get("name", "")
            role = comp.get("role", "")
            exposed = comp.get("exposed", False)

            if exposed:
                boundary = TrustBoundary(
                    name=f"{name}_external",
                    description=f"External trust boundary for {name} ({role})",
                    entry_points=comp.get("entry_points", []),
                    exit_points=comp.get("exit_points", []),
                    controls=comp.get("security_controls", []),
                )
                boundaries.append(boundary)

        self._boundaries.extend(boundaries)
        return boundaries

    def get_findings(self, severity: str | None = None) -> list[BehavioralFinding]:
        """Get all behavioral findings, optionally filtered by severity."""
        if severity:
            return [f for f in self._findings if f.severity == severity]
        return list(self._findings)

    def get_boundaries(self) -> list[TrustBoundary]:
        return list(self._boundaries)

    def reset(self):
        self._findings.clear()
        self._boundaries.clear()
