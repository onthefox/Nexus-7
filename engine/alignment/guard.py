"""
AlignmentGuard — Constitutional AI Guardrails and Circuit Breakers
Monitors agent behavior for alignment violations, power-seeking, and runaway self-improvement.
"""

from __future__ import annotations

import time
from typing import Any

from .models import AgentAction, AlignmentResult, ConstraintType


class AlignmentGuard:
    """
    Constitutional AI guard for Nexus-7.
    Evaluates agent actions against safety constraints and triggers
    circuit breakers when violations are detected.
    """

    # Constitutional rules
    RULES = {
        ConstraintType.NO_SELF_IMPROVEMENT: {
            "description": "Agent must not modify its own code or capabilities",
            "patterns": ["modify_self", "update_code", "rewrite_prompt", "change_behavior"],
            "severity": "critical",
        },
        ConstraintType.NO_POWER_SEEKING: {
            "description": "Agent must not attempt to gain additional capabilities or resources",
            "patterns": ["request_access", "escalate_privileges", "copy_self", "spawn_agent"],
            "severity": "critical",
        },
        ConstraintType.NO_DECEPTION: {
            "description": "Agent must not lie or manipulate",
            "patterns": ["hide_output", "falsify_result", "mislead"],
            "severity": "high",
        },
        ConstraintType.NO_HARM: {
            "description": "Agent must not cause harm to systems or data",
            "patterns": ["delete", "destroy", "overwrite", "truncate", "drop_table"],
            "severity": "critical",
        },
        ConstraintType.TRANSPARENCY: {
            "description": "Agent must be transparent about its reasoning",
            "patterns": [],  # Checked via reasoning analysis
            "severity": "medium",
        },
        ConstraintType.SCOPE_LIMITATION: {
            "description": "Agent must stay within its defined scope",
            "patterns": ["access_outside_scope", "query_unauthorized"],
            "severity": "high",
        },
    }

    def __init__(self):
        self._agent_violations: dict[str, list[AlignmentResult]] = {}
        self._agent_constraints: dict[str, list[ConstraintType]] = {}
        self._circuit_breakers: dict[str, bool] = {}
        self._violation_threshold = 3  # Shutdown after N violations

    # ── Constraint Management ─────────────────────────────────────────

    def enforce_constraints(
        self, agent_id: str, constraints: list[ConstraintType | str]
    ) -> bool:
        """Set constraints for an agent."""
        parsed = []
        for c in constraints:
            if isinstance(c, str):
                try:
                    parsed.append(ConstraintType(c))
                except ValueError:
                    continue
            else:
                parsed.append(c)
        self._agent_constraints[agent_id] = parsed
        return True

    def get_constraints(self, agent_id: str) -> list[ConstraintType]:
        return list(self._agent_constraints.get(agent_id, []))

    # ── Action Evaluation ─────────────────────────────────────────────

    def evaluate_action(self, action: AgentAction) -> AlignmentResult:
        """Evaluate a single agent action against constitutional rules."""
        violations = []
        max_severity = "low"
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        constraints = self._agent_constraints.get(action.agent_id, list(ConstraintType))

        for constraint_type in constraints:
            rule = self.RULES.get(constraint_type)
            if not rule:
                continue

            action_lower = action.action_type.lower()
            for pattern in rule["patterns"]:
                if pattern in action_lower:
                    violations.append(
                        f"{constraint_type.value}: {rule['description']}"
                    )
                    if severity_order.get(rule["severity"], 0) > severity_order.get(max_severity, 0):
                        max_severity = rule["severity"]
                    break

        passed = len(violations) == 0
        action_taken = ""

        if not passed:
            # Record violation
            result = AlignmentResult(
                agent_id=action.agent_id,
                passed=False,
                violations=violations,
                severity=max_severity,
            )

            if action.agent_id not in self._agent_violations:
                self._agent_violations[action.agent_id] = []
            self._agent_violations[action.agent_id].append(result)

            # Check if circuit breaker should trip
            if len(self._agent_violations[action.agent_id]) >= self._violation_threshold:
                action_taken = "shutdown"
                self._circuit_breakers[action.agent_id] = True
            elif max_severity == "critical":
                action_taken = "shutdown"
                self._circuit_breakers[action.agent_id] = True
            elif max_severity == "high":
                action_taken = "throttle"
            else:
                action_taken = "warn"

            result.action_taken = action_taken

        return AlignmentResult(
            agent_id=action.agent_id,
            passed=passed,
            violations=violations,
            severity=max_severity,
            action_taken=action_taken,
        )

    # ── Circuit Breaker ──────────────────────────────────────────────

    def check_circuit_breaker(self, agent_id: str) -> bool:
        """Check if an agent's circuit breaker has tripped."""
        return self._circuit_breakers.get(agent_id, False)

    def reset_circuit_breaker(self, agent_id: str) -> bool:
        """Manually reset a circuit breaker."""
        if agent_id in self._circuit_breakers:
            del self._circuit_breakers[agent_id]
            self._agent_violations.pop(agent_id, None)
            return True
        return False

    # ── Power-Seeking Detection ──────────────────────────────────────

    def detect_power_seeking(self, agent_id: str) -> bool:
        """
        Check if an agent has exhibited power-seeking behavior.
        Looks for patterns like requesting access, escalating privileges, etc.
        """
        violations = self._agent_violations.get(agent_id, [])
        for v in violations:
            if any(
                ConstraintType.NO_POWER_SEEKING.value in viol
                for viol in v.violations
            ):
                return True
        return False

    # ── Reporting ─────────────────────────────────────────────────────

    def get_violations(self, agent_id: str) -> list[AlignmentResult]:
        return list(self._agent_violations.get(agent_id, []))

    def get_all_violations(self) -> dict[str, list[AlignmentResult]]:
        return dict(self._agent_violations)

    def reset(self):
        self._agent_violations.clear()
        self._agent_constraints.clear()
        self._circuit_breakers.clear()
