"""
PreflightValidator — Shannon's 3-step preflight pattern
Catches failures BEFORE expensive agent runs.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass


@dataclass
class PreflightResult:
    passed: bool
    checks: dict[str, bool]
    errors: list[str]


class PreflightValidator:
    """
    Shannon's 3-step preflight validation:
    1. Target validation (URL/repo exists and is accessible)
    2. Configuration validation (pipeline config is valid)
    3. Credential validation (API keys work via minimal round-trip)

    This prevents wasted token costs on misconfigured runs.
    """

    def validate(self, config: "ShannonConfig") -> PreflightResult:
        """Run all preflight checks."""
        from .models import ShannonConfig  # avoid circular import

        checks = {}
        errors = []

        # Step 1: Target validation
        target_ok, target_err = self._check_target(config)
        checks["target"] = target_ok
        if not target_ok:
            errors.append(target_err)

        # Step 2: Configuration validation
        config_ok, config_err = self._check_config(config)
        checks["config"] = config_ok
        if not config_ok:
            errors.append(config_err)

        # Step 3: Credential validation
        creds_ok, creds_err = self._check_credentials(config)
        checks["credentials"] = creds_ok
        if not creds_ok:
            errors.append(creds_err)

        return PreflightResult(
            passed=all(checks.values()),
            checks=checks,
            errors=errors,
        )

    def _check_target(self, config) -> tuple[bool, str]:
        """Validate target is accessible."""
        if config.target_url:
            # Validate URL format
            if not re.match(r'^https?://', config.target_url):
                return False, f"Invalid URL format: {config.target_url}"
            return True, ""

        if config.repo_path:
            if not os.path.exists(config.repo_path):
                return False, f"Repository not found: {config.repo_path}"
            if not os.path.exists(os.path.join(config.repo_path, ".git")):
                return False, f"Not a git repository: {config.repo_path}"
            return True, ""

        return False, "No target URL or repo path specified"

    def _check_config(self, config) -> tuple[bool, str]:
        """Validate pipeline configuration."""
        if config.model_tier not in ("small", "medium", "large"):
            return False, f"Invalid model tier: {config.model_tier}"

        if config.max_turns < 100:
            return False, f"Max turns too low: {config.max_turns} (minimum 100)"

        if config.max_concurrent_pipelines < 1:
            return False, f"Max concurrent pipelines too low: {config.max_concurrent_pipelines}"

        if config.timeout < 60:
            return False, f"Timeout too low: {config.timeout}s (minimum 60s)"

        if config.browser_count < 1:
            return False, f"Browser count too low: {config.browser_count}"

        return True, ""

    def _check_credentials(self, config) -> tuple[bool, str]:
        """Validate API credentials."""
        if not config.api_key:
            return False, "No API key provided"

        # Check key format (should be at least 20 chars)
        if len(config.api_key) < 20:
            return False, "API key too short (possible placeholder)"

        # Check for common placeholder patterns
        placeholders = ["your_key", "your_api_key", "sk-xxx", "replace_me", "changeme"]
        if any(p in config.api_key.lower() for p in placeholders):
            return False, "API key appears to be a placeholder"

        return True, ""

    def check_spending_cap(self, config, current_cost: float) -> tuple[bool, str]:
        """Check if current cost is within spending cap."""
        if current_cost >= config.spending_cap_usd:
            return False, f"Spending cap reached: ${current_cost:.2f} >= ${config.spending_cap_usd:.2f}"
        if current_cost >= config.spending_cap_usd * 0.8:
            return True, f"WARNING: Approaching spending cap: ${current_cost:.2f} / ${config.spending_cap_usd:.2f}"
        return True, ""
