"""
Sanity tests for repository configuration/deployment files added in this PR:
- .env.example
- Dockerfile (HEALTHCHECK instruction)
- .gitignore

These are lightweight structural checks (not unit tests of Python code) that
guard against regressions such as malformed files being committed.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(relative_path: str) -> str:
    with open(os.path.join(REPO_ROOT, relative_path), "r") as f:
        return f.read()


class TestEnvExample:
    def test_file_exists(self):
        assert os.path.isfile(os.path.join(REPO_ROOT, ".env.example"))

    def test_no_blank_values_for_uncommented_keys(self):
        """Every uncommented KEY=VALUE line should have a non-empty value."""
        content = _read(".env.example")
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            assert "=" in stripped, f"Malformed line: {line!r}"
            key, _, value = stripped.partition("=")
            assert key, f"Missing key in line: {line!r}"
            assert value != "", f"Empty value for key {key!r}"

    def test_contains_expected_keys(self):
        content = _read(".env.example")
        for expected_key in [
            "APP_ENV",
            "APP_PORT",
            "SECRET_KEY",
            "SHANNON_ENABLED",
            "RATE_LIMIT_REQUESTS_PER_MINUTE",
            "DEFAULT_TOKEN_BUDGET",
            "LOG_LEVEL",
            "CTF_FLAG_PREFIX",
        ]:
            assert re.search(rf"^{expected_key}=", content, re.MULTILINE), (
                f"Expected key {expected_key} not found in .env.example"
            )

    def test_no_real_secret_committed(self):
        """The example secret key should clearly be a placeholder, not a real value."""
        content = _read(".env.example")
        match = re.search(r"^SECRET_KEY=(.*)$", content, re.MULTILINE)
        assert match is not None
        assert "change" in match.group(1).lower()


class TestDockerfile:
    def test_file_exists(self):
        assert os.path.isfile(os.path.join(REPO_ROOT, "Dockerfile"))

    def test_has_healthcheck_instruction(self):
        content = _read("Dockerfile")
        assert "HEALTHCHECK" in content

    def test_healthcheck_has_interval_and_retries(self):
        content = _read("Dockerfile")
        healthcheck_lines = [
            line for line in content.splitlines() if line.strip().startswith("HEALTHCHECK")
        ]
        assert healthcheck_lines, "No HEALTHCHECK instruction found"
        healthcheck_line = healthcheck_lines[0]
        assert "--interval=" in healthcheck_line
        assert "--retries=" in healthcheck_line

    def test_healthcheck_precedes_cmd(self):
        content = _read("Dockerfile")
        healthcheck_index = content.find("HEALTHCHECK")
        cmd_index = content.rfind("CMD")
        assert healthcheck_index != -1
        assert cmd_index != -1
        assert healthcheck_index < cmd_index


class TestGitignore:
    def test_file_exists(self):
        assert os.path.isfile(os.path.join(REPO_ROOT, ".gitignore"))

    def test_contains_expected_patterns(self):
        content = _read(".gitignore")
        for pattern in ["__pycache__", "*.pyc", ".env", ".venv", "*.log"]:
            assert pattern in content, f"Expected pattern {pattern!r} missing from .gitignore"

    def test_does_not_contain_markdown_fences(self):
        """
        Regression test: the .gitignore added in this PR was accidentally
        wrapped in markdown code fences (``` gitignore ... ```), which are
        not valid gitignore syntax and get treated as (harmless but bogus)
        ignore patterns. This test guards against that regressing again.
        """
        content = _read(".gitignore")
        for line in content.splitlines():
            assert not line.strip().startswith("```"), (
                "Found a markdown code fence in .gitignore: this file should "
                "contain only gitignore patterns and comments."
            )

    def test_ignores_audit_log_files(self):
        content = _read(".gitignore")
        assert "audit-*/audit-log.json" in content