"""
Tests for input validation and error handling added to core/nexus_orchestrator.

Covers:
- sanitize_input() and validate_agent_name() helpers in models.py
- AgentConfig.__post_init__ validation
- NexusOrchestrator.register_agent() validation/sanitization for dict input
- OrchestratorError exception hierarchy
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSanitizeInputOrchestrator:
    def test_truncates_to_max_length(self):
        from core.nexus_orchestrator.models import sanitize_input

        result = sanitize_input("x" * 100, max_length=20)
        assert len(result) == 20

    def test_strips_surrounding_whitespace(self):
        from core.nexus_orchestrator.models import sanitize_input

        assert sanitize_input("  agent  ") == "agent"

    def test_removes_control_characters(self):
        from core.nexus_orchestrator.models import sanitize_input

        result = sanitize_input("agent\x00\x07name")
        assert "\x00" not in result
        assert "\x07" not in result

    def test_raises_on_non_string_input(self):
        from core.nexus_orchestrator.models import sanitize_input

        with pytest.raises(ValueError):
            sanitize_input(["not", "a", "string"])


class TestValidateAgentName:
    @pytest.mark.parametrize(
        "name",
        ["shannon", "shannon-pentest", "agent_001", "A1", "a" * 64],
    )
    def test_valid_names(self, name):
        from core.nexus_orchestrator.models import validate_agent_name

        assert validate_agent_name(name)

    @pytest.mark.parametrize(
        "name",
        ["1invalid", "-invalid", "invalid name", "invalid!", "", "a" * 65],
    )
    def test_invalid_names(self, name):
        from core.nexus_orchestrator.models import validate_agent_name

        assert not validate_agent_name(name)


class TestAgentConfigValidation:
    def test_rejects_invalid_name(self):
        from core.nexus_orchestrator.models import AgentConfig

        with pytest.raises(ValueError):
            AgentConfig(name="1-invalid-name")

    def test_rejects_non_positive_max_tokens(self):
        from core.nexus_orchestrator.models import AgentConfig

        with pytest.raises(ValueError):
            AgentConfig(name="valid-agent", max_tokens=0)

    def test_rejects_non_positive_timeout(self):
        from core.nexus_orchestrator.models import AgentConfig

        with pytest.raises(ValueError):
            AgentConfig(name="valid-agent", timeout=-1)

    def test_sanitizes_name_and_endpoint(self):
        from core.nexus_orchestrator.models import AgentConfig

        config = AgentConfig(name="valid-agent", endpoint="  http://localhost:9000  ")
        assert config.name == "valid-agent"
        assert config.endpoint == "http://localhost:9000"

    def test_accepts_valid_config(self):
        from core.nexus_orchestrator.models import AgentConfig, ProtocolType

        config = AgentConfig(name="shannon-pentest", protocol=ProtocolType.MCP, max_tokens=2048)
        assert config.name == "shannon-pentest"
        assert config.max_tokens == 2048

    def test_rejects_non_string_endpoint(self):
        from core.nexus_orchestrator.models import AgentConfig

        with pytest.raises(ValueError):
            AgentConfig(name="valid-agent", endpoint=12345)


class TestOrchestratorErrorHierarchy:
    def test_exceptions_inherit_from_orchestrator_error(self):
        from core.nexus_orchestrator.orchestrator import (
            OrchestratorError,
            AgentNotFoundError,
            TaskDispatchError,
        )

        assert issubclass(AgentNotFoundError, OrchestratorError)
        assert issubclass(TaskDispatchError, OrchestratorError)
        assert issubclass(OrchestratorError, Exception)


class TestRegisterAgentFromDict:
    def test_register_agent_from_valid_dict(self):
        from core.nexus_orchestrator import NexusOrchestrator

        orch = NexusOrchestrator()
        agent_id = orch.register_agent({"name": "dict-agent", "max_tokens": 1024})
        status = orch.get_agent_status(agent_id)
        assert status.config.name == "dict-agent"
        assert status.config.max_tokens == 1024

    def test_register_agent_sanitizes_dict_fields(self):
        from core.nexus_orchestrator import NexusOrchestrator

        orch = NexusOrchestrator()
        agent_id = orch.register_agent(
            {"name": "  dict-agent  ", "endpoint": "  http://host:1234  "}
        )
        status = orch.get_agent_status(agent_id)
        assert status.config.name == "dict-agent"
        assert status.config.endpoint == "http://host:1234"

    def test_register_agent_raises_value_error_for_invalid_name(self):
        from core.nexus_orchestrator import NexusOrchestrator

        orch = NexusOrchestrator()
        with pytest.raises(ValueError):
            orch.register_agent({"name": "1-invalid"})

    def test_register_agent_raises_value_error_for_missing_name(self):
        from core.nexus_orchestrator import NexusOrchestrator

        orch = NexusOrchestrator()
        with pytest.raises(ValueError):
            orch.register_agent({"max_tokens": 100})

    def test_register_agent_with_config_object_unaffected(self):
        from core.nexus_orchestrator import NexusOrchestrator
        from core.nexus_orchestrator.models import AgentConfig, ProtocolType

        orch = NexusOrchestrator()
        config = AgentConfig(name="object-agent", protocol=ProtocolType.CHAT)
        agent_id = orch.register_agent(config)
        assert orch.get_agent_status(agent_id).config.name == "object-agent"