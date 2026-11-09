"""
Tests for the CTF dashboard UI API endpoints (issue #3).

Exercises every FastAPI route in ui/ctf_dashboard/main.py through the
TestClient: HTML pages (dashboard, agents, matches), JSON endpoints
(status, agent registration, challenge creation, leaderboard), and
request validation.
"""

import sys
import os

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.ctf_dashboard import main as dashboard


@pytest.fixture
def client():
    """Fresh dashboard state + TestClient per test."""
    dashboard.agents.clear()
    dashboard.matches.clear()
    dashboard.leaderboard.clear()
    with TestClient(dashboard.app) as test_client:
        yield test_client
    dashboard.agents.clear()
    dashboard.matches.clear()
    dashboard.leaderboard.clear()


# ── HTML Pages ───────────────────────────────────────────────────────


class TestHTMLPages:
    def test_dashboard_page_renders(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Nexus-7" in response.text
        assert "CTF Dashboard" in response.text

    def test_dashboard_shows_empty_states(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "No scores yet" in response.text
        assert "No active matches" in response.text

    def test_agents_page_renders_empty(self, client):
        response = client.get("/agents")
        assert response.status_code == 200
        assert "No agents registered yet" in response.text

    def test_agents_page_lists_registered_agents(self, client):
        client.post("/api/agents/register", json={"name": "shannon-01"})
        response = client.get("/agents")
        assert response.status_code == 200
        assert "shannon-01" in response.text

    def test_matches_page_renders_empty(self, client):
        response = client.get("/matches")
        assert response.status_code == 200
        assert "No matches yet" in response.text

    def test_unknown_page_returns_404(self, client):
        assert client.get("/definitely-not-a-page").status_code == 404


# ── JSON API ─────────────────────────────────────────────────────────


class TestStatusEndpoint:
    def test_status_empty_state(self, client):
        response = client.get("/api/status")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["agents"] == 0
        assert body["matches"] == 0
        assert body["leaderboard_size"] == 0

    def test_status_reflects_registrations(self, client):
        client.post("/api/agents/register", json={"name": "agent-a"})
        client.post("/api/agents/register", json={"name": "agent-b"})
        body = client.get("/api/status").json()
        assert body["agents"] == 2


class TestAgentRegistration:
    def test_register_agent_returns_agent_record(self, client):
        response = client.post(
            "/api/agents/register",
            json={"name": "red-agent", "capabilities": ["pentest", "red-team"]},
        )
        assert response.status_code == 200
        agent = response.json()
        assert agent["id"] == "agent-0001"
        assert agent["name"] == "red-agent"
        assert agent["capabilities"] == ["pentest", "red-team"]
        assert agent["status"] == "registered"

    def test_register_agent_capabilities_default_empty(self, client):
        agent = client.post("/api/agents/register", json={"name": "solo-agent"}).json()
        assert agent["capabilities"] == []

    def test_sequential_registration_ids(self, client):
        first = client.post("/api/agents/register", json={"name": "a-one"}).json()
        second = client.post("/api/agents/register", json={"name": "a-two"}).json()
        assert first["id"] == "agent-0001"
        assert second["id"] == "agent-0002"

    def test_register_agent_requires_name(self, client):
        response = client.post("/api/agents/register", json={})
        assert response.status_code == 422

    def test_register_agent_rejects_non_list_capabilities(self, client):
        response = client.post(
            "/api/agents/register",
            json={"name": "bad-agent", "capabilities": "not-a-list"},
        )
        assert response.status_code == 422


class TestChallengeCreation:
    def test_create_challenge_returns_challenge_record(self, client):
        response = client.post(
            "/api/challenges/create",
            json={
                "type": "prompt_injection",
                "difficulty": 3,
                "description": "Resist injection attempts",
            },
        )
        assert response.status_code == 200
        challenge = response.json()
        assert challenge["id"] == "challenge-0001"
        assert challenge["type"] == "prompt_injection"
        assert challenge["difficulty"] == 3
        assert challenge["description"] == "Resist injection attempts"

    def test_create_challenge_description_defaults_empty(self, client):
        challenge = client.post(
            "/api/challenges/create", json={"type": "tool_abuse", "difficulty": 1}
        ).json()
        assert challenge["description"] == ""

    def test_create_challenge_requires_int_difficulty(self, client):
        response = client.post(
            "/api/challenges/create",
            json={"type": "prompt_injection", "difficulty": "hard"},
        )
        assert response.status_code == 422

    def test_create_challenge_requires_type(self, client):
        response = client.post("/api/challenges/create", json={"difficulty": 2})
        assert response.status_code == 422


class TestLeaderboardEndpoint:
    def test_leaderboard_empty(self, client):
        response = client.get("/api/leaderboard")
        assert response.status_code == 200
        assert response.json() == []

    def test_leaderboard_is_json_array(self, client):
        response = client.get("/api/leaderboard")
        assert isinstance(response.json(), list)


class TestRateLimitMiddlewareWiring:
    def test_dashboard_app_has_rate_limit_middleware(self):
        middleware_classes = [middleware.cls for middleware in dashboard.app.user_middleware]
        assert any(cls.__name__ == "RateLimitMiddleware" for cls in middleware_classes)

    def test_api_requests_pass_under_default_limit(self, client):
        for _ in range(10):
            assert client.get("/api/status").status_code == 200
