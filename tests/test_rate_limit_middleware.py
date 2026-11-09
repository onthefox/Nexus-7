"""
Tests for ui/ctf_dashboard/rate_limit_middleware.py (issue #2).

Covers the real HTTP rate limiting middleware end to end:
- requests under the limit pass through
- exceeding the limit returns 429 with Retry-After
- per-client buckets (X-Forwarded-For handling with and without proxy trust)
- limiter reset via the exposed property
"""

import sys
import os

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.ctf_dashboard.rate_limit_middleware import RateLimitMiddleware


def build_app(max_requests: int = 3, **middleware_kwargs) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        RateLimitMiddleware,
        max_requests=max_requests,
        window_seconds=60,
        block_duration_seconds=300,
        **middleware_kwargs,
    )

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    return app


class TestRateLimitMiddleware:
    def test_requests_under_limit_pass(self):
        client = TestClient(build_app(max_requests=5))
        for _ in range(5):
            response = client.get("/ping")
            assert response.status_code == 200
            assert response.json() == {"ok": True}

    def test_exceeding_limit_returns_429(self):
        client = TestClient(build_app(max_requests=2))
        assert client.get("/ping").status_code == 200
        assert client.get("/ping").status_code == 200
        blocked = client.get("/ping")
        assert blocked.status_code == 429
        assert blocked.json()["detail"] == "Rate limit exceeded"

    def test_429_includes_retry_after_header(self):
        client = TestClient(build_app(max_requests=1))
        client.get("/ping")
        blocked = client.get("/ping")
        assert blocked.status_code == 429
        retry_after = blocked.headers.get("Retry-After")
        assert retry_after is not None
        assert int(retry_after) >= 1

    def test_blocked_client_stays_blocked(self):
        client = TestClient(build_app(max_requests=1))
        client.get("/ping")
        for _ in range(3):
            assert client.get("/ping").status_code == 429

    def test_limiter_reset_unblocks_client(self):
        middleware = RateLimitMiddleware(app=None, max_requests=1)
        assert middleware.limiter.is_allowed("client-x") is True
        assert middleware.limiter.is_allowed("client-x") is False
        middleware.limiter.reset("client-x")
        assert middleware.limiter.is_allowed("client-x") is True


class TestPerClientBuckets:
    def test_forwarded_for_clients_tracked_separately_when_trusted(self):
        client = TestClient(build_app(max_requests=1, trust_forwarded_for=True))
        assert client.get("/ping", headers={"X-Forwarded-For": "10.0.0.1"}).status_code == 200
        assert client.get("/ping", headers={"X-Forwarded-For": "10.0.0.2"}).status_code == 200
        assert client.get("/ping", headers={"X-Forwarded-For": "10.0.0.1"}).status_code == 429

    def test_first_forwarded_hop_is_used(self):
        client = TestClient(build_app(max_requests=1, trust_forwarded_for=True))
        chained = {"X-Forwarded-For": "10.0.0.1, 10.0.0.2"}
        assert client.get("/ping", headers=chained).status_code == 200
        assert client.get("/ping", headers=chained).status_code == 429

    def test_forwarded_for_ignored_when_proxy_not_trusted(self):
        client = TestClient(build_app(max_requests=1, trust_forwarded_for=False))
        assert client.get("/ping", headers={"X-Forwarded-For": "10.0.0.1"}).status_code == 200
        # Spoofed header does not open a second bucket: same peer, same bucket
        assert client.get("/ping", headers={"X-Forwarded-For": "10.0.0.2"}).status_code == 429
