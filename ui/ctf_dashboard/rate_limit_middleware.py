"""HTTP rate limiting middleware for the Nexus-7 CTF dashboard.

Wraps the sliding-window :class:`core.symbio_ctf.rate_limiter.RateLimiter` as a
Starlette-compatible ASGI middleware. Requests exceeding the configured limit
receive an HTTP 429 response with a ``Retry-After`` header.

Clients are keyed by the first hop in ``X-Forwarded-For`` (when the deployment
sits behind a trusted proxy) and fall back to the direct peer address.
"""

from __future__ import annotations

from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from core.symbio_ctf.rate_limiter import RateLimiter

FORWARDED_FOR_HEADER = "x-forwarded-for"
RETRY_AFTER_HEADER = "Retry-After"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-client request rate limiting for the dashboard HTTP surface.

    Args:
        app: The wrapped ASGI application.
        max_requests: Maximum requests allowed per client inside the window.
        window_seconds: Length of the sliding window in seconds.
        block_duration_seconds: How long a client stays blocked after
            exceeding the limit.
        trust_forwarded_for: Trust ``X-Forwarded-For`` for client
            identification. Enable only when deployed behind a trusted proxy.
    """

    def __init__(
        self,
        app,
        max_requests: int = 60,
        window_seconds: int = 60,
        block_duration_seconds: int = 300,
        trust_forwarded_for: bool = False,
    ) -> None:
        super().__init__(app)
        self._limiter = RateLimiter(
            max_requests=max_requests,
            window_seconds=window_seconds,
            block_duration_seconds=block_duration_seconds,
        )
        self._trust_forwarded_for = trust_forwarded_for

    @property
    def limiter(self) -> RateLimiter:
        """Expose the underlying limiter for introspection and resets."""
        return self._limiter

    def _client_key(self, request: Request) -> str:
        if self._trust_forwarded_for:
            forwarded = request.headers.get(FORWARDED_FOR_HEADER)
            if forwarded:
                first_hop = forwarded.split(",")[0].strip()
                if first_hop:
                    return first_hop
        client = request.client
        return client.host if client else "unknown"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        client_key = self._client_key(request)
        if not self._limiter.is_allowed(client_key):
            retry_after: Optional[float] = self._limiter.get_retry_after(client_key)
            headers = {}
            if retry_after is not None:
                headers[RETRY_AFTER_HEADER] = str(max(1, int(retry_after) + 1))
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers=headers,
            )
        return await call_next(request)
