"""
Tests for core/symbio_ctf/rate_limiter.py

Covers the RateLimiter sliding-window implementation, the RateLimitConfig
and RequestRecord dataclasses, the `rate_limit` decorator, and the
RateLimitExceeded exception.
"""

import sys
import os
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestRateLimitConfig:
    def test_defaults(self):
        from core.symbio_ctf.rate_limiter import RateLimitConfig

        config = RateLimitConfig()
        assert config.max_requests == 100
        assert config.window_seconds == 60
        assert config.block_duration_seconds == 300

    def test_custom_values(self):
        from core.symbio_ctf.rate_limiter import RateLimitConfig

        config = RateLimitConfig(max_requests=5, window_seconds=10, block_duration_seconds=20)
        assert config.max_requests == 5
        assert config.window_seconds == 10
        assert config.block_duration_seconds == 20


class TestRequestRecord:
    def test_defaults(self):
        from core.symbio_ctf.rate_limiter import RequestRecord

        record = RequestRecord()
        assert record.timestamps == []
        assert record.blocked_until is None
        assert record.total_requests == 0
        assert record.blocked_count == 0

    def test_records_are_independent(self):
        """Each RequestRecord instance should have its own timestamps list."""
        from core.symbio_ctf.rate_limiter import RequestRecord

        record_a = RequestRecord()
        record_b = RequestRecord()
        record_a.timestamps.append(123.0)
        assert record_b.timestamps == []


class TestRateLimiterIsAllowed:
    def test_allows_requests_under_limit(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        limiter = RateLimiter(max_requests=3, window_seconds=60, block_duration_seconds=300)
        assert limiter.is_allowed("client-1")
        assert limiter.is_allowed("client-1")
        assert limiter.is_allowed("client-1")

    def test_blocks_after_exceeding_limit(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        limiter = RateLimiter(max_requests=2, window_seconds=60, block_duration_seconds=300)
        assert limiter.is_allowed("client-1")
        assert limiter.is_allowed("client-1")
        # Third request exceeds the limit
        assert not limiter.is_allowed("client-1")

    def test_blocked_client_stays_blocked_within_block_duration(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        with patch("core.symbio_ctf.rate_limiter.time.time") as mock_time:
            mock_time.return_value = 1000.0
            limiter = RateLimiter(max_requests=1, window_seconds=60, block_duration_seconds=300)
            assert limiter.is_allowed("client-1")
            assert not limiter.is_allowed("client-1")  # exceeded -> blocked

            # Still within block window
            mock_time.return_value = 1000.0 + 100
            assert not limiter.is_allowed("client-1")

    def test_block_expires_and_resets_history(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        with patch("core.symbio_ctf.rate_limiter.time.time") as mock_time:
            mock_time.return_value = 1000.0
            limiter = RateLimiter(max_requests=1, window_seconds=60, block_duration_seconds=300)
            assert limiter.is_allowed("client-1")
            assert not limiter.is_allowed("client-1")  # now blocked until 1300.0

            # Advance time past the block duration
            mock_time.return_value = 1300.1
            assert limiter.is_allowed("client-1")

    def test_sliding_window_cleans_up_old_requests(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        with patch("core.symbio_ctf.rate_limiter.time.time") as mock_time:
            mock_time.return_value = 1000.0
            limiter = RateLimiter(max_requests=2, window_seconds=10, block_duration_seconds=300)
            assert limiter.is_allowed("client-1")

            # Advance beyond the window so the first request expires
            mock_time.return_value = 1011.0
            assert limiter.is_allowed("client-1")
            assert limiter.is_allowed("client-1")

    def test_independent_clients_tracked_separately(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        limiter = RateLimiter(max_requests=1, window_seconds=60, block_duration_seconds=300)
        assert limiter.is_allowed("client-a")
        assert not limiter.is_allowed("client-a")
        # A different client should not be affected
        assert limiter.is_allowed("client-b")


class TestRateLimiterRemainingAndRetry:
    def test_get_remaining_requests(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        limiter = RateLimiter(max_requests=5, window_seconds=60, block_duration_seconds=300)
        assert limiter.get_remaining_requests("client-1") == 5
        limiter.is_allowed("client-1")
        limiter.is_allowed("client-1")
        assert limiter.get_remaining_requests("client-1") == 3

    def test_get_remaining_requests_when_blocked(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        limiter = RateLimiter(max_requests=1, window_seconds=60, block_duration_seconds=300)
        limiter.is_allowed("client-1")
        limiter.is_allowed("client-1")  # triggers block
        assert limiter.get_remaining_requests("client-1") == 0

    def test_get_retry_after_returns_none_when_no_history(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        limiter = RateLimiter(max_requests=5, window_seconds=60, block_duration_seconds=300)
        assert limiter.get_retry_after("unknown-client") is None

    def test_get_retry_after_when_blocked(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        with patch("core.symbio_ctf.rate_limiter.time.time") as mock_time:
            mock_time.return_value = 1000.0
            limiter = RateLimiter(max_requests=1, window_seconds=60, block_duration_seconds=300)
            limiter.is_allowed("client-1")
            limiter.is_allowed("client-1")  # triggers block until 1300.0

            mock_time.return_value = 1100.0
            retry_after = limiter.get_retry_after("client-1")
            assert retry_after == pytest.approx(200.0)

    def test_get_retry_after_based_on_oldest_timestamp(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        with patch("core.symbio_ctf.rate_limiter.time.time") as mock_time:
            mock_time.return_value = 1000.0
            limiter = RateLimiter(max_requests=5, window_seconds=60, block_duration_seconds=300)
            limiter.is_allowed("client-1")

            mock_time.return_value = 1030.0
            retry_after = limiter.get_retry_after("client-1")
            # Oldest timestamp (1000) + window (60) - now (1030) = 30
            assert retry_after == pytest.approx(30.0)


class TestRateLimiterResetAndStats:
    def test_reset_clears_client_history(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        limiter = RateLimiter(max_requests=1, window_seconds=60, block_duration_seconds=300)
        limiter.is_allowed("client-1")
        limiter.is_allowed("client-1")  # blocked
        limiter.reset("client-1")
        assert limiter.is_allowed("client-1")  # allowed again after reset

    def test_reset_unknown_client_is_noop(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        limiter = RateLimiter()
        # Should not raise even though the client has no history
        limiter.reset("never-seen")

    def test_get_stats_tracks_usage(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        limiter = RateLimiter(max_requests=2, window_seconds=60, block_duration_seconds=300)
        limiter.is_allowed("client-1")
        limiter.is_allowed("client-1")
        limiter.is_allowed("client-1")  # exceeds -> blocked, blocked_count += 1

        stats = limiter.get_stats("client-1")
        assert stats["total_requests"] == 2
        assert stats["blocked_count"] == 1
        assert stats["remaining_requests"] == 0
        assert stats["is_blocked"] is True
        assert stats["retry_after"] is not None

    def test_get_stats_for_unknown_client(self):
        from core.symbio_ctf.rate_limiter import RateLimiter

        limiter = RateLimiter(max_requests=5, window_seconds=60, block_duration_seconds=300)
        stats = limiter.get_stats("never-seen")
        assert stats["total_requests"] == 0
        assert stats["blocked_count"] == 0
        assert stats["is_blocked"] is False


class TestRateLimitDecorator:
    def test_decorator_allows_calls_under_limit(self):
        from core.symbio_ctf.rate_limiter import RateLimiter, rate_limit

        limiter = RateLimiter(max_requests=3, window_seconds=60, block_duration_seconds=300)

        @rate_limit(limiter, client_id_func=lambda client_id, value: client_id)
        def add_one(client_id, value):
            return value + 1

        assert add_one("client-1", 1) == 2
        assert add_one("client-1", 2) == 3

    def test_decorator_raises_when_limit_exceeded(self):
        from core.symbio_ctf.rate_limiter import RateLimiter, rate_limit, RateLimitExceeded

        limiter = RateLimiter(max_requests=1, window_seconds=60, block_duration_seconds=300)

        @rate_limit(limiter, client_id_func=lambda client_id: client_id)
        def do_action(client_id):
            return "ok"

        assert do_action("client-1") == "ok"
        with pytest.raises(RateLimitExceeded):
            do_action("client-1")

    def test_decorator_default_client_id_shares_bucket(self):
        from core.symbio_ctf.rate_limiter import RateLimiter, rate_limit, RateLimitExceeded

        limiter = RateLimiter(max_requests=1, window_seconds=60, block_duration_seconds=300)

        @rate_limit(limiter)
        def do_action():
            return "ok"

        assert do_action() == "ok"
        with pytest.raises(RateLimitExceeded):
            do_action()

    def test_exception_carries_retry_after(self):
        from core.symbio_ctf.rate_limiter import RateLimiter, rate_limit, RateLimitExceeded

        limiter = RateLimiter(max_requests=1, window_seconds=60, block_duration_seconds=300)

        @rate_limit(limiter, client_id_func=lambda client_id: client_id)
        def do_action(client_id):
            return "ok"

        do_action("client-1")
        with pytest.raises(RateLimitExceeded) as exc_info:
            do_action("client-1")
        assert exc_info.value.retry_after is not None
        assert exc_info.value.retry_after > 0


class TestRateLimitExceeded:
    def test_message_and_default_retry_after(self):
        from core.symbio_ctf.rate_limiter import RateLimitExceeded

        exc = RateLimitExceeded("too many requests")
        assert str(exc) == "too many requests"
        assert exc.retry_after is None

    def test_with_explicit_retry_after(self):
        from core.symbio_ctf.rate_limiter import RateLimitExceeded

        exc = RateLimitExceeded("blocked", retry_after=42.5)
        assert exc.retry_after == 42.5
        assert isinstance(exc, Exception)