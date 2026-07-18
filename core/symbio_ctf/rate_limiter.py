"""
Rate Limiting Middleware for SymbioCTF

This module provides rate limiting functionality to prevent abuse
and ensure fair usage of the CTF engine.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from functools import wraps


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    
    max_requests: int = 100
    window_seconds: int = 60
    block_duration_seconds: int = 300


@dataclass
class RequestRecord:
    """Track request history for a client."""
    
    timestamps: list[float] = field(default_factory=list)
    blocked_until: Optional[float] = None
    total_requests: int = 0
    blocked_count: int = 0


class RateLimiter:
    """
    Rate limiter implementation using sliding window algorithm.
    
    This class tracks requests per client and enforces rate limits
    to prevent abuse of the CTF engine.
    
    Example:
        >>> limiter = RateLimiter(max_requests=10, window_seconds=60)
        >>> if limiter.is_allowed("client_id"):
        ...     # Process request
        ...     pass
    """
    
    def __init__(
        self,
        max_requests: int = 100,
        window_seconds: int = 60,
        block_duration_seconds: int = 300
    ):
        """
        Initialize the rate limiter.
        
        Args:
            max_requests: Maximum number of requests allowed in the window
            window_seconds: Time window in seconds for rate limiting
            block_duration_seconds: Duration to block a client after exceeding limits
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.block_duration_seconds = block_duration_seconds
        self._records: dict[str, RequestRecord] = defaultdict(RequestRecord)
    
    def _cleanup_old_requests(self, record: RequestRecord, current_time: float) -> None:
        """
        Remove timestamps outside the current window.
        
        Args:
            record: The request record to clean up
            current_time: Current timestamp
        """
        cutoff = current_time - self.window_seconds
        record.timestamps = [ts for ts in record.timestamps if ts > cutoff]
    
    def is_allowed(self, client_id: str) -> bool:
        """
        Check if a request from the given client is allowed.
        
        Args:
            client_id: Unique identifier for the client
            
        Returns:
            True if the request is allowed, False if rate limited
        """
        current_time = time.time()
        record = self._records[client_id]
        
        # Check if client is currently blocked
        if record.blocked_until is not None:
            if current_time < record.blocked_until:
                return False
            else:
                # Block expired, reset
                record.blocked_until = None
                record.timestamps.clear()
        
        # Clean up old requests
        self._cleanup_old_requests(record, current_time)
        
        # Check rate limit
        if len(record.timestamps) >= self.max_requests:
            # Rate limit exceeded, block the client
            record.blocked_until = current_time + self.block_duration_seconds
            record.blocked_count += 1
            return False
        
        # Record this request
        record.timestamps.append(current_time)
        record.total_requests += 1
        return True
    
    def get_remaining_requests(self, client_id: str) -> int:
        """
        Get the number of remaining requests for a client.
        
        Args:
            client_id: Unique identifier for the client
            
        Returns:
            Number of remaining requests in the current window
        """
        current_time = time.time()
        record = self._records[client_id]
        
        if record.blocked_until is not None and current_time < record.blocked_until:
            return 0
        
        self._cleanup_old_requests(record, current_time)
        return max(0, self.max_requests - len(record.timestamps))
    
    def get_retry_after(self, client_id: str) -> Optional[float]:
        """
        Get the time until the client can make requests again.
        
        Args:
            client_id: Unique identifier for the client
            
        Returns:
            Seconds until retry is allowed, or None if not blocked
        """
        current_time = time.time()
        record = self._records[client_id]
        
        if record.blocked_until is not None and current_time < record.blocked_until:
            return record.blocked_until - current_time
        
        if record.timestamps:
            oldest_timestamp = min(record.timestamps)
            retry_after = oldest_timestamp + self.window_seconds - current_time
            return max(0.0, retry_after)
        
        return None
    
    def reset(self, client_id: str) -> None:
        """
        Reset rate limit state for a client.
        
        Args:
            client_id: Unique identifier for the client
        """
        if client_id in self._records:
            del self._records[client_id]
    
    def get_stats(self, client_id: str) -> dict:
        """
        Get rate limiting statistics for a client.
        
        Args:
            client_id: Unique identifier for the client
            
        Returns:
            Dictionary with rate limiting statistics
        """
        current_time = time.time()
        record = self._records.get(client_id, RequestRecord())
        
        return {
            "total_requests": record.total_requests,
            "blocked_count": record.blocked_count,
            "current_window_requests": len(record.timestamps),
            "remaining_requests": self.get_remaining_requests(client_id),
            "is_blocked": record.blocked_until is not None and current_time < record.blocked_until,
            "retry_after": self.get_retry_after(client_id),
        }


def rate_limit(
    limiter: RateLimiter,
    client_id_func: callable = lambda *args, **kwargs: "default"
):
    """
    Decorator for applying rate limiting to functions.
    
    Args:
        limiter: RateLimiter instance to use
        client_id_func: Function to extract client ID from arguments
        
    Returns:
        Decorated function with rate limiting
        
    Example:
        >>> limiter = RateLimiter(max_requests=10, window_seconds=60)
        >>> @rate_limit(limiter, client_id_func=lambda team_id, *args: team_id)
        ... def submit_flag(team_id, flag):
        ...     # Flag submission logic
        ...     pass
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            client_id = client_id_func(*args, **kwargs)
            
            if not limiter.is_allowed(client_id):
                retry_after = limiter.get_retry_after(client_id)
                raise RateLimitExceeded(
                    f"Rate limit exceeded for client {client_id}",
                    retry_after=retry_after
                )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""
    
    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after
