"""
Rate Limiter for API endpoints
Prevents abuse and ensures fair usage
"""

import logging
from time import time
from threading import Lock
from typing import Dict, List
from app.constants import Config

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Token bucket rate limiter with thread safety

    Tracks requests per client and enforces rate limits
    """

    def __init__(
        self,
        max_requests: int = Config.RATE_LIMIT_MAX_REQUESTS,
        window_seconds: int = Config.RATE_LIMIT_WINDOW_SECONDS,
    ):
        """
        Initialize rate limiter

        Args:
            max_requests: Maximum requests allowed per window (default from Config)
            window_seconds: Time window in seconds (default from Config)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = {}
        self.lock = Lock()
        logger.info(f"RateLimiter initialized: {max_requests} requests per {window_seconds}s")

    def is_allowed(self, client_id: str) -> bool:
        """
        Check if request is allowed for client

        Args:
            client_id: Unique client identifier

        Returns:
            True if request is allowed, False if rate limited
        """
        with self.lock:
            now = time()
            window_start = now - self.window_seconds

            # Initialize client tracking if first request
            if client_id not in self.requests:
                self.requests[client_id] = []

            # Remove expired requests outside the window
            self.requests[client_id] = [
                req_time for req_time in self.requests[client_id] if req_time > window_start
            ]

            # Check if limit exceeded
            if len(self.requests[client_id]) >= self.max_requests:
                logger.warning(
                    f"Rate limit exceeded for client (hashed). "
                    f"Current: {len(self.requests[client_id])}, Max: {self.max_requests}"
                )
                return False

            # Allow request and record timestamp
            self.requests[client_id].append(now)
            return True

    def get_remaining(self, client_id: str) -> int:
        """
        Get remaining requests for client in current window

        Args:
            client_id: Unique client identifier

        Returns:
            Number of remaining requests allowed
        """
        with self.lock:
            if client_id not in self.requests:
                return self.max_requests

            now = time()
            window_start = now - self.window_seconds

            # Count active requests in window
            active_requests = sum(
                1 for req_time in self.requests[client_id] if req_time > window_start
            )

            return max(0, self.max_requests - active_requests)

    def reset(self, client_id: str) -> None:
        """
        Reset rate limit for specific client (for testing)

        Args:
            client_id: Unique client identifier
        """
        with self.lock:
            if client_id in self.requests:
                del self.requests[client_id]

    def clear_all(self) -> None:
        """Clear all rate limit data (for testing)"""
        with self.lock:
            self.requests.clear()
