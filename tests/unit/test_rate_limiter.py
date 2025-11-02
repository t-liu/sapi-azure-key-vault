"""
Unit tests for Rate Limiter
"""

import pytest
import time
from app.rate_limiter import RateLimiter


class TestRateLimiter:
    """Test RateLimiter class"""

    def test_initialization(self):
        """Test rate limiter initialization"""
        limiter = RateLimiter(max_requests=10, window_seconds=60)
        assert limiter.max_requests == 10
        assert limiter.window_seconds == 60
        assert limiter.requests == {}

    def test_first_request_allowed(self):
        """Test that first request is always allowed"""
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        assert limiter.is_allowed("client1") is True

    def test_within_limit_allowed(self):
        """Test that requests within limit are allowed"""
        limiter = RateLimiter(max_requests=5, window_seconds=60)

        for i in range(5):
            assert limiter.is_allowed("client1") is True, f"Request {i + 1} should be allowed"

    def test_exceeds_limit_blocked(self):
        """Test that requests exceeding limit are blocked"""
        limiter = RateLimiter(max_requests=5, window_seconds=60)

        # Make 5 allowed requests
        for _ in range(5):
            limiter.is_allowed("client1")

        # 6th request should be blocked
        assert limiter.is_allowed("client1") is False

    def test_different_clients_separate_limits(self):
        """Test that different clients have separate limits"""
        limiter = RateLimiter(max_requests=3, window_seconds=60)

        # Client 1 uses all 3 requests
        for _ in range(3):
            assert limiter.is_allowed("client1") is True

        # Client 1's 4th request blocked
        assert limiter.is_allowed("client1") is False

        # Client 2 should still have full quota
        assert limiter.is_allowed("client2") is True

    def test_window_expiry(self):
        """Test that old requests expire after window"""
        limiter = RateLimiter(max_requests=2, window_seconds=1)

        # Use up the quota
        assert limiter.is_allowed("client1") is True
        assert limiter.is_allowed("client1") is True
        assert limiter.is_allowed("client1") is False

        # Wait for window to expire
        time.sleep(1.1)

        # Should be allowed again
        assert limiter.is_allowed("client1") is True

    def test_get_remaining(self):
        """Test get_remaining returns correct count"""
        limiter = RateLimiter(max_requests=5, window_seconds=60)

        assert limiter.get_remaining("client1") == 5

        limiter.is_allowed("client1")
        assert limiter.get_remaining("client1") == 4

        limiter.is_allowed("client1")
        assert limiter.get_remaining("client1") == 3

    def test_reset_client(self):
        """Test resetting a specific client"""
        limiter = RateLimiter(max_requests=2, window_seconds=60)

        # Use up quota
        limiter.is_allowed("client1")
        limiter.is_allowed("client1")
        assert limiter.is_allowed("client1") is False

        # Reset client
        limiter.reset("client1")

        # Should be allowed again
        assert limiter.is_allowed("client1") is True

    def test_clear_all(self):
        """Test clearing all rate limit data"""
        limiter = RateLimiter(max_requests=2, window_seconds=60)

        # Multiple clients use quota
        limiter.is_allowed("client1")
        limiter.is_allowed("client2")

        assert len(limiter.requests) == 2

        # Clear all
        limiter.clear_all()

        assert len(limiter.requests) == 0

    def test_thread_safety_simulation(self):
        """Test that rate limiter handles concurrent-like requests"""
        limiter = RateLimiter(max_requests=10, window_seconds=60)

        # Simulate rapid requests
        allowed_count = 0
        for _ in range(15):
            if limiter.is_allowed("client1"):
                allowed_count += 1

        # Should allow exactly 10
        assert allowed_count == 10

    def test_partial_window_expiry(self):
        """Test that only old requests expire, not all"""
        limiter = RateLimiter(max_requests=3, window_seconds=1)

        # First request
        assert limiter.is_allowed("client1") is True

        # Wait 0.6 seconds
        time.sleep(0.6)

        # Second and third requests
        assert limiter.is_allowed("client1") is True
        assert limiter.is_allowed("client1") is True

        # Fourth should be blocked
        assert limiter.is_allowed("client1") is False

        # Wait for first request to expire (another 0.5 seconds)
        time.sleep(0.5)

        # Should be allowed again (first request expired)
        assert limiter.is_allowed("client1") is True
