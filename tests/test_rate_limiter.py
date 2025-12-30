"""
tests/test_rate_limiter.py
-----------------------------------------------------------------------------
Unit tests for the rate limiting and access control module
-----------------------------------------------------------------------------
"""
import pytest
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts" / "9_utilities"))


class TestAccessControl:
    """Test IP allowlist/blocklist access control."""

    def test_empty_access_control(self):
        """Empty config should allow all IPs."""
        from rate_limiter import AccessControl

        with patch("rate_limiter._load_config", return_value={}):
            ac = AccessControl()
            assert ac.is_allowlisted("192.168.1.100") is False
            assert ac.is_blocklisted("192.168.1.100") is False

    def test_allowlist_match(self):
        """IPs on allowlist should be detected."""
        from rate_limiter import AccessControl

        config = {"allowlist": ["192.168.1.100", "10.0.0.0/24"]}
        with patch("rate_limiter._load_config", return_value=config):
            ac = AccessControl()

            # Exact match
            assert ac.is_allowlisted("192.168.1.100") is True

            # CIDR match
            assert ac.is_allowlisted("10.0.0.50") is True
            assert ac.is_allowlisted("10.0.0.255") is True

            # Non-match
            assert ac.is_allowlisted("192.168.1.101") is False
            assert ac.is_allowlisted("10.0.1.1") is False

    def test_blocklist_match(self):
        """IPs on blocklist should be detected."""
        from rate_limiter import AccessControl

        config = {"blocklist": ["1.2.3.4", "203.0.113.0/24"]}
        with patch("rate_limiter._load_config", return_value=config):
            ac = AccessControl()

            # Exact match
            assert ac.is_blocklisted("1.2.3.4") is True

            # CIDR match
            assert ac.is_blocklisted("203.0.113.100") is True

            # Non-match
            assert ac.is_blocklisted("1.2.3.5") is False

    def test_check_access_blocklist_precedence(self):
        """Blocklist should take precedence over allowlist."""
        from rate_limiter import AccessControl

        config = {
            "allowlist": ["192.168.1.0/24"],
            "blocklist": ["192.168.1.100"],  # Specific IP on blocklist
        }
        with patch("rate_limiter._load_config", return_value=config):
            ac = AccessControl()

            # Blocklisted IP (even though in allowlist range)
            action, skip_ml = ac.check_access("192.168.1.100")
            assert action == "block"
            assert skip_ml is True

            # Allowlisted IP (not on blocklist)
            action, skip_ml = ac.check_access("192.168.1.50")
            assert action == "allow"
            assert skip_ml is True

            # Neither list
            action, skip_ml = ac.check_access("8.8.8.8")
            assert action == "check"
            assert skip_ml is False

    def test_get_stats(self):
        """get_stats should return configuration info."""
        from rate_limiter import AccessControl

        config = {
            "allowlist": ["192.168.1.1", "10.0.0.0/24"],
            "blocklist": ["1.2.3.4"],
        }
        with patch("rate_limiter._load_config", return_value=config):
            ac = AccessControl()
            stats = ac.get_stats()

            assert stats["allowlist_count"] == 2
            assert stats["blocklist_count"] == 1


class TestRateLimiter:
    """Test rate limiting functionality."""

    def test_allows_under_limit(self):
        """Requests under limit should be allowed."""
        from rate_limiter import RateLimiter

        config = {"rate_limiting": {"enabled": True, "default_limit": 10, "window_seconds": 60}}
        with patch("rate_limiter._load_config", return_value=config):
            limiter = RateLimiter()

            # First 10 requests should be allowed
            for _ in range(10):
                assert limiter.is_allowed("192.168.1.100") is True

    def test_blocks_over_limit(self):
        """Requests over limit should be blocked."""
        from rate_limiter import RateLimiter

        config = {"rate_limiting": {"enabled": True, "default_limit": 5, "window_seconds": 60}}
        with patch("rate_limiter._load_config", return_value=config):
            limiter = RateLimiter()

            # First 5 requests should be allowed
            for _ in range(5):
                assert limiter.is_allowed("192.168.1.100") is True

            # 6th request should be blocked
            assert limiter.is_allowed("192.168.1.100") is False

    def test_disabled_allows_all(self):
        """Disabled rate limiting should allow all requests."""
        from rate_limiter import RateLimiter

        config = {"rate_limiting": {"enabled": False, "default_limit": 1}}
        with patch("rate_limiter._load_config", return_value=config):
            limiter = RateLimiter()

            # Should allow many requests even with limit=1
            for _ in range(100):
                assert limiter.is_allowed("192.168.1.100") is True

    def test_exempt_ips_bypass(self):
        """Exempt IPs should bypass rate limiting."""
        from rate_limiter import RateLimiter

        config = {
            "rate_limiting": {
                "enabled": True,
                "default_limit": 1,
                "exempt_ips": ["127.0.0.1"],
            }
        }
        with patch("rate_limiter._load_config", return_value=config):
            limiter = RateLimiter()

            # Exempt IP should bypass limits
            for _ in range(100):
                assert limiter.is_allowed("127.0.0.1") is True

    def test_per_ip_isolation(self):
        """Rate limits should be per-IP."""
        from rate_limiter import RateLimiter

        config = {"rate_limiting": {"enabled": True, "default_limit": 2, "window_seconds": 60}}
        with patch("rate_limiter._load_config", return_value=config):
            limiter = RateLimiter()

            # IP 1 uses its limit
            assert limiter.is_allowed("192.168.1.100") is True
            assert limiter.is_allowed("192.168.1.100") is True
            assert limiter.is_allowed("192.168.1.100") is False

            # IP 2 has its own limit
            assert limiter.is_allowed("192.168.1.101") is True
            assert limiter.is_allowed("192.168.1.101") is True
            assert limiter.is_allowed("192.168.1.101") is False

    def test_get_remaining(self):
        """get_remaining should return correct count."""
        from rate_limiter import RateLimiter

        config = {"rate_limiting": {"enabled": True, "default_limit": 5, "window_seconds": 60}}
        with patch("rate_limiter._load_config", return_value=config):
            limiter = RateLimiter()

            # Initial remaining should be 5
            assert limiter.get_remaining("192.168.1.100") == 5

            # After 3 requests, remaining should be 2
            limiter.is_allowed("192.168.1.100")
            limiter.is_allowed("192.168.1.100")
            limiter.is_allowed("192.168.1.100")
            assert limiter.get_remaining("192.168.1.100") == 2

    def test_reset(self):
        """reset should clear rate limit counters."""
        from rate_limiter import RateLimiter

        config = {"rate_limiting": {"enabled": True, "default_limit": 2, "window_seconds": 60}}
        with patch("rate_limiter._load_config", return_value=config):
            limiter = RateLimiter()

            # Use up limit
            limiter.is_allowed("192.168.1.100")
            limiter.is_allowed("192.168.1.100")
            assert limiter.is_allowed("192.168.1.100") is False

            # Reset and try again
            limiter.reset("192.168.1.100")
            assert limiter.is_allowed("192.168.1.100") is True


class TestCheckRateLimit:
    """Test the Flask integration helper."""

    def test_check_rate_limit_returns_headers(self):
        """check_rate_limit should return proper headers."""
        from rate_limiter import check_rate_limit

        config = {"rate_limiting": {"enabled": True, "default_limit": 100, "window_seconds": 60}}
        with patch("rate_limiter._load_config", return_value=config):
            allowed, headers = check_rate_limit("192.168.1.100")

            assert allowed is True
            assert "X-RateLimit-Limit" in headers
            assert "X-RateLimit-Remaining" in headers
            assert "X-RateLimit-Window" in headers


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
