"""
tests/test_validators.py
-----------------------------------------------------------------------------
Unit tests for the validators module
-----------------------------------------------------------------------------
"""
import pytest
import sys
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts" / "9_utilities"))

from validators import (
    validate_ip,
    validate_ip_or_cidr,
    validate_threshold,
    validate_int,
    validate_positive_int,
    sanitize_string,
    validate_safe_string,
    validate_path,
    validate_config_value,
    validate_feature_vector,
)


class TestIPValidation:
    """Test IP address validation."""

    def test_valid_ipv4(self):
        """Valid IPv4 addresses should pass."""
        valid, error = validate_ip("192.168.1.100")
        assert valid is True
        assert error == ""

    def test_valid_ipv6(self):
        """Valid IPv6 addresses should pass."""
        valid, error = validate_ip("2001:db8::1")
        assert valid is True
        assert error == ""

    def test_empty_ip(self):
        """Empty IP should fail."""
        valid, error = validate_ip("")
        assert valid is False
        assert "empty" in error.lower()

    def test_none_ip(self):
        """None IP should fail."""
        valid, error = validate_ip(None)
        assert valid is False

    def test_loopback_rejected(self):
        """Loopback addresses should be rejected."""
        valid, error = validate_ip("127.0.0.1")
        assert valid is False
        assert "loopback" in error.lower()

    def test_injection_prevented(self):
        """Dangerous characters should be rejected."""
        valid, error = validate_ip("192.168.1.1; rm -rf /")
        assert valid is False
        assert "dangerous" in error.lower()

        valid, error = validate_ip("192.168.1.1 | cat /etc/passwd")
        assert valid is False

    def test_invalid_format(self):
        """Invalid IP format should fail."""
        valid, error = validate_ip("not-an-ip")
        assert valid is False


class TestCIDRValidation:
    """Test CIDR notation validation."""

    def test_valid_cidr(self):
        """Valid CIDR should pass."""
        valid, error = validate_ip_or_cidr("192.168.1.0/24")
        assert valid is True

    def test_valid_ip_without_prefix(self):
        """Single IP should also pass."""
        valid, error = validate_ip_or_cidr("192.168.1.1")
        assert valid is True

    def test_invalid_cidr(self):
        """Invalid CIDR should fail."""
        valid, error = validate_ip_or_cidr("192.168.1.0/99")
        assert valid is False


class TestNumericValidation:
    """Test numeric validation functions."""

    def test_threshold_valid(self):
        """Valid threshold should be returned."""
        assert validate_threshold(0.7) == 0.7
        assert validate_threshold("0.5") == 0.5

    def test_threshold_clamped(self):
        """Out-of-range threshold returns default."""
        assert validate_threshold(1.5, default=0.7) == 0.7
        assert validate_threshold(-0.1, default=0.7) == 0.7

    def test_threshold_invalid(self):
        """Invalid threshold returns default."""
        assert validate_threshold("not-a-number", default=0.7) == 0.7
        assert validate_threshold(None, default=0.7) == 0.7

    def test_int_valid(self):
        """Valid int should be returned."""
        assert validate_int(42) == 42
        assert validate_int("42") == 42

    def test_int_bounded(self):
        """Int out of bounds returns default."""
        assert validate_int(150, default=10, max_val=100) == 10
        assert validate_int(-5, default=10, min_val=0) == 10

    def test_positive_int(self):
        """Positive int validation."""
        assert validate_positive_int(5) == 5
        assert validate_positive_int(0, default=1) == 1
        assert validate_positive_int(-1, default=1) == 1


class TestStringValidation:
    """Test string validation and sanitization."""

    def test_sanitize_basic(self):
        """Basic sanitization should work."""
        assert sanitize_string("  hello  ") == "hello"
        assert sanitize_string(None) == ""

    def test_sanitize_length(self):
        """Length limit should be enforced."""
        long_string = "a" * 500
        result = sanitize_string(long_string, max_length=100)
        assert len(result) == 100

    def test_safe_string_valid(self):
        """Safe strings should pass."""
        valid, error = validate_safe_string("hello_world-123")
        assert valid is True

    def test_safe_string_invalid(self):
        """Strings with special chars should fail."""
        valid, error = validate_safe_string("hello world!")
        assert valid is False


class TestConfigValidation:
    """Test configuration value extraction."""

    def test_config_value_int(self):
        """Int config value extraction."""
        config = {"threshold": 5, "name": "test"}
        assert validate_config_value(config, "threshold", int) == 5
        assert validate_config_value(config, "missing", int, default=10) == 10

    def test_config_value_bool(self):
        """Bool config value extraction."""
        config = {"enabled": True, "disabled": "false"}
        assert validate_config_value(config, "enabled", bool) is True
        assert validate_config_value(config, "disabled", bool) is False

    def test_config_value_bounded(self):
        """Bounded config value extraction."""
        config = {"value": 150}
        assert validate_config_value(config, "value", int, default=10, max_val=100) == 10


class TestFeatureValidation:
    """Test ML feature vector validation."""

    def test_valid_features(self):
        """Valid feature vector should pass."""
        features = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0]
        valid, error, result = validate_feature_vector(features)
        assert valid is True
        assert len(result) == 13

    def test_wrong_length(self):
        """Wrong length should fail."""
        features = [1.0, 2.0, 3.0]
        valid, error, result = validate_feature_vector(features)
        assert valid is False
        assert "expected" in error.lower()

    def test_nan_rejected(self):
        """NaN values should be rejected."""
        features = [float('nan')] + [0.0] * 12
        valid, error, result = validate_feature_vector(features)
        assert valid is False
        assert "nan" in error.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
