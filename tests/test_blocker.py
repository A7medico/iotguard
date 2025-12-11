"""
tests/test_blocker.py
-----------------------------------------------------------------------------
Unit tests for the IP blocking module (blocker.py)
-----------------------------------------------------------------------------
"""
import pytest
import sys
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from blocker import validate_ip, block_ip


class TestValidateIP:
    """Test IP address validation (security-critical)"""
    
    def test_valid_ipv4(self):
        """Valid IPv4 addresses should pass"""
        valid, msg = validate_ip("192.168.1.1")
        assert valid is True
        assert msg == ""
    
    def test_valid_ipv4_public(self):
        """Public IPv4 addresses should pass"""
        valid, msg = validate_ip("8.8.8.8")
        assert valid is True
    
    def test_invalid_format(self):
        """Invalid formats should fail"""
        valid, msg = validate_ip("not-an-ip")
        assert valid is False
        assert "Invalid IP" in msg
    
    def test_empty_ip(self):
        """Empty IP should fail"""
        valid, msg = validate_ip("")
        assert valid is False
        assert "empty" in msg.lower()
    
    def test_none_ip(self):
        """None IP should fail"""
        valid, msg = validate_ip(None)
        assert valid is False
    
    def test_loopback_blocked(self):
        """Loopback addresses cannot be blocked (safety)"""
        valid, msg = validate_ip("127.0.0.1")
        assert valid is False
        assert "loopback" in msg.lower()
    
    def test_link_local_blocked(self):
        """Link-local addresses cannot be blocked"""
        valid, msg = validate_ip("169.254.1.1")
        assert valid is False
        assert "link-local" in msg.lower()
    
    def test_command_injection_semicolon(self):
        """Command injection with semicolon should be rejected"""
        valid, msg = validate_ip("192.168.1.1; rm -rf /")
        assert valid is False
        assert "dangerous" in msg.lower()
    
    def test_command_injection_pipe(self):
        """Command injection with pipe should be rejected"""
        valid, msg = validate_ip("192.168.1.1 | cat /etc/passwd")
        assert valid is False
        assert "dangerous" in msg.lower()
    
    def test_command_injection_backtick(self):
        """Command injection with backtick should be rejected"""
        valid, msg = validate_ip("192.168.1.1`whoami`")
        assert valid is False
        assert "dangerous" in msg.lower()
    
    def test_ipv6_valid(self):
        """Valid IPv6 addresses should pass"""
        valid, msg = validate_ip("2001:db8::1")
        assert valid is True


class TestBlockIP:
    """Test the block_ip function"""
    
    def test_block_none_ip(self):
        """Blocking None should fail gracefully"""
        success, msg = block_ip(None)
        assert success is False
        assert "no ip" in msg.lower()
    
    def test_block_invalid_ip(self):
        """Blocking invalid IP should fail with validation error"""
        success, msg = block_ip("invalid")
        assert success is False
        assert "validation" in msg.lower()
    
    def test_block_loopback_rejected(self):
        """Blocking loopback should be rejected"""
        success, msg = block_ip("127.0.0.1")
        assert success is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
