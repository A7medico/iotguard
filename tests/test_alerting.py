"""
tests/test_alerting.py
-----------------------------------------------------------------------------
Unit tests for the alerting module (alerting.py)
-----------------------------------------------------------------------------
"""
import pytest
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))


class TestAlertingConfig:
    """Test alerting configuration loading"""
    
    def test_config_disabled_by_default(self):
        """Alerting should be disabled by default"""
        from alerting import _get_config
        
        # Clear env vars
        for key in list(os.environ.keys()):
            if key.startswith("IOTGUARD_"):
                del os.environ[key]
        
        cfg = _get_config()
        assert cfg["enabled"] is False
    
    def test_config_from_env(self):
        """Config should load from environment variables"""
        from alerting import _get_config
        
        os.environ["IOTGUARD_ALERTING_ENABLED"] = "true"
        os.environ["IOTGUARD_SLACK_WEBHOOK"] = "https://test.webhook"
        
        cfg = _get_config()
        
        assert cfg["enabled"] is True
        assert cfg["slack_webhook"] == "https://test.webhook"
        
        # Cleanup
        del os.environ["IOTGUARD_ALERTING_ENABLED"]
        del os.environ["IOTGUARD_SLACK_WEBHOOK"]


class TestSeverity:
    """Test severity levels"""
    
    def test_severity_colors_defined(self):
        """All severity levels should have colors"""
        from alerting import SEVERITY_COLORS
        
        assert "critical" in SEVERITY_COLORS
        assert "high" in SEVERITY_COLORS
        assert "medium" in SEVERITY_COLORS
        assert "low" in SEVERITY_COLORS
        assert "info" in SEVERITY_COLORS
    
    def test_severity_emoji_defined(self):
        """All severity levels should have emojis"""
        from alerting import SEVERITY_EMOJI
        
        assert "critical" in SEVERITY_EMOJI
        assert "high" in SEVERITY_EMOJI


class TestSendAlert:
    """Test the main send_alert function"""
    
    def test_send_alert_disabled(self):
        """send_alert should return all False when disabled"""
        from alerting import send_alert
        
        # Ensure alerting is disabled
        os.environ["IOTGUARD_ALERTING_ENABLED"] = "false"
        
        results = send_alert(
            title="Test",
            message="Test message",
            severity="high"
        )
        
        assert results["email"] is False
        assert results["slack"] is False
        assert results["telegram"] is False
    
    def test_rate_limiting(self):
        """Alerts should be rate limited"""
        from alerting import send_alert, _get_config
        import alerting
        
        # Reset last alert time
        alerting._last_alert_time = 0
        os.environ["IOTGUARD_ALERTING_ENABLED"] = "true"
        os.environ["IOTGUARD_ALERT_INTERVAL"] = "60"
        
        # First alert (should work but no channels configured)
        results1 = send_alert("Test1", "Message1", force=True)
        
        # Second alert within interval (should be rate limited)
        alerting._last_alert_time = float('inf')  # Simulate recent alert
        results2 = send_alert("Test2", "Message2")
        
        # All should be False due to rate limiting
        assert all(v is False for v in results2.values())
        
        # Cleanup
        del os.environ["IOTGUARD_ALERTING_ENABLED"]
        del os.environ["IOTGUARD_ALERT_INTERVAL"]


class TestSlackAlert:
    """Test Slack webhook alerting"""
    
    @patch("urllib.request.urlopen")
    def test_slack_alert_success(self, mock_urlopen):
        """Slack alert should succeed with valid webhook"""
        from alerting import send_slack_alert
        
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response
        
        cfg = {
            "slack_webhook": "https://hooks.slack.com/test"
        }
        
        result = send_slack_alert(
            title="Test Alert",
            message="Test message",
            severity="high",
            src_ip="192.168.1.100",
            cfg=cfg
        )
        
        assert result is True
        mock_urlopen.assert_called_once()
    
    def test_slack_alert_no_webhook(self):
        """Slack alert should fail gracefully without webhook"""
        from alerting import send_slack_alert
        
        result = send_slack_alert(
            title="Test",
            message="Test",
            cfg={"slack_webhook": ""}
        )
        
        assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
