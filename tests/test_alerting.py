"""
tests/test_alerting.py
-----------------------------------------------------------------------------
Unit tests for the alert system (alerts.py / AlertManager)
-----------------------------------------------------------------------------
"""
import pytest
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts" / "4_response"))


class TestAlertManagerConfig:
    """Test AlertManager configuration loading"""

    def test_no_channels_by_default(self):
        """Without env vars, no external channels should be enabled"""
        # Clear relevant env vars
        saved = {}
        for key in list(os.environ.keys()):
            if key.startswith("IOTGUARD_SMTP") or key.startswith("IOTGUARD_SLACK"):
                saved[key] = os.environ.pop(key)

        from alerts import AlertManager
        manager = AlertManager()

        assert manager.email_enabled is False
        assert manager.slack_enabled is False

        # Restore
        os.environ.update(saved)

    def test_min_severity_default(self):
        """Default minimum severity should be 'medium'"""
        saved = os.environ.pop("IOTGUARD_ALERT_MIN_SEVERITY", None)

        from alerts import AlertManager
        manager = AlertManager()

        assert manager.min_severity == "medium"

        if saved is not None:
            os.environ["IOTGUARD_ALERT_MIN_SEVERITY"] = saved


class TestSeverityLevels:
    """Test severity level handling"""

    def test_severity_to_level(self):
        """Severity strings should map to correct numeric levels"""
        from alerts import AlertManager
        manager = AlertManager()

        assert manager._severity_to_level("low") == 1
        assert manager._severity_to_level("medium") == 2
        assert manager._severity_to_level("high") == 3
        assert manager._severity_to_level("critical") == 4

    def test_severity_emoji(self):
        """All severity levels should have emojis"""
        from alerts import AlertManager
        manager = AlertManager()

        for sev in ["low", "medium", "high", "critical"]:
            emoji = manager._get_emoji(sev)
            assert len(emoji) > 0, f"No emoji for severity '{sev}'"

    def test_should_alert_filtering(self):
        """Alerts below minimum severity should be suppressed"""
        from alerts import AlertManager
        manager = AlertManager()
        manager.min_severity = "high"

        assert manager._should_alert("low") is False
        assert manager._should_alert("medium") is False
        assert manager._should_alert("high") is True
        assert manager._should_alert("critical") is True


class TestSendAlert:
    """Test the main send_alert function"""

    def test_send_alert_below_threshold(self):
        """send_alert should suppress alerts below minimum severity"""
        from alerts import AlertManager
        manager = AlertManager()
        manager.min_severity = "critical"

        results = manager.send_alert(
            title="Test",
            message="Test message",
            severity="low"
        )

        # Console always True in result, but email/slack False
        assert results["email"] is False
        assert results["slack"] is False

    def test_send_alert_returns_dict(self):
        """send_alert should return a dict with channel statuses"""
        from alerts import AlertManager
        manager = AlertManager()
        manager.min_severity = "low"

        results = manager.send_alert(
            title="Test",
            message="Test message",
            severity="medium"
        )

        assert isinstance(results, dict)
        assert "console" in results
        assert "email" in results
        assert "slack" in results


class TestSendThreatAlert:
    """Test the convenience send_threat_alert function"""

    def test_send_threat_alert_returns_dict(self):
        """send_threat_alert should return channel status dict"""
        from alerts import send_threat_alert

        results = send_threat_alert(
            ip="192.168.1.100",
            score=0.95,
            attack_type="SYN_Flood"
        )

        assert isinstance(results, dict)
        assert "console" in results

    def test_get_alert_manager_singleton(self):
        """get_alert_manager should return the same instance"""
        from alerts import get_alert_manager

        m1 = get_alert_manager()
        m2 = get_alert_manager()

        assert m1 is m2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
