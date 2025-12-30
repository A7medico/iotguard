"""
tests/test_logging_config.py
-----------------------------------------------------------------------------
Unit tests for the logging configuration module (logging_config.py)
-----------------------------------------------------------------------------
"""
import pytest
import sys
import os
import json
import logging
from pathlib import Path
from unittest.mock import patch

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts" / "9_utilities"))


class TestGetLogger:
    """Test the get_logger function."""

    def test_get_logger_returns_logger(self):
        """get_logger should return a logging.Logger instance."""
        from logging_config import get_logger

        logger = get_logger("test_module")
        assert isinstance(logger, logging.Logger)

    def test_get_logger_same_name_returns_same_logger(self):
        """Getting the same logger name should return the same instance."""
        from logging_config import get_logger

        logger1 = get_logger("test_same_name")
        logger2 = get_logger("test_same_name")
        assert logger1 is logger2

    def test_get_logger_different_names(self):
        """Different names should return different loggers."""
        from logging_config import get_logger

        logger1 = get_logger("test_name_a")
        logger2 = get_logger("test_name_b")
        assert logger1 is not logger2

    def test_logger_has_handlers(self):
        """Logger should have handlers configured."""
        from logging_config import get_logger

        logger = get_logger("test_handlers")
        assert len(logger.handlers) > 0


class TestAuditLogger:
    """Test the audit logger."""

    def test_get_audit_logger(self):
        """get_audit_logger should return a logger."""
        from logging_config import get_audit_logger

        audit_logger = get_audit_logger()
        assert isinstance(audit_logger, logging.Logger)
        assert "audit" in audit_logger.name.lower()


class TestLogEvent:
    """Test the log_event helper function."""

    def test_log_event_basic(self):
        """log_event should log a basic message."""
        from logging_config import get_logger, log_event

        logger = get_logger("test_log_event")

        # Should not raise
        log_event(logger, "info", "Test message")

    def test_log_event_with_extra_data(self):
        """log_event should handle extra data."""
        from logging_config import get_logger, log_event

        logger = get_logger("test_log_event_extra")

        # Should not raise
        log_event(logger, "warning", "Test with data", user_id=123, action="block")


class TestJSONFormatter:
    """Test the JSON formatter for structured logging."""

    def test_json_formatter_output(self):
        """JSONFormatter should produce valid JSON."""
        from logging_config import JSONFormatter

        formatter = JSONFormatter()

        # Create a log record
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        # Should be valid JSON
        parsed = json.loads(output)
        assert "timestamp" in parsed
        assert "level" in parsed
        assert parsed["level"] == "INFO"
        assert "message" in parsed
        assert parsed["message"] == "Test message"


class TestColoredFormatter:
    """Test the colored console formatter."""

    def test_colored_formatter_has_colors(self):
        """ColoredFormatter should have color codes defined."""
        from logging_config import ColoredFormatter

        formatter = ColoredFormatter("%(levelname)s: %(message)s")

        # Should have color mappings
        assert logging.DEBUG in formatter.COLORS
        assert logging.INFO in formatter.COLORS
        assert logging.WARNING in formatter.COLORS
        assert logging.ERROR in formatter.COLORS
        assert logging.CRITICAL in formatter.COLORS

    def test_colored_formatter_formats_message(self):
        """ColoredFormatter should format messages."""
        from logging_config import ColoredFormatter

        formatter = ColoredFormatter("%(levelname)s: %(message)s")

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=10,
            msg="Error occurred",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        # Should contain the message
        assert "Error occurred" in output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
