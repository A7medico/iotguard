"""
scripts/logging_config.py
-----------------------------------------------------------------------------
IoTGuard Component — Centralized Logging Configuration

Purpose
    - Provide a consistent logging setup across all IoTGuard scripts.
    - Configure file rotation to prevent unbounded log growth.
    - Support both console and file output with different log levels.
    - Include structured JSON logging for production environments.

Usage
    from logging_config import get_logger
    logger = get_logger(__name__)
    logger.info("Processing started", extra={"rows": 100})

Environment Variables
    - IOTGUARD_LOG_LEVEL: Set log level (DEBUG, INFO, WARNING, ERROR). Default: INFO
    - IOTGUARD_LOG_JSON: Set to "1" for JSON-formatted logs. Default: False
-----------------------------------------------------------------------------
"""

import os
import sys
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime, timezone


# ---------- Configuration ----------
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

DEFAULT_LOG_LEVEL = os.getenv("IOTGUARD_LOG_LEVEL", "INFO").upper()
USE_JSON_LOGS = os.getenv("IOTGUARD_LOG_JSON", "").lower() in ("1", "true", "yes")

# Rotation settings: 5MB per file, keep 5 backups
MAX_BYTES = 5 * 1024 * 1024  # 5 MB
BACKUP_COUNT = 5


# ---------- Custom Formatters ----------
class ColoredFormatter(logging.Formatter):
    """Console formatter with colors for different log levels."""
    
    COLORS = {
        logging.DEBUG: "\033[36m",     # Cyan
        logging.INFO: "\033[32m",      # Green
        logging.WARNING: "\033[33m",   # Yellow
        logging.ERROR: "\033[31m",     # Red
        logging.CRITICAL: "\033[35m",  # Magenta
    }
    RESET = "\033[0m"
    
    def format(self, record):
        color = self.COLORS.get(record.levelno, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging (useful for log aggregation)."""
    
    def format(self, record):
        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add extra fields if present
        if hasattr(record, "extra_data"):
            log_obj.update(record.extra_data)
        
        # Add exception info if present
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_obj)


# ---------- Logger Factory ----------
_loggers = {}


def get_logger(name: str, log_file: str = None) -> logging.Logger:
    """
    Get or create a configured logger.
    
    Args:
        name: Logger name (typically __name__ of the calling module)
        log_file: Optional specific log file name. If None, uses 'iotguard.log'
    
    Returns:
        Configured logging.Logger instance
    """
    if name in _loggers:
        return _loggers[name]
    
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, DEFAULT_LOG_LEVEL, logging.INFO))
    
    # Prevent duplicate handlers if logger already exists
    if logger.handlers:
        _loggers[name] = logger
        return logger
    
    # ---------- Console Handler ----------
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    
    if USE_JSON_LOGS:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_format = "%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s"
        console_handler.setFormatter(ColoredFormatter(console_format, datefmt="%H:%M:%S"))
    
    logger.addHandler(console_handler)
    
    # ---------- File Handler (with rotation) ----------
    log_filename = log_file or "iotguard.log"
    log_path = LOG_DIR / log_filename
    
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)  # File gets all levels
    
    if USE_JSON_LOGS:
        file_handler.setFormatter(JSONFormatter())
    else:
        file_format = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        file_handler.setFormatter(logging.Formatter(file_format, datefmt="%Y-%m-%d %H:%M:%S"))
    
    logger.addHandler(file_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    _loggers[name] = logger
    return logger


def get_audit_logger() -> logging.Logger:
    """
    Get a specialized audit logger for security-relevant events.
    Writes to logs/audit.log with JSON format for easy parsing.
    """
    return get_logger("iotguard.audit", log_file="audit.log")


# ---------- Convenience Functions ----------
def log_event(logger: logging.Logger, level: str, message: str, **kwargs):
    """
    Log an event with additional structured data.
    
    Args:
        logger: Logger instance
        level: Log level as string (info, warning, error, etc.)
        message: Log message
        **kwargs: Additional fields to include in the log
    """
    log_func = getattr(logger, level.lower(), logger.info)
    
    # For JSON logging, attach extra data
    if kwargs:
        extra = {"extra_data": kwargs}
        log_func(message, extra=extra)
    else:
        log_func(message)


# ---------- Module-level logger for this file ----------
_module_logger = get_logger("logging_config")
_module_logger.debug("Logging configuration initialized")


