"""Logging configuration for Website Authenticity Detector

Provides structured logging in JSON format for better log parsing and analysis.
"""

import logging
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict
from logging import LogRecord


class JSONFormatter(logging.Formatter):
    """Custom formatter that outputs logs in JSON format"""

    def format(self, record: LogRecord) -> str:
        """Format log record as JSON string
        
        Args:
            record: Log record to format
            
        Returns:
            JSON string representation of log record
        """
        log_data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields from record
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        return json.dumps(log_data)


def setup_logging(
    level: str = "INFO",
    log_file: str = None,
    json_format: bool = True
) -> None:
    """Set up logging configuration
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file. If None, logs to stdout only
        json_format: If True, use JSON formatter; otherwise use standard formatter
    """
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    logger.handlers.clear()

    # Create formatter
    if json_format:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    # Console handler (stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper()))
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, level.upper()))
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.info("Logging configured", extra={"extra_fields": {"log_level": level, "json_format": json_format}})


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the specified name
    
    Args:
        name: Logger name (typically __name__ of the module)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


# Default logging configuration
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_JSON_FORMAT = True
