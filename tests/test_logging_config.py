"""Tests for logging configuration"""

import json
import logging
from io import StringIO
from config.logging_config import setup_logging, get_logger, JSONFormatter


def test_json_formatter_basic():
    """Test that JSONFormatter produces valid JSON output"""
    formatter = JSONFormatter()
    
    # Create a log record
    logger = logging.getLogger("test")
    record = logger.makeRecord(
        name="test.module",
        level=logging.INFO,
        fn="test.py",
        lno=42,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    
    # Format the record
    formatted = formatter.format(record)
    
    # Should be valid JSON
    log_data = json.loads(formatted)
    
    # Check required fields
    assert "timestamp" in log_data
    assert log_data["level"] == "INFO"
    assert log_data["logger"] == "test.module"
    assert log_data["message"] == "Test message"
    assert log_data["line"] == 42


def test_json_formatter_with_exception():
    """Test that JSONFormatter includes exception info"""
    formatter = JSONFormatter()
    
    try:
        raise ValueError("Test exception")
    except ValueError:
        logger = logging.getLogger("test")
        import sys
        exc_info = sys.exc_info()
        
        record = logger.makeRecord(
            name="test.exception",
            level=logging.ERROR,
            fn="test.py",
            lno=100,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )
        
        formatted = formatter.format(record)
        log_data = json.loads(formatted)
        
        assert "exception" in log_data
        assert "ValueError" in log_data["exception"]
        assert "Test exception" in log_data["exception"]


def test_setup_logging():
    """Test that setup_logging configures logger correctly"""
    # Setup logging with JSON format
    setup_logging(level="DEBUG", json_format=True)
    
    # Get root logger
    logger = logging.getLogger()
    
    # Should have at least one handler
    assert len(logger.handlers) >= 1
    
    # Should be set to DEBUG level
    assert logger.level == logging.DEBUG


def test_get_logger():
    """Test that get_logger returns a logger instance"""
    logger = get_logger("test.module")
    
    assert isinstance(logger, logging.Logger)
    assert logger.name == "test.module"


def test_logging_output_format():
    """Test that logging produces valid JSON output"""
    # Create string buffer to capture log output
    log_stream = StringIO()
    
    # Setup logging to write to our buffer
    logger = logging.getLogger("test.output")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    
    handler = logging.StreamHandler(log_stream)
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)
    
    # Log a message
    logger.info("Test log message")
    
    # Get the output
    output = log_stream.getvalue().strip()
    
    # Should be valid JSON
    log_data = json.loads(output)
    assert log_data["message"] == "Test log message"
    assert log_data["level"] == "INFO"
