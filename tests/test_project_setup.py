"""Tests to verify project setup and dependencies"""

import sys
import pytest


def test_python_version():
    """Verify Python version is 3.8 or higher and below 4.0"""
    version = sys.version_info
    assert version.major == 3
    assert version.minor >= 8
    assert version.major < 4


def test_playwright_import():
    """Verify Playwright can be imported"""
    try:
        import playwright
        assert playwright is not None
    except ImportError:
        pytest.fail("Playwright is not installed")


def test_hypothesis_import():
    """Verify Hypothesis can be imported"""
    try:
        import hypothesis
        assert hypothesis is not None
    except ImportError:
        pytest.fail("Hypothesis is not installed")


def test_pytest_import():
    """Verify pytest can be imported"""
    try:
        import pytest
        assert pytest is not None
    except ImportError:
        pytest.fail("pytest is not installed")


def test_python_dateutil_import():
    """Verify python-dateutil can be imported"""
    try:
        import dateutil
        assert dateutil is not None
    except ImportError:
        pytest.fail("python-dateutil is not installed")


def test_jsonschema_import():
    """Verify jsonschema can be imported"""
    try:
        import jsonschema
        assert jsonschema is not None
    except ImportError:
        pytest.fail("jsonschema is not installed")


def test_requests_import():
    """Verify requests can be imported"""
    try:
        import requests
        assert requests is not None
    except ImportError:
        pytest.fail("requests is not installed")


def test_project_structure():
    """Verify project directory structure exists"""
    import os
    
    # Get project root (parent of tests directory)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Check required directories exist
    assert os.path.isdir(os.path.join(project_root, "src"))
    assert os.path.isdir(os.path.join(project_root, "tests"))
    assert os.path.isdir(os.path.join(project_root, "config"))
    
    # Check required files exist
    assert os.path.isfile(os.path.join(project_root, "requirements.txt"))
    assert os.path.isfile(os.path.join(project_root, "pyproject.toml"))
    assert os.path.isfile(os.path.join(project_root, "README.md"))
    assert os.path.isfile(os.path.join(project_root, ".gitignore"))


def test_config_logging_exists():
    """Verify logging configuration module exists"""
    try:
        from config import logging_config
        assert hasattr(logging_config, "setup_logging")
        assert hasattr(logging_config, "get_logger")
        assert hasattr(logging_config, "JSONFormatter")
    except ImportError:
        pytest.fail("config.logging_config module not found")
