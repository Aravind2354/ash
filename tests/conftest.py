"""Pytest configuration and shared fixtures."""

import os
import pytest


@pytest.fixture(scope="session")
def sandbox_container_id():
    """Get the SANDBOX_CONTAINER_ID from environment."""
    return os.environ.get('SANDBOX_CONTAINER_ID')
