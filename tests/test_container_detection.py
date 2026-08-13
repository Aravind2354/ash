"""Focused tests for container environment detection logic.

These tests verify the _detect_container_environment helper correctly identifies
container environments while maintaining fail-closed security.
"""

import os
import sys
import pytest
from unittest.mock import patch, mock_open

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.sandbox import SandboxManager
from src.violation_monitor import ViolationMonitor


class TestContainerDetection:
    """Test container environment detection logic."""

    @pytest.fixture
    def sandbox_manager(self):
        """Create a SandboxManager for testing."""
        violation_monitor = ViolationMonitor()
        return SandboxManager(violation_monitor=violation_monitor)

    def test_detects_docker_via_dockerenv_file(self, sandbox_manager):
        """Test that /.dockerenv file indicates Docker environment."""
        with patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            assert sandbox_manager._detect_container_environment() is True
            mock_exists.assert_called_with('/.dockerenv')

    def test_detects_docker_via_cgroup_v1_docker_marker(self, sandbox_manager):
        """Test that cgroup v1 'docker' marker indicates container."""
        with patch('os.path.exists', return_value=False):
            with patch('builtins.open', mock_open(read_data='12:pids:/docker/abc123\n')):
                assert sandbox_manager._detect_container_environment() is True

    def test_detects_kubernetes_via_cgroup_v1_kubepods_marker(self, sandbox_manager):
        """Test that cgroup v1 'kubepods' marker indicates container."""
        with patch('os.path.exists', return_value=False):
            with patch('builtins.open', mock_open(read_data='12:pids:/kubepods/pod123\n')):
                assert sandbox_manager._detect_container_environment() is True

    def test_cgroup_v2_without_dockerenv_not_detected(self, sandbox_manager):
        """Test that cgroup v2 '0::/' without /.dockerenv is NOT detected as container."""
        with patch('os.path.exists', return_value=False):
            with patch('builtins.open', mock_open(read_data='0::/\n')):
                assert sandbox_manager._detect_container_environment() is False

    def test_non_container_environment_rejected(self, sandbox_manager):
        """Test that ordinary non-container environment is rejected."""
        with patch('os.path.exists', return_value=False):
            with patch('builtins.open', mock_open(read_data='')):
                assert sandbox_manager._detect_container_environment() is False

    def test_cgroup_read_failure_handled_gracefully(self, sandbox_manager):
        """Test that cgroup read failure is handled gracefully."""
        with patch('os.path.exists', return_value=False):
            with patch('builtins.open', side_effect=FileNotFoundError):
                assert sandbox_manager._detect_container_environment() is False


class TestIsolationValidationWithDetection:
    """Test isolation validation with container detection."""

    @pytest.fixture
    def sandbox_manager(self):
        """Create a SandboxManager for testing."""
        violation_monitor = ViolationMonitor()
        return SandboxManager(violation_monitor=violation_monitor)

    def test_detected_container_without_validation_fails(self, sandbox_manager):
        """Test that detected container without validation state FAILS."""
        with patch('os.path.exists', return_value=True):
            is_valid, message = sandbox_manager.validate_isolation()
            assert is_valid is False
            assert "not been validated" in message

    def test_detected_container_without_container_id_fails(self, sandbox_manager):
        """Test that detected container without container_id FAILS."""
        sandbox_manager._isolation_validated = True
        sandbox_manager._container_id = None

        with patch('os.path.exists', return_value=True):
            is_valid, message = sandbox_manager.validate_isolation()
            assert is_valid is False
            assert "not been validated" in message

    def test_detected_container_with_valid_state_passes(self, sandbox_manager):
        """Test that detected container with valid validation state PASSES."""
        sandbox_manager._isolation_validated = True
        sandbox_manager._container_id = "test-container-id"

        with patch('os.path.exists', return_value=True):
            is_valid, message = sandbox_manager.validate_isolation()
            assert is_valid is True
            assert message == ""

    def test_non_container_environment_fails_closed(self, sandbox_manager):
        """Test that non-container environment FAILS CLOSED."""
        with patch('os.path.exists', return_value=False):
            with patch('builtins.open', mock_open(read_data='')):
                is_valid, message = sandbox_manager.validate_isolation()
                assert is_valid is False
                assert "NOT running in a Docker container" in message

    def test_detection_failure_fails_closed(self, sandbox_manager):
        """Test that detection failure causes FAIL CLOSED."""
        with patch.object(sandbox_manager, '_detect_container_environment', side_effect=Exception("Detection failed")):
            is_valid, message = sandbox_manager.validate_isolation()
            assert is_valid is False
            # Should fail closed on detection error
            assert "NOT running in a Docker container" in message
