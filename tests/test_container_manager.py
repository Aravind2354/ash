"""Unit tests for ContainerManager.

Tests the ContainerManager class that creates and validates Docker containers
with isolation enforcement before use.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

# Add src to path for imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from src.container_manager import ContainerManager
    from src.violation_monitor import ViolationMonitor
    docker_available = True
except ImportError:
    docker_available = False


@pytest.mark.skipif(not docker_available, reason="Docker Python SDK not installed")
class TestContainerManager:
    """Test ContainerManager isolation validation."""

    @pytest.fixture
    def container_manager(self):
        """Create a ContainerManager instance for testing."""
        with patch('src.container_manager.docker'):
            with patch('src.container_validator.ContainerValidator'):
                with patch('src.container_validator.docker'):
                    with patch('src.isolation_orchestrator.IsolationOrchestrator'):
                        with patch('src.isolation_orchestrator.docker'):
                            violation_monitor = ViolationMonitor()
                            return ContainerManager(violation_monitor=violation_monitor)

    @pytest.fixture
    def mock_container(self):
        """Create a mock Docker container."""
        container = Mock()
        container.id = 'abc123def456789'
        container.start = Mock()
        container.remove = Mock()
        return container

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock()
        return client

    def test_validate_isolation_passes(self, container_manager, mock_container):
        """Test that validate_isolation returns (True, "") when validation passes."""
        with patch.object(container_manager.isolation_orchestrator, 'validate_isolation') as mock_validate:
            # Mock successful validation
            mock_assessment = Mock()
            mock_assessment.valid = True
            mock_assessment.assessment_type = "PASS"
            mock_assessment.error_message = None
            mock_assessment.security_critical_failures = []
            mock_assessment.timestamp = datetime.now(timezone.utc)
            mock_assessment.evidence = Mock()
            mock_assessment.evidence.network_evidence = {}  # Empty dict to avoid type error
            mock_validate.return_value = mock_assessment

            is_valid, error_msg = container_manager.validate_isolation(mock_container)

            assert is_valid is True
            assert error_msg == ""
            mock_validate.assert_called_once_with(mock_container)

    def test_validate_isolation_fails(self, container_manager, mock_container):
        """Test that validate_isolation returns (False, error) when validation fails."""
        with patch.object(container_manager.isolation_orchestrator, 'validate_isolation') as mock_validate:
            # Mock failed validation
            mock_assessment = Mock()
            mock_assessment.valid = False
            mock_assessment.assessment_type = "FAIL"
            mock_assessment.error_message = "Privileged mode enabled"
            mock_assessment.security_critical_failures = ["privileged"]
            mock_assessment.timestamp = datetime.now(timezone.utc)
            mock_assessment.evidence = Mock()
            mock_assessment.evidence.network_evidence = {}  # Empty dict to avoid type error
            mock_validate.return_value = mock_assessment

            is_valid, error_msg = container_manager.validate_isolation(mock_container)

            assert is_valid is False
            assert "Privileged mode enabled" in error_msg
            assert "privileged" in error_msg
            mock_validate.assert_called_once_with(mock_container)

    def test_create_container_validates_before_returning(self, container_manager, mock_docker_client):
        """Test that create_container validates isolation before returning container."""
        with patch.object(container_manager, 'docker_client', mock_docker_client):
            with patch.object(container_manager, 'validate_isolation') as mock_validate:
                # Mock container creation
                mock_container = Mock()
                mock_container.id = 'abc123def456789'
                mock_container.start = Mock()
                mock_docker_client.containers.create.return_value = mock_container

                # Mock successful validation
                mock_validate.return_value = (True, "")

                container = container_manager.create_container()

                assert container == mock_container
                mock_validate.assert_called_once_with(mock_container)

    def test_create_container_terminates_on_validation_failure(self, container_manager, mock_docker_client):
        """Test that create_container terminates container on validation failure."""
        with patch.object(container_manager, 'docker_client', mock_docker_client):
            with patch.object(container_manager, 'validate_isolation') as mock_validate:
                # Mock container creation
                mock_container = Mock()
                mock_container.id = 'abc123def456789'
                mock_container.start = Mock()
                mock_container.remove = Mock()
                mock_docker_client.containers.create.return_value = mock_container

                # Mock failed validation
                mock_validate.return_value = (False, "Privileged mode enabled")

                # Should raise RuntimeError
                with pytest.raises(RuntimeError) as exc_info:
                    container_manager.create_container()

                assert "isolation validation failed" in str(exc_info.value)
                assert "Privileged mode enabled" in str(exc_info.value)
                mock_container.remove.assert_called_once_with(force=True)

    def test_get_container_raises_when_no_container(self, container_manager):
        """Test that get_container raises when no validated container exists."""
        with pytest.raises(RuntimeError) as exc_info:
            container_manager.get_container()

        assert "No validated container exists" in str(exc_info.value)

    def test_get_container_returns_validated_container(self, container_manager, mock_container):
        """Test that get_container returns validated container."""
        container_manager.current_container = mock_container
        container_manager._is_validated = True

        result = container_manager.get_container()

        assert result == mock_container

    def test_reset_container_terminates_and_creates_new(self, container_manager, mock_container):
        """Test that reset_container terminates and creates new container."""
        container_manager.current_container = mock_container
        with patch.object(container_manager, 'create_container') as mock_create:
            mock_create.return_value = mock_container

            result = container_manager.reset_container()

            # Verify container was terminated (remove called)
            mock_container.remove.assert_called_once_with(force=True)
            mock_create.assert_called_once()
            assert result == mock_container

    def test_terminate_container_force(self, container_manager, mock_container):
        """Test that terminate_container with force=True force terminates."""
        container_manager.current_container = mock_container

        container_manager.terminate_container(force=True)

        mock_container.remove.assert_called_once_with(force=True)
        assert container_manager.current_container is None
        assert container_manager._is_validated is False

    def test_cleanup(self, container_manager):
        """Test that cleanup terminates container."""
        with patch.object(container_manager, 'terminate_container') as mock_terminate:
            container_manager.cleanup()

            mock_terminate.assert_called_once_with(force=True)

    def test_check_for_violations_logs_internal_ips(self, container_manager):
        """Test that _check_for_violations logs internal IP addresses."""
        mock_assessment = Mock()
        mock_assessment.evidence = Mock()
        mock_assessment.evidence.network_evidence = {
            'network_interface_evidence': Mock(
                passed=True,
                observed_value={'addresses': ['192.168.1.1', '8.8.8.8']}
            )
        }

        container_manager._check_for_violations(mock_assessment, 'abc123')

        # Should have logged violation for 192.168.1.1 but not 8.8.8.8
        violations = container_manager.violation_monitor.get_violations()
        assert len(violations) == 1
        assert violations[0]['target'] == '192.168.1.1'
        assert violations[0]['violation_type'] == 'internal_network'

    def test_check_for_violations_with_empty_evidence(self, container_manager):
        """Test that _check_for_violations handles empty evidence gracefully."""
        mock_assessment = Mock()
        mock_assessment.evidence = Mock()
        mock_assessment.evidence.network_evidence = {}

        # Should not raise error
        container_manager._check_for_violations(mock_assessment, 'abc123')

        # Should not have logged any violations
        assert not container_manager.violation_monitor.has_violations()

    def test_check_for_violations_skips_public_ips(self, container_manager):
        """Test that _check_for_violations skips public IP addresses."""
        mock_assessment = Mock()
        mock_assessment.evidence = Mock()
        mock_assessment.evidence.network_evidence = {
            'network_interface_evidence': Mock(
                passed=True,
                observed_value={'addresses': ['8.8.8.8', '1.1.1.1']}
            )
        }

        container_manager._check_for_violations(mock_assessment, 'abc123')

        # Should not have logged any violations
        assert not container_manager.violation_monitor.has_violations()

    def test_check_for_violations_with_empty_evidence(self, container_manager):
        """Test that _check_for_violations handles empty evidence gracefully."""
        mock_assessment = Mock()
        mock_assessment.evidence = Mock()
        mock_assessment.evidence.network_evidence = {}

        # Should not raise error
        container_manager._check_for_violations(mock_assessment, 'abc123')

        # Should not have logged any violations
        assert not container_manager.violation_monitor.has_violations()
