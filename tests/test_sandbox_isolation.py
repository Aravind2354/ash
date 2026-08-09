"""Unit tests for SandboxManager isolation validation integration.

Tests the SandboxManager.validate_isolation() method and integration
with isolation validation before website loading and runtime violation monitoring.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock, AsyncMock, mock_open
from datetime import datetime, timezone

# Add src to path for imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.sandbox import SandboxManager
from src.violation_monitor import ViolationMonitor


class TestSandboxManagerIsolationValidation:
    """Test SandboxManager isolation validation."""

    @pytest.fixture
    def sandbox_manager(self):
        """Create a SandboxManager instance for testing."""
        return SandboxManager()

    def test_validate_isolation_in_container_validated(self, sandbox_manager):
        """Test validate_isolation returns True when running in validated container."""
        with patch('builtins.open', mock_open(read_data='docker')):
            sandbox_manager._isolation_validated = True
            sandbox_manager._container_id = 'abc123'

            is_valid, error_msg = sandbox_manager.validate_isolation()

            assert is_valid is True
            assert error_msg == ""

    def test_validate_isolation_in_container_not_validated(self, sandbox_manager):
        """Test validate_isolation returns False when container not validated."""
        with patch('builtins.open', mock_open(read_data='docker')):
            sandbox_manager._isolation_validated = False

            is_valid, error_msg = sandbox_manager.validate_isolation()

            assert is_valid is False
            assert "not been validated" in error_msg

    def test_validate_isolation_not_in_container(self, sandbox_manager):
        """Test validate_isolation fails closed when not running in container."""
        with patch('builtins.open', side_effect=FileNotFoundError):
            is_valid, error_msg = sandbox_manager.validate_isolation()

            # Returns False with fail-closed behavior for local development
            assert is_valid is False
            assert "NOT running in a Docker container" in error_msg

    def test_set_isolation_validated(self, sandbox_manager):
        """Test set_isolation_validated marks container as validated."""
        sandbox_manager.set_isolation_validated('abc123')

        assert sandbox_manager._isolation_validated is True
        assert sandbox_manager._container_id == 'abc123'


@pytest.mark.asyncio
class TestSandboxIsolationValidation:
    """Test Sandbox isolation validation before URL loading."""

    @pytest.fixture
    def sandbox_manager(self):
        """Create a SandboxManager instance for testing."""
        return SandboxManager()

    @pytest.fixture
    def mock_sandbox(self, sandbox_manager):
        """Create a mock Sandbox."""
        from src.sandbox import Sandbox
        mock_browser = Mock()
        mock_context = Mock()
        sandbox = Sandbox(mock_browser, mock_context, sandbox_manager)
        sandbox.page = Mock()
        sandbox.page.goto = AsyncMock(return_value=None)
        return sandbox

    async def test_load_url_validates_isolation(self, mock_sandbox):
        """Test that load_url validates isolation before loading."""
        mock_sandbox.sandbox_manager._isolation_validated = True
        mock_sandbox.sandbox_manager._container_id = 'abc123'

        with patch.object(mock_sandbox.sandbox_manager, 'validate_isolation') as mock_validate:
            mock_validate.return_value = (True, "")
            mock_sandbox.page.goto = AsyncMock(return_value=None)

            result = await mock_sandbox.load_url("https://example.com")

            assert result is True
            mock_validate.assert_called_once()

    async def test_load_url_blocks_on_validation_failure(self, mock_sandbox):
        """Test that load_url blocks URL when validation fails."""
        mock_sandbox.sandbox_manager._isolation_validated = False

        with patch.object(mock_sandbox.sandbox_manager, 'validate_isolation') as mock_validate:
            with patch.object(mock_sandbox.sandbox_manager, 'terminate_sandbox') as mock_terminate:
                mock_validate.return_value = (False, "Isolation not validated")

                with pytest.raises(RuntimeError) as exc_info:
                    await mock_sandbox.load_url("https://example.com")

                assert "Isolation validation failed" in str(exc_info.value)
                mock_terminate.assert_called_once_with(force=True)


from unittest.mock import mock_open


@pytest.mark.asyncio
class TestSandboxManagerLifecycleIsolation:
    """Test isolation validation in SandboxManager lifecycle."""

    @pytest.fixture
    def sandbox_manager(self):
        """Create a SandboxManager instance for testing."""
        return SandboxManager()

    async def test_create_sandbox_validates_isolation(self, sandbox_manager):
        """Test that create_sandbox validates isolation after creation."""
        with patch.object(sandbox_manager, '_create_sandbox_internal') as mock_create:
            with patch.object(sandbox_manager, 'validate_isolation') as mock_validate:
                mock_sandbox = Mock()
                mock_sandbox.is_healthy = Mock(return_value=True)
                mock_create.return_value = mock_sandbox
                mock_validate.return_value = (True, "")

                result = await sandbox_manager.create_sandbox()

                assert result == mock_sandbox
                mock_validate.assert_called_once()

    async def test_create_sandbox_terminates_on_validation_failure(self, sandbox_manager):
        """Test that create_sandbox terminates on validation failure."""
        with patch.object(sandbox_manager, '_create_sandbox_internal') as mock_create:
            with patch.object(sandbox_manager, 'validate_isolation') as mock_validate:
                with patch.object(sandbox_manager, 'terminate_sandbox') as mock_terminate:
                    mock_sandbox = Mock()
                    mock_sandbox.is_healthy = Mock(return_value=True)
                    mock_create.return_value = mock_sandbox
                    mock_validate.return_value = (False, "Isolation failed")

                    with pytest.raises(Exception) as exc_info:
                        await sandbox_manager.create_sandbox()

                    assert "Isolation validation failed" in str(exc_info.value)
                    mock_terminate.assert_called_once_with(force=True)

    async def test_reset_sandbox_revalidates(self, sandbox_manager):
        """Test that reset_sandbox creates new sandbox with validation."""
        sandbox_manager.current_sandbox = Mock()
        with patch.object(sandbox_manager, 'terminate_sandbox') as mock_terminate:
            with patch.object(sandbox_manager, '_cleanup_partial_initialization') as mock_cleanup:
                with patch.object(sandbox_manager, 'create_sandbox') as mock_create:
                    mock_sandbox = Mock()
                    mock_create.return_value = mock_sandbox

                    await sandbox_manager.reset_sandbox()

                    mock_terminate.assert_called_once()
                    mock_cleanup.assert_called_once()
                    mock_create.assert_called_once()


@pytest.mark.asyncio
class TestRuntimeViolationMonitoring:
    """Test runtime violation monitoring integration (Requirement 6.5)."""

    @pytest.fixture
    async def sandbox_manager(self):
        """Create a SandboxManager with ViolationMonitor marked as validated."""
        violation_monitor = ViolationMonitor()
        manager = SandboxManager(violation_monitor=violation_monitor)
        # Mark as validated to avoid isolation validation blocking the tests
        manager._isolation_validated = True
        manager._container_id = 'test_container'
        # Mock validate_isolation to always return True in this test class
        manager.validate_isolation = Mock(return_value=(True, ""))
        return manager

    @pytest.fixture
    def mock_sandbox(self, sandbox_manager):
        """Create a mock Sandbox with ViolationMonitor."""
        from src.sandbox import Sandbox
        mock_browser = Mock()
        mock_context = Mock()
        sandbox = Sandbox(mock_browser, mock_context, sandbox_manager, sandbox_manager.violation_monitor)
        sandbox.page = Mock()
        sandbox.page.goto = AsyncMock(return_value=None)
        return sandbox

    async def test_load_url_detects_internal_ip_violation(self, mock_sandbox):
        """Test that load_url detects internal IP violations in target URL."""
        # Mock validate_isolation to return True
        mock_sandbox.sandbox_manager.validate_isolation = Mock(return_value=(True, ""))

        # Target URL with internal IP
        internal_url = "http://192.168.1.1/test"

        # Mock the route method to avoid async issues
        with patch.object(mock_sandbox.page, 'route', return_value=None):
            with pytest.raises(RuntimeError) as exc_info:
                await mock_sandbox.load_url(internal_url)

        assert "internal network address" in str(exc_info.value)
        assert "192.168.1.1" in str(exc_info.value)

        # Verify violation was logged
        assert mock_sandbox.violation_monitor.has_violations() is True
        violations = mock_sandbox.violation_monitor.get_violations()
        assert len(violations) == 1
        assert violations[0]['violation_type'] == "internal_network"
        assert violations[0]['target'] == "192.168.1.1"

    async def test_load_url_allows_public_ip(self, mock_sandbox):
        """Test that load_url allows public IP addresses."""
        # Mock validate_isolation to return True
        mock_sandbox.sandbox_manager.validate_isolation = Mock(return_value=(True, ""))

        # Target URL with public IP
        public_url = "http://8.8.8.8/test"

        # Mock the route method to avoid async issues
        with patch.object(mock_sandbox.page, 'route', return_value=None):
            result = await mock_sandbox.load_url(public_url)

        assert result is True
        assert not mock_sandbox.violation_monitor.has_violations()

    async def test_load_url_detects_localhost_violation(self, mock_sandbox):
        """Test that load_url detects localhost violations."""
        # Mock validate_isolation to return True
        mock_sandbox.sandbox_manager.validate_isolation = Mock(return_value=(True, ""))

        # Target URL with localhost
        localhost_url = "http://127.0.0.1/test"

        # Mock the route method to avoid async issues
        with patch.object(mock_sandbox.page, 'route', return_value=None):
            with pytest.raises(RuntimeError) as exc_info:
                await mock_sandbox.load_url(localhost_url)

            assert "internal network address" in str(exc_info.value)

            # Verify violation was logged
            assert mock_sandbox.violation_monitor.has_violations() is True
            violations = mock_sandbox.violation_monitor.get_violations()
            assert violations[0]['target'] == "127.0.0.1"

    async def test_violation_triggers_sandbox_termination(self, mock_sandbox):
        """Test that detected violations trigger sandbox termination."""
        # Mock validate_isolation to return True
        mock_sandbox.sandbox_manager.validate_isolation = Mock(return_value=(True, ""))

        with patch.object(mock_sandbox.sandbox_manager, 'terminate_sandbox') as mock_terminate:
            with patch.object(mock_sandbox.page, 'route', return_value=None):
                internal_url = "http://192.168.1.1/test"

                with pytest.raises(RuntimeError):
                    await mock_sandbox.load_url(internal_url)

                # Verify sandbox was terminated
                mock_terminate.assert_called_once_with(force=True)

    async def test_no_violation_monitor_allows_any_url(self, mock_sandbox):
        """Test that without ViolationMonitor, URLs load normally."""
        # Mock validate_isolation to return True
        mock_sandbox.sandbox_manager.validate_isolation = Mock(return_value=(True, ""))

        # Remove violation monitor
        mock_sandbox.violation_monitor = None

        # Even internal IP should be allowed without monitor
        internal_url = "http://192.168.1.1/test"
        result = await mock_sandbox.load_url(internal_url)

    async def test_request_interceptor_blocks_metadata_service(self, mock_sandbox):
        """Test that request interceptor blocks cloud metadata service."""
        # Mock validate_isolation to return True
        mock_sandbox.sandbox_manager.validate_isolation = Mock(return_value=(True, ""))

        metadata_url = "http://169.254.169.254/latest/meta-data/"

        # Mock the route method to avoid async issues
        with patch.object(mock_sandbox.page, 'route', return_value=None):
            with pytest.raises(RuntimeError) as exc_info:
                await mock_sandbox.load_url(metadata_url)

            assert "internal network address" in str(exc_info.value)

    async def test_request_interceptor_blocks_link_local(self, mock_sandbox):
        """Test that request interceptor blocks link-local addresses."""
        # Mock validate_isolation to return True
        mock_sandbox.sandbox_manager.validate_isolation = Mock(return_value=(True, ""))

        link_local_url = "http://169.254.1.1/test"

        # Mock the route method to avoid async issues
        with patch.object(mock_sandbox.page, 'route', return_value=None):
            with pytest.raises(RuntimeError) as exc_info:
                await mock_sandbox.load_url(link_local_url)

            assert "internal network address" in str(exc_info.value)

    async def test_external_url_allowed(self, mock_sandbox):
        """Test that external URLs are allowed."""
        # Mock validate_isolation to return True
        mock_sandbox.sandbox_manager.validate_isolation = Mock(return_value=(True, ""))

        external_url = "http://example.com"

        # Mock the route method to avoid async issues
        with patch.object(mock_sandbox.page, 'route', return_value=None):
            result = await mock_sandbox.load_url(external_url)

        # Should succeed (URL load attempt, not actual network success)
        assert result is True

    async def test_load_url_detects_internal_ip_violation(self, mock_sandbox):
        """Test that load_url detects internal IP violations in target URL."""
        # Target URL with internal IP
        internal_url = "http://192.168.1.1/test"

        # Mock the route method to avoid async issues
        with patch.object(mock_sandbox.page, 'route', return_value=None):
            with pytest.raises(RuntimeError) as exc_info:
                await mock_sandbox.load_url(internal_url)

        assert "internal network address" in str(exc_info.value)
        assert "192.168.1.1" in str(exc_info.value)

        # Verify violation was logged
        assert mock_sandbox.violation_monitor.has_violations() is True
        violations = mock_sandbox.violation_monitor.get_violations()
        assert len(violations) == 1
        assert violations[0]['violation_type'] == "internal_network"
        assert violations[0]['target'] == "192.168.1.1"

    async def test_load_url_allows_public_ip(self, mock_sandbox):
        """Test that load_url allows public IP addresses."""
        # Target URL with public IP
        public_url = "http://8.8.8.8/test"

        # Mock the route method to avoid async issues
        with patch.object(mock_sandbox.page, 'route', return_value=None):
            result = await mock_sandbox.load_url(public_url)

        assert result is True
        assert not mock_sandbox.violation_monitor.has_violations()

    async def test_load_url_detects_localhost_violation(self, mock_sandbox):
        """Test that load_url detects localhost violations."""
        # Target URL with localhost
        localhost_url = "http://127.0.0.1/test"

        # Mock the route method to avoid async issues
        with patch.object(mock_sandbox.page, 'route', return_value=None):
            with pytest.raises(RuntimeError) as exc_info:
                await mock_sandbox.load_url(localhost_url)

        assert "internal network address" in str(exc_info.value)

        # Verify violation was logged
        assert mock_sandbox.violation_monitor.has_violations() is True
        violations = mock_sandbox.violation_monitor.get_violations()
        assert violations[0]['target'] == "127.0.0.1"

    async def test_violation_triggers_sandbox_termination(self, mock_sandbox):
        """Test that detected violations trigger sandbox termination."""

        with patch.object(mock_sandbox.sandbox_manager, 'terminate_sandbox') as mock_terminate:
            with patch.object(mock_sandbox.page, 'route', return_value=None):
                internal_url = "http://192.168.1.1/test"

                with pytest.raises(RuntimeError):
                    await mock_sandbox.load_url(internal_url)

                # Verify sandbox was terminated
                mock_terminate.assert_called_once_with(force=True)

    async def test_no_violation_monitor_allows_any_url(self, mock_sandbox):
        """Test that without ViolationMonitor, URLs load normally."""
        # Remove violation monitor
        mock_sandbox.violation_monitor = None

        # Even internal IP should be allowed without monitor
        internal_url = "http://192.168.1.1/test"
        result = await mock_sandbox.load_url(internal_url)

    async def test_request_interceptor_blocks_metadata_service(self, mock_sandbox):
        """Test that request interceptor blocks cloud metadata service."""
        metadata_url = "http://169.254.169.254/latest/meta-data/"

        # Mock the route method to avoid async issues
        with patch.object(mock_sandbox.page, 'route', return_value=None):
            with pytest.raises(RuntimeError) as exc_info:
                await mock_sandbox.load_url(metadata_url)

        assert "internal network address" in str(exc_info.value)

    async def test_request_interceptor_blocks_link_local(self, mock_sandbox):
        """Test that request interceptor blocks link-local addresses."""
        link_local_url = "http://169.254.1.1/test"

        # Mock the route method to avoid async issues
        with patch.object(mock_sandbox.page, 'route', return_value=None):
            with pytest.raises(RuntimeError) as exc_info:
                await mock_sandbox.load_url(link_local_url)

        assert "internal network address" in str(exc_info.value)

    async def test_external_url_allowed(self, mock_sandbox):
        """Test that external URLs are allowed."""
        external_url = "http://example.com"

        # Mock the route method to avoid async issues
        with patch.object(mock_sandbox.page, 'route', return_value=None):
            result = await mock_sandbox.load_url(external_url)

        # Should succeed (URL load attempt, not actual network success)
        assert result is True
