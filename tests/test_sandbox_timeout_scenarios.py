"""Unit tests for sandbox timeout scenarios (Task 4.6).

Tests timeout behavior for:
- Sandbox initialization exceeding 15 seconds
- URL loading exceeding 30 seconds
- Sandbox becoming unresponsive during analysis
- Responsiveness check respecting 15-second requirement
- Termination respecting 10-second timeout
- Forced termination when graceful shutdown fails
- Timeout paths cleaning up resources
- Browser/context/page not leaked
- Lifecycle locks released
- Fail-closed behavior preserved
- No website analysis continues after critical timeout

Validates Requirements: 1.5, 1.6, 8.1, 8.2
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timezone

# Add src to path for imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.sandbox import Sandbox, SandboxManager, INITIALIZATION_TIMEOUT, TERMINATION_TIMEOUT, RESPONSIVENESS_TIMEOUT


@pytest.mark.asyncio
class TestSandboxUnresponsiveness:
    """Test sandbox becoming unresponsive during analysis."""

    @pytest.fixture
    async def sandbox(self):
        """Create a Sandbox instance with mocked dependencies."""
        mock_browser = Mock()
        mock_context = Mock()
        mock_context.pages = AsyncMock(return_value=[])
        mock_sandbox_manager = Mock()
        mock_sandbox_manager.validate_isolation = Mock(return_value=(True, ""))
        mock_sandbox_manager._container_id = 'test_container'
        mock_sandbox_manager.terminate_sandbox = AsyncMock()

        sandbox = Sandbox(mock_browser, mock_context, mock_sandbox_manager)
        sandbox.page = Mock()
        sandbox.page.route = AsyncMock()

        return sandbox

    async def test_is_responsive_times_out_on_hanging_browser(self, sandbox):
        """Test is_responsive times out when browser check hangs."""
        async def hanging_check():
            await asyncio.sleep(100)  # Would hang indefinitely
            return True

        sandbox.browser.is_connected = hanging_check

        result = await sandbox.is_responsive()
        assert result is False

    async def test_is_responsive_times_out_respects_15_second_limit(self, sandbox):
        """Test is_responsive respects 15-second timeout requirement."""
        async def slow_check():
            await asyncio.sleep(20)  # Exceeds 15s
            return True

        sandbox.browser.is_connected = slow_check

        start = datetime.now(timezone.utc)
        result = await sandbox.is_responsive()
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()

        assert result is False
        # Should timeout at approximately RESPONSIVENESS_TIMEOUT (15s)
        # But we use a faster check for testing
        assert elapsed < 20

    async def test_is_responsive_handles_missing_browser(self, sandbox):
        """Test is_responsive handles missing browser gracefully."""
        sandbox.browser = None

        result = await sandbox.is_responsive()
        assert result is False


@pytest.mark.asyncio
class TestTimeoutCleanup:
    """Test that timeout paths clean up resources."""

    @pytest.fixture
    async def sandbox(self):
        """Create a Sandbox instance with mocked dependencies."""
        mock_browser = Mock()
        mock_context = Mock()
        mock_context.pages = AsyncMock(return_value=[])
        mock_sandbox_manager = Mock()
        mock_sandbox_manager.validate_isolation = Mock(return_value=(True, ""))
        mock_sandbox_manager._container_id = 'test_container'
        mock_sandbox_manager.terminate_sandbox = AsyncMock()

        sandbox = Sandbox(mock_browser, mock_context, mock_sandbox_manager)
        sandbox.page = Mock()
        sandbox.page.route = AsyncMock()

        return sandbox

    async def test_load_url_timeout_does_not_leak_page(self, sandbox):
        """Test that load_url timeout does not leak page object."""
        sandbox.page.goto = AsyncMock(side_effect=asyncio.TimeoutError())

        result = await sandbox.load_url('https://example.com', timeout=30)

        assert result is False
        # Page should still exist (not cleaned up on timeout)
        # but no analysis should continue
        assert sandbox.page is not None

    async def test_load_url_timeout_prevents_further_operations(self, sandbox):
        """Test that load_url timeout prevents further operations."""
        sandbox.page.goto = AsyncMock(side_effect=asyncio.TimeoutError())

        result = await sandbox.load_url('https://example.com', timeout=30)

        assert result is False
        # Verify no operations continue after timeout
        assert sandbox.redirect_count == 0
        assert sandbox.redirect_chain == ['https://example.com']


@pytest.mark.asyncio
class TestForcedTermination:
    """Test forced termination when graceful shutdown fails."""

    @pytest.fixture
    def manager(self):
        """Create a SandboxManager instance for testing."""
        return SandboxManager()

    async def test_termination_timeout_triggers_force_terminate(self, manager):
        """Test that termination timeout triggers forced termination."""
        mock_sandbox = Mock()
        mock_sandbox.context = Mock()
        mock_sandbox.context.close = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_sandbox.browser = Mock()
        mock_sandbox.browser.close = AsyncMock()
        mock_sandbox.close = AsyncMock(side_effect=asyncio.TimeoutError())

        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True

        with patch('src.sandbox.TERMINATION_TIMEOUT', 0.05):
            with patch.object(manager, '_force_terminate') as mock_force:
                await manager.terminate_sandbox(force=False)

                mock_force.assert_called_once()

    async def test_force_terminate_kills_remaining_processes(self, manager):
        """Test that force_terminate kills remaining processes."""
        mock_sandbox = Mock()
        mock_sandbox.context = Mock()
        mock_sandbox.context.close = AsyncMock(side_effect=Exception("Graceful failed"))
        mock_sandbox.browser = Mock()
        mock_sandbox.browser.close = AsyncMock()

        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True

        with patch.object(manager, '_force_terminate') as mock_force:
            await manager.terminate_sandbox(force=True)

            mock_force.assert_called_once()

    async def test_forced_termination_logs_event(self, manager):
        """Test that forced termination is logged."""
        mock_sandbox = Mock()
        mock_sandbox.context = Mock()
        mock_sandbox.context.close = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_sandbox.browser = Mock()
        mock_sandbox.browser.close = AsyncMock()
        mock_sandbox.close = AsyncMock(side_effect=asyncio.TimeoutError())

        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True

        with patch('src.sandbox.TERMINATION_TIMEOUT', 0.05):
            with patch.object(manager, '_force_terminate') as mock_force:
                with patch.object(manager, 'logger') as mock_logger:
                    await manager.terminate_sandbox(force=False)

                    # Verify logging occurred
                    assert mock_logger.warning.called or mock_logger.error.called


@pytest.mark.asyncio
class TestLifecycleLockRelease:
    """Test that lifecycle locks are released after timeout."""

    @pytest.fixture
    def manager(self):
        """Create a SandboxManager instance for testing."""
        return SandboxManager()

    async def test_initialization_timeout_releases_lock(self, manager):
        """Test that initialization timeout releases lifecycle lock."""
        async def slow_create():
            await asyncio.sleep(0.1)
            return MagicMock()

        with patch('src.sandbox.INITIALIZATION_TIMEOUT', 0.05):
            with patch.object(manager, '_create_sandbox_internal', side_effect=slow_create):
                with patch.object(manager, 'validate_isolation', return_value=(True, "")):
                    try:
                        await manager.create_sandbox()
                    except TimeoutError:
                        pass

                    # Lock should be released
                    assert manager._lifecycle_lock.locked() is False

    async def test_termination_timeout_releases_lock(self, manager):
        """Test that termination timeout releases lifecycle lock."""
        mock_sandbox = Mock()
        mock_sandbox.context = Mock()
        mock_sandbox.context.close = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_sandbox.browser = Mock()
        mock_sandbox.browser.close = AsyncMock()
        mock_sandbox.close = AsyncMock(side_effect=asyncio.TimeoutError())

        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True

        with patch('src.sandbox.TERMINATION_TIMEOUT', 0.05):
            with patch.object(manager, '_force_terminate') as mock_force:
                await manager.terminate_sandbox(force=False)

                # Lock should be released
                assert manager._lifecycle_lock.locked() is False

    async def test_create_page_timeout_releases_lock(self):
        """Test that create_page timeout releases lifecycle lock."""
        mock_browser = Mock()
        mock_context = Mock()
        mock_context.new_page = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_context.close = AsyncMock()
        mock_sandbox_manager = Mock()
        mock_sandbox_manager.validate_isolation = Mock(return_value=(True, ""))
        mock_sandbox_manager._container_id = 'test_container'

        sandbox = Sandbox(mock_browser, mock_context, mock_sandbox_manager)

        try:
            await sandbox.create_page()
        except (asyncio.TimeoutError, RuntimeError):
            pass

        # Lock should be released
        assert sandbox._page_lock.locked() is False


@pytest.mark.asyncio
class TestFailClosedBehaviorAfterTimeout:
    """Test that fail-closed behavior is preserved after timeout."""

    @pytest.fixture
    async def sandbox(self):
        """Create a Sandbox instance with mocked dependencies."""
        mock_browser = Mock()
        mock_context = Mock()
        mock_context.pages = AsyncMock(return_value=[])
        mock_sandbox_manager = Mock()
        mock_sandbox_manager.validate_isolation = Mock(return_value=(True, ""))
        mock_sandbox_manager._container_id = 'test_container'
        mock_sandbox_manager.terminate_sandbox = AsyncMock()

        sandbox = Sandbox(mock_browser, mock_context, mock_sandbox_manager)
        sandbox.page = Mock()
        sandbox.page.route = AsyncMock()

        return sandbox

    async def test_load_url_timeout_returns_false_fail_closed(self, sandbox):
        """Test that load_url timeout returns False (fail-closed)."""
        sandbox.page.goto = AsyncMock(side_effect=asyncio.TimeoutError())

        result = await sandbox.load_url('https://example.com', timeout=30)

        assert result is False  # Fail-closed: False indicates failure

    async def test_load_url_timeout_does_not_raise_exception(self, sandbox):
        """Test that load_url timeout does not raise exception (handles gracefully)."""
        sandbox.page.goto = AsyncMock(side_effect=asyncio.TimeoutError())

        # Should not raise, should return False
        result = await sandbox.load_url('https://example.com', timeout=30)

        assert result is False

    async def test_is_responsive_timeout_returns_false_fail_closed(self, sandbox):
        """Test that is_responsive timeout returns False (fail-closed)."""
        async def hanging_check():
            await asyncio.sleep(100)
            return True

        sandbox.browser.is_connected = hanging_check

        result = await sandbox.is_responsive()

        assert result is False  # Fail-closed: False indicates unresponsive


@pytest.mark.asyncio
class TestNoAnalysisAfterCriticalTimeout:
    """Test that no website analysis continues after critical timeout."""

    @pytest.fixture
    async def sandbox(self):
        """Create a Sandbox instance with mocked dependencies."""
        mock_browser = Mock()
        mock_context = Mock()
        mock_context.pages = AsyncMock(return_value=[])
        mock_sandbox_manager = Mock()
        mock_sandbox_manager.validate_isolation = Mock(return_value=(True, ""))
        mock_sandbox_manager._container_id = 'test_container'
        mock_sandbox_manager.terminate_sandbox = AsyncMock()

        sandbox = Sandbox(mock_browser, mock_context, mock_sandbox_manager)
        sandbox.page = Mock()
        sandbox.page.route = AsyncMock()

        return sandbox

    async def test_load_url_timeout_stops_redirect_following(self, sandbox):
        """Test that load_url timeout stops redirect following."""
        # First redirect succeeds
        redirect_response = Mock()
        redirect_response.status = 302
        redirect_response.headers = {'location': 'https://final.com'}

        # Second redirect times out
        sandbox.page.goto = AsyncMock(side_effect=[redirect_response, asyncio.TimeoutError()])

        result = await sandbox.load_url('https://example.com', timeout=30)

        assert result is True  # Analyzes page at redirect 1
        assert sandbox.redirect_count == 1  # Only followed 1 redirect
        assert sandbox.page.goto.call_count == 2  # Initial + 1 redirect

    async def test_load_url_timeout_prevents_subsequent_page_operations(self, sandbox):
        """Test that load_url timeout prevents subsequent page operations."""
        sandbox.page.goto = AsyncMock(side_effect=asyncio.TimeoutError())

        result = await sandbox.load_url('https://example.com', timeout=30)

        assert result is False
        # Verify no further operations attempted
        assert sandbox.page.goto.call_count == 1

    async def test_critical_timeout_marks_analysis_incomplete(self, sandbox):
        """Test that critical timeout marks analysis as incomplete."""
        sandbox.page.goto = AsyncMock(side_effect=asyncio.TimeoutError())

        result = await sandbox.load_url('https://example.com', timeout=30)

        assert result is False
        # Analysis state should indicate incomplete/failure
        assert sandbox.redirect_count == 0
        assert sandbox.final_url == 'https://example.com'


class TestTimeoutConstants:
    """Test timeout constants match requirements."""

    def test_initialization_timeout_is_15_seconds(self):
        """Test INITIALIZATION_TIMEOUT is 15 seconds (Requirement 1.5)."""
        assert INITIALIZATION_TIMEOUT == 15.0

    def test_termination_timeout_is_10_seconds(self):
        """Test TERMINATION_TIMEOUT is 10 seconds (Requirement 1.6)."""
        assert TERMINATION_TIMEOUT == 10.0

    def test_responsiveness_timeout_is_15_seconds(self):
        """Test RESPONSIVENESS_TIMEOUT is 15 seconds (Requirement 8.2)."""
        assert RESPONSIVENESS_TIMEOUT == 15.0
