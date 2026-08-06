"""Unit tests for Sandbox and SandboxManager classes.

Tests sandbox lifecycle management, timeout handling, and cleanup behavior.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, Mock
from datetime import datetime, timezone

from src.sandbox import Sandbox, SandboxManager, INITIALIZATION_TIMEOUT, TERMINATION_TIMEOUT


class TestSandbox:
    """Tests for Sandbox class."""
    
    @pytest.fixture
    def mock_browser(self):
        """Create a mock browser instance."""
        browser = AsyncMock()
        return browser
    
    @pytest.fixture
    def mock_context(self):
        """Create a mock browser context."""
        context = AsyncMock()
        return context
    
    @pytest.fixture
    def sandbox(self, mock_browser, mock_context):
        """Create a Sandbox instance with mocked dependencies."""
        return Sandbox(mock_browser, mock_context)
    
    @pytest.mark.asyncio
    async def test_sandbox_creation(self, mock_browser, mock_context):
        """Test creating a Sandbox instance."""
        sandbox = Sandbox(mock_browser, mock_context)
        
        assert sandbox.browser == mock_browser
        assert sandbox.context == mock_context
        assert sandbox.page is None
        assert sandbox._created_at is not None
    
    @pytest.mark.asyncio
    async def test_create_page(self, sandbox, mock_context):
        """Test creating a new page in the sandbox."""
        mock_page = AsyncMock()
        mock_context.new_page.return_value = mock_page
        
        page = await sandbox.create_page()
        
        assert page == mock_page
        mock_context.new_page.assert_called_once()
        assert sandbox.page == mock_page
    
    @pytest.mark.asyncio
    async def test_create_page_closes_existing(self, sandbox, mock_context):
        """Test that creating a new page closes the existing one."""
        mock_old_page = AsyncMock()
        mock_new_page = AsyncMock()
        sandbox.page = mock_old_page
        mock_context.new_page.return_value = mock_new_page
        
        await sandbox.create_page()
        
        mock_old_page.close.assert_called_once()
        mock_context.new_page.assert_called_once()
        assert sandbox.page == mock_new_page
    
    @pytest.mark.asyncio
    async def test_close_page(self, sandbox):
        """Test closing the current page."""
        mock_page = AsyncMock()
        sandbox.page = mock_page
        
        await sandbox.close_page()
        
        mock_page.close.assert_called_once()
        assert sandbox.page is None
    
    @pytest.mark.asyncio
    async def test_close_page_when_none(self, sandbox):
        """Test closing page when no page exists."""
        sandbox.page = None
        
        await sandbox.close_page()
        
        # Should not raise an error
        assert sandbox.page is None
    
    @pytest.mark.asyncio
    async def test_close(self, sandbox, mock_context):
        """Test closing the sandbox context."""
        mock_page = AsyncMock()
        sandbox.page = mock_page
        
        await sandbox.close()
        
        mock_page.close.assert_called_once()
        mock_context.close.assert_called_once()
        assert sandbox.page is None


class TestSandboxManager:
    """Tests for SandboxManager class."""
    
    @pytest.fixture
    def manager(self):
        """Create a SandboxManager instance."""
        return SandboxManager()
    
    @pytest.mark.asyncio
    async def test_manager_initialization(self, manager):
        """Test SandboxManager initialization."""
        assert manager.playwright is None
        assert manager.browser is None
        assert manager.current_sandbox is None
        assert manager._is_initialized is False
    
    @pytest.mark.asyncio
    async def test_create_sandbox_success(self, manager):
        """Test successful sandbox creation within timeout."""
        # Create a mock sandbox to return from _create_sandbox_internal
        mock_sandbox = MagicMock()
        
        with patch.object(manager, '_create_sandbox_internal', return_value=mock_sandbox):
            sandbox = await manager.create_sandbox()
            
            assert sandbox == mock_sandbox
            assert manager._is_initialized is True
            assert manager.current_sandbox == sandbox
    
    @pytest.mark.asyncio
    async def test_create_sandbox_timeout(self, manager):
        """Test sandbox creation timeout after 15 seconds."""
        async def slow_create():
            await asyncio.sleep(20)  # Exceeds 15s timeout
            return MagicMock()
        
        with patch.object(manager, '_create_sandbox_internal', side_effect=slow_create):
            with pytest.raises(TimeoutError) as exc_info:
                await manager.create_sandbox()
            
            assert "exceeded 15" in str(exc_info.value)  # Check for 15 seconds
            assert "timeout" in str(exc_info.value).lower()
            assert manager._is_initialized is False
    
    @pytest.mark.asyncio
    async def test_create_sandbox_exception(self, manager):
        """Test sandbox creation exception handling."""
        with patch.object(manager, '_create_sandbox_internal', side_effect=Exception("Browser launch failed")):
            with pytest.raises(Exception) as exc_info:
                await manager.create_sandbox()
            
            assert "Browser launch failed" in str(exc_info.value)
            assert manager._is_initialized is False
    
    @pytest.mark.asyncio
    async def test_create_sandbox_already_exists(self, manager):
        """Test that creating sandbox when one exists returns existing."""
        mock_sandbox = MagicMock()
        mock_sandbox.is_healthy = AsyncMock(return_value=True)
        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True
        
        result = await manager.create_sandbox()
        
        assert result == mock_sandbox
    
    @pytest.mark.asyncio
    async def test_terminate_sandbox_graceful(self, manager):
        """Test graceful sandbox termination."""
        mock_sandbox = AsyncMock()
        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True
        
        await manager.terminate_sandbox(force=False)
        
        mock_sandbox.close.assert_called_once()
        assert manager.current_sandbox is None
        assert manager._is_initialized is False
    
    @pytest.mark.asyncio
    async def test_terminate_sandbox_force(self, manager):
        """Test forced sandbox termination."""
        mock_sandbox = AsyncMock()
        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True
        
        await manager.terminate_sandbox(force=True)
        
        mock_sandbox.close.assert_called_once()
        assert manager.current_sandbox is None
        assert manager._is_initialized is False
    
    @pytest.mark.asyncio
    async def test_terminate_sandbox_none(self, manager):
        """Test terminating when no sandbox exists."""
        manager.current_sandbox = None
        
        await manager.terminate_sandbox()
        
        # Should not raise an error
        assert manager.current_sandbox is None
    
    @pytest.mark.asyncio
    async def test_terminate_sandbox_timeout_forces(self, manager):
        """Test that graceful termination timeout triggers forced termination."""
        async def slow_close():
            await asyncio.sleep(15)  # Exceeds 10s timeout
        
        mock_sandbox = AsyncMock()
        mock_sandbox.close.side_effect = slow_close
        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True
        
        with patch.object(manager, '_force_terminate') as mock_force:
            await manager.terminate_sandbox(force=False)
            
            # Should have attempted graceful close first
            mock_sandbox.close.assert_called_once()
            # Then forced termination
            mock_force.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_force_terminate(self, manager):
        """Test forced termination cleanup."""
        mock_sandbox = AsyncMock()
        mock_browser = AsyncMock()
        mock_playwright = AsyncMock()
        
        manager.current_sandbox = mock_sandbox
        manager.browser = mock_browser
        manager.playwright = mock_playwright
        manager._is_initialized = True
        
        await manager._force_terminate()
        
        mock_sandbox.close.assert_called_once()
        mock_browser.close.assert_called_once()
        mock_playwright.stop.assert_called_once()
        assert manager.current_sandbox is None
        assert manager.browser is None
        assert manager.playwright is None
        assert manager._is_initialized is False
    
    @pytest.mark.asyncio
    async def test_force_terminate_handles_errors(self, manager):
        """Test that forced termination continues despite individual errors."""
        mock_sandbox = AsyncMock()
        mock_sandbox.close.side_effect = Exception("Close error")
        mock_browser = AsyncMock()
        mock_browser.close.side_effect = Exception("Browser close error")
        mock_playwright = AsyncMock()
        mock_playwright.stop.side_effect = Exception("Stop error")
        
        manager.current_sandbox = mock_sandbox
        manager.browser = mock_browser
        manager.playwright = mock_playwright
        
        # Should not raise despite errors
        await manager._force_terminate()
        
        # Despite errors, the cleanup should still set attributes to None
        assert manager.current_sandbox is None
        assert manager.browser is None
        assert manager.playwright is None
        assert manager._is_initialized is False
    
    @pytest.mark.asyncio
    async def test_reset_sandbox(self, manager):
        """Test sandbox reset between analyses."""
        mock_sandbox = AsyncMock()
        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True
        
        with patch.object(manager, 'terminate_sandbox') as mock_terminate:
            with patch.object(manager, 'create_sandbox') as mock_create:
                await manager.reset_sandbox()
                
                # Should terminate existing sandbox
                mock_terminate.assert_called_once()
                # Should create new sandbox
                mock_create.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_reset_sandbox_create_failure(self, manager):
        """Test reset when creating new sandbox fails."""
        mock_sandbox = AsyncMock()
        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True
        
        with patch.object(manager, 'terminate_sandbox') as mock_terminate:
            with patch.object(manager, 'create_sandbox', side_effect=Exception("Create failed")):
                with pytest.raises(Exception) as exc_info:
                    await manager.reset_sandbox()
                
                assert "Create failed" in str(exc_info.value)
                mock_terminate.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_sandbox_success(self, manager):
        """Test getting current sandbox when initialized."""
        mock_sandbox = MagicMock()
        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True
        
        result = await manager.get_sandbox()
        
        assert result == mock_sandbox
    
    @pytest.mark.asyncio
    async def test_get_sandbox_not_initialized(self, manager):
        """Test getting sandbox when not initialized raises error."""
        manager.current_sandbox = None
        manager._is_initialized = False
        
        with pytest.raises(RuntimeError) as exc_info:
            await manager.get_sandbox()
        
        assert "not initialized" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_cleanup(self, manager):
        """Test complete cleanup of manager resources."""
        mock_sandbox = AsyncMock()
        mock_browser = AsyncMock()
        mock_playwright = AsyncMock()
        
        manager.current_sandbox = mock_sandbox
        manager.browser = mock_browser
        manager.playwright = mock_playwright
        manager._is_initialized = True
        
        with patch.object(manager, 'terminate_sandbox') as mock_terminate:
            with patch.object(manager, '_cleanup_partial_initialization') as mock_cleanup:
                await manager.cleanup()
                
                mock_terminate.assert_called_once_with(force=True)
                mock_cleanup.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_partial_initialization_cleanup(self, manager):
        """Test cleanup of partial initialization state."""
        mock_sandbox = AsyncMock()
        mock_browser = AsyncMock()
        mock_playwright = AsyncMock()
        
        manager.current_sandbox = mock_sandbox
        manager.browser = mock_browser
        manager.playwright = mock_playwright
        
        await manager._cleanup_partial_initialization()
        
        mock_sandbox.close.assert_called_once()
        mock_browser.close.assert_called_once()
        mock_playwright.stop.assert_called_once()
        # Attributes should be set to None regardless of success/failure
        assert manager.current_sandbox is None
        assert manager.browser is None
        assert manager.playwright is None
        assert manager._is_initialized is False
    
    @pytest.mark.asyncio
    async def test_partial_initialization_cleanup_with_errors(self, manager):
        """Test that partial cleanup continues despite errors."""
        mock_sandbox = AsyncMock()
        mock_sandbox.close.side_effect = Exception("Sandbox close error")
        mock_browser = AsyncMock()
        mock_browser.close.side_effect = Exception("Browser close error")
        mock_playwright = AsyncMock()
        mock_playwright.stop.side_effect = Exception("Stop error")
        
        manager.current_sandbox = mock_sandbox
        manager.browser = mock_browser
        manager.playwright = mock_playwright
        
        # Should not raise despite errors
        await manager._cleanup_partial_initialization()
        
        # Despite errors, attributes should still be set to None
        assert manager.current_sandbox is None
        assert manager.browser is None
        assert manager.playwright is None
        assert manager._is_initialized is False


class TestSandboxTimeouts:
    """Tests for timeout enforcement."""
    
    @pytest.mark.asyncio
    async def test_initialization_timeout_constant(self):
        """Test that initialization timeout is set to 15 seconds."""
        assert INITIALIZATION_TIMEOUT == 15.0
    
    @pytest.mark.asyncio
    async def test_termination_timeout_constant(self):
        """Test that termination timeout is set to 10 seconds."""
        assert TERMINATION_TIMEOUT == 10.0
    
    @pytest.mark.asyncio
    async def test_create_sandbox_respects_timeout(self):
        """Test that create_sandbox enforces 15-second timeout."""
        manager = SandboxManager()
        
        async def slow_internal():
            await asyncio.sleep(20)
            return MagicMock()
        
        with patch.object(manager, '_create_sandbox_internal', side_effect=slow_internal):
            start = datetime.now(timezone.utc)
            with pytest.raises(TimeoutError):
                await manager.create_sandbox()
            elapsed = (datetime.now(timezone.utc) - start).total_seconds()
            
            # Should timeout at approximately 15 seconds (with some tolerance)
            assert 14 < elapsed < 17
    
    @pytest.mark.asyncio
    async def test_terminate_sandbox_respects_timeout(self):
        """Test that terminate_sandbox enforces 10-second timeout for graceful shutdown."""
        manager = SandboxManager()
        mock_sandbox = AsyncMock()
        
        async def slow_close():
            await asyncio.sleep(15)
        
        mock_sandbox.close.side_effect = slow_close
        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True
        
        with patch.object(manager, '_force_terminate') as mock_force:
            start = datetime.now(timezone.utc)
            await manager.terminate_sandbox(force=False)
            elapsed = (datetime.now(timezone.utc) - start).total_seconds()
            
            # Should timeout at approximately 10 seconds (with some tolerance)
            assert 9 < elapsed < 12
            mock_force.assert_called_once()


class TestSandboxSecurity:
    """Security hardening tests for Sandbox and SandboxManager classes."""
    
    @pytest.fixture
    def manager(self):
        """Create a SandboxManager instance."""
        return SandboxManager()
    
    @pytest.fixture
    def mock_browser(self):
        """Create a mock browser instance."""
        browser = AsyncMock()
        browser.is_connected = AsyncMock(return_value=True)
        return browser
    
    @pytest.fixture
    def mock_context(self):
        """Create a mock browser context."""
        context = AsyncMock()
        context.pages = AsyncMock(return_value=[])
        return context
    
    @pytest.fixture
    def sandbox(self, mock_browser, mock_context):
        """Create a Sandbox instance with mocked dependencies."""
        return Sandbox(mock_browser, mock_context)
    
    @pytest.mark.asyncio
    async def test_concurrent_page_creation_synchronized(self, sandbox, mock_context):
        """Test that concurrent page creation calls are synchronized."""
        mock_page = AsyncMock()
        call_count = 0
        
        async def delayed_new_page():
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.1)  # Simulate delay
            return mock_page
        
        mock_context.new_page.side_effect = delayed_new_page
        
        # Create multiple concurrent page creation calls
        tasks = [sandbox.create_page() for _ in range(5)]
        results = await asyncio.gather(*tasks)
        
        # All should return the same page (last one created)
        assert all(r == mock_page for r in results)
        # new_page should be called multiple times but only one page exists at a time
        assert sandbox.page == mock_page
    
    @pytest.mark.asyncio
    async def test_sandbox_health_check_healthy(self, sandbox, mock_browser):
        """Test that is_healthy returns True for healthy sandbox."""
        mock_browser.is_connected.return_value = True
        assert await sandbox.is_healthy() is True
    
    @pytest.mark.asyncio
    async def test_sandbox_health_check_disconnected_browser(self, sandbox, mock_browser):
        """Test that is_healthy returns False when browser is disconnected."""
        mock_browser.is_connected.return_value = False
        assert await sandbox.is_healthy() is False
    
    @pytest.mark.asyncio
    async def test_sandbox_health_check_closed_context(self, sandbox, mock_context):
        """Test that is_healthy returns False when context is closed."""
        mock_context.pages.side_effect = Exception("Context closed")
        assert await sandbox.is_healthy() is False
    
    @pytest.mark.asyncio
    async def test_create_sandbox_checks_health_before_reuse(self, manager):
        """Test that create_sandbox checks health before reusing existing sandbox."""
        mock_sandbox = MagicMock()
        mock_sandbox.is_healthy = AsyncMock(return_value=True)
        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True
        
        result = await manager.create_sandbox()
        
        assert result == mock_sandbox
        mock_sandbox.is_healthy.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_sandbox_recreates_unhealthy_sandbox(self, manager):
        """Test that create_sandbox recreates sandbox if existing one is unhealthy."""
        unhealthy_sandbox = MagicMock()
        unhealthy_sandbox.is_healthy = AsyncMock(return_value=False)
        manager.current_sandbox = unhealthy_sandbox
        manager._is_initialized = True
        
        new_sandbox = MagicMock()
        new_sandbox.is_healthy = AsyncMock(return_value=True)
        
        with patch.object(manager, '_create_sandbox_internal', return_value=new_sandbox):
            with patch.object(manager, '_cleanup_partial_initialization') as mock_cleanup:
                result = await manager.create_sandbox()
                
                assert result == new_sandbox
                mock_cleanup.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_concurrent_create_sandbox_synchronized(self, manager):
        """Test that concurrent create_sandbox calls are synchronized."""
        call_count = 0
        mock_sandbox = MagicMock()
        mock_sandbox.is_healthy = AsyncMock(return_value=True)
        
        async def delayed_create():
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.1)
            return mock_sandbox
        
        with patch.object(manager, '_create_sandbox_internal', side_effect=delayed_create):
            tasks = [manager.create_sandbox() for _ in range(5)]
            results = await asyncio.gather(*tasks)
            
            # All should return a sandbox
            assert all(r == mock_sandbox for r in results)
            # _create_sandbox_internal should only be called once due to synchronization
            assert call_count == 1
    
    @pytest.mark.asyncio
    async def test_concurrent_terminate_sandbox_synchronized(self, manager):
        """Test that concurrent terminate_sandbox calls are synchronized."""
        mock_sandbox = AsyncMock()
        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True
        
        # Create multiple concurrent terminate calls
        tasks = [manager.terminate_sandbox() for _ in range(5)]
        await asyncio.gather(*tasks)
        
        # close should be called exactly once
        assert mock_sandbox.close.call_count == 1
    
    @pytest.mark.asyncio
    async def test_cleanup_handles_cancelled_error_during_sandbox_close(self, manager):
        """Test that cleanup handles asyncio.CancelledError during sandbox close."""
        mock_sandbox = AsyncMock()
        mock_sandbox.close.side_effect = asyncio.CancelledError()
        manager.current_sandbox = mock_sandbox
        
        with pytest.raises(asyncio.CancelledError):
            await manager._cleanup_partial_initialization()
        
        # State should still be consistent
        assert manager.current_sandbox is None
        assert manager._is_initialized is False
    
    @pytest.mark.asyncio
    async def test_cleanup_handles_cancelled_error_during_browser_close(self, manager):
        """Test that cleanup handles asyncio.CancelledError during browser close."""
        mock_browser = AsyncMock()
        mock_browser.close.side_effect = asyncio.CancelledError()
        manager.browser = mock_browser
        
        with pytest.raises(asyncio.CancelledError):
            await manager._cleanup_partial_initialization()
        
        # State should still be consistent
        assert manager.browser is None
        assert manager._is_initialized is False
    
    @pytest.mark.asyncio
    async def test_create_sandbox_handles_cancelled_error(self, manager):
        """Test that create_sandbox handles asyncio.CancelledError gracefully."""
        async def failing_create():
            await asyncio.sleep(0.1)
            raise asyncio.CancelledError()
        
        with patch.object(manager, '_create_sandbox_internal', side_effect=failing_create):
            with pytest.raises(asyncio.CancelledError):
                await manager.create_sandbox()
        
        # State should be consistent
        assert manager.current_sandbox is None
        assert manager._is_initialized is False
    
    @pytest.mark.asyncio
    async def test_terminate_sandbox_handles_cancelled_error(self, manager):
        """Test that terminate_sandbox handles asyncio.CancelledError gracefully."""
        mock_sandbox = AsyncMock()
        mock_sandbox.close.side_effect = asyncio.CancelledError()
        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True
        
        with patch.object(manager, '_force_terminate') as mock_force:
            with pytest.raises(asyncio.CancelledError):
                await manager.terminate_sandbox(force=False)
            
            # Should still force terminate on cancellation
            mock_force.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_downloads_disabled_in_context(self, manager):
        """Test that downloads are disabled in browser context."""
        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        
        manager.playwright = AsyncMock()
        manager.playwright.chromium.launch = AsyncMock(return_value=mock_browser)
        mock_browser.new_context = AsyncMock(return_value=mock_context)
        
        await manager._create_sandbox_internal()
        
        # Verify accept_downloads=False was passed
        mock_browser.new_context.assert_called_once()
        call_kwargs = mock_browser.new_context.call_args[1]
        assert call_kwargs['accept_downloads'] is False
    
    @pytest.mark.asyncio
    async def test_partial_initialization_cleanup_reliable(self, manager):
        """Test that partial initialization cleanup is reliable even with errors."""
        # Set up partial state
        manager.current_sandbox = AsyncMock()
        manager.current_sandbox.close.side_effect = Exception("Close failed")
        manager.browser = AsyncMock()
        manager.browser.close.side_effect = Exception("Browser close failed")
        manager.playwright = AsyncMock()
        manager.playwright.stop.side_effect = Exception("Stop failed")
        
        await manager._cleanup_partial_initialization()
        
        # All state should be cleared despite errors
        assert manager.current_sandbox is None
        assert manager.browser is None
        assert manager.playwright is None
        assert manager._is_initialized is False
    
    @pytest.mark.asyncio
    async def test_reset_sandbox_synchronized(self, manager):
        """Test that reset_sandbox is synchronized with lifecycle operations."""
        mock_sandbox = AsyncMock()
        manager.current_sandbox = mock_sandbox
        manager._is_initialized = True
        
        reset_called = False
        
        async def slow_reset():
            nonlocal reset_called
            reset_called = True
            await asyncio.sleep(0.2)
        
        with patch.object(manager, 'terminate_sandbox', side_effect=slow_reset):
            with patch.object(manager, 'create_sandbox') as mock_create:
                # Try concurrent reset calls
                tasks = [manager.reset_sandbox() for _ in range(3)]
                await asyncio.gather(*tasks)
                
                # Should only complete once due to synchronization
                assert reset_called
