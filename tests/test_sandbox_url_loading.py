"""Unit tests for Sandbox URL loading and redirect handling (Task 4.4).

Tests the Sandbox.load_url() method with:
- 30-second URL loading timeout
- 15-second responsiveness check
- Redirect following (max 5 redirects, 10s per redirect)
- Excessive redirect marking
- Pre-authentication content handling
- Security validation on redirects
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timezone

# Add src to path for imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.sandbox import Sandbox, RESPONSIVENESS_TIMEOUT, REDIRECT_TIMEOUT, MAX_REDIRECTS


@pytest.mark.asyncio
class TestSandboxURLLoading:
    """Test Sandbox.load_url() basic functionality."""

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
        mock_sandbox_manager.terminate_sandbox = AsyncMock()

        sandbox = Sandbox(mock_browser, mock_context, mock_sandbox_manager)
        sandbox.page = Mock()
        sandbox.page.goto = AsyncMock()
        sandbox.page.route = AsyncMock()
        sandbox.page.url = 'https://example.com'

        return sandbox

    async def test_load_url_success(self, sandbox):
        """Test successful URL loading with no redirects."""
        # Mock successful response (not a redirect)
        mock_response = Mock()
        mock_response.status = 200
        mock_response.headers = {}
        sandbox.page.goto = AsyncMock(return_value=mock_response)

        result = await sandbox.load_url('https://example.com')
        assert result is True
        assert sandbox.final_url == 'https://example.com'
        assert sandbox.redirect_count == 0
        assert sandbox.redirect_chain == ['https://example.com']

    async def test_load_url_timeout(self, sandbox):
        """Test URL loading timeout after 30 seconds."""
        sandbox.page.goto = AsyncMock(side_effect=asyncio.TimeoutError())

        result = await sandbox.load_url('https://example.com', timeout=30)
        assert result is False

    async def test_load_url_sets_redirect_tracking(self, sandbox):
        """Test that load_url initializes redirect tracking."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.headers = {}
        sandbox.page.goto = AsyncMock(return_value=mock_response)

        await sandbox.load_url('https://example.com')
        assert sandbox.redirect_chain == ['https://example.com']
        assert sandbox.redirect_count == 0
        assert sandbox.final_url == 'https://example.com'
        assert sandbox.suspicious_indicators == []


@pytest.mark.asyncio
class TestSandboxResponsiveness:
    """Test Sandbox.is_responsive() method."""

    @pytest.fixture
    async def sandbox(self):
        """Create a Sandbox instance with mocked dependencies."""
        mock_browser = Mock()
        mock_context = Mock()
        mock_context.pages = AsyncMock(return_value=[])
        mock_sandbox_manager = Mock()

        sandbox = Sandbox(mock_browser, mock_context, mock_sandbox_manager)
        return sandbox

    async def test_is_responsive_healthy_sandbox(self, sandbox):
        """Test is_responsive returns True for healthy sandbox."""
        sandbox.browser.is_connected = Mock(return_value=True)

        result = await sandbox.is_responsive()
        assert result is True

    async def test_is_responsive_unresponsive_sandbox(self, sandbox):
        """Test is_responsive returns False for unresponsive sandbox."""
        sandbox.browser.is_connected = Mock(return_value=False)

        result = await sandbox.is_responsive()
        assert result is False

    async def test_is_responsive_missing_browser(self, sandbox):
        """Test is_responsive returns False when browser is missing."""
        sandbox.browser = None

        result = await sandbox.is_responsive()
        assert result is False

    async def test_is_responsive_timeout(self, sandbox):
        """Test is_responsive handles timeout correctly."""
        async def slow_check():
            await asyncio.sleep(20)  # Exceeds RESPONSIVENESS_TIMEOUT
            return True

        sandbox.browser.is_connected = slow_check

        result = await sandbox.is_responsive()
        assert result is False


@pytest.mark.asyncio
class TestRedirectFollowing:
    """Test redirect following with limits."""

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
        sandbox.page.url = 'https://example.com'

        return sandbox

    async def test_zero_redirects(self, sandbox):
        """Test loading URL with no redirects."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.headers = {}
        sandbox.page.goto = AsyncMock(return_value=mock_response)

        result = await sandbox.load_url('https://example.com')
        assert result is True
        assert sandbox.redirect_count == 0
        assert len(sandbox.redirect_chain) == 1

    async def test_one_redirect(self, sandbox):
        """Test following one redirect."""
        # First call returns redirect
        redirect_response = Mock()
        redirect_response.status = 302
        redirect_response.headers = {'location': 'https://final.com'}

        # Second call returns final page
        final_response = Mock()
        final_response.status = 200
        final_response.headers = {}

        sandbox.page.goto = AsyncMock(side_effect=[redirect_response, final_response])

        result = await sandbox.load_url('https://example.com')
        assert result is True
        assert sandbox.redirect_count == 1
        assert sandbox.redirect_chain == ['https://example.com', 'https://final.com']

    async def test_five_redirects(self, sandbox):
        """Test following exactly 5 redirects."""
        responses = []
        for i in range(5):
            resp = Mock()
            resp.status = 302
            resp.headers = {'location': f'https://redirect{i}.com'}
            responses.append(resp)

        # Final response
        final = Mock()
        final.status = 200
        final.headers = {}
        responses.append(final)

        sandbox.page.goto = AsyncMock(side_effect=responses)

        result = await sandbox.load_url('https://example.com', timeout=60)  # Give enough time
        assert result is True
        assert sandbox.redirect_count == 5
        assert len(sandbox.redirect_chain) == 6  # initial + 5 redirects

    async def test_excessive_redirects_stops_at_5(self, sandbox):
        """Test that more than 5 redirects stops at redirect 5."""
        responses = []
        for i in range(5):
            resp = Mock()
            resp.status = 302
            resp.headers = {'location': f'https://redirect{i}.com'}
            responses.append(resp)

        sandbox.page.goto = AsyncMock(side_effect=responses)

        result = await sandbox.load_url('https://example.com', timeout=60)  # Give enough time
        assert result is True
        assert sandbox.redirect_count == 5
        assert len(sandbox.redirect_chain) == 6
        assert 'Excessive redirects' in str(sandbox.suspicious_indicators)
        # Should not attempt redirect 6
        assert sandbox.page.goto.call_count == 5

    async def test_redirect_timeout(self, sandbox):
        """Test that redirect timeout is enforced."""
        # First redirect succeeds
        redirect_response = Mock()
        redirect_response.status = 302
        redirect_response.headers = {'location': 'https://final.com'}

        # Second redirect times out
        sandbox.page.goto = AsyncMock(side_effect=[redirect_response, asyncio.TimeoutError()])

        result = await sandbox.load_url('https://example.com')
        assert result is True  # Analyzes page at redirect 1
        assert sandbox.redirect_count == 1


@pytest.mark.asyncio
class TestRedirectSecurityValidation:
    """Test security validation on redirect targets."""

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

        from src.violation_monitor import ViolationMonitor
        violation_monitor = ViolationMonitor()

        sandbox = Sandbox(mock_browser, mock_context, mock_sandbox_manager, violation_monitor)
        sandbox.page = Mock()
        sandbox.page.route = AsyncMock()
        sandbox.page.url = 'https://example.com'

        return sandbox

    async def test_redirect_to_internal_ip_blocked(self, sandbox):
        """Test that redirect to internal IP is blocked."""
        # First response redirects to internal IP
        redirect_response = Mock()
        redirect_response.status = 302
        redirect_response.headers = {'location': 'http://192.168.1.1/test'}

        sandbox.page.goto = AsyncMock(return_value=redirect_response)

        with pytest.raises(RuntimeError) as exc_info:
            await sandbox.load_url('https://example.com')

        assert "internal network address" in str(exc_info.value)
        assert "192.168.1.1" in str(exc_info.value)

    async def test_redirect_dns_rebinding_blocked(self, sandbox):
        """Test that DNS rebinding in redirect is blocked."""
        # First response redirects to public hostname that resolves to private IP
        redirect_response = Mock()
        redirect_response.status = 302
        redirect_response.headers = {'location': 'http://evil.com/test'}

        sandbox.page.goto = AsyncMock(return_value=redirect_response)

        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            # Simulate evil.com resolving to private IP
            mock_getaddrinfo.return_value = [
                (2, 1, 6, '', ('192.168.1.1', 0))
            ]

            with pytest.raises(RuntimeError) as exc_info:
                await sandbox.load_url('https://example.com')

            assert "DNS rebinding detected" in str(exc_info.value)
            assert "192.168.1.1" in str(exc_info.value)


@pytest.mark.asyncio
class TestRedirectChainTracking:
    """Test redirect chain tracking."""

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
        sandbox.page.url = 'https://example.com'

        return sandbox

    async def test_redirect_chain_recorded_correctly(self, sandbox):
        """Test that redirect chain is recorded in order."""
        responses = []
        redirect_urls = ['https://r1.com', 'https://r2.com', 'https://r3.com']

        for url in redirect_urls:
            resp = Mock()
            resp.status = 302
            resp.headers = {'location': url}
            responses.append(resp)

        final = Mock()
        final.status = 200
        final.headers = {}
        responses.append(final)

        sandbox.page.goto = AsyncMock(side_effect=responses)

        await sandbox.load_url('https://example.com')

        expected_chain = ['https://example.com'] + redirect_urls
        assert sandbox.redirect_chain == expected_chain
        assert sandbox.redirect_count == 3


class TestTimeoutConstants:
    """Test timeout constants are correctly defined."""

    def test_responsiveness_timeout_constant(self):
        """Test RESPONSIVENESS_TIMEOUT is 15 seconds."""
        assert RESPONSIVENESS_TIMEOUT == 15.0

    def test_redirect_timeout_constant(self):
        """Test REDIRECT_TIMEOUT is 10 seconds."""
        assert REDIRECT_TIMEOUT == 10.0

    def test_max_redirects_constant(self):
        """Test MAX_REDIRECTS is 5."""
        assert MAX_REDIRECTS == 5
