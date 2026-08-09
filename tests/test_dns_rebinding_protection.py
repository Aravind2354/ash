"""Unit tests for DNS rebinding protection.

Tests the DNS rebinding protection implemented in sandbox.py for detecting
when public hostnames resolve to private IP addresses.
"""

import pytest
import socket
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timezone

# Add src to path for imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.sandbox import Sandbox
from src.violation_monitor import ViolationMonitor


class TestDNSRebindingProtection:
    """Test DNS rebinding protection in Sandbox.load_url."""

    @pytest.fixture
    def violation_monitor(self):
        """Create a ViolationMonitor instance for testing."""
        return ViolationMonitor()

    @pytest.fixture
    def mock_browser(self):
        """Create a mock browser."""
        browser = Mock()
        browser.is_connected = Mock(return_value=True)
        return browser

    @pytest.fixture
    def mock_context(self):
        """Create a mock browser context."""
        context = Mock()
        context.new_page = AsyncMock()
        context.pages = AsyncMock(return_value=[])
        context.close = AsyncMock()
        return context

    @pytest.fixture
    def mock_sandbox_manager(self):
        """Create a mock SandboxManager."""
        manager = Mock()
        manager.validate_isolation = Mock(return_value=(True, ""))
        manager._container_id = "test_container"
        manager.terminate_sandbox = AsyncMock()
        return manager

    @pytest.fixture
    def sandbox(self, mock_browser, mock_context, mock_sandbox_manager, violation_monitor):
        """Create a Sandbox instance with mocked dependencies."""
        return Sandbox(mock_browser, mock_context, mock_sandbox_manager, violation_monitor)

    @pytest.mark.asyncio
    async def test_dns_rebinding_detected_main_url(self, sandbox, mock_sandbox_manager, violation_monitor):
        """Test DNS rebinding detection for main URL hostname."""
        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            # Simulate public hostname resolving to private IP
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 0))
            ]

            with pytest.raises(RuntimeError) as exc_info:
                await sandbox.load_url('http://example.com')

            assert "DNS rebinding detected" in str(exc_info.value)
            assert "example.com" in str(exc_info.value)
            assert "192.168.1.1" in str(exc_info.value)

            # Verify violation was logged
            assert violation_monitor.has_violations()
            violations = violation_monitor.get_violations()
            assert any(v['violation_type'] == 'internal_network' for v in violations)

            # Verify sandbox was terminated
            mock_sandbox_manager.terminate_sandbox.assert_called_once_with(force=True)

    @pytest.mark.asyncio
    async def test_dns_rebinding_allowed_public_ip(self, sandbox, mock_sandbox_manager, violation_monitor):
        """Test that public IPs resolving from hostnames are allowed."""
        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            # Simulate public hostname resolving to public IP
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))  # example.com
            ]

            with patch.object(sandbox, 'create_page', new_callable=AsyncMock):
                mock_page = Mock()
                mock_page.goto = AsyncMock()
                sandbox.page = mock_page

                result = await sandbox.load_url('http://example.com')

                assert result is True
                assert not violation_monitor.has_violations()
                mock_sandbox_manager.terminate_sandbox.assert_not_called()

    @pytest.mark.asyncio
    async def test_dns_rebinding_multi_ip_resolution(self, sandbox, mock_sandbox_manager, violation_monitor):
        """Test DNS rebinding detection when one of multiple IPs is private."""
        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            # Simulate hostname resolving to both public and private IPs
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 0))
            ]

            with pytest.raises(RuntimeError) as exc_info:
                await sandbox.load_url('http://example.com')

            assert "DNS rebinding detected" in str(exc_info.value)
            assert violation_monitor.has_violations()

    @pytest.mark.asyncio
    async def test_dns_rebinding_ipv6_private(self, sandbox, mock_sandbox_manager, violation_monitor):
        """Test DNS rebinding detection for IPv6 private addresses."""
        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            # Simulate hostname resolving to IPv6 ULA
            mock_getaddrinfo.return_value = [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('fd00::1', 0, 0))
            ]

            with pytest.raises(RuntimeError) as exc_info:
                await sandbox.load_url('http://example.com')

            assert "DNS rebinding detected" in str(exc_info.value)
            assert violation_monitor.has_violations()

    @pytest.mark.asyncio
    async def test_dns_rebinding_link_local(self, sandbox, mock_sandbox_manager, violation_monitor):
        """Test DNS rebinding detection for link-local addresses."""
        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            # Simulate hostname resolving to link-local IP
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.1.1', 0))
            ]

            with pytest.raises(RuntimeError) as exc_info:
                await sandbox.load_url('http://example.com')

            assert "DNS rebinding detected" in str(exc_info.value)
            assert violation_monitor.has_violations()

    @pytest.mark.asyncio
    async def test_dns_resolution_failure_handling(self, sandbox, mock_sandbox_manager, violation_monitor):
        """Test that DNS resolution failures fail closed for security."""
        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            # Simulate DNS resolution failure
            mock_getaddrinfo.side_effect = socket.gaierror("DNS resolution failed")

            with patch.object(sandbox, 'create_page', new_callable=AsyncMock):
                mock_page = Mock()
                mock_page.goto = AsyncMock()
                sandbox.page = mock_page

                # Should raise RuntimeError due to fail-closed behavior
                with pytest.raises(RuntimeError) as exc_info:
                    result = await sandbox.load_url('http://example.com')

                assert "DNS resolution failed" in str(exc_info.value)
                assert "Cannot safely load URL" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_direct_internal_ip_blocked(self, sandbox, mock_sandbox_manager, violation_monitor):
        """Test that URLs with direct internal IPs are blocked before DNS resolution."""
        with pytest.raises(RuntimeError) as exc_info:
            await sandbox.load_url('http://192.168.1.1')

        assert "internal network address" in str(exc_info.value)
        assert violation_monitor.has_violations()
        mock_sandbox_manager.terminate_sandbox.assert_called_once_with(force=True)

    @pytest.mark.asyncio
    async def test_localhost_blocked(self, sandbox, mock_sandbox_manager, violation_monitor):
        """Test that localhost URLs are blocked."""
        with pytest.raises(RuntimeError) as exc_info:
            await sandbox.load_url('http://localhost:8080')

        assert "internal network address" in str(exc_info.value)
        assert violation_monitor.has_violations()
        mock_sandbox_manager.terminate_sandbox.assert_called_once_with(force=True)

    @pytest.mark.asyncio
    async def test_metadata_service_blocked(self, sandbox, mock_sandbox_manager, violation_monitor):
        """Test that cloud metadata service URLs are blocked."""
        with pytest.raises(RuntimeError) as exc_info:
            await sandbox.load_url('http://169.254.169.254')

        assert "internal network address" in str(exc_info.value)
        assert violation_monitor.has_violations()
        mock_sandbox_manager.terminate_sandbox.assert_called_once_with(force=True)

    @pytest.mark.asyncio
    async def test_subresource_dns_reblocking(self, sandbox, violation_monitor):
        """Test DNS rebinding protection for subresource requests."""
        with patch.object(sandbox, 'create_page', new_callable=AsyncMock):
            mock_page = Mock()
            mock_page.route = Mock()
            mock_page.goto = AsyncMock()
            sandbox.page = mock_page

            await sandbox.load_url('http://example.com')

            # Get the request handler that was registered
            assert mock_page.route.called
            route_handler = mock_page.route.call_args[0][1]

            # Test the handler with a request to a rebinding hostname
            mock_route = Mock()
            mock_route.abort = Mock()
            mock_route.continue_ = Mock()

            mock_request = Mock()
            mock_request.url = 'http://evil.com/resource.js'
            mock_request.resource_type = 'script'

            with patch('socket.getaddrinfo') as mock_getaddrinfo:
                # Simulate evil.com resolving to private IP
                mock_getaddrinfo.return_value = [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 0))
                ]

                # Call the handler (sync function)
                route_handler(mock_route, mock_request)

                # Should have blocked the request
                mock_route.abort.assert_called_once()
                mock_route.continue_.assert_not_called()
                assert violation_monitor.has_violations()


class TestViolationMonitorIsGlobal:
    """Test ViolationMonitor.is_internal_ip using ip.is_global."""

    @pytest.fixture
    def monitor(self):
        """Create a ViolationMonitor instance for testing."""
        return ViolationMonitor()

    def test_is_global_coverage(self, monitor):
        """Test that is_global provides comprehensive coverage."""
        # RFC1918
        assert monitor.is_internal_ip('10.0.0.1') is True
        assert monitor.is_internal_ip('172.16.0.1') is True
        assert monitor.is_internal_ip('192.168.0.1') is True

        # IPv6 ULA
        assert monitor.is_internal_ip('fc00::1') is True
        assert monitor.is_internal_ip('fd00::1') is True

        # IPv6 link-local
        assert monitor.is_internal_ip('fe80::1') is True

        # IPv6 unspecified
        assert monitor.is_internal_ip('::') is True

        # IPv6 loopback
        assert monitor.is_internal_ip('::1') is True

        # Link-local IPv4
        assert monitor.is_internal_ip('169.254.1.1') is True

        # Carrier-grade NAT
        assert monitor.is_internal_ip('100.64.0.1') is True

        # Public IPv4
        assert monitor.is_internal_ip('8.8.8.8') is False
        assert monitor.is_internal_ip('1.1.1.1') is False

        # Public IPv6
        assert monitor.is_internal_ip('2001:4860:4860::8888') is False
        assert monitor.is_internal_ip('2606:4700:4700::1111') is False

    def test_hostname_check_before_resolution(self, monitor):
        """Test that hostname strings are checked before IP resolution."""
        assert monitor.is_internal_ip('localhost') is True
        assert monitor.is_internal_ip('LOCALHOST') is True  # Case insensitive
        assert monitor.is_internal_ip('127.0.0.1') is True
        assert monitor.is_internal_ip('::1') is True

    def test_invalid_ip_treated_as_external(self, monitor):
        """Test that invalid IP addresses are treated as external."""
        assert monitor.is_internal_ip('not-an-ip') is False
        assert monitor.is_internal_ip('999.999.999.999') is False
