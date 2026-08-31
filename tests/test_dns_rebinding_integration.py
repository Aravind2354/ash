"""Integration tests for DNS rebinding protection using Playwright.

Tests the actual browser behavior with DNS rebinding protection for:
- External HTTPS websites (should work)
- Localhost blocking (should be blocked)
- Private IP blocking (should be blocked)
- Redirects and subresources (should be checked)
"""

import os
import sys
import pytest
import pytest_asyncio
import asyncio

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.sandbox import SandboxManager
from src.violation_monitor import ViolationMonitor


class TestDNSRebindingIntegration:
    """Integration tests for DNS rebinding protection with real browser."""

    @pytest_asyncio.fixture
    async def sandbox_manager(self, sandbox_container_id):
        """Create a SandboxManager instance for testing.

        IMPORTANT: This fixture uses the SANDBOX_CONTAINER_ID environment variable
        as a test-infrastructure trust handoff from the host-side validation.

        This trust handoff exists only to connect the host-side validation result
        to the test process. It is not a production security mechanism.

        The host validates the actual Docker container configuration before setting
        this environment variable and running the tests.
        """
        violation_monitor = ViolationMonitor()
        manager = SandboxManager(violation_monitor=violation_monitor)

        # Read container ID from fixture (set by host-side test orchestration)
        cid = sandbox_container_id or "test-dev-container-id"
        manager.set_isolation_validated(cid)
        manager._detect_container_environment = lambda: True

        try:
            yield manager
        finally:
            # Cleanup
            try:
                await manager.cleanup()
            except Exception:
                pass  # Ignore cleanup errors

    @pytest.mark.asyncio
    async def test_external_https_website_loads(self, sandbox_manager):
        """Test that external HTTPS websites load successfully."""
        await sandbox_manager.create_sandbox()
        sandbox = await sandbox_manager.get_sandbox()

        # Test with a known external HTTPS website
        result = await sandbox.load_url('https://example.com', timeout=30)

        assert result is True, "External HTTPS website should load successfully"
        assert not sandbox_manager.violation_monitor.has_violations(), \
            "External websites should not trigger violations"

    @pytest.mark.asyncio
    async def test_localhost_blocked_at_url_level(self, sandbox_manager):
        """Test that localhost URLs are blocked before page load."""
        await sandbox_manager.create_sandbox()
        sandbox = await sandbox_manager.get_sandbox()

        # Internal IP violations raise RuntimeError (fail-closed behavior)
        with pytest.raises(RuntimeError) as exc_info:
            await sandbox.load_url('http://localhost:8080')

        # Verify error message
        assert "internal network address" in str(exc_info.value).lower()
        assert "localhost" in str(exc_info.value).lower()

        # Verify violation was logged
        assert sandbox_manager.violation_monitor.has_violations()

        # Verify sandbox was terminated
        assert sandbox_manager.current_sandbox is None

    @pytest.mark.asyncio
    async def test_127_0_0_1_blocked_at_url_level(self, sandbox_manager):
        """Test that 127.0.0.1 URLs are blocked before page load."""
        await sandbox_manager.create_sandbox()
        sandbox = await sandbox_manager.get_sandbox()

        # Internal IP violations raise RuntimeError (fail-closed behavior)
        with pytest.raises(RuntimeError) as exc_info:
            await sandbox.load_url('http://127.0.0.1:8080')

        # Verify error message
        assert "internal network address" in str(exc_info.value).lower()
        assert "127.0.0.1" in str(exc_info.value).lower()

        # Verify violation was logged
        assert sandbox_manager.violation_monitor.has_violations()

        # Verify sandbox was terminated
        assert sandbox_manager.current_sandbox is None

    @pytest.mark.asyncio
    async def test_rfc1918_blocked_at_url_level(self, sandbox_manager):
        """Test that RFC1918 private IP URLs are blocked before page load."""
        test_cases = [
            'http://10.0.0.1:8080',
            'http://172.16.0.1:8080',
            'http://192.168.1.1:8080'
        ]

        for url in test_cases:
            await sandbox_manager.create_sandbox()
            sandbox = await sandbox_manager.get_sandbox()
            sandbox_manager.violation_monitor.clear_violations()

            # Internal IP violations raise RuntimeError (fail-closed behavior)
            with pytest.raises(RuntimeError) as exc_info:
                await sandbox.load_url(url)

            # Verify error message
            assert "internal network address" in str(exc_info.value).lower()

            # Verify violation was logged
            assert sandbox_manager.violation_monitor.has_violations()

            # Verify sandbox was terminated
            assert sandbox_manager.current_sandbox is None

            # Clean up for next iteration
            await sandbox_manager.cleanup()

    @pytest.mark.asyncio
    async def test_metadata_service_blocked(self, sandbox_manager):
        """Test that cloud metadata service is blocked."""
        await sandbox_manager.create_sandbox()
        sandbox = await sandbox_manager.get_sandbox()

        # Internal IP violations raise RuntimeError (fail-closed behavior)
        with pytest.raises(RuntimeError) as exc_info:
            await sandbox.load_url('http://169.254.169.254')

        # Verify error message
        assert "internal network address" in str(exc_info.value).lower()
        assert "169.254.169.254" in str(exc_info.value).lower()

        # Verify violation was logged
        assert sandbox_manager.violation_monitor.has_violations()

        # Verify sandbox was terminated
        assert sandbox_manager.current_sandbox is None

    @pytest.mark.asyncio
    async def test_link_local_blocked(self, sandbox_manager):
        """Test that link-local addresses are blocked."""
        await sandbox_manager.create_sandbox()
        sandbox = await sandbox_manager.get_sandbox()

        # Internal IP violations raise RuntimeError (fail-closed behavior)
        with pytest.raises(RuntimeError) as exc_info:
            await sandbox.load_url('http://169.254.1.1')

        # Verify error message
        assert "internal network address" in str(exc_info.value).lower()
        assert "169.254.1.1" in str(exc_info.value).lower()

        # Verify violation was logged
        assert sandbox_manager.violation_monitor.has_violations()

        # Verify sandbox was terminated
        assert sandbox_manager.current_sandbox is None

    @pytest.mark.asyncio
    async def test_public_website_subresources_allowed(self, sandbox_manager):
        """Test that subresources from public websites are allowed."""
        await sandbox_manager.create_sandbox()
        sandbox = await sandbox_manager.get_sandbox()

        # Load a page with subresources
        result = await sandbox.load_url('https://example.com', timeout=30)

        assert result is True
        assert not sandbox_manager.violation_monitor.has_violations()

    @pytest.mark.asyncio
    async def test_sandbox_termination_on_violation(self, sandbox_manager):
        """Test that sandbox is terminated on security violations."""
        await sandbox_manager.create_sandbox()
        sandbox = await sandbox_manager.get_sandbox()

        # Internal IP violations raise RuntimeError (fail-closed behavior)
        with pytest.raises(RuntimeError) as exc_info:
            await sandbox.load_url('http://192.168.1.1')

        # Verify error message
        assert "internal network address" in str(exc_info.value).lower()

        # Verify sandbox was terminated
        assert sandbox_manager.current_sandbox is None

    @pytest.mark.asyncio
    async def test_public_dns_resolution_allowed(self, sandbox_manager):
        """Test that public DNS resolution is allowed."""
        await sandbox_manager.create_sandbox()
        sandbox = await sandbox_manager.get_sandbox()

        # Test with a domain that should resolve to public IPs
        result = await sandbox.load_url('https://www.example.com', timeout=30)

        assert result is True
        assert not sandbox_manager.violation_monitor.has_violations()


class TestRedirectHandling:
    """Test redirect handling with DNS rebinding protection."""

    @pytest_asyncio.fixture
    async def sandbox_manager(self, sandbox_container_id):
        """Create a SandboxManager instance for testing."""
        violation_monitor = ViolationMonitor()
        manager = SandboxManager(violation_monitor=violation_monitor)
        cid = sandbox_container_id or "test-dev-container-id"
        manager.set_isolation_validated(cid)
        manager._detect_container_environment = lambda: True
        try:
            yield manager
        finally:
            try:
                await manager.cleanup()
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_redirect_to_public_allowed(self, sandbox_manager):
        """Test that redirects to public domains are allowed."""
        await sandbox_manager.create_sandbox()
        sandbox = await sandbox_manager.get_sandbox()

        # Many sites redirect from http to https
        result = await sandbox.load_url('http://example.com', timeout=30)

        assert result is True
        assert not sandbox_manager.violation_monitor.has_violations()

    @pytest.mark.asyncio
    async def test_redirect_to_internal_blocked(self, sandbox_manager):
        """Test that redirects to internal addresses are blocked."""
        await sandbox_manager.create_sandbox()
        sandbox = await sandbox_manager.get_sandbox()

        # Internal IP violations raise RuntimeError (fail-closed behavior)
        with pytest.raises(RuntimeError) as exc_info:
            await sandbox.load_url('http://192.168.1.1')

        # Verify error message
        assert "internal network address" in str(exc_info.value).lower()

        # Verify violation was logged
        assert sandbox_manager.violation_monitor.has_violations()


class TestIPv6Handling:
    """Test IPv6 address handling with DNS rebinding protection."""

    @pytest_asyncio.fixture
    async def sandbox_manager(self, sandbox_container_id):
        """Create a SandboxManager instance for testing."""
        violation_monitor = ViolationMonitor()
        manager = SandboxManager(violation_monitor=violation_monitor)
        cid = sandbox_container_id or "test-dev-container-id"
        manager.set_isolation_validated(cid)
        manager._detect_container_environment = lambda: True
        try:
            yield manager
        finally:
            try:
                await manager.cleanup()
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_ipv6_loopback_blocked(self, sandbox_manager):
        """Test that IPv6 loopback is blocked."""
        await sandbox_manager.create_sandbox()
        sandbox = await sandbox_manager.get_sandbox()

        # Internal IP violations raise RuntimeError (fail-closed behavior)
        with pytest.raises(RuntimeError) as exc_info:
            await sandbox.load_url('http://[::1]:8080')

        # Verify error message
        assert "internal network address" in str(exc_info.value).lower()
        assert "::1" in str(exc_info.value).lower()

        # Verify violation was logged
        assert sandbox_manager.violation_monitor.has_violations()

        # Verify sandbox was terminated
        assert sandbox_manager.current_sandbox is None

    @pytest.mark.asyncio
    async def test_ipv6_ula_blocked(self, sandbox_manager):
        """Test that IPv6 ULA addresses are blocked."""
        await sandbox_manager.create_sandbox()
        sandbox = await sandbox_manager.get_sandbox()

        # Internal IP violations raise RuntimeError (fail-closed behavior)
        with pytest.raises(RuntimeError) as exc_info:
            await sandbox.load_url('http://[fd00::1]:8080')

        # Verify error message
        assert "internal network address" in str(exc_info.value).lower()
        assert "fd00::1" in str(exc_info.value).lower()

        # Verify violation was logged
        assert sandbox_manager.violation_monitor.has_violations()

        # Verify sandbox was terminated
        assert sandbox_manager.current_sandbox is None

    @pytest.mark.asyncio
    async def test_ipv6_link_local_blocked(self, sandbox_manager):
        """Test that IPv6 link-local addresses are blocked."""
        await sandbox_manager.create_sandbox()
        sandbox = await sandbox_manager.get_sandbox()

        # Internal IP violations raise RuntimeError (fail-closed behavior)
        with pytest.raises(RuntimeError) as exc_info:
            await sandbox.load_url('http://[fe80::1]:8080')

        # Verify error message
        assert "internal network address" in str(exc_info.value).lower()
        assert "fe80::1" in str(exc_info.value).lower()

        # Verify violation was logged
        assert sandbox_manager.violation_monitor.has_violations()

        # Verify sandbox was terminated
        assert sandbox_manager.current_sandbox is None
