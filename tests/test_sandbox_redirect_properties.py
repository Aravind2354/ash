"""Property-based tests for redirect handling (Task 4.5).

Tests Property 28: Redirect Following Limit and Property 29: Excessive Redirect Marking
using Hypothesis to generate random redirect chains.

Validates Requirements 8.6, 8.7.
"""

import pytest
import asyncio
from hypothesis import given, strategies as st, settings, HealthCheck
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timezone

# Add src to path for imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.sandbox import Sandbox, MAX_REDIRECTS, REDIRECT_TIMEOUT


@pytest.mark.asyncio
class TestProperty28RedirectFollowingLimit:
    """Property 28: Redirect Following Limit.

    *For any* redirect chain of length N, the system SHALL follow up to 5 redirects
    and analyze the page at redirect N if N ≤ 5, or the page at redirect 5 if N > 5.

    Validates: Requirements 8.6
    """

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

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=50
    )
    @given(
        redirect_count=st.integers(min_value=0, max_value=10)
    )
    async def test_redirect_following_limit(self, sandbox, redirect_count):
        """Property 28: For any redirect chain length N, follow up to 5 redirects.

        - If N <= 5: follow all redirects, analyze redirect N
        - If N > 5: follow only 5 redirects, analyze redirect 5
        - Never follow redirect 6+
        """
        # Create mock responses for redirect chain
        responses = []
        for i in range(redirect_count):
            resp = Mock()
            resp.status = 302
            resp.headers = {'location': f'https://redirect{i}.com'}
            responses.append(resp)

        # Final response (if any redirects)
        final = Mock()
        final.status = 200
        final.headers = {}
        responses.append(final)

        # Set up goto to return responses in sequence
        sandbox.page.goto = AsyncMock(side_effect=responses)

        # Load URL
        result = await sandbox.load_url('https://example.com', timeout=60)

        # Verify behavior based on redirect count
        if redirect_count <= MAX_REDIRECTS:
            # Should follow all redirects
            assert result is True
            assert sandbox.redirect_count == redirect_count
            assert len(sandbox.redirect_chain) == redirect_count + 1  # initial + redirects
            # When redirect_count == MAX_REDIRECTS, we stop at redirect 5 and don't load final response
            expected_calls = redirect_count + 1 if redirect_count < MAX_REDIRECTS else redirect_count
            assert sandbox.page.goto.call_count == expected_calls
        else:
            # Should stop at MAX_REDIRECTS
            assert result is True
            assert sandbox.redirect_count == MAX_REDIRECTS
            assert len(sandbox.redirect_chain) == MAX_REDIRECTS + 1
            assert sandbox.page.goto.call_count == MAX_REDIRECTS  # Only the 5 redirects, no final load
            assert 'Excessive redirects' in str(sandbox.suspicious_indicators)


@pytest.mark.asyncio
class TestProperty29ExcessiveRedirectMarking:
    """Property 29: Excessive Redirect Marking.

    *For any* redirect chain exceeding 5 redirects, the system SHALL mark the site
    as suspicious in Analysis_Data and analyze the page reached at the 5th redirect.

    Validates: Requirements 8.7
    """

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

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=50
    )
    @given(
        redirect_count=st.integers(min_value=6, max_value=10)
    )
    async def test_excessive_redirect_marking(self, sandbox, redirect_count):
        """Property 29: For chains >5 redirects, mark suspicious and analyze redirect 5.

        - Stop following at redirect 5
        - Analyze page at redirect 5
        - Mark site as suspicious
        - Never follow redirect 6+
        """
        # Create mock responses for redirect chain (more than 5)
        responses = []
        for i in range(redirect_count):
            resp = Mock()
            resp.status = 302
            resp.headers = {'location': f'https://redirect{i}.com'}
            responses.append(resp)

        sandbox.page.goto = AsyncMock(side_effect=responses)

        # Load URL
        result = await sandbox.load_url('https://example.com', timeout=60)

        # Verify excessive redirect marking
        assert result is True
        assert sandbox.redirect_count == MAX_REDIRECTS
        assert len(sandbox.suspicious_indicators) > 0
        assert any('Excessive redirects' in str(ind) for ind in sandbox.suspicious_indicators)
        assert f'max {MAX_REDIRECTS}' in str(sandbox.suspicious_indicators)

        # Verify never followed redirect 6+
        assert sandbox.page.goto.call_count == MAX_REDIRECTS  # Only the 5 redirects


@pytest.mark.asyncio
class TestRedirectChainTracking:
    """Test redirect chain tracking with Hypothesis."""

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

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=30
    )
    @given(
        redirect_count=st.integers(min_value=0, max_value=5)
    )
    async def test_redirect_chain_preserved(self, sandbox, redirect_count):
        """Verify redirect chain is preserved in correct order."""
        responses = []
        expected_chain = ['https://example.com']

        for i in range(redirect_count):
            resp = Mock()
            resp.status = 302
            resp.headers = {'location': f'https://redirect{i}.com'}
            responses.append(resp)
            expected_chain.append(f'https://redirect{i}.com')

        final = Mock()
        final.status = 200
        final.headers = {}
        responses.append(final)

        sandbox.page.goto = AsyncMock(side_effect=responses)

        await sandbox.load_url('https://example.com', timeout=60)

        assert sandbox.redirect_chain == expected_chain


@pytest.mark.asyncio
class TestRedirectZeroToOne:
    """Test boundary cases: 0 and 1 redirect."""

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

    async def test_zero_redirects(self, sandbox):
        """Test 0 redirects - direct load."""
        final = Mock()
        final.status = 200
        final.headers = {}
        sandbox.page.goto = AsyncMock(return_value=final)

        result = await sandbox.load_url('https://example.com')

        assert result is True
        assert sandbox.redirect_count == 0
        assert sandbox.redirect_chain == ['https://example.com']
        assert sandbox.page.goto.call_count == 1

    async def test_one_redirect(self, sandbox):
        """Test 1 redirect."""
        redirect = Mock()
        redirect.status = 302
        redirect.headers = {'location': 'https://final.com'}

        final = Mock()
        final.status = 200
        final.headers = {}

        sandbox.page.goto = AsyncMock(side_effect=[redirect, final])

        result = await sandbox.load_url('https://example.com')

        assert result is True
        assert sandbox.redirect_count == 1
        assert sandbox.redirect_chain == ['https://example.com', 'https://final.com']
        assert sandbox.page.goto.call_count == 2


@pytest.mark.asyncio
class TestRedirectBoundaries:
    """Test boundary values: 2-4 and exactly 5 redirects."""

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

    async def test_two_to_four_redirects(self, sandbox):
        """Test 2-4 redirects (within limit)."""
        for n in [2, 3, 4]:
            sandbox.redirect_count = 0
            sandbox.redirect_chain = []
            sandbox.suspicious_indicators = []

            responses = []
            for i in range(n):
                resp = Mock()
                resp.status = 302
                resp.headers = {'location': f'https://redirect{i}.com'}
                responses.append(resp)

            final = Mock()
            final.status = 200
            final.headers = {}
            responses.append(final)

            sandbox.page.goto = AsyncMock(side_effect=responses)

            result = await sandbox.load_url('https://example.com', timeout=60)

            assert result is True
            assert sandbox.redirect_count == n
            assert len(sandbox.redirect_chain) == n + 1
            # Load n redirect pages + 1 final page
            assert sandbox.page.goto.call_count == n + 1

    async def test_exactly_five_redirects(self, sandbox):
        """Test exactly 5 redirects (at limit)."""
        responses = []
        for i in range(5):
            resp = Mock()
            resp.status = 302
            resp.headers = {'location': f'https://redirect{i}.com'}
            responses.append(resp)

        final = Mock()
        final.status = 200
        final.headers = {}
        responses.append(final)

        sandbox.page.goto = AsyncMock(side_effect=responses)

        result = await sandbox.load_url('https://example.com', timeout=60)

        assert result is True
        assert sandbox.redirect_count == 5
        assert len(sandbox.redirect_chain) == 6
        # With exactly 5 redirects, we load 5 pages and get 5 redirect headers, then stop
        # The final response (non-redirect) is never loaded
        assert sandbox.page.goto.call_count == 5
