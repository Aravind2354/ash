"""Unit tests for collection timeout scenarios (Task 6.13).

Tests timeout behavior and category threshold invariants for DataCollector:
- Verification of default 60-second collection timeout parameter
- Actual timeout execution with in-progress tasks cancelled and awaited
- timeout_occurred flag semantics (True only on actual timeout, False on success/error/NA)
- Category count thresholds: 0, 1, 2 (< 3 threshold), 3 (minimum decision threshold), 4, 5 categories
- Per-category timeout isolation (Network, DOM, JavaScript, Visual, SSL)
- Multiple concurrent timeouts (2, 3, 4, 5 hanging tasks)
- Cancellation tracking and resource cleanup
- Mixed category failures + timeouts + successes in a single execution
- Exception resilience returning safe AnalysisData

Validates Requirements: 2.7, 8.3
"""

import pytest
import asyncio
import inspect
from typing import Optional
from unittest.mock import Mock, AsyncMock, patch

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.data_collector import DataCollector
from src.models import (
    AnalysisData,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
)


# ---------------------------------------------------------------------------
# Helper Mock Factory Functions
# ---------------------------------------------------------------------------

def _mock_successful_network() -> NetworkData:
    return NetworkData(request_count=5, unique_domains=["example.com"], protocol_distribution={"https": 5})

def _mock_successful_dom() -> DOMData:
    return DOMData(html_content="<html><body><h1>Test</h1></body></html>", structure_metrics={"elements": 10})

def _mock_successful_js() -> JavaScriptData:
    return JavaScriptData(script_count=2, dom_modifications=1, external_api_calls=1)

def _mock_successful_visual() -> VisualData:
    return VisualData(screenshot_path="/tmp/test.png", layout_characteristics={"width": 1280})

def _mock_successful_ssl() -> SSLData:
    return SSLData(issuer="CN=Test CA, O=Test Org, C=US", expiration_date="2030-01-01T00:00:00Z", chain_valid=True)


# ---------------------------------------------------------------------------
# Test Suite 1: Default Timeout Parameter & In-Progress Task Cancellation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDefaultTimeoutAndInProgressTasks:
    """Validate default 60-second timeout parameter and in-progress task cancellation."""

    @pytest.fixture
    def collector(self):
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        sandbox = Mock()
        sandbox.page = Mock()
        return sandbox

    async def test_default_timeout_parameter_is_60_seconds(self, collector):
        """Requirement 2.7: Verify DataCollector.collect_all default timeout parameter is exactly 60 seconds."""
        sig = inspect.signature(collector.collect_all)
        timeout_param = sig.parameters.get("timeout")
        assert timeout_param is not None, "collect_all must accept a 'timeout' parameter"
        assert timeout_param.default == 60, (
            f"Expected default timeout of 60 seconds (Req 2.7), got {timeout_param.default}"
        )

    async def test_collect_all_passes_default_60s_to_wait_for(self, collector, mock_sandbox):
        """Verify collect_all passes timeout=60 to asyncio.wait_for when called without explicit timeout."""
        collector.collect_network_data = AsyncMock(return_value=_mock_successful_network())
        collector.collect_dom_data = AsyncMock(return_value=_mock_successful_dom())
        collector.collect_javascript_data = AsyncMock(return_value=_mock_successful_js())
        collector.collect_visual_data = AsyncMock(return_value=_mock_successful_visual())
        collector.collect_ssl_data = AsyncMock(return_value=_mock_successful_ssl())

        with patch('asyncio.wait_for', wraps=asyncio.wait_for) as spy_wait_for:
            result = await collector.collect_all(mock_sandbox, "https://example.com")
            spy_wait_for.assert_called_once()
            _, kwargs = spy_wait_for.call_args
            assert kwargs.get("timeout") == 60, f"Expected wait_for timeout=60, got {kwargs.get('timeout')}"
            assert result.timeout_occurred is False
            assert result.categories_collected == 5

    async def test_in_progress_tasks_cancelled_on_timeout(self, collector, mock_sandbox):
        """Requirement 2.7: In-progress tasks must be cancelled and awaited on timeout."""
        cancelled_events = {"network": False, "dom": False}

        async def hanging_network(sandbox):
            try:
                await asyncio.sleep(10)
                return _mock_successful_network()
            except asyncio.CancelledError:
                cancelled_events["network"] = True
                raise

        async def hanging_dom(sandbox):
            try:
                await asyncio.sleep(10)
                return _mock_successful_dom()
            except asyncio.CancelledError:
                cancelled_events["dom"] = True
                raise

        collector.collect_network_data = AsyncMock(side_effect=hanging_network)
        collector.collect_dom_data = AsyncMock(side_effect=hanging_dom)
        collector.collect_javascript_data = AsyncMock(return_value=_mock_successful_js())
        collector.collect_visual_data = AsyncMock(return_value=_mock_successful_visual())
        collector.collect_ssl_data = AsyncMock(return_value=_mock_successful_ssl())

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        # Invariant 1: Timeout occurred flag is True
        assert result.timeout_occurred is True

        # Invariant 2: Hanging tasks received CancelledError
        assert cancelled_events["network"] is True, "Network task must receive cancellation"
        assert cancelled_events["dom"] is True, "DOM task must receive cancellation"

        # Invariant 3: Fast tasks preserved
        assert result.javascript is not None
        assert result.javascript.failed is False
        assert result.visual is not None
        assert result.visual.failed is False
        assert result.ssl is not None
        assert result.ssl.failed is False

        # Invariant 4: Timed-out tasks are None in partial result
        assert result.network is None
        assert result.dom is None

        # Invariant 5: categories_collected accurately counts completed categories
        assert result.categories_collected == 3


# ---------------------------------------------------------------------------
# Test Suite 2: Timeout Flag Marking Invariants
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestTimeoutFlagMarking:
    """Verify timeout_occurred is True ONLY on actual timeout and False for all non-timeout outcomes."""

    @pytest.fixture
    def collector(self):
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        sandbox = Mock()
        sandbox.page = Mock()
        return sandbox

    async def test_timeout_flag_true_on_actual_timeout(self, collector, mock_sandbox):
        """Invariant: timeout_occurred must be True when timeout occurs."""
        async def hang(sandbox):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(side_effect=hang)
        collector.collect_dom_data = AsyncMock(side_effect=hang)
        collector.collect_javascript_data = AsyncMock(side_effect=hang)
        collector.collect_visual_data = AsyncMock(side_effect=hang)
        collector.collect_ssl_data = AsyncMock(side_effect=hang)

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)
        assert result.timeout_occurred is True

    async def test_timeout_flag_false_on_successful_collection(self, collector, mock_sandbox):
        """Invariant: timeout_occurred must be False when all collectors succeed."""
        collector.collect_network_data = AsyncMock(return_value=_mock_successful_network())
        collector.collect_dom_data = AsyncMock(return_value=_mock_successful_dom())
        collector.collect_javascript_data = AsyncMock(return_value=_mock_successful_js())
        collector.collect_visual_data = AsyncMock(return_value=_mock_successful_visual())
        collector.collect_ssl_data = AsyncMock(return_value=_mock_successful_ssl())

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=1.0)
        assert result.timeout_occurred is False
        assert result.categories_collected == 5

    async def test_timeout_flag_false_when_categories_fail_without_timeout(self, collector, mock_sandbox):
        """Invariant: Category-level errors (exceptions) must NOT set timeout_occurred=True."""
        collector.collect_network_data = AsyncMock(side_effect=RuntimeError("DNS failure"))
        collector.collect_dom_data = AsyncMock(side_effect=ValueError("Invalid DOM"))
        collector.collect_javascript_data = AsyncMock(return_value=_mock_successful_js())
        collector.collect_visual_data = AsyncMock(return_value=_mock_successful_visual())
        collector.collect_ssl_data = AsyncMock(side_effect=ConnectionError("SSL handshake refused"))

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=1.0)

        # Failure flags are set, but timeout_occurred is strictly False
        assert result.timeout_occurred is False
        assert result.network.failed is True
        assert result.dom.failed is True
        assert result.ssl.failed is True
        assert result.javascript.failed is False
        assert result.visual.failed is False
        assert result.categories_collected == 2

    async def test_timeout_flag_false_for_non_https_url(self, collector, mock_sandbox):
        """Invariant: HTTP/non-HTTPS URLs (marking SSL as N/A) must NOT set timeout_occurred=True."""
        collector.collect_network_data = AsyncMock(return_value=_mock_successful_network())
        collector.collect_dom_data = AsyncMock(return_value=_mock_successful_dom())
        collector.collect_javascript_data = AsyncMock(return_value=_mock_successful_js())
        collector.collect_visual_data = AsyncMock(return_value=_mock_successful_visual())

        result = await collector.collect_all(mock_sandbox, "http://insecure-example.com", timeout=1.0)

        assert result.timeout_occurred is False
        assert result.ssl.failed is True
        assert result.categories_collected == 4


# ---------------------------------------------------------------------------
# Test Suite 3: Category Count Thresholds (0..5 Categories)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCategoryCountThresholds:
    """Validate categories_collected for 0, 1, 2 (< 3 threshold), 3, 4, and 5 categories."""

    @pytest.fixture
    def collector(self):
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        sandbox = Mock()
        sandbox.page = Mock()
        return sandbox

    async def test_zero_categories_collected_all_timeout(self, collector, mock_sandbox):
        """0 categories collected: all 5 collectors time out."""
        async def hang(*args):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(side_effect=hang)
        collector.collect_dom_data = AsyncMock(side_effect=hang)
        collector.collect_javascript_data = AsyncMock(side_effect=hang)
        collector.collect_visual_data = AsyncMock(side_effect=hang)
        collector.collect_ssl_data = AsyncMock(side_effect=hang)

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        assert isinstance(result, AnalysisData)
        assert result.timeout_occurred is True
        assert result.categories_collected == 0
        assert result.network is None
        assert result.dom is None
        assert result.javascript is None
        assert result.visual is None
        assert result.ssl is None

    async def test_one_category_collected_four_timeout(self, collector, mock_sandbox):
        """1 category collected: Network succeeds, 4 time out."""
        async def hang(*args):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(return_value=_mock_successful_network())
        collector.collect_dom_data = AsyncMock(side_effect=hang)
        collector.collect_javascript_data = AsyncMock(side_effect=hang)
        collector.collect_visual_data = AsyncMock(side_effect=hang)
        collector.collect_ssl_data = AsyncMock(side_effect=hang)

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        assert result.timeout_occurred is True
        assert result.categories_collected == 1
        assert result.network is not None and not result.network.failed
        assert result.dom is None
        assert result.javascript is None
        assert result.visual is None
        assert result.ssl is None

    async def test_two_categories_collected_three_timeout(self, collector, mock_sandbox):
        """2 categories collected (< 3 threshold for Req 8.3): DOM and SSL succeed, 3 time out."""
        async def hang(*args):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(side_effect=hang)
        collector.collect_dom_data = AsyncMock(return_value=_mock_successful_dom())
        collector.collect_javascript_data = AsyncMock(side_effect=hang)
        collector.collect_visual_data = AsyncMock(side_effect=hang)
        collector.collect_ssl_data = AsyncMock(return_value=_mock_successful_ssl())

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        assert result.timeout_occurred is True
        assert result.categories_collected == 2
        assert result.dom is not None and not result.dom.failed
        assert result.ssl is not None and not result.ssl.failed
        assert result.network is None
        assert result.javascript is None
        assert result.visual is None

    async def test_three_categories_collected_two_timeout(self, collector, mock_sandbox):
        """3 categories collected (minimum threshold for AI decisions): Network, JS, Visual succeed."""
        async def hang(*args):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(return_value=_mock_successful_network())
        collector.collect_dom_data = AsyncMock(side_effect=hang)
        collector.collect_javascript_data = AsyncMock(return_value=_mock_successful_js())
        collector.collect_visual_data = AsyncMock(return_value=_mock_successful_visual())
        collector.collect_ssl_data = AsyncMock(side_effect=hang)

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        assert result.timeout_occurred is True
        assert result.categories_collected == 3
        assert result.network is not None and not result.network.failed
        assert result.javascript is not None and not result.javascript.failed
        assert result.visual is not None and not result.visual.failed
        assert result.dom is None
        assert result.ssl is None

    async def test_four_categories_collected_one_timeout(self, collector, mock_sandbox):
        """4 categories collected: Network, DOM, JS, SSL succeed, Visual times out."""
        async def hang(*args):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(return_value=_mock_successful_network())
        collector.collect_dom_data = AsyncMock(return_value=_mock_successful_dom())
        collector.collect_javascript_data = AsyncMock(return_value=_mock_successful_js())
        collector.collect_visual_data = AsyncMock(side_effect=hang)
        collector.collect_ssl_data = AsyncMock(return_value=_mock_successful_ssl())

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        assert result.timeout_occurred is True
        assert result.categories_collected == 4
        assert result.network is not None
        assert result.dom is not None
        assert result.javascript is not None
        assert result.ssl is not None
        assert result.visual is None

    async def test_all_five_categories_collected_no_timeout(self, collector, mock_sandbox):
        """5 categories collected: All succeed within timeout."""
        collector.collect_network_data = AsyncMock(return_value=_mock_successful_network())
        collector.collect_dom_data = AsyncMock(return_value=_mock_successful_dom())
        collector.collect_javascript_data = AsyncMock(return_value=_mock_successful_js())
        collector.collect_visual_data = AsyncMock(return_value=_mock_successful_visual())
        collector.collect_ssl_data = AsyncMock(return_value=_mock_successful_ssl())

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=1.0)

        assert result.timeout_occurred is False
        assert result.categories_collected == 5


# ---------------------------------------------------------------------------
# Test Suite 4: Per-Category Timeout Isolation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestPerCategoryTimeoutIsolation:
    """Verify that each collector can individually time out while preserving the other 4."""

    @pytest.fixture
    def collector(self):
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        sandbox = Mock()
        sandbox.page = Mock()
        return sandbox

    async def test_network_timeout_isolated(self, collector, mock_sandbox):
        """Network hangs; DOM, JS, Visual, SSL succeed."""
        async def hang(*args):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(side_effect=hang)
        collector.collect_dom_data = AsyncMock(return_value=_mock_successful_dom())
        collector.collect_javascript_data = AsyncMock(return_value=_mock_successful_js())
        collector.collect_visual_data = AsyncMock(return_value=_mock_successful_visual())
        collector.collect_ssl_data = AsyncMock(return_value=_mock_successful_ssl())

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        assert result.timeout_occurred is True
        assert result.network is None
        assert result.dom is not None and not result.dom.failed
        assert result.javascript is not None and not result.javascript.failed
        assert result.visual is not None and not result.visual.failed
        assert result.ssl is not None and not result.ssl.failed
        assert result.categories_collected == 4

    async def test_dom_timeout_isolated(self, collector, mock_sandbox):
        """DOM hangs; Network, JS, Visual, SSL succeed."""
        async def hang(*args):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(return_value=_mock_successful_network())
        collector.collect_dom_data = AsyncMock(side_effect=hang)
        collector.collect_javascript_data = AsyncMock(return_value=_mock_successful_js())
        collector.collect_visual_data = AsyncMock(return_value=_mock_successful_visual())
        collector.collect_ssl_data = AsyncMock(return_value=_mock_successful_ssl())

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        assert result.timeout_occurred is True
        assert result.dom is None
        assert result.network is not None and not result.network.failed
        assert result.javascript is not None and not result.javascript.failed
        assert result.visual is not None and not result.visual.failed
        assert result.ssl is not None and not result.ssl.failed
        assert result.categories_collected == 4

    async def test_javascript_timeout_isolated(self, collector, mock_sandbox):
        """JavaScript hangs; Network, DOM, Visual, SSL succeed."""
        async def hang(*args):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(return_value=_mock_successful_network())
        collector.collect_dom_data = AsyncMock(return_value=_mock_successful_dom())
        collector.collect_javascript_data = AsyncMock(side_effect=hang)
        collector.collect_visual_data = AsyncMock(return_value=_mock_successful_visual())
        collector.collect_ssl_data = AsyncMock(return_value=_mock_successful_ssl())

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        assert result.timeout_occurred is True
        assert result.javascript is None
        assert result.network is not None and not result.network.failed
        assert result.dom is not None and not result.dom.failed
        assert result.visual is not None and not result.visual.failed
        assert result.ssl is not None and not result.ssl.failed
        assert result.categories_collected == 4

    async def test_visual_timeout_isolated(self, collector, mock_sandbox):
        """Visual hangs; Network, DOM, JS, SSL succeed."""
        async def hang(*args):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(return_value=_mock_successful_network())
        collector.collect_dom_data = AsyncMock(return_value=_mock_successful_dom())
        collector.collect_javascript_data = AsyncMock(return_value=_mock_successful_js())
        collector.collect_visual_data = AsyncMock(side_effect=hang)
        collector.collect_ssl_data = AsyncMock(return_value=_mock_successful_ssl())

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        assert result.timeout_occurred is True
        assert result.visual is None
        assert result.network is not None and not result.network.failed
        assert result.dom is not None and not result.dom.failed
        assert result.javascript is not None and not result.javascript.failed
        assert result.ssl is not None and not result.ssl.failed
        assert result.categories_collected == 4

    async def test_ssl_timeout_isolated(self, collector, mock_sandbox):
        """SSL hangs; Network, DOM, JS, Visual succeed."""
        async def hang(*args):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(return_value=_mock_successful_network())
        collector.collect_dom_data = AsyncMock(return_value=_mock_successful_dom())
        collector.collect_javascript_data = AsyncMock(return_value=_mock_successful_js())
        collector.collect_visual_data = AsyncMock(return_value=_mock_successful_visual())
        collector.collect_ssl_data = AsyncMock(side_effect=hang)

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        assert result.timeout_occurred is True
        assert result.ssl is None
        assert result.network is not None and not result.network.failed
        assert result.dom is not None and not result.dom.failed
        assert result.javascript is not None and not result.javascript.failed
        assert result.visual is not None and not result.visual.failed
        assert result.categories_collected == 4


# ---------------------------------------------------------------------------
# Test Suite 5: Multiple Timeouts & Mixed Failure Scenarios
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestMultipleTimeoutsAndMixedFailures:
    """Validate multiple concurrent timeouts and mixed failure + timeout interactions."""

    @pytest.fixture
    def collector(self):
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        sandbox = Mock()
        sandbox.page = Mock()
        return sandbox

    async def test_two_hanging_three_successful(self, collector, mock_sandbox):
        """2 hanging tasks (Network, DOM) + 3 successful (JS, Visual, SSL)."""
        async def hang(*args):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(side_effect=hang)
        collector.collect_dom_data = AsyncMock(side_effect=hang)
        collector.collect_javascript_data = AsyncMock(return_value=_mock_successful_js())
        collector.collect_visual_data = AsyncMock(return_value=_mock_successful_visual())
        collector.collect_ssl_data = AsyncMock(return_value=_mock_successful_ssl())

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        assert result.timeout_occurred is True
        assert result.categories_collected == 3

    async def test_three_hanging_two_successful(self, collector, mock_sandbox):
        """3 hanging tasks (Network, DOM, JS) + 2 successful (Visual, SSL)."""
        async def hang(*args):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(side_effect=hang)
        collector.collect_dom_data = AsyncMock(side_effect=hang)
        collector.collect_javascript_data = AsyncMock(side_effect=hang)
        collector.collect_visual_data = AsyncMock(return_value=_mock_successful_visual())
        collector.collect_ssl_data = AsyncMock(return_value=_mock_successful_ssl())

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        assert result.timeout_occurred is True
        assert result.categories_collected == 2

    async def test_four_hanging_one_successful(self, collector, mock_sandbox):
        """4 hanging tasks + 1 successful (SSL)."""
        async def hang(*args):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(side_effect=hang)
        collector.collect_dom_data = AsyncMock(side_effect=hang)
        collector.collect_javascript_data = AsyncMock(side_effect=hang)
        collector.collect_visual_data = AsyncMock(side_effect=hang)
        collector.collect_ssl_data = AsyncMock(return_value=_mock_successful_ssl())

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        assert result.timeout_occurred is True
        assert result.categories_collected == 1

    async def test_mixed_failure_and_timeout_and_success(self, collector, mock_sandbox):
        """Mixed execution: 1 category error (DOM), 2 timeouts (JS, Visual), 2 successes (Network, SSL)."""
        async def hang(*args):
            await asyncio.sleep(10)

        collector.collect_network_data = AsyncMock(return_value=_mock_successful_network())
        collector.collect_dom_data = AsyncMock(side_effect=RuntimeError("DOM parser crashed"))
        collector.collect_javascript_data = AsyncMock(side_effect=hang)
        collector.collect_visual_data = AsyncMock(side_effect=hang)
        collector.collect_ssl_data = AsyncMock(return_value=_mock_successful_ssl())

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.05)

        # Invariant 1: Timeout flag is True because overall timeout occurred
        assert result.timeout_occurred is True

        # Invariant 2: Completed successful categories are preserved
        assert result.network is not None and not result.network.failed
        assert result.ssl is not None and not result.ssl.failed

        # Invariant 3: Category error handled through safe wrapper (failed=True)
        assert result.dom is not None and result.dom.failed is True

        # Invariant 4: Hanging categories cancelled (None)
        assert result.javascript is None
        assert result.visual is None

        # Invariant 5: categories_collected accurately counts only successful non-failed categories
        assert result.categories_collected == 2

    async def test_unexpected_error_in_orchestration_returns_empty_analysis_data(self, collector, mock_sandbox):
        """Unexpected exception during overall orchestration safely returns AnalysisData."""
        with patch.object(collector, '_collect_network_data_safe', side_effect=TypeError("Unexpected error")):
            with patch.object(collector, '_collect_dom_data_safe', side_effect=TypeError("Unexpected error")):
                with patch.object(collector, '_collect_javascript_data_safe', side_effect=TypeError("Unexpected error")):
                    with patch.object(collector, '_collect_visual_data_safe', side_effect=TypeError("Unexpected error")):
                        with patch.object(collector, '_collect_ssl_data_safe', side_effect=TypeError("Unexpected error")):
                            result = await collector.collect_all(mock_sandbox, "https://example.com")
                            assert isinstance(result, AnalysisData)
                            assert result.categories_collected == 0
