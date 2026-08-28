"""Unit tests for DataCollector core framework (Task 6.1).

Tests the DataCollector class for:
- Concurrent collection orchestration
- Per-category failure isolation
- Overall timeout handling
- AnalysisData aggregation
- Partial collection support
- Resource cleanup

Validates Requirements: 2.6, 2.7, 2.8
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timezone

# Add src to path for imports
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
    SSLData
)


@pytest.mark.asyncio
class TestDataCollectorConcurrentCollection:
    """Test concurrent collection orchestration."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Create a mock Sandbox instance."""
        sandbox = Mock()
        sandbox.page = Mock()
        return sandbox

    async def test_collect_all_concurrent_collection(self, collector, mock_sandbox):
        """Test that all five categories are collected concurrently."""
        # Mock the individual collection methods
        collector.collect_network_data = AsyncMock(
            return_value=NetworkData(
                request_count=10,
                unique_domains=["example.com"],
                protocol_distribution={"https": 10}
            )
        )
        collector.collect_dom_data = AsyncMock(
            return_value=DOMData(
                html_content="<html></html>",
                structure_metrics={"elements": 5}
            )
        )
        collector.collect_javascript_data = AsyncMock(
            return_value=JavaScriptData(
                script_count=3,
                dom_modifications=2,
                external_api_calls=1
            )
        )
        collector.collect_visual_data = AsyncMock(
            return_value=VisualData(
                screenshot_path="/tmp/screenshot.png",
                layout_characteristics={"width": 1920}
            )
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=SSLData(
                issuer="Let's Encrypt",
                expiration_date="2025-01-01",
                chain_valid=True
            )
        )

        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.network is not None
        assert result.dom is not None
        assert result.javascript is not None
        assert result.visual is not None
        assert result.ssl is not None
        assert result.categories_collected == 5
        assert result.timeout_occurred is False

    async def test_collect_all_calls_all_methods(self, collector, mock_sandbox):
        """Test that collect_all calls all five collection methods."""
        collector.collect_network_data = AsyncMock(
            return_value=NetworkData(0, [], {})
        )
        collector.collect_dom_data = AsyncMock(
            return_value=DOMData("", {})
        )
        collector.collect_javascript_data = AsyncMock(
            return_value=JavaScriptData(0, 0, 0)
        )
        collector.collect_visual_data = AsyncMock(
            return_value=VisualData("", {})
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=SSLData("", "", False)
        )

        await collector.collect_all(mock_sandbox, "https://example.com")

        collector.collect_network_data.assert_called_once_with(mock_sandbox)
        collector.collect_dom_data.assert_called_once_with(mock_sandbox)
        collector.collect_javascript_data.assert_called_once_with(mock_sandbox)
        collector.collect_visual_data.assert_called_once_with(mock_sandbox)
        collector.collect_ssl_data.assert_called_once_with("https://example.com")


@pytest.mark.asyncio
class TestDataCollectorFailureIsolation:
    """Test per-category failure isolation."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Create a mock Sandbox instance."""
        sandbox = Mock()
        sandbox.page = Mock()
        return sandbox

    async def test_one_category_failure_does_not_cancel_others(self, collector, mock_sandbox):
        """Test that one category failure does not cancel other collections."""
        # Make network data fail
        collector.collect_network_data = AsyncMock(
            side_effect=Exception("Network collection failed")
        )
        # Other categories succeed
        collector.collect_dom_data = AsyncMock(
            return_value=DOMData("", {})
        )
        collector.collect_javascript_data = AsyncMock(
            return_value=JavaScriptData(0, 0, 0)
        )
        collector.collect_visual_data = AsyncMock(
            return_value=VisualData("", {})
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=SSLData("", "", False)
        )

        result = await collector.collect_all(mock_sandbox, "https://example.com")

        # Network should be marked as failed
        assert result.network is not None
        assert result.network.failed is True
        # Other categories should succeed
        assert result.dom is not None
        assert result.dom.failed is False
        assert result.javascript is not None
        assert result.javascript.failed is False
        assert result.visual is not None
        assert result.visual.failed is False
        assert result.ssl is not None
        assert result.ssl.failed is False
        # Categories collected should be 4 (network failed)
        assert result.categories_collected == 4

    async def test_multiple_category_failures(self, collector, mock_sandbox):
        """Test that multiple category failures are tracked correctly."""
        # Make network and DOM fail
        collector.collect_network_data = AsyncMock(
            side_effect=Exception("Network failed")
        )
        collector.collect_dom_data = AsyncMock(
            side_effect=Exception("DOM failed")
        )
        # Others succeed
        collector.collect_javascript_data = AsyncMock(
            return_value=JavaScriptData(0, 0, 0)
        )
        collector.collect_visual_data = AsyncMock(
            return_value=VisualData("", {})
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=SSLData("", "", False)
        )

        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.network.failed is True
        assert result.dom.failed is True
        assert result.javascript.failed is False
        assert result.visual.failed is False
        assert result.ssl.failed is False
        assert result.categories_collected == 3

    async def test_all_categories_fail(self, collector, mock_sandbox):
        """Test that all categories failing is handled correctly."""
        # Make all fail
        collector.collect_network_data = AsyncMock(
            side_effect=Exception("Network failed")
        )
        collector.collect_dom_data = AsyncMock(
            side_effect=Exception("DOM failed")
        )
        collector.collect_javascript_data = AsyncMock(
            side_effect=Exception("JS failed")
        )
        collector.collect_visual_data = AsyncMock(
            side_effect=Exception("Visual failed")
        )
        collector.collect_ssl_data = AsyncMock(
            side_effect=Exception("SSL failed")
        )

        result = await collector.collect_all(mock_sandbox, "https://example.com")

        # All should be marked as failed
        assert result.network.failed is True
        assert result.dom.failed is True
        assert result.javascript.failed is True
        assert result.visual.failed is True
        assert result.ssl.failed is True
        assert result.categories_collected == 0


@pytest.mark.asyncio
class TestDataCollectorTimeout:
    """Test overall timeout handling."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Create a mock Sandbox instance."""
        sandbox = Mock()
        sandbox.page = Mock()
        return sandbox

    async def test_overall_timeout_sets_flag(self, collector, mock_sandbox):
        """Test that overall timeout sets timeout_occurred flag."""
        # Make some collections slow
        async def slow_network(sandbox):
            await asyncio.sleep(10)
            return NetworkData(0, [], {})

        async def slow_dom(sandbox):
            await asyncio.sleep(10)
            return DOMData("", {})

        collector.collect_network_data = AsyncMock(side_effect=slow_network)
        collector.collect_dom_data = AsyncMock(side_effect=slow_dom)
        collector.collect_javascript_data = AsyncMock(
            return_value=JavaScriptData(0, 0, 0)
        )
        collector.collect_visual_data = AsyncMock(
            return_value=VisualData("", {})
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=SSLData("", "", False)
        )

        # Use very short timeout
        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.1)

        assert result.timeout_occurred is True

    async def test_timeout_aggregates_partial_results(self, collector, mock_sandbox):
        """Test that timeout aggregates partial results from completed tasks."""
        # Make some fast, some slow
        collector.collect_network_data = AsyncMock(
            return_value=NetworkData(5, ["example.com"], {"https": 5})
        )
        collector.collect_dom_data = AsyncMock(
            return_value=DOMData("<html></html>", {})
        )
        async def slow_js(sandbox):
            await asyncio.sleep(10)
            return JavaScriptData(0, 0, 0)
        collector.collect_javascript_data = AsyncMock(side_effect=slow_js)
        collector.collect_visual_data = AsyncMock(
            return_value=VisualData("", {})
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=SSLData("", "", False)
        )

        result = await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.1)

        assert result.timeout_occurred is True
        # Fast collections should have results
        assert result.network is not None
        assert result.dom is not None
        assert result.visual is not None
        assert result.ssl is not None
        # At least some should be collected
        assert result.categories_collected >= 3


@pytest.mark.asyncio
class TestDataCollectorAnalysisDataAggregation:
    """Test AnalysisData aggregation."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Create a mock Sandbox instance."""
        sandbox = Mock()
        sandbox.page = Mock()
        return sandbox

    async def test_aggregates_data_into_analysis_data(self, collector, mock_sandbox):
        """Test that collected data is aggregated into AnalysisData."""
        collector.collect_network_data = AsyncMock(
            return_value=NetworkData(10, ["example.com"], {"https": 10})
        )
        collector.collect_dom_data = AsyncMock(
            return_value=DOMData("<html></html>", {"elements": 5})
        )
        collector.collect_javascript_data = AsyncMock(
            return_value=JavaScriptData(3, 2, 1)
        )
        collector.collect_visual_data = AsyncMock(
            return_value=VisualData("/tmp/screenshot.png", {"width": 1920})
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=SSLData("Let's Encrypt", "2025-01-01", True)
        )

        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert isinstance(result, AnalysisData)
        assert result.network.request_count == 10
        assert result.dom.html_content == "<html></html>"
        assert result.javascript.script_count == 3
        assert result.visual.screenshot_path == "/tmp/screenshot.png"
        assert result.ssl.issuer == "Let's Encrypt"

    async def test_calculates_categories_collected_correctly(self, collector, mock_sandbox):
        """Test that categories_collected is calculated correctly."""
        # Make some fail
        collector.collect_network_data = AsyncMock(
            return_value=NetworkData(0, [], {})
        )
        collector.collect_dom_data = AsyncMock(
            side_effect=Exception("DOM failed")
        )
        collector.collect_javascript_data = AsyncMock(
            return_value=JavaScriptData(0, 0, 0)
        )
        collector.collect_visual_data = AsyncMock(
            side_effect=Exception("Visual failed")
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=SSLData("", "", False)
        )

        result = await collector.collect_all(mock_sandbox, "https://example.com")

        # Network, JS, SSL succeed = 3
        assert result.categories_collected == 3


@pytest.mark.asyncio
class TestDataCollectorResourceCleanup:
    """Test resource cleanup."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Create a mock Sandbox instance."""
        sandbox = Mock()
        sandbox.page = Mock()
        return sandbox

    async def test_cancels_pending_tasks_on_timeout(self, collector, mock_sandbox):
        """Test that pending tasks are cancelled on timeout."""
        cancelled_tasks = []

        async def slow_with_cancel(sandbox):
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                cancelled_tasks.append("cancelled")
                raise

        collector.collect_network_data = AsyncMock(side_effect=slow_with_cancel)
        collector.collect_dom_data = AsyncMock(
            return_value=DOMData("", {})
        )
        collector.collect_javascript_data = AsyncMock(
            return_value=JavaScriptData(0, 0, 0)
        )
        collector.collect_visual_data = AsyncMock(
            return_value=VisualData("", {})
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=SSLData("", "", False)
        )

        await collector.collect_all(mock_sandbox, "https://example.com", timeout=0.1)

        # Task should have been cancelled
        assert len(cancelled_tasks) > 0


@pytest.mark.asyncio
class TestDataCollectorDeterministicBehavior:
    """Test deterministic behavior."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Create a mock Sandbox instance."""
        sandbox = Mock()
        sandbox.page = Mock()
        return sandbox

    async def test_returns_analysis_data_even_on_total_failure(self, collector, mock_sandbox):
        """Test that AnalysisData is returned even if all collections fail."""
        collector.collect_network_data = AsyncMock(
            side_effect=Exception("Network failed")
        )
        collector.collect_dom_data = AsyncMock(
            side_effect=Exception("DOM failed")
        )
        collector.collect_javascript_data = AsyncMock(
            side_effect=Exception("JS failed")
        )
        collector.collect_visual_data = AsyncMock(
            side_effect=Exception("Visual failed")
        )
        collector.collect_ssl_data = AsyncMock(
            side_effect=Exception("SSL failed")
        )

        result = await collector.collect_all(mock_sandbox, "https://example.com")

        # Should still return AnalysisData, not raise
        assert isinstance(result, AnalysisData)
        assert result.categories_collected == 0

    async def test_empty_analysis_data_on_unexpected_error(self, collector, mock_sandbox):
        """Test that unexpected errors return empty AnalysisData."""
        # Simulate unexpected error in the orchestration itself
        with patch.object(collector, '_collect_network_data_safe', side_effect=RuntimeError("Unexpected")):
            with patch.object(collector, '_collect_dom_data_safe', side_effect=RuntimeError("Unexpected")):
                with patch.object(collector, '_collect_javascript_data_safe', side_effect=RuntimeError("Unexpected")):
                    with patch.object(collector, '_collect_visual_data_safe', side_effect=RuntimeError("Unexpected")):
                        with patch.object(collector, '_collect_ssl_data_safe', side_effect=RuntimeError("Unexpected")):
                            result = await collector.collect_all(mock_sandbox, "https://example.com")

                            # Should return empty AnalysisData
                            assert isinstance(result, AnalysisData)
                            assert result.categories_collected == 0
