"""Unit tests for JavaScript data collection (Task 6.7).

Tests the collect_javascript_data method for:
- Script count
- DOM modification detection
- External API call detection
- Multiple scripts
- Multiple DOM modifications
- Multiple external API calls
- Empty/no-JavaScript case
- Collection failure
- JavaScriptData.failed behavior
- Correct JavaScriptData result structure
- Cleanup of listeners/instrumentation
- Compatibility with DataCollector.collect_all()
- Partial collection when another category fails

Validates Requirement: 2.3
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
from src.models import JavaScriptData


@pytest.mark.asyncio
class TestJavaScriptDataCollection:
    """Test JavaScript data collection functionality."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Create a mock Sandbox instance."""
        sandbox = Mock()
        sandbox.page = Mock()
        sandbox.page.query_selector_all = Mock(return_value=3)
        sandbox.page.evaluate = AsyncMock(side_effect=[None, None, 0, 0, None])  # observer, api, read mutations, read api, cleanup
        return sandbox

    async def test_script_count(self, collector, mock_sandbox):
        """Test that script count is collected."""
        mock_sandbox.page.query_selector_all = Mock(return_value=5)
        mock_sandbox.page.evaluate = AsyncMock(side_effect=[None, None, 0, 0, None])

        result = await collector.collect_javascript_data(mock_sandbox)

        assert isinstance(result, JavaScriptData)
        assert result.script_count == 5
        assert result.failed is False

    async def test_dom_modifications_detection(self, collector, mock_sandbox):
        """Test that DOM modifications are detected."""
        mock_sandbox.page.query_selector_all = Mock(return_value=3)
        mock_sandbox.page.evaluate = AsyncMock(side_effect=[None, None, 7, 0, None])  # 7 mutations

        result = await collector.collect_javascript_data(mock_sandbox)

        assert isinstance(result, JavaScriptData)
        assert result.dom_modifications == 7
        assert result.failed is False

    async def test_external_api_calls_detection(self, collector, mock_sandbox):
        """Test that external API calls are detected."""
        mock_sandbox.page.query_selector_all = Mock(return_value=3)
        mock_sandbox.page.evaluate = AsyncMock(side_effect=[None, None, 0, 4, None])  # 4 API calls

        result = await collector.collect_javascript_data(mock_sandbox)

        assert isinstance(result, JavaScriptData)
        assert result.external_api_calls == 4
        assert result.failed is False

    async def test_multiple_scripts(self, collector, mock_sandbox):
        """Test multiple scripts."""
        mock_sandbox.page.query_selector_all = Mock(return_value=10)
        mock_sandbox.page.evaluate = AsyncMock(side_effect=[None, None, 0, 0, None])

        result = await collector.collect_javascript_data(mock_sandbox)

        assert isinstance(result, JavaScriptData)
        assert result.script_count == 10
        assert result.failed is False

    async def test_all_metrics_collected(self, collector, mock_sandbox):
        """Test that all JavaScript metrics are collected together."""
        mock_sandbox.page.query_selector_all = Mock(return_value=7)
        mock_sandbox.page.evaluate = AsyncMock(side_effect=[None, None, 5, 3, None])  # 5 mutations, 3 API calls

        result = await collector.collect_javascript_data(mock_sandbox)

        assert isinstance(result, JavaScriptData)
        assert result.script_count == 7
        assert result.dom_modifications == 5
        assert result.external_api_calls == 3
        assert result.failed is False

    async def test_empty_javascript_case(self, collector, mock_sandbox):
        """Test empty/no-JavaScript case."""
        mock_sandbox.page.query_selector_all = Mock(return_value=0)
        mock_sandbox.page.evaluate = AsyncMock(side_effect=[None, None, 0, 0, None])

        result = await collector.collect_javascript_data(mock_sandbox)

        assert isinstance(result, JavaScriptData)
        assert result.script_count == 0
        assert result.dom_modifications == 0
        assert result.external_api_calls == 0
        assert result.failed is False

    async def test_collection_failure(self, collector, mock_sandbox):
        """Test that collection failure is handled."""
        mock_sandbox.page.query_selector_all = Mock(side_effect=Exception("Page error"))

        with pytest.raises(Exception):
            await collector.collect_javascript_data(mock_sandbox)

    async def test_failed_true_behavior(self, collector, mock_sandbox):
        """Test that failed=True is set on error through safe wrapper."""
        mock_sandbox.page.query_selector_all = Mock(side_effect=Exception("Page error"))

        # Call through safe wrapper
        result = await collector._collect_javascript_data_safe(mock_sandbox)

        assert isinstance(result, JavaScriptData)
        assert result.failed is True
        assert result.script_count == 0
        assert result.dom_modifications == 0
        assert result.external_api_calls == 0

    async def test_correct_javascriptdata_result(self, collector, mock_sandbox):
        """Test that correct JavaScriptData object is returned."""
        mock_sandbox.page.query_selector_all = Mock(return_value=3)
        mock_sandbox.page.evaluate = AsyncMock(side_effect=[None, None, 0, 0, None])

        result = await collector.collect_javascript_data(mock_sandbox)

        assert isinstance(result, JavaScriptData)
        assert hasattr(result, 'script_count')
        assert hasattr(result, 'dom_modifications')
        assert hasattr(result, 'external_api_calls')
        assert hasattr(result, 'failed')
        assert result.failed is False

    async def test_missing_page(self, collector, mock_sandbox):
        """Test behavior when page is None."""
        mock_sandbox.page = None

        with pytest.raises(ValueError, match="page is not available"):
            await collector.collect_javascript_data(mock_sandbox)

    async def test_instrumentation_cleanup(self, collector, mock_sandbox):
        """Test that instrumentation is cleaned up after collection."""
        mock_sandbox.page.query_selector_all = Mock(return_value=3)
        cleanup_called = []

        def mock_evaluate(script):
            if 'disconnect' in script or 'delete' in script:
                cleanup_called.append(script)
            return None

        mock_sandbox.page.evaluate = AsyncMock(side_effect=[
            None,  # observer setup
            None,  # api intercept setup
            0,     # read mutations
            0,     # read api
            None   # cleanup
        ])

        await collector.collect_javascript_data(mock_sandbox)

        # Verify cleanup was called
        assert mock_sandbox.page.evaluate.call_count == 5


@pytest.mark.asyncio
class TestJavaScriptDataIntegration:
    """Test JavaScript data collection integration with DataCollector."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Create a mock Sandbox instance."""
        sandbox = Mock()
        sandbox.page = Mock()
        sandbox.page.query_selector_all = Mock(return_value=5)
        sandbox.page.evaluate = AsyncMock(side_effect=[None, None, 0, 0, None])
        return sandbox

    async def test_compatibility_with_collect_all(self, collector, mock_sandbox):
        """Test that collect_javascript_data works with DataCollector.collect_all()."""
        # Mock other collection methods
        collector.collect_network_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_dom_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_visual_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=Mock(failed=False)
        )

        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.javascript is not None
        assert isinstance(result.javascript, JavaScriptData)
        assert result.javascript.failed is False

    async def test_partial_collection_when_network_fails(self, collector, mock_sandbox):
        """Test partial collection when another category fails."""
        # Make network fail
        collector.collect_network_data = AsyncMock(
            side_effect=Exception("Network failed")
        )
        collector.collect_dom_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_visual_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=Mock(failed=False)
        )

        result = await collector.collect_all(mock_sandbox, "https://example.com")

        # Network should fail, JavaScript should succeed
        assert result.network.failed is True
        assert result.javascript.failed is False
        assert result.javascript.script_count == 5
