"""Unit tests for DOM data collection (Task 6.5).

Tests the collect_dom_data method for:
- HTML content collection
- Element count
- Form count
- Iframe count
- Script count
- Correct DOMData result
- Empty/minimal DOM
- Collection failure
- Failed=True behavior
- Compatibility with DataCollector.collect_all()
- Partial collection when another category fails

Validates Requirement: 2.2
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
from src.models import DOMData


@pytest.mark.asyncio
class TestDOMDataCollection:
    """Test DOM data collection functionality."""

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

    async def test_html_content_collected(self, collector, mock_sandbox):
        """Test that HTML content is collected."""
        mock_sandbox.page.content = AsyncMock(return_value="<html><body>Hello</body></html>")

        result = await collector.collect_dom_data(mock_sandbox)

        assert isinstance(result, DOMData)
        assert result.html_content == "<html><body>Hello</body></html>"
        assert result.failed is False

    async def test_element_count(self, collector, mock_sandbox):
        """Test that element count is calculated."""
        mock_sandbox.page.content = AsyncMock(return_value="<html><body><div><p></p></div></body></html>")
        mock_sandbox.page.query_selector_all = Mock(return_value=5)

        result = await collector.collect_dom_data(mock_sandbox)

        assert isinstance(result, DOMData)
        assert result.structure_metrics['element_count'] == 5
        assert result.failed is False

    async def test_form_count(self, collector, mock_sandbox):
        """Test that form count is calculated."""
        mock_sandbox.page.content = AsyncMock(return_value="<html><body><form></form></body></html>")
        mock_sandbox.page.query_selector_all = Mock(side_effect=[3, 1, 0, 0])  # *, form, iframe, script

        result = await collector.collect_dom_data(mock_sandbox)

        assert isinstance(result, DOMData)
        assert result.structure_metrics['form_count'] == 1
        assert result.failed is False

    async def test_iframe_count(self, collector, mock_sandbox):
        """Test that iframe count is calculated."""
        mock_sandbox.page.content = AsyncMock(return_value="<html><body><iframe></iframe></body></html>")
        mock_sandbox.page.query_selector_all = Mock(side_effect=[3, 0, 1, 0])  # *, form, iframe, script

        result = await collector.collect_dom_data(mock_sandbox)

        assert isinstance(result, DOMData)
        assert result.structure_metrics['iframe_count'] == 1
        assert result.failed is False

    async def test_script_count(self, collector, mock_sandbox):
        """Test that script count is calculated."""
        mock_sandbox.page.content = AsyncMock(return_value="<html><body><script></script></body></html>")
        mock_sandbox.page.query_selector_all = Mock(side_effect=[3, 0, 0, 1])  # *, form, iframe, script

        result = await collector.collect_dom_data(mock_sandbox)

        assert isinstance(result, DOMData)
        assert result.structure_metrics['script_count'] == 1
        assert result.failed is False

    async def test_all_metrics_collected(self, collector, mock_sandbox):
        """Test that all DOM metrics are collected together."""
        mock_sandbox.page.content = AsyncMock(return_value="<html><body><form></form><iframe></iframe><script></script></body></html>")
        mock_sandbox.page.query_selector_all = Mock(side_effect=[5, 1, 1, 1])  # *, form, iframe, script

        result = await collector.collect_dom_data(mock_sandbox)

        assert isinstance(result, DOMData)
        assert result.structure_metrics['element_count'] == 5
        assert result.structure_metrics['form_count'] == 1
        assert result.structure_metrics['iframe_count'] == 1
        assert result.structure_metrics['script_count'] == 1
        assert result.failed is False

    async def test_empty_dom(self, collector, mock_sandbox):
        """Test empty/minimal DOM."""
        mock_sandbox.page.content = AsyncMock(return_value="<html><body></body></html>")
        mock_sandbox.page.query_selector_all = Mock(side_effect=[2, 0, 0, 0])  # *, form, iframe, script

        result = await collector.collect_dom_data(mock_sandbox)

        assert isinstance(result, DOMData)
        assert result.structure_metrics['element_count'] == 2  # html, body
        assert result.structure_metrics['form_count'] == 0
        assert result.structure_metrics['iframe_count'] == 0
        assert result.structure_metrics['script_count'] == 0
        assert result.failed is False

    async def test_collection_failure(self, collector, mock_sandbox):
        """Test that collection failure is handled."""
        mock_sandbox.page.content = AsyncMock(side_effect=Exception("Page error"))

        with pytest.raises(Exception):
            await collector.collect_dom_data(mock_sandbox)

    async def test_failed_true_behavior(self, collector, mock_sandbox):
        """Test that failed=True is set on error through safe wrapper."""
        # This tests the safe wrapper behavior indirectly
        mock_sandbox.page.content = AsyncMock(side_effect=Exception("Page error"))

        # Call through safe wrapper
        result = await collector._collect_dom_data_safe(mock_sandbox)

        assert isinstance(result, DOMData)
        assert result.failed is True
        assert result.html_content == ""
        assert result.structure_metrics == {}

    async def test_correct_domdata_result(self, collector, mock_sandbox):
        """Test that correct DOMData object is returned."""
        mock_sandbox.page.content = AsyncMock(return_value="<html><body></body></html>")
        mock_sandbox.page.query_selector_all = AsyncMock(side_effect=[2, 0, 0, 0])

        result = await collector.collect_dom_data(mock_sandbox)

        assert isinstance(result, DOMData)
        assert hasattr(result, 'html_content')
        assert hasattr(result, 'structure_metrics')
        assert hasattr(result, 'failed')
        assert result.failed is False

    async def test_missing_page(self, collector, mock_sandbox):
        """Test behavior when page is None."""
        mock_sandbox.page = None

        with pytest.raises(ValueError, match="page is not available"):
            await collector.collect_dom_data(mock_sandbox)


@pytest.mark.asyncio
class TestDOMDataIntegration:
    """Test DOM data collection integration with DataCollector."""

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

    async def test_compatibility_with_collect_all(self, collector, mock_sandbox):
        """Test that collect_dom_data works with DataCollector.collect_all()."""
        # Mock other collection methods
        collector.collect_network_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_javascript_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_visual_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=Mock(failed=False)
        )

        # Set up DOM data
        mock_sandbox.page.content = AsyncMock(return_value="<html><body></body></html>")
        mock_sandbox.page.query_selector_all = Mock(side_effect=[2, 0, 0, 0])

        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.dom is not None
        assert isinstance(result.dom, DOMData)
        assert result.dom.failed is False

    async def test_partial_collection_when_network_fails(self, collector, mock_sandbox):
        """Test partial collection when another category fails."""
        # Make network fail
        collector.collect_network_data = AsyncMock(
            side_effect=Exception("Network failed")
        )
        collector.collect_javascript_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_visual_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=Mock(failed=False)
        )

        # Set up DOM data
        mock_sandbox.page.content = AsyncMock(return_value="<html><body></body></html>")
        mock_sandbox.page.query_selector_all = AsyncMock(side_effect=[2, 0, 0, 0])

        result = await collector.collect_all(mock_sandbox, "https://example.com")

        # Network should fail, DOM should succeed
        assert result.network.failed is True
        assert result.dom.failed is False
        assert result.dom.html_content == "<html><body></body></html>"
