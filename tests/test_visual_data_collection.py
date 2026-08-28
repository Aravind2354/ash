"""Unit tests for visual data collection (Task 6.9).

Tests the collect_visual_data method for:
- Successful screenshot capture
- Correct VisualData structure
- Screenshot path handling
- Layout characteristics (viewport, images, colors)
- Empty/minimal page
- Screenshot failure
- VisualData.failed behavior
- Cleanup of temporary visual resources
- Compatibility with DataCollector.collect_all()
- Partial collection when another category fails
- Repeated visual collection without resource leakage

Validates Requirement: 2.4
"""

import pytest
import asyncio
import os
import tempfile
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timezone

# Add src to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.data_collector import DataCollector
from src.models import VisualData


@pytest.mark.asyncio
class TestVisualDataCollection:
    """Test visual data collection functionality."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Create a mock Sandbox instance."""
        sandbox = Mock()
        sandbox.page = Mock()
        sandbox.page.viewport_size = {'width': 1920, 'height': 1080}
        sandbox.page.query_selector_all = Mock(return_value=5)
        sandbox.page.screenshot = AsyncMock()
        return sandbox

    async def test_successful_screenshot_capture(self, collector, mock_sandbox):
        """Test that screenshot is captured successfully."""
        mock_sandbox.page.screenshot = AsyncMock()

        result = await collector.collect_visual_data(mock_sandbox)

        assert isinstance(result, VisualData)
        assert result.screenshot_path != ""
        assert result.failed is False
        mock_sandbox.page.screenshot.assert_called_once()

    async def test_correct_visualdata_structure(self, collector, mock_sandbox):
        """Test that correct VisualData object is returned."""
        mock_sandbox.page.screenshot = AsyncMock()

        result = await collector.collect_visual_data(mock_sandbox)

        assert isinstance(result, VisualData)
        assert hasattr(result, 'screenshot_path')
        assert hasattr(result, 'layout_characteristics')
        assert hasattr(result, 'failed')
        assert result.failed is False

    async def test_screenshot_path_handling(self, collector, mock_sandbox):
        """Test that screenshot path is set correctly."""
        mock_sandbox.page.screenshot = AsyncMock()

        result = await collector.collect_visual_data(mock_sandbox)

        assert isinstance(result, VisualData)
        assert result.screenshot_path.endswith('.png')
        assert tempfile.gettempdir() in result.screenshot_path

    async def test_layout_characteristics_viewport(self, collector, mock_sandbox):
        """Test that viewport size is collected."""
        mock_sandbox.page.screenshot = AsyncMock()
        mock_sandbox.page.viewport_size = {'width': 1280, 'height': 720}

        result = await collector.collect_visual_data(mock_sandbox)

        assert isinstance(result, VisualData)
        assert result.layout_characteristics['viewport_width'] == 1280
        assert result.layout_characteristics['viewport_height'] == 720

    async def test_layout_characteristics_images(self, collector, mock_sandbox):
        """Test that image count is collected."""
        mock_sandbox.page.screenshot = AsyncMock()
        mock_sandbox.page.query_selector_all = Mock(return_value=10)

        result = await collector.collect_visual_data(mock_sandbox)

        assert isinstance(result, VisualData)
        assert result.layout_characteristics['image_count'] == 10

    async def test_all_layout_metrics(self, collector, mock_sandbox):
        """Test that all layout characteristics are collected."""
        mock_sandbox.page.screenshot = AsyncMock()
        mock_sandbox.page.viewport_size = {'width': 1920, 'height': 1080}
        mock_sandbox.page.query_selector_all = Mock(return_value=7)

        result = await collector.collect_visual_data(mock_sandbox)

        assert isinstance(result, VisualData)
        assert result.layout_characteristics['viewport_width'] == 1920
        assert result.layout_characteristics['viewport_height'] == 1080
        assert result.layout_characteristics['image_count'] == 7
        assert result.layout_characteristics['color_analysis_available'] is True

    async def test_empty_minimal_page(self, collector, mock_sandbox):
        """Test empty/minimal page."""
        mock_sandbox.page.screenshot = AsyncMock()
        mock_sandbox.page.viewport_size = {'width': 800, 'height': 600}
        mock_sandbox.page.query_selector_all = Mock(return_value=0)

        result = await collector.collect_visual_data(mock_sandbox)

        assert isinstance(result, VisualData)
        assert result.layout_characteristics['image_count'] == 0
        assert result.failed is False

    async def test_screenshot_failure(self, collector, mock_sandbox):
        """Test that screenshot failure is handled."""
        mock_sandbox.page.screenshot = AsyncMock(side_effect=Exception("Screenshot failed"))

        with pytest.raises(Exception):
            await collector.collect_visual_data(mock_sandbox)

    async def test_failed_true_behavior(self, collector, mock_sandbox):
        """Test that failed=True is set on error through safe wrapper."""
        mock_sandbox.page.screenshot = AsyncMock(side_effect=Exception("Screenshot failed"))

        # Call through safe wrapper
        result = await collector._collect_visual_data_safe(mock_sandbox)

        assert isinstance(result, VisualData)
        assert result.failed is True
        assert result.screenshot_path == ""
        assert result.layout_characteristics == {}

    async def test_missing_page(self, collector, mock_sandbox):
        """Test behavior when page is None."""
        mock_sandbox.page = None

        with pytest.raises(ValueError, match="page is not available"):
            await collector.collect_visual_data(mock_sandbox)

    async def test_screenshot_cleanup_on_failure(self, collector, mock_sandbox):
        """Test that screenshot cleanup is attempted on failure."""
        mock_sandbox.page.screenshot = AsyncMock(side_effect=Exception("Screenshot failed"))

        # Simulate a file being created before failure
        with patch('os.path.exists', return_value=True):
            with patch('os.remove') as mock_remove:
                try:
                    await collector.collect_visual_data(mock_sandbox)
                except Exception:
                    pass

                # Verify cleanup was attempted
                mock_remove.assert_called_once()

    async def test_no_screenshot_created_on_early_failure(self, collector, mock_sandbox):
        """Test that no screenshot is created if page is None."""
        mock_sandbox.page = None

        with patch('os.remove') as mock_remove:
            try:
                await collector.collect_visual_data(mock_sandbox)
            except ValueError:
                pass

            # No cleanup should be called since no screenshot was created
            mock_remove.assert_not_called()


@pytest.mark.asyncio
class TestVisualDataIntegration:
    """Test visual data collection integration with DataCollector."""

    @pytest.fixture
    def collector(self):
        """Create a DataCollector instance."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Create a mock Sandbox instance."""
        sandbox = Mock()
        sandbox.page = Mock()
        sandbox.page.viewport_size = {'width': 1920, 'height': 1080}
        sandbox.page.query_selector_all = Mock(return_value=5)
        sandbox.page.screenshot = AsyncMock()
        return sandbox

    async def test_compatibility_with_collect_all(self, collector, mock_sandbox):
        """Test that collect_visual_data works with DataCollector.collect_all()."""
        # Mock other collection methods
        collector.collect_network_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_dom_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_javascript_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=Mock(failed=False)
        )

        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.visual is not None
        assert isinstance(result.visual, VisualData)
        assert result.visual.failed is False

    async def test_partial_collection_when_network_fails(self, collector, mock_sandbox):
        """Test partial collection when another category fails."""
        # Make network fail
        collector.collect_network_data = AsyncMock(
            side_effect=Exception("Network failed")
        )
        collector.collect_dom_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_javascript_data = AsyncMock(
            return_value=Mock(failed=False)
        )
        collector.collect_ssl_data = AsyncMock(
            return_value=Mock(failed=False)
        )

        result = await collector.collect_all(mock_sandbox, "https://example.com")

        # Network should fail, Visual should succeed
        assert result.network.failed is True
        assert result.visual.failed is False
        assert result.visual.screenshot_path != ""

    async def test_repeated_collection_no_leakage(self, collector, mock_sandbox):
        """Test that repeated collection doesn't leak resources."""
        mock_sandbox.page.screenshot = AsyncMock()

        # Collect multiple times
        for _ in range(3):
            result = await collector.collect_visual_data(mock_sandbox)
            assert isinstance(result, VisualData)
            assert result.failed is False
            assert result.screenshot_path != ""

        # Verify screenshot was called each time
        assert mock_sandbox.page.screenshot.call_count == 3
