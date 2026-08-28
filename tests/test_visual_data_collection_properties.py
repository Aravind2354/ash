"""Property-based tests for Visual Data Collection (Task 6.10).

Property 4: Visual Data Collection

*For any* rendered webpage in the virtual environment, the data collector
SHALL collect visual rendering characteristics and include them in
Analysis_Data.

Validates: Requirements 2.4

Design:
-------
collect_visual_data() works by:
  1. Creating a unique screenshot filepath (.png in tempfile.gettempdir())
  2. Invoking await sandbox.page.screenshot(path=screenshot_path, full_page=False)
  3. Reading sandbox.page.viewport_size (if present: viewport_width and viewport_height)
  4. Counting image elements via sandbox.page.query_selector_all('img')
  5. Setting layout_characteristics['color_analysis_available'] = True
  6. Returning a VisualData instance with failed=False
  7. On exception: cleaning up screenshot file if created and propagating exception.
     Safe wrapper _collect_visual_data_safe returns VisualData(failed=True).

Test Strategy:
  - Generate arbitrary visual scenarios using Hypothesis (viewport dimensions,
    present/None viewport, image counts).
  - Verify screenshot arguments, path validity, viewport metrics extraction,
    image counts, and color analysis flag across property sweeps.
  - Verify integration with DataCollector.collect_all() -> AnalysisData.visual.
  - Verify deterministic boundary cases and cleanup behaviors.
"""

import pytest
import asyncio
import os
import tempfile
from typing import Dict, Any, Optional
from unittest.mock import Mock, AsyncMock, patch

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from hypothesis import given, strategies as st, settings, HealthCheck

from src.data_collector import DataCollector
from src.models import AnalysisData, VisualData


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

viewport_width_strategy = st.integers(min_value=320, max_value=3840)
viewport_height_strategy = st.integers(min_value=240, max_value=2160)
image_count_strategy = st.integers(min_value=0, max_value=200)
has_viewport_strategy = st.booleans()


@st.composite
def visual_scenario_strategy(draw) -> Dict[str, Any]:
    """Generate arbitrary visual rendering scenarios."""
    has_viewport = draw(has_viewport_strategy)
    if has_viewport:
        width = draw(viewport_width_strategy)
        height = draw(viewport_height_strategy)
        viewport_size = {"width": width, "height": height}
    else:
        viewport_size = None

    image_count = draw(image_count_strategy)
    return {
        "viewport_size": viewport_size,
        "image_count": image_count,
    }


def _make_mock_sandbox(scenario: Dict[str, Any]) -> Mock:
    """Create a mock Sandbox instance configured with the visual scenario."""
    sandbox = Mock()
    page = Mock()
    page.viewport_size = scenario["viewport_size"]
    page.query_selector_all = Mock(return_value=scenario["image_count"])
    page.screenshot = AsyncMock()
    sandbox.page = page
    return sandbox


# ---------------------------------------------------------------------------
# Property 4 -- Primary Test Class
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty4VisualDataCollection:
    """Property 4: Visual Data Collection.

    *For any* rendered webpage in the virtual environment, the data collector
    SHALL collect visual rendering characteristics and include them in
    Analysis_Data.

    Validates: Requirements 2.4
    """

    @pytest.fixture
    def collector(self):
        """Create a fresh DataCollector instance."""
        return DataCollector()

    # ------------------------------------------------------------------
    # Primary combined property test: all invariants verified across 100 examples
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=100,
    )
    @given(scenario=visual_scenario_strategy())
    async def test_property_4_all_invariants(self, collector, scenario: Dict[str, Any]):
        """Property 4: For any generated visual rendering scenario, verify screenshot
        execution, viewport characteristics, image count, color flag, and data integrity.
        """
        sandbox = _make_mock_sandbox(scenario)

        result = await collector.collect_visual_data(sandbox)

        # Invariant 1: Result is VisualData instance
        assert isinstance(result, VisualData), f"Expected VisualData, got {type(result)}"

        # Invariant 2: failed flag is False on success
        assert result.failed is False, "failed flag must be False for successful collection"

        # Invariant 3: Screenshot path is valid, ends with .png, and is in tempdir
        assert result.screenshot_path != "", "screenshot_path must not be empty"
        assert result.screenshot_path.endswith(".png"), "screenshot_path must end with .png"
        assert tempfile.gettempdir() in result.screenshot_path, "screenshot_path must reside in temp directory"

        # Invariant 4: page.screenshot was called once with exact path and full_page=False
        sandbox.page.screenshot.assert_called_once()
        call_kwargs = sandbox.page.screenshot.call_args.kwargs
        assert call_kwargs.get("path") == result.screenshot_path, (
            f"screenshot path '{call_kwargs.get('path')}' does not match result.screenshot_path '{result.screenshot_path}'"
        )
        assert call_kwargs.get("full_page") is False, "screenshot must be called with full_page=False"

        # Invariant 5: Viewport dimensions
        if scenario["viewport_size"] is not None:
            assert result.layout_characteristics["viewport_width"] == scenario["viewport_size"]["width"], (
                f"viewport_width={result.layout_characteristics.get('viewport_width')}, "
                f"expected={scenario['viewport_size']['width']}"
            )
            assert result.layout_characteristics["viewport_height"] == scenario["viewport_size"]["height"], (
                f"viewport_height={result.layout_characteristics.get('viewport_height')}, "
                f"expected={scenario['viewport_size']['height']}"
            )
        else:
            assert "viewport_width" not in result.layout_characteristics
            assert "viewport_height" not in result.layout_characteristics

        # Invariant 6: Image count
        assert result.layout_characteristics["image_count"] == scenario["image_count"], (
            f"image_count={result.layout_characteristics.get('image_count')}, "
            f"expected={scenario['image_count']}"
        )

        # Invariant 7: Color analysis availability flag
        assert result.layout_characteristics["color_analysis_available"] is True, (
            "color_analysis_available must be True"
        )

    # ------------------------------------------------------------------
    # Independent Property Tests for Shrinking & Isolation
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(scenario=visual_scenario_strategy())
    async def test_property_4_screenshot_path_and_options(self, collector, scenario: Dict[str, Any]):
        """Invariant: screenshot() is called with full_page=False and accurate temp path."""
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_visual_data(sandbox)

        sandbox.page.screenshot.assert_called_once_with(path=result.screenshot_path, full_page=False)
        assert result.screenshot_path.endswith(".png")

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(scenario=visual_scenario_strategy())
    async def test_property_4_viewport_characteristics(self, collector, scenario: Dict[str, Any]):
        """Invariant: Viewport width/height are captured when present, omitted when None."""
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_visual_data(sandbox)

        if scenario["viewport_size"] is not None:
            assert result.layout_characteristics["viewport_width"] == scenario["viewport_size"]["width"]
            assert result.layout_characteristics["viewport_height"] == scenario["viewport_size"]["height"]
        else:
            assert "viewport_width" not in result.layout_characteristics
            assert "viewport_height" not in result.layout_characteristics

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(scenario=visual_scenario_strategy())
    async def test_property_4_image_count_captured(self, collector, scenario: Dict[str, Any]):
        """Invariant: image_count accurately matches query_selector_all('img')."""
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_visual_data(sandbox)
        assert result.layout_characteristics["image_count"] == scenario["image_count"]

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(scenario=visual_scenario_strategy())
    async def test_property_4_color_analysis_flag(self, collector, scenario: Dict[str, Any]):
        """Invariant: color_analysis_available flag is True."""
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_visual_data(sandbox)
        assert result.layout_characteristics["color_analysis_available"] is True

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(scenario=visual_scenario_strategy())
    async def test_property_4_failed_flag_false(self, collector, scenario: Dict[str, Any]):
        """Invariant: failed is False for all valid collections."""
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_visual_data(sandbox)
        assert result.failed is False


# ---------------------------------------------------------------------------
# collect_all() Integration Property Test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty4CollectAllIntegration:
    """Verify VisualData is correctly placed into AnalysisData.visual during collect_all()."""

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=50,
    )
    @given(scenario=visual_scenario_strategy())
    async def test_visual_data_in_analysis_data(self, scenario: Dict[str, Any]):
        """Property 4 integration: collect_all() aggregates VisualData into AnalysisData.visual."""
        collector = DataCollector()
        sandbox = _make_mock_sandbox(scenario)

        # Mock unrelated collectors so the test focuses cleanly on visual collection
        collector.collect_network_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_dom_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_javascript_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_ssl_data = AsyncMock(return_value=Mock(failed=False))

        result = await collector.collect_all(sandbox, "https://example.com")

        assert isinstance(result, AnalysisData)
        assert result.visual is not None
        assert isinstance(result.visual, VisualData)
        assert result.visual.failed is False
        assert result.visual.screenshot_path != ""
        assert result.visual.layout_characteristics["image_count"] == scenario["image_count"]
        assert result.visual.layout_characteristics["color_analysis_available"] is True

        if scenario["viewport_size"] is not None:
            assert result.visual.layout_characteristics["viewport_width"] == scenario["viewport_size"]["width"]
            assert result.visual.layout_characteristics["viewport_height"] == scenario["viewport_size"]["height"]


# ---------------------------------------------------------------------------
# Boundary & Failure Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty4BoundaryAndFailureCases:
    """Deterministic boundary tests covering specific viewports, error paths, and cleanups."""

    @pytest.fixture
    def collector(self):
        return DataCollector()

    async def test_mobile_viewport(self, collector):
        """Boundary 1: Mobile viewport 375x667."""
        scenario = {"viewport_size": {"width": 375, "height": 667}, "image_count": 3}
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_visual_data(sandbox)

        assert result.layout_characteristics["viewport_width"] == 375
        assert result.layout_characteristics["viewport_height"] == 667
        assert result.layout_characteristics["image_count"] == 3
        assert result.failed is False

    async def test_desktop_viewport(self, collector):
        """Boundary 2: Standard desktop viewport 1920x1080."""
        scenario = {"viewport_size": {"width": 1920, "height": 1080}, "image_count": 8}
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_visual_data(sandbox)

        assert result.layout_characteristics["viewport_width"] == 1920
        assert result.layout_characteristics["viewport_height"] == 1080
        assert result.layout_characteristics["image_count"] == 8
        assert result.failed is False

    async def test_ultrawide_viewport(self, collector):
        """Boundary 3: Ultrawide / 4K viewport 3840x2160."""
        scenario = {"viewport_size": {"width": 3840, "height": 2160}, "image_count": 25}
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_visual_data(sandbox)

        assert result.layout_characteristics["viewport_width"] == 3840
        assert result.layout_characteristics["viewport_height"] == 2160
        assert result.layout_characteristics["image_count"] == 25
        assert result.failed is False

    async def test_viewport_size_none(self, collector):
        """Boundary 4: viewport_size is None."""
        scenario = {"viewport_size": None, "image_count": 0}
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_visual_data(sandbox)

        assert "viewport_width" not in result.layout_characteristics
        assert "viewport_height" not in result.layout_characteristics
        assert result.layout_characteristics["image_count"] == 0
        assert result.failed is False

    async def test_zero_images(self, collector):
        """Boundary 5: Zero images on the page."""
        scenario = {"viewport_size": {"width": 1280, "height": 720}, "image_count": 0}
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_visual_data(sandbox)

        assert result.layout_characteristics["image_count"] == 0
        assert result.failed is False

    async def test_high_image_count(self, collector):
        """Boundary 6: High volume of images (500)."""
        scenario = {"viewport_size": {"width": 1920, "height": 1080}, "image_count": 500}
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_visual_data(sandbox)

        assert result.layout_characteristics["image_count"] == 500
        assert result.failed is False

    async def test_screenshot_failure_raises_exception(self, collector):
        """Failure 7: page.screenshot failure raises exception in direct collect_visual_data."""
        sandbox = Mock()
        sandbox.page = Mock()
        sandbox.page.screenshot = AsyncMock(side_effect=RuntimeError("GPU rasterization error"))

        with pytest.raises(RuntimeError, match="GPU rasterization error"):
            await collector.collect_visual_data(sandbox)

    async def test_screenshot_failure_handled_by_safe_wrapper(self, collector):
        """Failure 8: screenshot failure sets failed=True via safe wrapper."""
        sandbox = Mock()
        sandbox.page = Mock()
        sandbox.page.screenshot = AsyncMock(side_effect=RuntimeError("GPU rasterization error"))

        result = await collector._collect_visual_data_safe(sandbox)

        assert isinstance(result, VisualData)
        assert result.failed is True
        assert result.screenshot_path == ""
        assert result.layout_characteristics == {}

    async def test_screenshot_cleanup_on_failure(self, collector):
        """Failure 9: Screenshot file is removed if failure occurs after file creation."""
        sandbox = Mock()
        sandbox.page = Mock()
        sandbox.page.screenshot = AsyncMock(side_effect=RuntimeError("Failure during screenshot"))

        # Simulate screenshot file existing on filesystem before error handler runs
        with patch("os.path.exists", return_value=True):
            with patch("os.remove") as mock_remove:
                try:
                    await collector.collect_visual_data(sandbox)
                except RuntimeError:
                    pass

                mock_remove.assert_called_once()

    async def test_missing_page_raises_value_error(self, collector):
        """Failure 10: sandbox.page=None raises ValueError in collect_visual_data."""
        sandbox = Mock()
        sandbox.page = None

        with pytest.raises(ValueError, match="Sandbox page is not available"):
            await collector.collect_visual_data(sandbox)

    async def test_missing_page_handled_by_safe_wrapper(self, collector):
        """Failure 11: sandbox.page=None sets failed=True via safe wrapper."""
        sandbox = Mock()
        sandbox.page = None

        result = await collector._collect_visual_data_safe(sandbox)

        assert isinstance(result, VisualData)
        assert result.failed is True
        assert result.screenshot_path == ""
        assert result.layout_characteristics == {}
