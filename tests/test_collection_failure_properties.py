"""Property-based tests for Collection Failure Handling (Task 6.2).

Property 7: Collection Failure Handling

*For any* subset of the five data collection categories that fail,
the system SHALL mark Analysis_Data with failure flags indicating
which specific categories failed and SHALL include successfully
collected data.

Validates: Requirements 2.8

These tests exercise DataCollector.collect_all() -- the real runtime
failure-handling path -- using Hypothesis to generate all 2**5 = 32
possible subsets of failing categories.
"""

import pytest
from typing import Set
from unittest.mock import Mock, AsyncMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from hypothesis import given, strategies as st, settings, HealthCheck

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
# Deterministic success data with unique, verifiable field values
# ---------------------------------------------------------------------------

GOOD_NETWORK = NetworkData(
    request_count=42,
    unique_domains=["example.com", "cdn.example.com"],
    protocol_distribution={"https": 40, "http": 2},
    failed=False,
)

GOOD_DOM = DOMData(
    html_content="<html><body>Property7Test</body></html>",
    structure_metrics={"total_elements": 17, "form_count": 1},
    failed=False,
)

GOOD_JAVASCRIPT = JavaScriptData(
    script_count=7,
    dom_modifications=13,
    external_api_calls=3,
    failed=False,
)

GOOD_VISUAL = VisualData(
    screenshot_path="/tmp/prop7_screenshot.png",
    layout_characteristics={"viewport_width": 1280, "viewport_height": 720},
    failed=False,
)

GOOD_SSL = SSLData(
    issuer="Let s Encrypt",
    expiration_date="2025-12-31T23:59:59Z",
    chain_valid=True,
    failed=False,
)


# ---------------------------------------------------------------------------
# Strategy: arbitrary subsets of the five category names
# min_size=0 -> all-succeed case; max_size=5 -> all-fail case
# ---------------------------------------------------------------------------

ALL_CATEGORIES = ["network", "dom", "javascript", "visual", "ssl"]

failing_subset_strategy = st.sets(
    st.sampled_from(ALL_CATEGORIES),
    min_size=0,
    max_size=5,
)


def _configure_collector(collector: DataCollector, failing: Set[str]) -> None:
    """Wire AsyncMock implementations based on which categories should fail.

    Failing categories use side_effect=Exception (non-timeout, per Req 2.8).
    Succeeding categories return their deterministic GOOD_* objects.
    """
    collector.collect_network_data = (
        AsyncMock(side_effect=Exception("network collection failed -- non-timeout"))
        if "network" in failing
        else AsyncMock(return_value=GOOD_NETWORK)
    )
    collector.collect_dom_data = (
        AsyncMock(side_effect=Exception("dom collection failed -- non-timeout"))
        if "dom" in failing
        else AsyncMock(return_value=GOOD_DOM)
    )
    collector.collect_javascript_data = (
        AsyncMock(side_effect=Exception("javascript collection failed -- non-timeout"))
        if "javascript" in failing
        else AsyncMock(return_value=GOOD_JAVASCRIPT)
    )
    collector.collect_visual_data = (
        AsyncMock(side_effect=Exception("visual collection failed -- non-timeout"))
        if "visual" in failing
        else AsyncMock(return_value=GOOD_VISUAL)
    )
    collector.collect_ssl_data = (
        AsyncMock(side_effect=Exception("ssl collection failed -- non-timeout"))
        if "ssl" in failing
        else AsyncMock(return_value=GOOD_SSL)
    )


# ---------------------------------------------------------------------------
# Property 7 -- Primary test class
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty7CollectionFailureHandling:
    """Property 7: Collection Failure Handling.

    *For any* subset of the five data collection categories that fail,
    the system SHALL mark Analysis_Data with failure flags indicating
    which specific categories failed and SHALL include successfully
    collected data.

    Validates: Requirements 2.8
    """

    @pytest.fixture
    def collector(self):
        """Fresh DataCollector for each Hypothesis example."""
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        """Minimal mock Sandbox -- page attribute not used by safe wrappers."""
        sandbox = Mock()
        sandbox.page = Mock()
        return sandbox

    # ------------------------------------------------------------------
    # Invariant 1: failure flags set correctly for every generated subset
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=100,
    )
    @given(failing=failing_subset_strategy)
    async def test_property_7_failure_flags_set_correctly(
        self, collector, mock_sandbox, failing: Set[str]
    ):
        """Property 7 inv-1: every category in the failing subset has failed=True;
        every category outside it has failed=False.

        Exercises DataCollector.collect_all(), not AnalysisData directly.
        """
        _configure_collector(collector, failing)
        result = await collector.collect_all(mock_sandbox, "https://example.com")

        # network
        assert result.network is not None, "network must not be None -- safe wrapper returns failed object"
        if "network" in failing:
            assert result.network.failed is True, f"network in {failing!r} but failed=False"
        else:
            assert result.network.failed is False, f"network not in {failing!r} but failed=True"

        # dom
        assert result.dom is not None, "dom must not be None"
        if "dom" in failing:
            assert result.dom.failed is True, f"dom in {failing!r} but failed=False"
        else:
            assert result.dom.failed is False, f"dom not in {failing!r} but failed=True"

        # javascript
        assert result.javascript is not None, "javascript must not be None"
        if "javascript" in failing:
            assert result.javascript.failed is True, f"javascript in {failing!r} but failed=False"
        else:
            assert result.javascript.failed is False, f"javascript not in {failing!r} but failed=True"

        # visual
        assert result.visual is not None, "visual must not be None"
        if "visual" in failing:
            assert result.visual.failed is True, f"visual in {failing!r} but failed=False"
        else:
            assert result.visual.failed is False, f"visual not in {failing!r} but failed=True"

        # ssl
        assert result.ssl is not None, "ssl must not be None"
        if "ssl" in failing:
            assert result.ssl.failed is True, f"ssl in {failing!r} but failed=False"
        else:
            assert result.ssl.failed is False, f"ssl not in {failing!r} but failed=True"

    # ------------------------------------------------------------------
    # Invariant 2: successful data preserved exactly
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=100,
    )
    @given(failing=failing_subset_strategy)
    async def test_property_7_successful_data_preserved(
        self, collector, mock_sandbox, failing: Set[str]
    ):
        """Property 7 inv-2: successful categories retain their exact field values.
        One category's failure must not corrupt another category's data.
        """
        _configure_collector(collector, failing)
        result = await collector.collect_all(mock_sandbox, "https://example.com")

        if "network" not in failing:
            assert result.network.request_count == GOOD_NETWORK.request_count
            assert result.network.unique_domains == GOOD_NETWORK.unique_domains
            assert result.network.protocol_distribution == GOOD_NETWORK.protocol_distribution

        if "dom" not in failing:
            assert result.dom.html_content == GOOD_DOM.html_content
            assert result.dom.structure_metrics == GOOD_DOM.structure_metrics

        if "javascript" not in failing:
            assert result.javascript.script_count == GOOD_JAVASCRIPT.script_count
            assert result.javascript.dom_modifications == GOOD_JAVASCRIPT.dom_modifications
            assert result.javascript.external_api_calls == GOOD_JAVASCRIPT.external_api_calls

        if "visual" not in failing:
            assert result.visual.screenshot_path == GOOD_VISUAL.screenshot_path
            assert result.visual.layout_characteristics == GOOD_VISUAL.layout_characteristics

        if "ssl" not in failing:
            assert result.ssl.issuer == GOOD_SSL.issuer
            assert result.ssl.expiration_date == GOOD_SSL.expiration_date
            assert result.ssl.chain_valid == GOOD_SSL.chain_valid

    # ------------------------------------------------------------------
    # Invariant 3: categories_collected == 5 - len(failing)
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=100,
    )
    @given(failing=failing_subset_strategy)
    async def test_property_7_categories_collected_count(
        self, collector, mock_sandbox, failing: Set[str]
    ):
        """Property 7 inv-3: categories_collected reflects only successful categories.
        Failed categories (failed=True) must not be counted.
        """
        _configure_collector(collector, failing)
        result = await collector.collect_all(mock_sandbox, "https://example.com")

        expected = 5 - len(failing)
        assert result.categories_collected == expected, (
            f"With failing={failing!r}: expected categories_collected={expected}, "
            f"got {result.categories_collected}"
        )
        assert 0 <= result.categories_collected <= 5

    # ------------------------------------------------------------------
    # Invariant 4: timeout_occurred is False for non-timeout failures
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=100,
    )
    @given(failing=failing_subset_strategy)
    async def test_property_7_no_timeout_flag_for_non_timeout_failures(
        self, collector, mock_sandbox, failing: Set[str]
    ):
        """Property 7 inv-4: timeout_occurred must be False.
        Non-timeout failures (Req 2.8) must not set the timeout flag (Req 2.7).
        """
        _configure_collector(collector, failing)
        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.timeout_occurred is False, (
            f"timeout_occurred must be False for non-timeout failures; "
            f"failing subset was {failing!r}"
        )

    # ------------------------------------------------------------------
    # Invariant 5: always returns AnalysisData (never raises)
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        max_examples=100,
    )
    @given(failing=failing_subset_strategy)
    async def test_property_7_always_returns_analysis_data(
        self, collector, mock_sandbox, failing: Set[str]
    ):
        """Property 7 inv-5: collect_all() always returns AnalysisData.
        Even when all five categories fail simultaneously no exception is raised.
        """
        _configure_collector(collector, failing)
        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert isinstance(result, AnalysisData), (
            f"collect_all() must return AnalysisData for any failure subset, "
            f"failing={failing!r}"
        )


# ---------------------------------------------------------------------------
# Boundary cases -- fixed tests for the two extreme subsets and each singleton
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty7BoundaryCases:
    """Fixed boundary tests complementing the Hypothesis enumeration.

    Covers:
    - Empty subset (all 5 succeed): categories_collected = 5
    - Full subset (all 5 fail):     categories_collected = 0
    - Each single-category failure in isolation
    - Cross-contamination check
    """

    @pytest.fixture
    def collector(self):
        return DataCollector()

    @pytest.fixture
    def mock_sandbox(self):
        sandbox = Mock()
        sandbox.page = Mock()
        return sandbox

    async def test_no_failures_all_five_succeed(self, collector, mock_sandbox):
        """Boundary: empty failing subset -- all 5 categories succeed."""
        _configure_collector(collector, set())
        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.categories_collected == 5
        assert result.network.failed is False
        assert result.dom.failed is False
        assert result.javascript.failed is False
        assert result.visual.failed is False
        assert result.ssl.failed is False
        assert result.timeout_occurred is False
        # Data preserved
        assert result.network.request_count == GOOD_NETWORK.request_count
        assert result.dom.html_content == GOOD_DOM.html_content
        assert result.javascript.script_count == GOOD_JAVASCRIPT.script_count
        assert result.visual.screenshot_path == GOOD_VISUAL.screenshot_path
        assert result.ssl.issuer == GOOD_SSL.issuer

    async def test_all_five_fail(self, collector, mock_sandbox):
        """Boundary: full failing subset -- all 5 categories fail."""
        _configure_collector(collector, set(ALL_CATEGORIES))
        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.categories_collected == 0
        assert result.network.failed is True
        assert result.dom.failed is True
        assert result.javascript.failed is True
        assert result.visual.failed is True
        assert result.ssl.failed is True
        assert result.timeout_occurred is False
        assert isinstance(result, AnalysisData)

    async def test_only_network_fails(self, collector, mock_sandbox):
        """Boundary: single failure -- network only."""
        _configure_collector(collector, {"network"})
        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.categories_collected == 4
        assert result.network.failed is True
        assert result.dom.failed is False
        assert result.javascript.failed is False
        assert result.visual.failed is False
        assert result.ssl.failed is False
        assert result.dom.html_content == GOOD_DOM.html_content

    async def test_only_dom_fails(self, collector, mock_sandbox):
        """Boundary: single failure -- dom only."""
        _configure_collector(collector, {"dom"})
        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.categories_collected == 4
        assert result.network.failed is False
        assert result.dom.failed is True
        assert result.javascript.failed is False
        assert result.visual.failed is False
        assert result.ssl.failed is False
        assert result.network.request_count == GOOD_NETWORK.request_count

    async def test_only_javascript_fails(self, collector, mock_sandbox):
        """Boundary: single failure -- javascript only."""
        _configure_collector(collector, {"javascript"})
        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.categories_collected == 4
        assert result.network.failed is False
        assert result.dom.failed is False
        assert result.javascript.failed is True
        assert result.visual.failed is False
        assert result.ssl.failed is False
        assert result.ssl.issuer == GOOD_SSL.issuer

    async def test_only_visual_fails(self, collector, mock_sandbox):
        """Boundary: single failure -- visual only."""
        _configure_collector(collector, {"visual"})
        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.categories_collected == 4
        assert result.network.failed is False
        assert result.dom.failed is False
        assert result.javascript.failed is False
        assert result.visual.failed is True
        assert result.ssl.failed is False

    async def test_only_ssl_fails(self, collector, mock_sandbox):
        """Boundary: single failure -- ssl only."""
        _configure_collector(collector, {"ssl"})
        result = await collector.collect_all(mock_sandbox, "https://example.com")

        assert result.categories_collected == 4
        assert result.network.failed is False
        assert result.dom.failed is False
        assert result.javascript.failed is False
        assert result.visual.failed is False
        assert result.ssl.failed is True
        assert result.network.request_count == GOOD_NETWORK.request_count

    async def test_one_failure_does_not_corrupt_others(self, collector, mock_sandbox):
        """Cross-contamination: ssl failure must not corrupt other categories data."""
        _configure_collector(collector, {"ssl"})
        result = await collector.collect_all(mock_sandbox, "https://example.com")

        # Network data fully intact
        assert result.network.request_count == 42
        assert result.network.unique_domains == ["example.com", "cdn.example.com"]
        assert result.network.protocol_distribution == {"https": 40, "http": 2}
        # DOM data fully intact
        assert result.dom.html_content == "<html><body>Property7Test</body></html>"
        assert result.dom.structure_metrics == {"total_elements": 17, "form_count": 1}
        # JS data fully intact
        assert result.javascript.script_count == 7
        assert result.javascript.dom_modifications == 13
        assert result.javascript.external_api_calls == 3
        # Visual data fully intact
        assert result.visual.screenshot_path == "/tmp/prop7_screenshot.png"
        assert result.visual.layout_characteristics == {
            "viewport_width": 1280,
            "viewport_height": 720,
        }
        # SSL is failed
        assert result.ssl.failed is True
