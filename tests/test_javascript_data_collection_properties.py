"""Property-based tests for JavaScript Behavior Collection (Task 6.8).

Property 3: JavaScript Behavior Collection

*For any* JavaScript execution in the virtual environment, the data collector
SHALL count scripts executed, DOM modifications, and external API calls and
include them in Analysis_Data.

Validates: Requirements 2.3

Design:
-------
collect_javascript_data() works by:
  1. Counting script elements via sandbox.page.query_selector_all('script')
  2. Injecting MutationObserver instrumentation via sandbox.page.evaluate()
  3. Injecting fetch / XMLHttpRequest interception via sandbox.page.evaluate()
  4. Waiting for activity via asyncio.sleep(0.1)
  5. Reading back metrics:
     - window.__dataCollectorMutationCount || 0
     - window.__dataCollectorApiCallCount || 0
  6. Injecting cleanup script to disconnect observer and remove global variables.
  7. Returning a JavaScriptData dataclass instance with failed=False.

Test Strategy:
  - Generate arbitrary JavaScript scenarios using Hypothesis (script_count,
    dom_modifications, external_api_calls).
  - Mock sandbox.page.evaluate() dynamically to inspect the evaluated script,
    record execution history, and return the ground-truth values when counter
    queries are performed.
  - Verify all invariants across property-based sweeps and explicit boundary cases.
  - Verify integration with DataCollector.collect_all() -> AnalysisData.javascript.
"""

import pytest
import asyncio
from typing import Dict, Any, List
from unittest.mock import Mock, AsyncMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from hypothesis import given, strategies as st, settings, HealthCheck

from src.data_collector import DataCollector
from src.models import AnalysisData, JavaScriptData


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

script_count_strategy = st.integers(min_value=0, max_value=100)
dom_modifications_strategy = st.integers(min_value=0, max_value=500)
external_api_calls_strategy = st.integers(min_value=0, max_value=250)


@st.composite
def js_scenario_strategy(draw) -> Dict[str, int]:
    """Generate arbitrary JavaScript activity scenarios."""
    return {
        "script_count": draw(script_count_strategy),
        "dom_modifications": draw(dom_modifications_strategy),
        "external_api_calls": draw(external_api_calls_strategy),
    }


def _make_mock_sandbox(scenario: Dict[str, int]) -> Mock:
    """Create a mock Sandbox instance configured with dynamic page.evaluate dispatch."""
    sandbox = Mock()
    page = Mock()
    page.query_selector_all = Mock(return_value=scenario["script_count"])

    evaluated_scripts: List[str] = []

    async def evaluate_mock(script: str):
        evaluated_scripts.append(script)
        if "__dataCollectorMutationCount || 0" in script:
            return scenario["dom_modifications"]
        elif "__dataCollectorApiCallCount || 0" in script:
            return scenario["external_api_calls"]
        elif "MutationObserver" in script:
            return None  # MutationObserver setup script
        elif "originalFetch" in script or "originalOpen" in script:
            return None  # API intercept setup script
        elif "disconnect" in script or "delete window" in script:
            return None  # Cleanup script
        return None

    page.evaluate = AsyncMock(side_effect=evaluate_mock)
    sandbox.page = page
    sandbox._evaluated_scripts = evaluated_scripts
    return sandbox


# ---------------------------------------------------------------------------
# Property 3 -- Primary Test Class
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty3JavaScriptBehaviorCollection:
    """Property 3: JavaScript Behavior Collection.

    *For any* JavaScript execution in the virtual environment, the data collector
    SHALL count scripts executed, DOM modifications, and external API calls and
    include them in Analysis_Data.

    Validates: Requirements 2.3
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
    @given(scenario=js_scenario_strategy())
    async def test_property_3_all_invariants(self, collector, scenario: Dict[str, int]):
        """Property 3: For any generated JavaScript execution scenario, verify all
        three metrics, instrumentation execution, cleanup, and structural invariants.
        """
        sandbox = _make_mock_sandbox(scenario)

        result = await collector.collect_javascript_data(sandbox)

        # Invariant 1: Result is JavaScriptData instance
        assert isinstance(result, JavaScriptData), f"Expected JavaScriptData, got {type(result)}"

        # Invariant 2: script_count matches generated count
        assert result.script_count == scenario["script_count"], (
            f"script_count={result.script_count}, expected={scenario['script_count']}"
        )

        # Invariant 3: dom_modifications matches generated count
        assert result.dom_modifications == scenario["dom_modifications"], (
            f"dom_modifications={result.dom_modifications}, expected={scenario['dom_modifications']}"
        )

        # Invariant 4: external_api_calls matches generated count
        assert result.external_api_calls == scenario["external_api_calls"], (
            f"external_api_calls={result.external_api_calls}, expected={scenario['external_api_calls']}"
        )

        # Invariant 5: failed is False on success
        assert result.failed is False, "failed flag must be False for successful collection"

        # Invariant 6: Required instrumentation and cleanup scripts were evaluated
        scripts = sandbox._evaluated_scripts
        assert len(scripts) >= 5, f"Expected at least 5 evaluate() calls, got {len(scripts)}"
        assert any("MutationObserver" in s for s in scripts), "MutationObserver setup script was not evaluated"
        assert any("originalFetch" in s or "originalOpen" in s for s in scripts), "API intercept script was not evaluated"
        assert any("__dataCollectorMutationCount || 0" in s for s in scripts), "Mutation count read was not evaluated"
        assert any("__dataCollectorApiCallCount || 0" in s for s in scripts), "API call count read was not evaluated"
        assert any("disconnect" in s and "delete window" in s for s in scripts), "Cleanup script was not evaluated"

    # ------------------------------------------------------------------
    # Independent Property Tests for Shrinking & Isolation
    # ------------------------------------------------------------------

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(scenario=js_scenario_strategy())
    async def test_property_3_script_count_captured(self, collector, scenario: Dict[str, int]):
        """Invariant: script_count equals the number of script elements."""
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_javascript_data(sandbox)
        assert result.script_count == scenario["script_count"]

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(scenario=js_scenario_strategy())
    async def test_property_3_dom_modifications_captured(self, collector, scenario: Dict[str, int]):
        """Invariant: dom_modifications accurately captures dynamic mutations."""
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_javascript_data(sandbox)
        assert result.dom_modifications == scenario["dom_modifications"]

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(scenario=js_scenario_strategy())
    async def test_property_3_external_api_calls_captured(self, collector, scenario: Dict[str, int]):
        """Invariant: external_api_calls accurately captures fetch/XHR calls."""
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_javascript_data(sandbox)
        assert result.external_api_calls == scenario["external_api_calls"]

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=80,
    )
    @given(scenario=js_scenario_strategy())
    async def test_property_3_failed_flag_false(self, collector, scenario: Dict[str, int]):
        """Invariant: failed flag is False for all valid collections."""
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_javascript_data(sandbox)
        assert result.failed is False

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=50,
    )
    @given(scenario=js_scenario_strategy())
    async def test_property_3_instrumentation_order_and_cleanup(self, collector, scenario: Dict[str, int]):
        """Invariant: Instrumentation setup occurs before readback, and cleanup occurs last."""
        sandbox = _make_mock_sandbox(scenario)
        await collector.collect_javascript_data(sandbox)

        scripts = sandbox._evaluated_scripts
        # Find indices
        observer_idx = next(i for i, s in enumerate(scripts) if "MutationObserver" in s)
        api_idx = next(i for i, s in enumerate(scripts) if "originalFetch" in s or "originalOpen" in s)
        read_mutations_idx = next(i for i, s in enumerate(scripts) if "__dataCollectorMutationCount || 0" in s)
        read_api_idx = next(i for i, s in enumerate(scripts) if "__dataCollectorApiCallCount || 0" in s)
        cleanup_idx = next(i for i, s in enumerate(scripts) if "disconnect" in s and "delete window" in s)

        # Setup must occur before readback
        assert observer_idx < read_mutations_idx
        assert api_idx < read_api_idx
        # Cleanup must occur after readback
        assert read_mutations_idx < cleanup_idx
        assert read_api_idx < cleanup_idx


# ---------------------------------------------------------------------------
# collect_all() Integration Property Test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty3CollectAllIntegration:
    """Verify JavaScriptData is correctly placed into AnalysisData.javascript during collect_all()."""

    @settings(
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
        max_examples=50,
    )
    @given(scenario=js_scenario_strategy())
    async def test_javascript_data_in_analysis_data(self, scenario: Dict[str, int]):
        """Property 3 integration: collect_all() aggregates JavaScriptData into AnalysisData.javascript."""
        collector = DataCollector()
        sandbox = _make_mock_sandbox(scenario)

        # Mock unrelated collectors so the test focuses cleanly on JavaScript collection
        collector.collect_network_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_dom_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_visual_data = AsyncMock(return_value=Mock(failed=False))
        collector.collect_ssl_data = AsyncMock(return_value=Mock(failed=False))

        result = await collector.collect_all(sandbox, "https://example.com")

        assert isinstance(result, AnalysisData)
        assert result.javascript is not None
        assert isinstance(result.javascript, JavaScriptData)
        assert result.javascript.failed is False
        assert result.javascript.script_count == scenario["script_count"]
        assert result.javascript.dom_modifications == scenario["dom_modifications"]
        assert result.javascript.external_api_calls == scenario["external_api_calls"]


# ---------------------------------------------------------------------------
# Boundary & Failure Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProperty3BoundaryAndFailureCases:
    """Deterministic boundary tests covering specific edge cases, instrumentation details, and errors."""

    @pytest.fixture
    def collector(self):
        return DataCollector()

    async def test_zero_activity(self, collector):
        """Boundary 1: Zero scripts, zero mutations, zero API calls."""
        scenario = {"script_count": 0, "dom_modifications": 0, "external_api_calls": 0}
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_javascript_data(sandbox)

        assert result.script_count == 0
        assert result.dom_modifications == 0
        assert result.external_api_calls == 0
        assert result.failed is False

    async def test_scripts_only(self, collector):
        """Boundary 2: Scripts present, no dynamic mutations or API calls."""
        scenario = {"script_count": 15, "dom_modifications": 0, "external_api_calls": 0}
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_javascript_data(sandbox)

        assert result.script_count == 15
        assert result.dom_modifications == 0
        assert result.external_api_calls == 0
        assert result.failed is False

    async def test_dom_modifications_only(self, collector):
        """Boundary 3: DOM modifications present, no scripts or API calls."""
        scenario = {"script_count": 0, "dom_modifications": 42, "external_api_calls": 0}
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_javascript_data(sandbox)

        assert result.script_count == 0
        assert result.dom_modifications == 42
        assert result.external_api_calls == 0
        assert result.failed is False

    async def test_api_calls_only(self, collector):
        """Boundary 4: API calls present, no scripts or dynamic mutations."""
        scenario = {"script_count": 0, "dom_modifications": 0, "external_api_calls": 28}
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_javascript_data(sandbox)

        assert result.script_count == 0
        assert result.dom_modifications == 0
        assert result.external_api_calls == 28
        assert result.failed is False

    async def test_high_volume_activity(self, collector):
        """Boundary 5: High volume of scripts, mutations, and API calls."""
        scenario = {"script_count": 250, "dom_modifications": 10000, "external_api_calls": 5000}
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_javascript_data(sandbox)

        assert result.script_count == 250
        assert result.dom_modifications == 10000
        assert result.external_api_calls == 5000
        assert result.failed is False

    async def test_all_metrics_simultaneously(self, collector):
        """Boundary 6: All metrics active with distinct values."""
        scenario = {"script_count": 7, "dom_modifications": 19, "external_api_calls": 11}
        sandbox = _make_mock_sandbox(scenario)
        result = await collector.collect_javascript_data(sandbox)

        assert result.script_count == 7
        assert result.dom_modifications == 19
        assert result.external_api_calls == 11
        assert result.failed is False

    async def test_cleanup_removes_observer_and_globals(self, collector):
        """Boundary 7: Cleanup script disconnects observer and cleans up window globals."""
        scenario = {"script_count": 1, "dom_modifications": 2, "external_api_calls": 3}
        sandbox = _make_mock_sandbox(scenario)
        await collector.collect_javascript_data(sandbox)

        cleanup_script = sandbox._evaluated_scripts[-1]
        assert "disconnect" in cleanup_script
        assert "delete window.__dataCollectorMutationObserver" in cleanup_script
        assert "delete window.__dataCollectorMutationCount" in cleanup_script
        assert "delete window.__dataCollectorApiCallCount" in cleanup_script

    async def test_evaluate_failure_raises_exception(self, collector):
        """Failure 8: page.evaluate() failure raises exception in collect_javascript_data."""
        sandbox = Mock()
        sandbox.page = Mock()
        sandbox.page.query_selector_all = Mock(return_value=5)
        sandbox.page.evaluate = AsyncMock(side_effect=RuntimeError("Script execution failed"))

        with pytest.raises(RuntimeError, match="Script execution failed"):
            await collector.collect_javascript_data(sandbox)

    async def test_evaluate_failure_handled_by_safe_wrapper(self, collector):
        """Failure 9: page.evaluate() failure sets failed=True in _collect_javascript_data_safe."""
        sandbox = Mock()
        sandbox.page = Mock()
        sandbox.page.query_selector_all = Mock(return_value=5)
        sandbox.page.evaluate = AsyncMock(side_effect=RuntimeError("Script execution failed"))

        result = await collector._collect_javascript_data_safe(sandbox)

        assert isinstance(result, JavaScriptData)
        assert result.failed is True
        assert result.script_count == 0
        assert result.dom_modifications == 0
        assert result.external_api_calls == 0

    async def test_missing_page_raises_value_error(self, collector):
        """Failure 10: sandbox.page=None raises ValueError in collect_javascript_data."""
        sandbox = Mock()
        sandbox.page = None

        with pytest.raises(ValueError, match="Sandbox page is not available"):
            await collector.collect_javascript_data(sandbox)

    async def test_missing_page_handled_by_safe_wrapper(self, collector):
        """Failure 11: sandbox.page=None sets failed=True via safe wrapper."""
        sandbox = Mock()
        sandbox.page = None

        result = await collector._collect_javascript_data_safe(sandbox)

        assert isinstance(result, JavaScriptData)
        assert result.failed is True
        assert result.script_count == 0
        assert result.dom_modifications == 0
        assert result.external_api_calls == 0
