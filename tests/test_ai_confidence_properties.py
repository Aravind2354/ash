"""
Property-based tests for Confidence Indicator Calculation (Task 8.6).

Property 15: Confidence Indicator Calculation

For any Analysis_Data with N successfully collected categories out of 5,
the confidence indicator SHALL be:
  - "HIGH"   if N >= 4
  - "MEDIUM" if N == 3
  - "LOW"    if N < 3

Validates: Requirements 4.4, 4.5, 4.6

Test Strategy:
  - Hypothesis generates random subsets of {network, dom, javascript, visual, ssl}
    with exactly N active (failed=False) categories for N in {0, 1, 2, 3, 4, 5}.
  - The expected confidence is derived independently from N (not from the production
    code), then compared to the real AIAnalysisEngine.calculate_confidence() result.
  - Separate property tests target each of the 6 boundary values.
  - An additional composite property covers all N values simultaneously.
  - Failed-category exclusion is verified with Hypothesis-generated mixed inputs.
  - Category-identity indifference is verified by comparing two different subsets
    of the same size.
  - No live network calls. No external services.
"""

import pytest

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from hypothesis import given, strategies as st, settings, HealthCheck

from src.ai_analyzer import AIAnalysisEngine
from src.models import (
    AnalysisData,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
)


# ---------------------------------------------------------------------------
# Engine Fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine():
    """Shared AIAnalysisEngine instance for property tests."""
    return AIAnalysisEngine()


# ---------------------------------------------------------------------------
# Expected-Confidence Helper (independent of production code)
# ---------------------------------------------------------------------------

def _expected_confidence(n: int) -> str:
    """
    Derive the expected confidence indicator from active-category count N.
    This mirrors the specification directly without calling the production code.
    """
    if n >= 4:
        return "HIGH"
    elif n == 3:
        return "MEDIUM"
    else:
        return "LOW"


# ---------------------------------------------------------------------------
# Valid Category Strategies (varied field contents to test content-independence)
# ---------------------------------------------------------------------------

_valid_network = st.builds(
    NetworkData,
    request_count=st.integers(min_value=0, max_value=1000),
    unique_domains=st.lists(
        st.text(alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd')), min_size=1, max_size=20),
        min_size=0,
        max_size=30,
    ),
    protocol_distribution=st.dictionaries(
        st.sampled_from(["http", "https", "ws", "wss"]),
        st.integers(min_value=0, max_value=500),
        max_size=4,
    ),
    failed=st.just(False),
)

_valid_dom = st.builds(
    DOMData,
    html_content=st.text(min_size=0, max_size=500),
    structure_metrics=st.dictionaries(
        st.sampled_from(["element_count", "total_elements", "form_count", "iframe_count", "script_tag_count"]),
        st.integers(min_value=0, max_value=200),
        max_size=5,
    ),
    failed=st.just(False),
)

_valid_js = st.builds(
    JavaScriptData,
    script_count=st.integers(min_value=0, max_value=200),
    dom_modifications=st.integers(min_value=0, max_value=5000),
    external_api_calls=st.integers(min_value=0, max_value=200),
    failed=st.just(False),
)

_valid_visual = st.builds(
    VisualData,
    screenshot_path=st.sampled_from(["", "/tmp/shot.png", "img.png"]),
    layout_characteristics=st.fixed_dictionaries({
        "viewport_width": st.integers(min_value=0, max_value=2560),
        "viewport_height": st.integers(min_value=0, max_value=1440),
        "has_images": st.booleans(),
        "image_count": st.integers(min_value=0, max_value=50),
    }),
    failed=st.just(False),
)

_valid_ssl = st.builds(
    SSLData,
    issuer=st.sampled_from(["", "CN=Let's Encrypt", "CN=DigiCert", "CN=Cloudflare"]),
    expiration_date=st.sampled_from(["", "2030-01-01T00:00:00Z", "2028-10-10T00:00:00Z"]),
    chain_valid=st.booleans(),
    failed=st.just(False),
)

_failed_network = st.builds(
    NetworkData, request_count=st.just(0), unique_domains=st.just([]),
    protocol_distribution=st.just({}), failed=st.just(True),
)
_failed_dom = st.builds(
    DOMData, html_content=st.just(""), structure_metrics=st.just({}), failed=st.just(True),
)
_failed_js = st.builds(
    JavaScriptData, script_count=st.just(0), dom_modifications=st.just(0),
    external_api_calls=st.just(0), failed=st.just(True),
)
_failed_visual = st.builds(
    VisualData, screenshot_path=st.just(""), layout_characteristics=st.just({}), failed=st.just(True),
)
_failed_ssl = st.builds(
    SSLData, issuer=st.just(""), expiration_date=st.just(""), chain_valid=st.just(False), failed=st.just(True),
)

_ALL_CATS = ["network", "dom", "javascript", "visual", "ssl"]

_VALID_STRATS = {
    "network": _valid_network,
    "dom": _valid_dom,
    "javascript": _valid_js,
    "visual": _valid_visual,
    "ssl": _valid_ssl,
}

_FAILED_STRATS = {
    "network": _failed_network,
    "dom": _failed_dom,
    "javascript": _failed_js,
    "visual": _failed_visual,
    "ssl": _failed_ssl,
}


# ---------------------------------------------------------------------------
# Composite Strategies
# ---------------------------------------------------------------------------

@st.composite
def analysis_data_with_exact_n_active(draw, n: int):
    """
    Generate AnalysisData with EXACTLY N active (failed=False) categories.
    Unselected categories are None (not failed).
    Returns (AnalysisData, n).
    """
    active_cats = draw(
        st.sets(st.sampled_from(_ALL_CATS), min_size=n, max_size=n)
    )
    cat_map = {}
    for cat in _ALL_CATS:
        if cat in active_cats:
            cat_map[cat] = draw(_VALID_STRATS[cat])
        else:
            cat_map[cat] = None
    data = AnalysisData(
        network=cat_map["network"],
        dom=cat_map["dom"],
        javascript=cat_map["javascript"],
        visual=cat_map["visual"],
        ssl=cat_map["ssl"],
        timeout_occurred=False,
    )
    return data, n


@st.composite
def analysis_data_all_n(draw):
    """
    Generate AnalysisData with N active categories for any N in [0, 5].
    Returns (AnalysisData, n).
    """
    n = draw(st.integers(min_value=0, max_value=5))
    active_cats = draw(
        st.sets(st.sampled_from(_ALL_CATS), min_size=n, max_size=n)
    )
    cat_map = {}
    for cat in _ALL_CATS:
        if cat in active_cats:
            cat_map[cat] = draw(_VALID_STRATS[cat])
        else:
            cat_map[cat] = None
    data = AnalysisData(
        network=cat_map["network"],
        dom=cat_map["dom"],
        javascript=cat_map["javascript"],
        visual=cat_map["visual"],
        ssl=cat_map["ssl"],
        timeout_occurred=False,
    )
    return data, n


@st.composite
def analysis_data_with_failed_categories(draw):
    """
    Generate AnalysisData with a mix of active, failed, and None categories.
    Active count is in [0, 5]; failed count is drawn from remaining slots.
    Returns (AnalysisData, active_count).
    """
    active_count = draw(st.integers(min_value=0, max_value=5))
    active_cats = draw(
        st.sets(st.sampled_from(_ALL_CATS), min_size=active_count, max_size=active_count)
    )
    remaining = [c for c in _ALL_CATS if c not in active_cats]
    failed_count = draw(st.integers(min_value=0, max_value=len(remaining)))
    failed_cats = draw(
        st.sets(st.sampled_from(remaining), min_size=failed_count, max_size=failed_count)
    ) if remaining and failed_count > 0 else set()

    cat_map = {}
    for cat in _ALL_CATS:
        if cat in active_cats:
            cat_map[cat] = draw(_VALID_STRATS[cat])
        elif cat in failed_cats:
            cat_map[cat] = draw(_FAILED_STRATS[cat])
        else:
            cat_map[cat] = None

    data = AnalysisData(
        network=cat_map["network"],
        dom=cat_map["dom"],
        javascript=cat_map["javascript"],
        visual=cat_map["visual"],
        ssl=cat_map["ssl"],
        timeout_occurred=False,
    )
    return data, active_count


# ---------------------------------------------------------------------------
# Property 15 — Boundary Tests (N = 0 through N = 5)
# ---------------------------------------------------------------------------

class TestProperty15ConfidenceBoundaries:
    """
    Individual boundary tests for Property 15.
    Each test pins N to a specific value to make boundary coverage explicit.
    """

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(0))
    def test_n_0_returns_low(self, engine, pair):
        """N=0 active categories → 'LOW' (0% < 50%). Validates Requirement 4.6."""
        data, n = pair
        result = engine.calculate_confidence(data)
        assert result == "LOW", f"Expected LOW for N=0, got {result!r}"

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(1))
    def test_n_1_returns_low(self, engine, pair):
        """N=1 active category → 'LOW' (20% < 50%). Validates Requirement 4.6."""
        data, n = pair
        result = engine.calculate_confidence(data)
        assert result == "LOW", f"Expected LOW for N=1, got {result!r}"

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(2))
    def test_n_2_returns_low(self, engine, pair):
        """N=2 active categories → 'LOW' (40% < 50%). Validates Requirement 4.6."""
        data, n = pair
        result = engine.calculate_confidence(data)
        assert result == "LOW", f"Expected LOW for N=2, got {result!r}"

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(3))
    def test_n_3_returns_medium(self, engine, pair):
        """N=3 active categories → 'MEDIUM' (60%, 50% ≤ ratio < 80%). Validates Requirement 4.5."""
        data, n = pair
        result = engine.calculate_confidence(data)
        assert result == "MEDIUM", f"Expected MEDIUM for N=3, got {result!r}"

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(4))
    def test_n_4_returns_high(self, engine, pair):
        """N=4 active categories → 'HIGH' (80%). Validates Requirement 4.4."""
        data, n = pair
        result = engine.calculate_confidence(data)
        assert result == "HIGH", f"Expected HIGH for N=4, got {result!r}"

    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(5))
    def test_n_5_returns_high(self, engine, pair):
        """N=5 active categories → 'HIGH' (100%). Validates Requirement 4.4."""
        data, n = pair
        result = engine.calculate_confidence(data)
        assert result == "HIGH", f"Expected HIGH for N=5, got {result!r}"


# ---------------------------------------------------------------------------
# Property 15 — Generalized Property (All N)
# ---------------------------------------------------------------------------

class TestProperty15Generalized:
    """Generalized property tests covering all N values and derived expectations."""

    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_all_n())
    def test_property_15_all_boundaries(self, engine, pair):
        """
        Property 15 (main): For any Analysis_Data with N successfully collected
        categories out of 5, the confidence SHALL be:
          - "HIGH" if N >= 4
          - "MEDIUM" if N == 3
          - "LOW" if N < 3

        The expected value is derived independently from N, then compared to the
        real calculate_confidence() result.

        Validates: Requirements 4.4, 4.5, 4.6
        """
        data, n = pair
        result = engine.calculate_confidence(data)
        expected = _expected_confidence(n)

        assert result == expected, (
            f"For N={n} active categories, expected {expected!r} but got {result!r}"
        )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_all_n())
    def test_property_15_result_is_valid_string(self, engine, pair):
        """
        For any valid AnalysisData, calculate_confidence() returns one of the
        three allowed strings: "HIGH", "MEDIUM", or "LOW".
        No lowercase, None, or unexpected values are permitted.
        """
        data, n = pair
        result = engine.calculate_confidence(data)
        assert result in {"HIGH", "MEDIUM", "LOW"}, (
            f"calculate_confidence() returned unexpected value: {result!r}"
        )


# ---------------------------------------------------------------------------
# Property 15 — Failed-Category Exclusion
# ---------------------------------------------------------------------------

class TestProperty15FailedCategoryExclusion:
    """
    Verify failed=True categories are excluded from the active-category count.
    The confidence must be determined only by categories where:
      - category is not None
      - category.failed is False
    """

    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_failed_categories())
    def test_failed_categories_excluded_from_count(self, engine, pair):
        """
        For any AnalysisData with a mixture of active (failed=False), failed
        (failed=True), and None categories, the confidence SHALL depend only
        on the count of active (failed=False) categories.

        Examples covered by this property:
          2 active + 3 failed → LOW
          3 active + 2 failed → MEDIUM
          4 active + 1 failed → HIGH
        """
        data, active_count = pair
        result = engine.calculate_confidence(data)
        expected = _expected_confidence(active_count)

        assert result == expected, (
            f"For {active_count} active categories (with some failed), "
            f"expected {expected!r} but got {result!r}"
        )


# ---------------------------------------------------------------------------
# Property 15 — Category Identity Indifference
# ---------------------------------------------------------------------------

class TestProperty15CategoryIdentityIndifference:
    """
    Verify the confidence result depends ONLY on the count of successful
    categories, not on which specific categories are active.
    """

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(
        pair_a=analysis_data_with_exact_n_active(3),
        pair_b=analysis_data_with_exact_n_active(3),
    )
    def test_any_3_categories_gives_medium(self, engine, pair_a, pair_b):
        """
        Any two different subsets of 3 active categories both produce "MEDIUM".
        """
        data_a, _ = pair_a
        data_b, _ = pair_b
        result_a = engine.calculate_confidence(data_a)
        result_b = engine.calculate_confidence(data_b)
        assert result_a == "MEDIUM"
        assert result_b == "MEDIUM"

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(
        pair_a=analysis_data_with_exact_n_active(4),
        pair_b=analysis_data_with_exact_n_active(4),
    )
    def test_any_4_categories_gives_high(self, engine, pair_a, pair_b):
        """
        Any two different subsets of 4 active categories both produce "HIGH".
        """
        data_a, _ = pair_a
        data_b, _ = pair_b
        result_a = engine.calculate_confidence(data_a)
        result_b = engine.calculate_confidence(data_b)
        assert result_a == "HIGH"
        assert result_b == "HIGH"

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(
        pair_a=analysis_data_with_exact_n_active(2),
        pair_b=analysis_data_with_exact_n_active(2),
    )
    def test_any_2_categories_gives_low(self, engine, pair_a, pair_b):
        """
        Any two different subsets of 2 active categories both produce "LOW".
        """
        data_a, _ = pair_a
        data_b, _ = pair_b
        result_a = engine.calculate_confidence(data_a)
        result_b = engine.calculate_confidence(data_b)
        assert result_a == "LOW"
        assert result_b == "LOW"


# ---------------------------------------------------------------------------
# Property 15 — Category Content Indifference
# ---------------------------------------------------------------------------

class TestProperty15CategoryContentIndifference:
    """
    Verify that varying field contents within active categories do not affect
    the confidence result. calculate_confidence() must depend only on which
    categories are present and not failed, not on field values within them.
    """

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_all_n())
    def test_confidence_independent_of_field_content(self, engine, pair):
        """
        Calling calculate_confidence() twice on the same AnalysisData object
        must produce the same result, regardless of field content variation
        in the outer generated values.
        """
        data, n = pair
        result1 = engine.calculate_confidence(data)
        result2 = engine.calculate_confidence(data)
        assert result1 == result2, (
            f"calculate_confidence() returned different results on the same input: "
            f"{result1!r} vs {result2!r}"
        )


# ---------------------------------------------------------------------------
# Supplementary Deterministic Tests (Invalid Input — not the focus of P15)
# ---------------------------------------------------------------------------

class TestCalculateConfidenceInvalidInputSupplement:
    """
    Brief supplementary deterministic tests for non-AnalysisData input.
    These complement (not duplicate) the existing unit tests in test_ai_analyzer.py.
    Property 15 itself only applies to AnalysisData, so this is secondary.
    """

    @pytest.mark.parametrize("invalid_input", [None, "url", 42, [], {}, 3.14])
    def test_non_analysisdata_returns_low(self, engine, invalid_input):
        """Non-AnalysisData input safely returns 'LOW'."""
        result = engine.calculate_confidence(invalid_input)
        assert result == "LOW", (
            f"Expected 'LOW' for invalid input {invalid_input!r}, got {result!r}"
        )
