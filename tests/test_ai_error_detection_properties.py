"""
Property-based tests for AI Error Detection (Task 8.4).

Property 11: Insufficient Data Detection
Property 12: Data Corruption Detection

Validates: Requirements 3.5, 3.6

Design:
-------
- Property 11: For any Analysis_Data with fewer than 3 successfully collected
  categories, the AI agent SHALL return an error indicating insufficient data
  and SHALL NOT generate scores.
- Property 12: For any Analysis_Data containing values that fail type validation
  or are outside expected ranges, the AI agent SHALL return an error indicating
  data corruption and SHALL NOT generate scores.

Test Strategy:
  - Hypothesis generates randomized insufficient-data combinations (0, 1, 2 active categories).
  - Hypothesis generates randomized data corruption across all 5 category types.
  - Each property test calls the REAL AIAnalysisEngine.validate_data() and analyze() methods.
  - No mocking of production validation methods.
  - Control tests confirm valid data still passes.
"""

import copy
import pytest

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from hypothesis import given, strategies as st, settings, HealthCheck

from src.ai_analyzer import AIAnalysisEngine
from src.models import (
    AnalysisData,
    AnalysisScores,
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
# Valid Category Strategies (from test_ai_scoring_properties.py, repeated here
# to keep this file self-contained)
# ---------------------------------------------------------------------------

valid_network_strategy = st.builds(
    NetworkData,
    request_count=st.integers(min_value=0, max_value=1000),
    unique_domains=st.lists(
        st.text(alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd')), min_size=1, max_size=20),
        min_size=0,
        max_size=20,
    ),
    protocol_distribution=st.dictionaries(
        st.sampled_from(["http", "https", "ws", "wss"]),
        st.integers(min_value=0, max_value=500),
        max_size=4,
    ),
    failed=st.just(False),
)

valid_dom_strategy = st.builds(
    DOMData,
    html_content=st.text(min_size=0, max_size=500),
    structure_metrics=st.dictionaries(
        st.sampled_from(["element_count", "total_elements", "form_count", "iframe_count", "script_tag_count"]),
        st.integers(min_value=0, max_value=200),
        max_size=5,
    ),
    failed=st.just(False),
)

valid_js_strategy = st.builds(
    JavaScriptData,
    script_count=st.integers(min_value=0, max_value=200),
    dom_modifications=st.integers(min_value=0, max_value=5000),
    external_api_calls=st.integers(min_value=0, max_value=200),
    failed=st.just(False),
)

valid_visual_strategy = st.builds(
    VisualData,
    screenshot_path=st.sampled_from(["", "/tmp/screenshot.png", "shot.png"]),
    layout_characteristics=st.fixed_dictionaries({
        "viewport_width": st.integers(min_value=0, max_value=2560),
        "viewport_height": st.integers(min_value=0, max_value=1440),
        "has_images": st.booleans(),
        "image_count": st.integers(min_value=0, max_value=50),
    }),
    failed=st.just(False),
)

valid_ssl_strategy = st.builds(
    SSLData,
    issuer=st.sampled_from(["", "CN=Let's Encrypt Authority X3", "CN=DigiCert"]),
    expiration_date=st.sampled_from(["", "2030-01-01T00:00:00Z", "2028-10-10T00:00:00Z"]),
    chain_valid=st.booleans(),
    failed=st.just(False),
)

# Strategies for exactly-failed categories
_failed_network = st.builds(
    NetworkData,
    request_count=st.just(0),
    unique_domains=st.just([]),
    protocol_distribution=st.just({}),
    failed=st.just(True),
)
_failed_dom = st.builds(
    DOMData,
    html_content=st.just(""),
    structure_metrics=st.just({}),
    failed=st.just(True),
)
_failed_js = st.builds(
    JavaScriptData,
    script_count=st.just(0),
    dom_modifications=st.just(0),
    external_api_calls=st.just(0),
    failed=st.just(True),
)
_failed_visual = st.builds(
    VisualData,
    screenshot_path=st.just(""),
    layout_characteristics=st.just({}),
    failed=st.just(True),
)
_failed_ssl = st.builds(
    SSLData,
    issuer=st.just(""),
    expiration_date=st.just(""),
    chain_valid=st.just(False),
    failed=st.just(True),
)

_VALID_CAT_STRATEGIES = {
    "network": valid_network_strategy,
    "dom": valid_dom_strategy,
    "javascript": valid_js_strategy,
    "visual": valid_visual_strategy,
    "ssl": valid_ssl_strategy,
}
_FAILED_CAT_STRATEGIES = {
    "network": _failed_network,
    "dom": _failed_dom,
    "javascript": _failed_js,
    "visual": _failed_visual,
    "ssl": _failed_ssl,
}
_ALL_CAT_NAMES = ["network", "dom", "javascript", "visual", "ssl"]


# ---------------------------------------------------------------------------
# Invalid (corrupted) value strategies
# ---------------------------------------------------------------------------

# Values that are invalid where a non-negative exact int is required
# (includes booleans because isinstance(True, int) == True in Python)
_invalid_for_non_negative_int = st.one_of(
    st.integers(max_value=-1),                       # negative int
    st.floats(allow_nan=False, allow_infinity=False), # float
    st.text(min_size=1, max_size=10),                # string
    st.just(True),                                    # bool (subclass of int)
    st.just(False),                                   # bool (subclass of int)
    st.just(None),                                    # None
    st.just([10]),                                    # list
    st.just({"v": 1}),                               # dict
)

# Values that are invalid where a str is required
_invalid_for_str = st.one_of(
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.just(True),
    st.just(False),
    st.just(None),
    st.just([]),
    st.just({}),
)

# Values that are invalid where a list[str] is required
_invalid_for_list_of_str = st.one_of(
    st.just("not_a_list"),
    st.just(123),
    st.just(True),
    st.just({}),
    st.just([1, 2, 3]),          # list of ints instead of strings
    st.just([True, False]),       # list of bools instead of strings
)

# Values that are invalid where a dict is required
_invalid_for_dict = st.one_of(
    st.just("not_a_dict"),
    st.just(123),
    st.just(True),
    st.just([]),
    st.just(None),
)

# Values invalid for bool (chain_valid, failed)
_invalid_for_bool = st.one_of(
    st.integers(),
    st.just(0),
    st.just(1),
    st.just("True"),
    st.just("False"),
    st.just(None),
    st.just([True]),
    st.just({"v": True}),
)

# Dict with a single corrupted count entry (negative/float/bool instead of non-neg int)
_invalid_protocol_distribution = st.one_of(
    st.just("not_a_dict"),
    st.just({"https": -1}),       # negative value
    st.just({"https": 3.5}),      # float value
    st.just({"https": True}),     # bool value
    st.just({1: 100}),            # non-string key
)

# Dict with a single corrupted structure_metrics entry
_invalid_structure_metrics = st.one_of(
    st.just("not_a_dict"),
    st.just({"form_count": -1}),   # negative
    st.just({"form_count": 3.5}),  # float
    st.just({"form_count": True}), # bool
)

# Invalid layout_characteristics (non-dict or dict with corrupted numeric dimension)
_invalid_layout_characteristics = st.one_of(
    st.just("not_a_dict"),
    st.just({"viewport_width": -1}),
    st.just({"viewport_width": 3.5}),
    st.just({"viewport_width": True}),
    st.just({"viewport_height": -5}),
    st.just({"image_count": -1}),
    st.just({"image_count": True}),
)


# ---------------------------------------------------------------------------
# Composite Strategies: Insufficient Data
# ---------------------------------------------------------------------------

@st.composite
def insufficient_data_strategy(draw):
    """
    Generate AnalysisData with exactly 0, 1, or 2 active (failed=False) categories.
    Unselected categories are None.
    """
    active_count = draw(st.integers(min_value=0, max_value=2))
    active_cats = draw(
        st.sets(st.sampled_from(_ALL_CAT_NAMES), min_size=active_count, max_size=active_count)
    )
    cat_map = {}
    for cat in _ALL_CAT_NAMES:
        if cat in active_cats:
            cat_map[cat] = draw(_VALID_CAT_STRATEGIES[cat])
        else:
            cat_map[cat] = None
    return AnalysisData(
        network=cat_map["network"],
        dom=cat_map["dom"],
        javascript=cat_map["javascript"],
        visual=cat_map["visual"],
        ssl=cat_map["ssl"],
        timeout_occurred=False,
    )


@st.composite
def insufficient_with_failed_categories_strategy(draw):
    """
    Generate AnalysisData with 0–2 active categories and 1–5 failed categories.
    Failed categories must NOT count toward the minimum.
    """
    active_count = draw(st.integers(min_value=0, max_value=2))
    active_cats = draw(
        st.sets(st.sampled_from(_ALL_CAT_NAMES), min_size=active_count, max_size=active_count)
    )
    remaining = [c for c in _ALL_CAT_NAMES if c not in active_cats]
    # How many of the remaining become failed (at least 1 to make this interesting)
    failed_count = draw(st.integers(min_value=1, max_value=len(remaining))) if remaining else 0
    failed_cats = draw(
        st.sets(st.sampled_from(remaining), min_size=failed_count, max_size=failed_count)
    ) if remaining and failed_count > 0 else set()

    cat_map = {}
    for cat in _ALL_CAT_NAMES:
        if cat in active_cats:
            cat_map[cat] = draw(_VALID_CAT_STRATEGIES[cat])
        elif cat in failed_cats:
            cat_map[cat] = draw(_FAILED_CAT_STRATEGIES[cat])
        else:
            cat_map[cat] = None

    return AnalysisData(
        network=cat_map["network"],
        dom=cat_map["dom"],
        javascript=cat_map["javascript"],
        visual=cat_map["visual"],
        ssl=cat_map["ssl"],
        timeout_occurred=False,
    )


# ---------------------------------------------------------------------------
# Composite Strategies: Corruption per Category
# ---------------------------------------------------------------------------

@st.composite
def corrupted_network_strategy(draw):
    """NetworkData with exactly one randomly chosen corrupted field."""
    base = draw(valid_network_strategy)
    field = draw(st.sampled_from(["request_count", "unique_domains", "protocol_distribution", "failed"]))
    if field == "request_count":
        base = NetworkData(
            request_count=draw(_invalid_for_non_negative_int),
            unique_domains=base.unique_domains,
            protocol_distribution=base.protocol_distribution,
            failed=base.failed,
        )
    elif field == "unique_domains":
        base = NetworkData(
            request_count=base.request_count,
            unique_domains=draw(_invalid_for_list_of_str),
            protocol_distribution=base.protocol_distribution,
            failed=base.failed,
        )
    elif field == "protocol_distribution":
        base = NetworkData(
            request_count=base.request_count,
            unique_domains=base.unique_domains,
            protocol_distribution=draw(_invalid_protocol_distribution),
            failed=base.failed,
        )
    else:  # failed
        base = NetworkData(
            request_count=base.request_count,
            unique_domains=base.unique_domains,
            protocol_distribution=base.protocol_distribution,
            failed=draw(_invalid_for_bool),
        )
    return base


@st.composite
def corrupted_dom_strategy(draw):
    """DOMData with exactly one randomly chosen corrupted field."""
    base = draw(valid_dom_strategy)
    field = draw(st.sampled_from(["html_content", "structure_metrics", "failed"]))
    if field == "html_content":
        base = DOMData(
            html_content=draw(_invalid_for_str),
            structure_metrics=base.structure_metrics,
            failed=base.failed,
        )
    elif field == "structure_metrics":
        base = DOMData(
            html_content=base.html_content,
            structure_metrics=draw(_invalid_structure_metrics),
            failed=base.failed,
        )
    else:  # failed
        base = DOMData(
            html_content=base.html_content,
            structure_metrics=base.structure_metrics,
            failed=draw(_invalid_for_bool),
        )
    return base


@st.composite
def corrupted_js_strategy(draw):
    """JavaScriptData with exactly one randomly chosen corrupted field."""
    base = draw(valid_js_strategy)
    field = draw(st.sampled_from(["script_count", "dom_modifications", "external_api_calls", "failed"]))
    if field == "script_count":
        base = JavaScriptData(
            script_count=draw(_invalid_for_non_negative_int),
            dom_modifications=base.dom_modifications,
            external_api_calls=base.external_api_calls,
            failed=base.failed,
        )
    elif field == "dom_modifications":
        base = JavaScriptData(
            script_count=base.script_count,
            dom_modifications=draw(_invalid_for_non_negative_int),
            external_api_calls=base.external_api_calls,
            failed=base.failed,
        )
    elif field == "external_api_calls":
        base = JavaScriptData(
            script_count=base.script_count,
            dom_modifications=base.dom_modifications,
            external_api_calls=draw(_invalid_for_non_negative_int),
            failed=base.failed,
        )
    else:  # failed
        base = JavaScriptData(
            script_count=base.script_count,
            dom_modifications=base.dom_modifications,
            external_api_calls=base.external_api_calls,
            failed=draw(_invalid_for_bool),
        )
    return base


@st.composite
def corrupted_visual_strategy(draw):
    """VisualData with exactly one randomly chosen corrupted field."""
    base = draw(valid_visual_strategy)
    field = draw(st.sampled_from(["screenshot_path", "layout_characteristics", "failed"]))
    if field == "screenshot_path":
        base = VisualData(
            screenshot_path=draw(_invalid_for_str),
            layout_characteristics=base.layout_characteristics,
            failed=base.failed,
        )
    elif field == "layout_characteristics":
        base = VisualData(
            screenshot_path=base.screenshot_path,
            layout_characteristics=draw(_invalid_layout_characteristics),
            failed=base.failed,
        )
    else:  # failed
        base = VisualData(
            screenshot_path=base.screenshot_path,
            layout_characteristics=base.layout_characteristics,
            failed=draw(_invalid_for_bool),
        )
    return base


@st.composite
def corrupted_ssl_strategy(draw):
    """SSLData with exactly one randomly chosen corrupted field."""
    base = draw(valid_ssl_strategy)
    field = draw(st.sampled_from(["issuer", "expiration_date", "chain_valid", "failed"]))
    if field == "issuer":
        base = SSLData(
            issuer=draw(_invalid_for_str),
            expiration_date=base.expiration_date,
            chain_valid=base.chain_valid,
            failed=base.failed,
        )
    elif field == "expiration_date":
        base = SSLData(
            issuer=base.issuer,
            expiration_date=draw(_invalid_for_str),
            chain_valid=base.chain_valid,
            failed=base.failed,
        )
    elif field == "chain_valid":
        base = SSLData(
            issuer=base.issuer,
            expiration_date=base.expiration_date,
            chain_valid=draw(_invalid_for_bool),
            failed=base.failed,
        )
    else:  # failed
        base = SSLData(
            issuer=base.issuer,
            expiration_date=base.expiration_date,
            chain_valid=base.chain_valid,
            failed=draw(_invalid_for_bool),
        )
    return base


# Mapping category name -> its corrupted strategy callable
_CORRUPTED_CATEGORY_STRATEGIES = {
    "network": corrupted_network_strategy,
    "dom": corrupted_dom_strategy,
    "javascript": corrupted_js_strategy,
    "visual": corrupted_visual_strategy,
    "ssl": corrupted_ssl_strategy,
}


@st.composite
def corrupted_analysis_data_strategy(draw):
    """
    Generate valid AnalysisData with 3–5 active categories, then replace one
    category with a structurally-valid but field-level-corrupted version.
    """
    # Choose which categories are active
    active_cats = draw(
        st.sets(st.sampled_from(_ALL_CAT_NAMES), min_size=3, max_size=5)
    )
    # Build valid data for all active categories
    cat_map = {}
    for cat in _ALL_CAT_NAMES:
        if cat in active_cats:
            cat_map[cat] = draw(_VALID_CAT_STRATEGIES[cat])
        else:
            cat_map[cat] = None

    # Pick one active category to corrupt
    target_cat = draw(st.sampled_from(sorted(active_cats)))
    cat_map[target_cat] = draw(_CORRUPTED_CATEGORY_STRATEGIES[target_cat]())

    return AnalysisData(
        network=cat_map["network"],
        dom=cat_map["dom"],
        javascript=cat_map["javascript"],
        visual=cat_map["visual"],
        ssl=cat_map["ssl"],
        timeout_occurred=False,
    )


# Composite valid data strategy (control)
@st.composite
def valid_analysis_data_strategy(draw):
    """Generate valid AnalysisData with 3–5 active categories (control strategy)."""
    active_cats = draw(
        st.sets(st.sampled_from(_ALL_CAT_NAMES), min_size=3, max_size=5)
    )
    cat_map = {}
    for cat in _ALL_CAT_NAMES:
        if cat in active_cats:
            cat_map[cat] = draw(_VALID_CAT_STRATEGIES[cat])
        else:
            cat_map[cat] = None
    return AnalysisData(
        network=cat_map["network"],
        dom=cat_map["dom"],
        javascript=cat_map["javascript"],
        visual=cat_map["visual"],
        ssl=cat_map["ssl"],
        timeout_occurred=False,
    )


# ---------------------------------------------------------------------------
# Property Tests
# ---------------------------------------------------------------------------

class TestInsufficientDataDetectionProperties:
    """Property 11: Insufficient Data Detection (Requirement 3.5)."""

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=insufficient_data_strategy())
    def test_property_11_insufficient_data_detection(self, engine, data):
        """
        Property 11: For any Analysis_Data with fewer than 3 successfully collected
        categories, validate_data SHALL return is_valid=False with an insufficient
        data error message, and analyze() SHALL raise ValueError.

        Validates: Requirement 3.5
        """
        is_valid, message = engine.validate_data(data)

        assert is_valid is False, (
            "validate_data() should return False for insufficient data"
        )
        assert "Insufficient data" in message, (
            f"Error message should contain 'Insufficient data', got: {message!r}"
        )

        with pytest.raises(ValueError) as exc_info:
            engine.analyze(data)
        assert "Insufficient data" in str(exc_info.value), (
            f"analyze() ValueError should contain 'Insufficient data', got: {exc_info.value!r}"
        )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=insufficient_with_failed_categories_strategy())
    def test_property_11_failed_categories_do_not_count(self, engine, data):
        """
        Property 11 (failed-category variant): failed=True categories SHALL NOT
        count toward the minimum 3 active category requirement.

        Cases: 0 active + 5 failed, 1 active + 4 failed, 2 active + 3 failed.
        All must be rejected as insufficient data.

        Validates: Requirement 3.5
        """
        is_valid, message = engine.validate_data(data)

        assert is_valid is False, (
            "validate_data() should return False when active categories < 3 (failed ones do not count)"
        )
        assert "Insufficient data" in message, (
            f"Error message should contain 'Insufficient data', got: {message!r}"
        )

        with pytest.raises(ValueError) as exc_info:
            engine.analyze(data)
        assert "Insufficient data" in str(exc_info.value)


class TestDataCorruptionDetectionProperties:
    """Property 12: Data Corruption Detection (Requirement 3.6)."""

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=corrupted_analysis_data_strategy())
    def test_property_12_data_corruption_detection(self, engine, data):
        """
        Property 12: For any Analysis_Data containing values that fail type
        validation or are outside expected ranges, validate_data SHALL return
        is_valid=False with a data corruption error message, and analyze()
        SHALL raise RuntimeError.

        Validates: Requirement 3.6
        """
        is_valid, message = engine.validate_data(data)

        assert is_valid is False, (
            "validate_data() should return False for corrupted data"
        )
        assert "Data corruption detected" in message, (
            f"Error message should contain 'Data corruption detected', got: {message!r}"
        )

        with pytest.raises(RuntimeError) as exc_info:
            engine.analyze(data)
        assert "Data corruption detected" in str(exc_info.value), (
            f"analyze() RuntimeError should contain 'Data corruption detected', got: {exc_info.value!r}"
        )

    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    @given(data=corrupted_analysis_data_strategy())
    def test_property_12_error_message_names_category(self, engine, data):
        """
        Property 12 (error-message specificity): The corruption error message
        SHALL identify the specific category and field where corruption was detected.

        Expected format: 'Data corruption detected in <category>.<field>: ...'
        Validates: Requirement 3.6
        """
        is_valid, message = engine.validate_data(data)
        assert is_valid is False

        # The message must name one of the 5 category namespaces
        assert any(cat in message for cat in ["network", "dom", "javascript", "visual", "ssl"]), (
            f"Corruption message should name the corrupted category, got: {message!r}"
        )

    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    @given(corrupt_network=corrupted_network_strategy())
    def test_property_12_network_corruption_detected(self, engine, corrupt_network):
        """Corrupted NetworkData in a 3-category setup triggers corruption error."""
        data = AnalysisData(
            network=corrupt_network,
            dom=DOMData(html_content="<html></html>", structure_metrics={"element_count": 5}, failed=False),
            javascript=JavaScriptData(script_count=2, dom_modifications=0, external_api_calls=0, failed=False),
            visual=None,
            ssl=None,
            timeout_occurred=False,
        )
        is_valid, message = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected" in message
        assert "network" in message

        with pytest.raises(RuntimeError):
            engine.analyze(data)

    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    @given(corrupt_dom=corrupted_dom_strategy())
    def test_property_12_dom_corruption_detected(self, engine, corrupt_dom):
        """Corrupted DOMData in a 3-category setup triggers corruption error."""
        data = AnalysisData(
            network=NetworkData(request_count=10, unique_domains=["a.com"], protocol_distribution={"https": 10}, failed=False),
            dom=corrupt_dom,
            javascript=JavaScriptData(script_count=1, dom_modifications=0, external_api_calls=0, failed=False),
            visual=None,
            ssl=None,
            timeout_occurred=False,
        )
        is_valid, message = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected" in message
        assert "dom" in message

        with pytest.raises(RuntimeError):
            engine.analyze(data)

    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    @given(corrupt_js=corrupted_js_strategy())
    def test_property_12_javascript_corruption_detected(self, engine, corrupt_js):
        """Corrupted JavaScriptData in a 3-category setup triggers corruption error."""
        data = AnalysisData(
            network=NetworkData(request_count=10, unique_domains=["a.com"], protocol_distribution={"https": 10}, failed=False),
            dom=DOMData(html_content="<html></html>", structure_metrics={"element_count": 5}, failed=False),
            javascript=corrupt_js,
            visual=None,
            ssl=None,
            timeout_occurred=False,
        )
        is_valid, message = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected" in message
        assert "javascript" in message

        with pytest.raises(RuntimeError):
            engine.analyze(data)

    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    @given(corrupt_visual=corrupted_visual_strategy())
    def test_property_12_visual_corruption_detected(self, engine, corrupt_visual):
        """Corrupted VisualData in a 4-category setup triggers corruption error."""
        data = AnalysisData(
            network=NetworkData(request_count=10, unique_domains=["a.com"], protocol_distribution={"https": 10}, failed=False),
            dom=DOMData(html_content="<html></html>", structure_metrics={"element_count": 5}, failed=False),
            javascript=JavaScriptData(script_count=1, dom_modifications=0, external_api_calls=0, failed=False),
            visual=corrupt_visual,
            ssl=None,
            timeout_occurred=False,
        )
        is_valid, message = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected" in message
        assert "visual" in message

        with pytest.raises(RuntimeError):
            engine.analyze(data)

    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    @given(corrupt_ssl=corrupted_ssl_strategy())
    def test_property_12_ssl_corruption_detected(self, engine, corrupt_ssl):
        """Corrupted SSLData in a 4-category setup triggers corruption error."""
        data = AnalysisData(
            network=NetworkData(request_count=10, unique_domains=["a.com"], protocol_distribution={"https": 10}, failed=False),
            dom=DOMData(html_content="<html></html>", structure_metrics={"element_count": 5}, failed=False),
            javascript=JavaScriptData(script_count=1, dom_modifications=0, external_api_calls=0, failed=False),
            visual=None,
            ssl=corrupt_ssl,
            timeout_occurred=False,
        )
        is_valid, message = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected" in message
        assert "ssl" in message

        with pytest.raises(RuntimeError):
            engine.analyze(data)


class TestBoolAsIntCorruption:
    """
    Explicit property tests for bool-as-int corruption.
    isinstance(True, int) == True in Python, so the engine must explicitly
    reject booleans where exact non-negative integers are required.
    """

    @pytest.mark.parametrize("bool_val", [True, False])
    def test_network_request_count_bool_rejected(self, engine, bool_val):
        """Boolean values for request_count must be detected as corruption."""
        data = AnalysisData(
            network=NetworkData(
                request_count=bool_val,
                unique_domains=["example.com"],
                protocol_distribution={"https": 10},
                failed=False,
            ),
            dom=DOMData(html_content="<html></html>", structure_metrics={"element_count": 5}, failed=False),
            javascript=JavaScriptData(script_count=1, dom_modifications=0, external_api_calls=0, failed=False),
            visual=None,
            ssl=None,
            timeout_occurred=False,
        )
        is_valid, message = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected" in message
        assert "network.request_count" in message

    @pytest.mark.parametrize("bool_val", [True, False])
    def test_javascript_script_count_bool_rejected(self, engine, bool_val):
        """Boolean values for script_count must be detected as corruption."""
        data = AnalysisData(
            network=NetworkData(request_count=10, unique_domains=[], protocol_distribution={}, failed=False),
            dom=DOMData(html_content="<html></html>", structure_metrics={}, failed=False),
            javascript=JavaScriptData(
                script_count=bool_val,
                dom_modifications=0,
                external_api_calls=0,
                failed=False,
            ),
            visual=None,
            ssl=None,
            timeout_occurred=False,
        )
        is_valid, message = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected" in message
        assert "javascript.script_count" in message

    @pytest.mark.parametrize("bool_val", [True, False])
    def test_javascript_dom_modifications_bool_rejected(self, engine, bool_val):
        """Boolean values for dom_modifications must be detected as corruption."""
        data = AnalysisData(
            network=NetworkData(request_count=10, unique_domains=[], protocol_distribution={}, failed=False),
            dom=DOMData(html_content="<html></html>", structure_metrics={}, failed=False),
            javascript=JavaScriptData(
                script_count=5,
                dom_modifications=bool_val,
                external_api_calls=0,
                failed=False,
            ),
            visual=None,
            ssl=None,
            timeout_occurred=False,
        )
        is_valid, message = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected" in message
        assert "javascript.dom_modifications" in message

    @pytest.mark.parametrize("bool_val", [True, False])
    def test_protocol_distribution_bool_value_rejected(self, engine, bool_val):
        """Boolean values in protocol_distribution must be detected as corruption."""
        data = AnalysisData(
            network=NetworkData(
                request_count=10,
                unique_domains=[],
                protocol_distribution={"https": bool_val},
                failed=False,
            ),
            dom=DOMData(html_content="<html></html>", structure_metrics={}, failed=False),
            javascript=JavaScriptData(script_count=5, dom_modifications=0, external_api_calls=0, failed=False),
            visual=None,
            ssl=None,
            timeout_occurred=False,
        )
        is_valid, message = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected" in message
        assert "network.protocol_distribution" in message

    @pytest.mark.parametrize("non_bool", [0, 1, "True", "False", None, [True]])
    def test_ssl_chain_valid_non_bool_rejected(self, engine, non_bool):
        """Non-boolean values for chain_valid must be detected as corruption."""
        data = AnalysisData(
            network=NetworkData(request_count=10, unique_domains=[], protocol_distribution={}, failed=False),
            dom=DOMData(html_content="<html></html>", structure_metrics={}, failed=False),
            javascript=None,
            visual=None,
            ssl=SSLData(
                issuer="CN=Let's Encrypt",
                expiration_date="2030-01-01T00:00:00Z",
                chain_valid=non_bool,
                failed=False,
            ),
            timeout_occurred=False,
        )
        is_valid, message = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected" in message
        assert "ssl.chain_valid" in message


class TestValidControlCases:
    """
    Control tests: confirm that valid AnalysisData always passes validation
    and generates scores. These verify the corruption strategies do not
    accidentally reject legitimate values.
    """

    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    @given(data=valid_analysis_data_strategy())
    def test_valid_data_passes_validation(self, engine, data):
        """
        Valid AnalysisData with >= 3 active categories always passes validate_data().
        """
        is_valid, message = engine.validate_data(data)
        assert is_valid is True, (
            f"validate_data() should return True for valid data, got message: {message!r}"
        )
        assert message == "", (
            f"validate_data() should return empty message for valid data, got: {message!r}"
        )

    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    @given(data=valid_analysis_data_strategy())
    def test_valid_data_generates_scores(self, engine, data):
        """
        Valid AnalysisData with >= 3 active categories always generates AnalysisScores.
        """
        scores = engine.analyze(data)
        assert isinstance(scores, AnalysisScores)
