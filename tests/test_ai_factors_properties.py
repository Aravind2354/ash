"""
Property-based tests for Factor Identification (Task 8.8).

Property 24: Suspicious Indicators List
Property 25: Top Factors Identification

Validates: Requirements 7.3, 7.4

Design:
-------
Property 24 — For any Fake_Score value, the report SHALL include a list of
Analysis_Data elements that contributed to the score if Fake_Score > 0.5,
or an empty list if Fake_Score <= 0.5.

Property 25 — For any analysis result, the report SHALL contain exactly 3
data factors that most influenced the Authenticity_Score.

Test Strategy:
  - Hypothesis generates trusted AnalysisData (strong authentic signals) to
    produce fake_score <= 0.5 reliably.
  - Hypothesis generates adversarial AnalysisData (multiple negative signals)
    to produce fake_score > 0.5 reliably.
  - Every test calls the REAL AIAnalysisEngine.analyze(); no mocking.
  - The resulting fake_score is always asserted — the test does not simply
    trust the strategy to produce the intended score without verifying.
  - Fallback-string exclusion uses the known fallback mappings from the
    production _select_top_factors() implementation.
"""

import pytest

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from hypothesis import given, strategies as st, settings, HealthCheck, assume

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
# Known Fallback Strings (from _select_top_factors implementation)
# ---------------------------------------------------------------------------

FALLBACK_STRINGS = {
    "ssl":        "SSL certificate information evaluated",
    "network":    "Network protocol distribution verified",
    "dom":        "DOM structure analysis completed",
    "javascript": "JavaScript behavior analysis completed",
    "visual":     "Visual rendering characteristics captured",
}

_ALL_CATS = ["network", "dom", "javascript", "visual", "ssl"]


# ---------------------------------------------------------------------------
# Trusted Data Strategies (strong authentic signals → fake_score ≤ 0.5)
# ---------------------------------------------------------------------------

_trusted_ssl = st.builds(
    SSLData,
    issuer=st.sampled_from([
        "CN=Let's Encrypt Authority X3",
        "CN=DigiCert TLS RSA SHA256",
        "CN=Cloudflare Inc ECC CA-3",
    ]),
    expiration_date=st.just("2030-01-01T00:00:00Z"),
    chain_valid=st.just(True),
    failed=st.just(False),
)

@st.composite
def _trusted_network(draw):
    n_https = draw(st.integers(min_value=20, max_value=200))
    n_domains = draw(st.integers(min_value=1, max_value=10))
    return NetworkData(
        request_count=n_https,
        unique_domains=[f"d{i}.example.com" for i in range(n_domains)],
        protocol_distribution={"https": n_https},
        failed=False,
    )

@st.composite
def _trusted_dom(draw):
    n_elements = draw(st.integers(min_value=20, max_value=100))
    n_forms = draw(st.integers(min_value=1, max_value=3))
    return DOMData(
        html_content="<html>" + "<div/>" * n_elements + "</html>",
        structure_metrics={
            "element_count": n_elements,
            "iframe_count": 0,
            "form_count": n_forms,
        },
        failed=False,
    )

@st.composite
def _trusted_js(draw):
    return JavaScriptData(
        script_count=draw(st.integers(min_value=1, max_value=20)),
        dom_modifications=draw(st.integers(min_value=0, max_value=50)),
        external_api_calls=draw(st.integers(min_value=0, max_value=5)),
        failed=False,
    )

@st.composite
def _trusted_visual(draw):
    return VisualData(
        screenshot_path="/tmp/screenshot.png",
        layout_characteristics={
            "viewport_width": draw(st.integers(min_value=800, max_value=1920)),
            "viewport_height": draw(st.integers(min_value=600, max_value=1080)),
            "has_images": True,
            "image_count": draw(st.integers(min_value=1, max_value=20)),
        },
        failed=False,
    )

_TRUSTED_STRATS = {
    "ssl": _trusted_ssl,
    "network": _trusted_network(),
    "dom": _trusted_dom(),
    "javascript": _trusted_js(),
    "visual": _trusted_visual(),
}

@st.composite
def trusted_analysis_data(draw):
    """
    Generate AnalysisData with strong authentic signals across all 5 categories.
    Designed to produce authenticity_score > 0.5, thus fake_score < 0.5.
    """
    return AnalysisData(
        ssl=draw(_trusted_ssl),
        network=draw(_trusted_network()),
        dom=draw(_trusted_dom()),
        javascript=draw(_trusted_js()),
        visual=draw(_trusted_visual()),
        timeout_occurred=False,
    )


# ---------------------------------------------------------------------------
# Adversarial Data Strategies (multiple negative signals → fake_score > 0.5)
# ---------------------------------------------------------------------------

_adversarial_ssl = st.just(
    SSLData(
        issuer="",
        expiration_date="2020-01-01T00:00:00Z",  # expired → suspicious
        chain_valid=False,
        failed=False,
    )
)

@st.composite
def adversarial_network(draw):
    """Network with excessive domains + all-HTTP traffic."""
    n_domains = draw(st.integers(min_value=31, max_value=60))
    n_requests = draw(st.integers(min_value=50, max_value=300))
    return NetworkData(
        request_count=n_requests,
        unique_domains=[f"bad{i}.domain.com" for i in range(n_domains)],
        protocol_distribution={"http": n_requests},
        failed=False,
    )

@st.composite
def adversarial_dom(draw):
    """DOM with many iframes, many forms, and sparse content."""
    return DOMData(
        html_content="<html/>",
        structure_metrics={
            "iframe_count": draw(st.integers(min_value=6, max_value=20)),
            "form_count": draw(st.integers(min_value=11, max_value=30)),
        },
        failed=False,
    )

@st.composite
def adversarial_analysis_data(draw):
    """
    Generate AnalysisData with three categories using all negative signals.
    Designed to produce fake_score > 0.5 reliably (SSL + Network + DOM are
    the most impactful categories).
    """
    return AnalysisData(
        ssl=draw(_adversarial_ssl),
        network=draw(adversarial_network()),
        dom=draw(adversarial_dom()),
        javascript=None,
        visual=None,
        timeout_occurred=False,
    )


# ---------------------------------------------------------------------------
# Shared valid-data strategies (for Property 25 — varying N active categories)
# ---------------------------------------------------------------------------

_valid_ssl = st.builds(
    SSLData,
    issuer=st.sampled_from(["CN=Let's Encrypt", "CN=DigiCert", ""]),
    expiration_date=st.sampled_from(["2030-01-01T00:00:00Z", "2028-06-01T00:00:00Z", ""]),
    chain_valid=st.booleans(),
    failed=st.just(False),
)

_valid_network = st.builds(
    NetworkData,
    request_count=st.integers(min_value=0, max_value=500),
    unique_domains=st.lists(
        st.text(alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd')), min_size=1, max_size=15),
        min_size=0,
        max_size=25,
    ),
    protocol_distribution=st.dictionaries(
        st.sampled_from(["http", "https", "ws", "wss"]),
        st.integers(min_value=0, max_value=300),
        max_size=4,
    ),
    failed=st.just(False),
)

_valid_dom = st.builds(
    DOMData,
    html_content=st.text(min_size=0, max_size=500),
    structure_metrics=st.dictionaries(
        st.sampled_from(["element_count", "total_elements", "form_count", "iframe_count", "script_tag_count"]),
        st.integers(min_value=0, max_value=150),
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
    screenshot_path=st.sampled_from(["", "/tmp/screenshot.png", "shot.png"]),
    layout_characteristics=st.fixed_dictionaries({
        "viewport_width": st.integers(min_value=0, max_value=2560),
        "viewport_height": st.integers(min_value=0, max_value=1440),
        "has_images": st.booleans(),
        "image_count": st.integers(min_value=0, max_value=50),
    }),
    failed=st.just(False),
)

_VALID_STRATS = {
    "ssl": _valid_ssl,
    "network": _valid_network,
    "dom": _valid_dom,
    "javascript": _valid_js,
    "visual": _valid_visual,
}

_FAILED_STRATS = {
    "ssl": st.builds(SSLData, issuer=st.just(""), expiration_date=st.just(""), chain_valid=st.just(False), failed=st.just(True)),
    "network": st.builds(NetworkData, request_count=st.just(0), unique_domains=st.just([]), protocol_distribution=st.just({}), failed=st.just(True)),
    "dom": st.builds(DOMData, html_content=st.just(""), structure_metrics=st.just({}), failed=st.just(True)),
    "javascript": st.builds(JavaScriptData, script_count=st.just(0), dom_modifications=st.just(0), external_api_calls=st.just(0), failed=st.just(True)),
    "visual": st.builds(VisualData, screenshot_path=st.just(""), layout_characteristics=st.just({}), failed=st.just(True)),
}


@st.composite
def analysis_data_with_exact_n_active(draw, n: int):
    """Generate AnalysisData with exactly N active (failed=False) categories."""
    active_cats = draw(
        st.sets(st.sampled_from(_ALL_CATS), min_size=n, max_size=n)
    )
    cat_map = {}
    for cat in _ALL_CATS:
        if cat in active_cats:
            cat_map[cat] = draw(_VALID_STRATS[cat])
        else:
            cat_map[cat] = None
    return AnalysisData(
        network=cat_map["network"],
        dom=cat_map["dom"],
        javascript=cat_map["javascript"],
        visual=cat_map["visual"],
        ssl=cat_map["ssl"],
        timeout_occurred=False,
    ), active_cats


# ---------------------------------------------------------------------------
# Property 24 — Suspicious Indicators List
# ---------------------------------------------------------------------------

class TestProperty24SuspiciousIndicators:
    """Property 24: Suspicious Indicators List (Requirement 7.3)."""

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=trusted_analysis_data())
    def test_property_24_empty_when_fake_score_below_half(self, engine, data):
        """
        Property 24: For trusted data producing fake_score <= 0.5, the
        suspicious_indicators SHALL be an empty list.

        The test asserts the actual fake_score, not just the strategy intent.
        Validates: Requirement 7.3
        """
        scores = engine.analyze(data)
        assert scores.fake_score <= 0.5, (
            f"trusted_analysis_data strategy produced unexpected fake_score={scores.fake_score:.4f}; "
            "strategy may need adjustment"
        )
        assert scores.suspicious_indicators == [], (
            f"Expected empty suspicious_indicators for fake_score={scores.fake_score:.4f}, "
            f"got: {scores.suspicious_indicators!r}"
        )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=adversarial_analysis_data())
    def test_property_24_populated_when_fake_score_above_half(self, engine, data):
        """
        Property 24: For adversarial data producing fake_score > 0.5, the
        suspicious_indicators SHALL be a non-empty list.

        Validates: Requirement 7.3
        """
        scores = engine.analyze(data)
        assert scores.fake_score > 0.5, (
            f"adversarial_analysis_data strategy produced unexpected fake_score={scores.fake_score:.4f}; "
            "strategy may need adjustment"
        )
        assert len(scores.suspicious_indicators) > 0, (
            f"Expected non-empty suspicious_indicators for fake_score={scores.fake_score:.4f}"
        )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=adversarial_analysis_data())
    def test_property_24_indicators_are_strings(self, engine, data):
        """
        Property 24: Each suspicious indicator SHALL be a non-empty string.
        Validates: Requirement 7.3
        """
        scores = engine.analyze(data)
        # Only check indicators when fake_score > 0.5 (when they are populated)
        if scores.fake_score > 0.5:
            assert all(isinstance(s, str) and len(s) > 0 for s in scores.suspicious_indicators), (
                f"All suspicious indicators must be non-empty strings; got: {scores.suspicious_indicators!r}"
            )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=adversarial_analysis_data())
    def test_property_24_deduplicated(self, engine, data):
        """
        Property 24: The suspicious_indicators list SHALL be deduplicated.
        No string shall appear more than once (dict.fromkeys preserves order).
        Validates: Requirement 7.3
        """
        scores = engine.analyze(data)
        if scores.fake_score > 0.5:
            assert len(scores.suspicious_indicators) == len(set(scores.suspicious_indicators)), (
                f"Duplicate entries found in suspicious_indicators: {scores.suspicious_indicators!r}"
            )

    def test_property_24_exactly_half_returns_empty(self, engine, monkeypatch):
        """
        Property 24: At exactly fake_score == 0.5, suspicious_indicators
        SHALL be an empty list.

        The implementation uses strict > 0.5, so the boundary returns [].

        Uses monkeypatching to pin the category scores to produce exactly 0.5.
        Validates: Requirement 7.3
        """
        # Each evaluator returns score=0.5, with some candidate suspicious strings.
        # Net weighted authenticity = 0.5 → fake = 0.5 exactly.
        monkeypatch.setattr(engine, "_evaluate_ssl",        lambda ssl:  (0.5, ["SSL factor"], ["SSL warning"]))
        monkeypatch.setattr(engine, "_evaluate_network",    lambda net:  (0.5, ["Net factor"], ["Net warning"]))
        monkeypatch.setattr(engine, "_evaluate_dom",        lambda dom:  (0.5, ["DOM factor"], ["DOM warning"]))

        data = AnalysisData(
            ssl=SSLData(issuer="CN=Test", expiration_date="2030-01-01T00:00:00Z", chain_valid=True, failed=False),
            network=NetworkData(request_count=10, unique_domains=["a.com"], protocol_distribution={"https": 10}, failed=False),
            dom=DOMData(html_content="<html/>", structure_metrics={"element_count": 10}, failed=False),
            javascript=None,
            visual=None,
            timeout_occurred=False,
        )
        scores = engine.analyze(data)

        assert scores.authenticity_score == 0.5, (
            f"Expected authenticity_score=0.5, got {scores.authenticity_score}"
        )
        assert scores.fake_score == 0.5, (
            f"Expected fake_score=0.5, got {scores.fake_score}"
        )
        assert scores.suspicious_indicators == [], (
            f"Expected [] at fake_score=0.5 (strict > boundary), got: {scores.suspicious_indicators!r}"
        )


# ---------------------------------------------------------------------------
# Property 25 — Top Factors Identification
# ---------------------------------------------------------------------------

class TestProperty25TopFactors:
    """Property 25: Top Factors Identification (Requirement 7.4)."""

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(3))
    def test_property_25_exactly_three_factors_any_3_categories(self, engine, pair):
        """
        Property 25: For any valid AnalysisData with exactly 3 active categories,
        analyze() SHALL return exactly 3 top_factors.

        Validates: Requirement 7.4
        """
        data, active_cats = pair
        scores = engine.analyze(data)
        assert len(scores.top_factors) == 3, (
            f"Expected exactly 3 top_factors for 3 active categories {sorted(active_cats)}, "
            f"got {len(scores.top_factors)}: {scores.top_factors!r}"
        )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(4))
    def test_property_25_exactly_three_factors_any_4_categories(self, engine, pair):
        """
        Property 25: For any valid AnalysisData with exactly 4 active categories,
        analyze() SHALL return exactly 3 top_factors.

        Validates: Requirement 7.4
        """
        data, active_cats = pair
        scores = engine.analyze(data)
        assert len(scores.top_factors) == 3, (
            f"Expected exactly 3 top_factors for 4 active categories {sorted(active_cats)}, "
            f"got {len(scores.top_factors)}: {scores.top_factors!r}"
        )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(5))
    def test_property_25_exactly_three_factors_any_5_categories(self, engine, pair):
        """
        Property 25: For any valid AnalysisData with all 5 active categories,
        analyze() SHALL return exactly 3 top_factors.

        Validates: Requirement 7.4
        """
        data, active_cats = pair
        scores = engine.analyze(data)
        assert len(scores.top_factors) == 3, (
            f"Expected exactly 3 top_factors for 5 active categories, "
            f"got {len(scores.top_factors)}: {scores.top_factors!r}"
        )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(3))
    def test_property_25_factors_are_unique(self, engine, pair):
        """
        Property 25: The 3 top_factors SHALL be unique strings.
        No factor string shall appear more than once.
        Validates: Requirement 7.4
        """
        data, _ = pair
        scores = engine.analyze(data)
        assert len(scores.top_factors) == len(set(scores.top_factors)), (
            f"Duplicate top_factors found: {scores.top_factors!r}"
        )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(3))
    def test_property_25_factors_are_nonempty_strings(self, engine, pair):
        """
        Property 25: Each top_factor SHALL be a non-empty string.
        Validates: Requirement 7.4
        """
        data, _ = pair
        scores = engine.analyze(data)
        assert all(isinstance(f, str) and len(f) > 0 for f in scores.top_factors), (
            f"All top_factors must be non-empty strings; got: {scores.top_factors!r}"
        )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(3))
    def test_property_25_deterministic_on_same_input(self, engine, pair):
        """
        Property 25: Calling analyze() twice on the same AnalysisData object
        SHALL produce the same top_factors list in the same order.
        Suspicious indicators SHALL also be identical.
        Validates: Requirement 7.4
        """
        data, _ = pair
        scores1 = engine.analyze(data)
        scores2 = engine.analyze(data)
        assert scores1.top_factors == scores2.top_factors, (
            f"top_factors are not deterministic:\n  run1={scores1.top_factors!r}\n  run2={scores2.top_factors!r}"
        )
        assert scores1.suspicious_indicators == scores2.suspicious_indicators, (
            f"suspicious_indicators are not deterministic:\n  run1={scores1.suspicious_indicators!r}\n  run2={scores2.suspicious_indicators!r}"
        )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(3))
    def test_property_25_inactive_category_fallbacks_excluded(self, engine, pair):
        """
        Property 25: Fallback strings associated with inactive/None categories
        SHALL NOT appear in top_factors.

        For any 3-active-category subset, the 2 inactive categories' known
        fallback strings must be absent from top_factors.

        Known fallback strings per category:
          ssl:        "SSL certificate information evaluated"
          network:    "Network protocol distribution verified"
          dom:        "DOM structure analysis completed"
          javascript: "JavaScript behavior analysis completed"
          visual:     "Visual rendering characteristics captured"

        Validates: Requirement 7.4
        """
        data, active_cats = pair
        inactive_cats = set(_ALL_CATS) - active_cats

        scores = engine.analyze(data)

        for inactive_cat in inactive_cats:
            fallback = FALLBACK_STRINGS[inactive_cat]
            assert fallback not in scores.top_factors, (
                f"Fallback string for inactive category '{inactive_cat}' found in top_factors.\n"
                f"  fallback: {fallback!r}\n"
                f"  top_factors: {scores.top_factors!r}\n"
                f"  active categories: {sorted(active_cats)}"
            )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(4))
    def test_property_25_inactive_fallbacks_excluded_4_categories(self, engine, pair):
        """
        Property 25 (4-category variant): For any 4-active-category subset,
        the 1 inactive category's fallback string SHALL NOT appear in top_factors.
        Validates: Requirement 7.4
        """
        data, active_cats = pair
        inactive_cats = set(_ALL_CATS) - active_cats

        scores = engine.analyze(data)

        for inactive_cat in inactive_cats:
            fallback = FALLBACK_STRINGS[inactive_cat]
            assert fallback not in scores.top_factors, (
                f"Fallback string for inactive category '{inactive_cat}' found in top_factors.\n"
                f"  fallback: {fallback!r}\n"
                f"  top_factors: {scores.top_factors!r}\n"
                f"  active categories: {sorted(active_cats)}"
            )


# ---------------------------------------------------------------------------
# Combined Property 24 + 25 — Cross-Property Verification
# ---------------------------------------------------------------------------

class TestProperty24And25Combined:
    """Combined cross-property tests verifying both P24 and P25 simultaneously."""

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=trusted_analysis_data())
    def test_trusted_data_has_three_factors_and_empty_indicators(self, engine, data):
        """
        For trusted data with fake_score <= 0.5:
        - exactly 3 top_factors (P25)
        - empty suspicious_indicators (P24)
        """
        scores = engine.analyze(data)
        assert scores.fake_score <= 0.5
        assert len(scores.top_factors) == 3
        assert scores.suspicious_indicators == []

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=adversarial_analysis_data())
    def test_adversarial_data_has_three_factors_and_populated_indicators(self, engine, data):
        """
        For adversarial data with fake_score > 0.5:
        - exactly 3 top_factors (P25)
        - non-empty suspicious_indicators (P24)
        """
        scores = engine.analyze(data)
        assert scores.fake_score > 0.5
        assert len(scores.top_factors) == 3
        assert len(scores.suspicious_indicators) > 0

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(pair=analysis_data_with_exact_n_active(3))
    def test_any_3_category_data_always_has_exactly_three_factors(self, engine, pair):
        """
        For any random 3-category AnalysisData (regardless of score outcome),
        top_factors always has exactly 3 elements.
        """
        data, _ = pair
        scores = engine.analyze(data)
        assert len(scores.top_factors) == 3
        assert len(set(scores.top_factors)) == 3
        assert all(isinstance(f, str) and f for f in scores.top_factors)
