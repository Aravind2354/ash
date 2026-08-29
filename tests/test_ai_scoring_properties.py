"""
Property-based tests for AI Score Generation and Validation (Task 8.2).

Property 8: AI Score Generation
Property 9: Score Range Validity
Property 10: Score Summation Invariant

Validates: Requirements 3.1, 3.2, 3.3, 3.4

Design & Properties:
--------------------
- Property 8: For any valid Analysis_Data with at least 3 categories, the AI agent
  SHALL generate both an Authenticity_Score and a Fake_Score.
- Property 9: For any generated analysis scores, both Authenticity_Score and Fake_Score
  SHALL be within the range [0.0, 1.0] inclusive.
- Property 10: For any generated Authenticity_Score and Fake_Score, the sum of the two
  scores SHALL equal 1.0 within a tolerance of 0.01 (i.e., |Authenticity_Score + Fake_Score - 1.0| <= 0.01).
- Summation Invariant: Verified without requiring exact normalization to 1.0.
- No live network calls or external AI services are invoked.
"""

import math
import pytest
from typing import Dict, List, Set

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
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine():
    """Shared AIAnalysisEngine instance for property tests."""
    return AIAnalysisEngine()


# ---------------------------------------------------------------------------
# Hypothesis Strategies for Valid Uncorrupted Category Data
# ---------------------------------------------------------------------------

valid_network_strategy = st.builds(
    NetworkData,
    request_count=st.integers(min_value=0, max_value=1000),
    unique_domains=st.lists(
        st.text(alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd')), min_size=1, max_size=20),
        min_size=0,
        max_size=50,
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
    html_content=st.text(min_size=0, max_size=1000),
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
    screenshot_path=st.sampled_from(["", "/tmp/screenshot.png", "screenshots/page.png", "images/shot.png"]),
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
    issuer=st.sampled_from(["", "CN=DigiCert Global Root CA, O=DigiCert Inc", "CN=Let's Encrypt Authority X3", "CN=Cloudflare Inc ECC CA-3"]),
    expiration_date=st.sampled_from(["", "2030-01-01T00:00:00Z", "2020-05-15T12:00:00Z", "2028-10-10T00:00:00Z"]),
    chain_valid=st.booleans(),
    failed=st.just(False),
)


# ---------------------------------------------------------------------------
# Hypothesis Strategies for Failed Category Data
# ---------------------------------------------------------------------------

failed_network_strategy = st.builds(
    NetworkData,
    request_count=st.just(0),
    unique_domains=st.just([]),
    protocol_distribution=st.just({}),
    failed=st.just(True),
)

failed_dom_strategy = st.builds(
    DOMData,
    html_content=st.just(""),
    structure_metrics=st.just({}),
    failed=st.just(True),
)

failed_js_strategy = st.builds(
    JavaScriptData,
    script_count=st.just(0),
    dom_modifications=st.just(0),
    external_api_calls=st.just(0),
    failed=st.just(True),
)

failed_visual_strategy = st.builds(
    VisualData,
    screenshot_path=st.just(""),
    layout_characteristics=st.just({}),
    failed=st.just(True),
)

failed_ssl_strategy = st.builds(
    SSLData,
    issuer=st.just(""),
    expiration_date=st.just(""),
    chain_valid=st.just(False),
    failed=st.just(True),
)


# ---------------------------------------------------------------------------
# Composite Strategy for Valid AnalysisData (3 to 5 Active Categories)
# ---------------------------------------------------------------------------

ALL_CATEGORY_NAMES = ["network", "dom", "javascript", "visual", "ssl"]

@st.composite
def valid_analysis_data_strategy(draw):
    """
    Generate valid AnalysisData with a random subset of 3, 4, or 5 active categories.
    Unselected categories are set to None.
    """
    category_subset: Set[str] = draw(
        st.sets(st.sampled_from(ALL_CATEGORY_NAMES), min_size=3, max_size=5)
    )

    network = draw(valid_network_strategy) if "network" in category_subset else None
    dom = draw(valid_dom_strategy) if "dom" in category_subset else None
    javascript = draw(valid_js_strategy) if "javascript" in category_subset else None
    visual = draw(valid_visual_strategy) if "visual" in category_subset else None
    ssl = draw(valid_ssl_strategy) if "ssl" in category_subset else None

    return AnalysisData(
        network=network,
        dom=dom,
        javascript=javascript,
        visual=visual,
        ssl=ssl,
        timeout_occurred=False,
    )


@st.composite
def mixed_failed_analysis_data_strategy(draw):
    """
    Generate AnalysisData with at least 3 active categories AND 1-2 failed categories.
    """
    active_count = draw(st.sampled_from([3, 4]))
    active_categories: Set[str] = draw(
        st.sets(st.sampled_from(ALL_CATEGORY_NAMES), min_size=active_count, max_size=active_count)
    )
    remaining_categories = [c for c in ALL_CATEGORY_NAMES if c not in active_categories]
    failed_count = draw(st.integers(min_value=1, max_value=len(remaining_categories)))
    failed_categories = draw(
        st.sets(st.sampled_from(remaining_categories), min_size=failed_count, max_size=failed_count)
    )

    cat_map = {}
    for cat in ALL_CATEGORY_NAMES:
        if cat in active_categories:
            if cat == "network":
                cat_map[cat] = draw(valid_network_strategy)
            elif cat == "dom":
                cat_map[cat] = draw(valid_dom_strategy)
            elif cat == "javascript":
                cat_map[cat] = draw(valid_js_strategy)
            elif cat == "visual":
                cat_map[cat] = draw(valid_visual_strategy)
            elif cat == "ssl":
                cat_map[cat] = draw(valid_ssl_strategy)
        elif cat in failed_categories:
            if cat == "network":
                cat_map[cat] = draw(failed_network_strategy)
            elif cat == "dom":
                cat_map[cat] = draw(failed_dom_strategy)
            elif cat == "javascript":
                cat_map[cat] = draw(failed_js_strategy)
            elif cat == "visual":
                cat_map[cat] = draw(failed_visual_strategy)
            elif cat == "ssl":
                cat_map[cat] = draw(failed_ssl_strategy)
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
# Property-Based Tests
# ---------------------------------------------------------------------------

class TestAIScoringProperties:
    """Property-based tests for AI score generation, range validity, and summation invariant."""

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=valid_analysis_data_strategy())
    def test_property_8_ai_score_generation(self, engine, data):
        """
        Property 8: AI Score Generation
        For any valid Analysis_Data with at least 3 categories, the AI agent
        SHALL generate both an Authenticity_Score and a Fake_Score.

        Validates: Requirement 3.1
        """
        scores = engine.analyze(data)

        # Output must be an AnalysisScores dataclass instance
        assert isinstance(scores, AnalysisScores), "Engine must return AnalysisScores instance"
        assert isinstance(scores.authenticity_score, float), "Authenticity_Score must be a float"
        assert isinstance(scores.fake_score, float), "Fake_Score must be a float"
        assert isinstance(scores.top_factors, list), "top_factors must be a list"
        assert isinstance(scores.suspicious_indicators, list), "suspicious_indicators must be a list"

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=valid_analysis_data_strategy())
    def test_property_9_score_range_validity(self, engine, data):
        """
        Property 9: Score Range Validity
        For any generated analysis scores, both Authenticity_Score and Fake_Score
        SHALL be within the range [0.0, 1.0] inclusive.

        Validates: Requirements 3.2, 3.3
        """
        scores = engine.analyze(data)

        assert 0.0 <= scores.authenticity_score <= 1.0, (
            f"Authenticity_Score {scores.authenticity_score} outside [0.0, 1.0]"
        )
        assert 0.0 <= scores.fake_score <= 1.0, (
            f"Fake_Score {scores.fake_score} outside [0.0, 1.0]"
        )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=valid_analysis_data_strategy())
    def test_property_10_score_summation_invariant(self, engine, data):
        """
        Property 10: Score Summation Invariant
        For any generated Authenticity_Score and Fake_Score, the sum of the two
        scores SHALL equal 1.0 within a tolerance of 0.01:
            |Authenticity_Score + Fake_Score - 1.0| <= 0.01

        Validates: Requirement 3.4
        """
        scores = engine.analyze(data)

        total_sum = scores.authenticity_score + scores.fake_score
        deviation = abs(total_sum - 1.0)
        assert deviation <= 0.01, (
            f"Score sum {total_sum:.6f} deviates from 1.0 by {deviation:.6f}, exceeding 0.01 tolerance"
        )

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=mixed_failed_analysis_data_strategy())
    def test_property_scoring_with_mixed_failed_categories(self, engine, data):
        """
        Score generation succeeds and adheres to Properties 8, 9, 10 when
        failed categories exist alongside >= 3 active categories.
        """
        scores = engine.analyze(data)

        assert isinstance(scores, AnalysisScores)
        assert 0.0 <= scores.authenticity_score <= 1.0
        assert 0.0 <= scores.fake_score <= 1.0
        assert abs(scores.authenticity_score + scores.fake_score - 1.0) <= 0.01

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=valid_analysis_data_strategy())
    def test_property_scoring_determinism(self, engine, data):
        """
        Score generation is deterministic: evaluating the same AnalysisData twice
        produces identical scores, top factors, and suspicious indicators.
        """
        result1 = engine.analyze(data)
        result2 = engine.analyze(data)

        assert result1.authenticity_score == result2.authenticity_score
        assert result1.fake_score == result2.fake_score
        assert result1.top_factors == result2.top_factors
        assert result1.suspicious_indicators == result2.suspicious_indicators

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(data=valid_analysis_data_strategy())
    def test_property_scores_no_nan_or_infinite(self, engine, data):
        """
        Generated scores are valid real numbers: never NaN, never positive or negative infinity.
        """
        scores = engine.analyze(data)

        assert not math.isnan(scores.authenticity_score), "Authenticity_Score is NaN"
        assert not math.isnan(scores.fake_score), "Fake_Score is NaN"
        assert not math.isinf(scores.authenticity_score), "Authenticity_Score is infinite"
        assert not math.isinf(scores.fake_score), "Fake_Score is infinite"
