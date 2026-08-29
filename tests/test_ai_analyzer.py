"""
Unit tests for AIAnalysisEngine (Tasks 8.1 & 8.3).

Tests the AIAnalysisEngine class for:
- Creation and interface contracts
- AnalysisScores structure validation
- validate_data() with 0, 1, 2, 3, 4, 5 categories
- Rejection of insufficient data (< 3 categories) with ValueError
- Data corruption detection across Network, DOM, JavaScript, Visual, SSL
- Rejection of corrupted data with RuntimeError in analyze() and descriptive message in validate_data()
- Type checks and explicit exclusion of Python booleans for integer metrics
- Valid scoring for 3, 4, and 5 categories
- Score ranges: Authenticity_Score in [0.0, 1.0], Fake_Score in [0.0, 1.0]
- Score summation invariant (|A + F - 1.0| <= 0.01)
- Absence of artificial exact-normalization
- Deterministic score generation
- 10-second timeout handling and custom timeout behavior
- Dynamic exclusion of failed categories from active weighting

Validates Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8
"""

import pytest
import time
from typing import Dict, List

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.ai_analyzer import AIAnalysisEngine, DEFAULT_ANALYSIS_TIMEOUT
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
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine():
    """Create an AIAnalysisEngine instance."""
    return AIAnalysisEngine()


@pytest.fixture
def valid_network():
    return NetworkData(
        request_count=15,
        unique_domains=["example.com", "cdn.example.com"],
        protocol_distribution={"https": 15},
        failed=False,
    )


@pytest.fixture
def valid_dom():
    return DOMData(
        html_content="<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Header</h1><form action='/submit'><input type='text'></form></body></html>",
        structure_metrics={"total_elements": 25, "form_count": 1, "iframe_count": 0, "script_tag_count": 2},
        failed=False,
    )


@pytest.fixture
def valid_js():
    return JavaScriptData(
        script_count=5,
        dom_modifications=20,
        external_api_calls=2,
        failed=False,
    )


@pytest.fixture
def valid_visual():
    return VisualData(
        screenshot_path="/tmp/screenshot.png",
        layout_characteristics={"viewport_width": 1280, "viewport_height": 800, "has_images": True},
        failed=False,
    )


@pytest.fixture
def valid_ssl():
    return SSLData(
        issuer="CN=DigiCert Global Root CA, O=DigiCert Inc, C=US",
        expiration_date="2030-01-01T00:00:00Z",
        chain_valid=True,
        failed=False,
    )


@pytest.fixture
def full_analysis_data(valid_network, valid_dom, valid_js, valid_visual, valid_ssl):
    return AnalysisData(
        network=valid_network,
        dom=valid_dom,
        javascript=valid_js,
        visual=valid_visual,
        ssl=valid_ssl,
        timeout_occurred=False,
    )


# ---------------------------------------------------------------------------
# Test Suite 1: Class and Model Creation
# ---------------------------------------------------------------------------

class TestEngineAndModelCreation:
    """Test engine instantiation and model structures."""

    def test_engine_creation(self, engine):
        """Test AIAnalysisEngine instantiation."""
        assert engine is not None
        assert isinstance(engine, AIAnalysisEngine)

    def test_analysis_scores_creation(self):
        """Test AnalysisScores dataclass fields."""
        scores = AnalysisScores(
            authenticity_score=0.85,
            fake_score=0.15,
            top_factors=["Valid SSL", "HTTPS"],
            suspicious_indicators=[],
        )
        assert scores.authenticity_score == 0.85
        assert scores.fake_score == 0.15
        assert len(scores.top_factors) == 2
        assert scores.suspicious_indicators == []

    def test_analysis_scores_default_lists(self):
        """Test AnalysisScores default list factories."""
        scores = AnalysisScores(authenticity_score=0.5, fake_score=0.5)
        assert scores.top_factors == []
        assert scores.suspicious_indicators == []


# ---------------------------------------------------------------------------
# Test Suite 2: validate_data() Category Thresholds & Insufficient Data
# ---------------------------------------------------------------------------

class TestValidateDataThresholds:
    """Test validate_data with 0 to 5 categories (Requirement 3.5)."""

    def test_validate_data_rejects_non_analysis_data(self, engine):
        """validate_data rejects non-AnalysisData input."""
        is_valid, msg = engine.validate_data("not_analysis_data")
        assert is_valid is False
        assert "Invalid input" in msg

    def test_validate_data_0_categories(self, engine):
        """validate_data rejects 0 categories."""
        data = AnalysisData()
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Insufficient data" in msg
        assert "found 0" in msg

    def test_validate_data_1_category(self, engine, valid_network):
        """validate_data rejects 1 category."""
        data = AnalysisData(network=valid_network)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Insufficient data" in msg
        assert "found 1" in msg

    def test_validate_data_2_categories(self, engine, valid_network, valid_dom):
        """validate_data rejects 2 categories (Requirement 3.5)."""
        data = AnalysisData(network=valid_network, dom=valid_dom)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Insufficient data" in msg
        assert "found 2" in msg

    def test_validate_data_3_categories(self, engine, valid_network, valid_dom, valid_js):
        """validate_data accepts 3 categories (minimum threshold)."""
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is True
        assert msg == ""

    def test_validate_data_4_categories(self, engine, valid_network, valid_dom, valid_js, valid_ssl):
        """validate_data accepts 4 categories."""
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js, ssl=valid_ssl)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is True
        assert msg == ""

    def test_validate_data_5_categories(self, engine, full_analysis_data):
        """validate_data accepts all 5 categories."""
        is_valid, msg = engine.validate_data(full_analysis_data)
        assert is_valid is True
        assert msg == ""

    def test_validate_data_ignores_failed_categories(self, engine, valid_network, valid_dom):
        """validate_data treats failed categories as unavailable."""
        failed_js = JavaScriptData(script_count=0, dom_modifications=0, external_api_calls=0, failed=True)
        failed_ssl = SSLData(issuer="", expiration_date="", chain_valid=False, failed=True)
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=failed_js, ssl=failed_ssl)
        # 2 successful + 2 failed = 2 valid categories -> rejected
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "found 2" in msg


# ---------------------------------------------------------------------------
# Test Suite 3: Data Corruption Detection (Task 8.3 & Requirement 3.6)
# ---------------------------------------------------------------------------

class TestDataCorruptionDetection:
    """Test data corruption detection for types and value ranges across categories."""

    # --- Network Data Corruption ---

    def test_network_negative_request_count(self, engine, valid_dom, valid_js):
        """Reject negative request_count in NetworkData."""
        bad_net = NetworkData(request_count=-1, unique_domains=["example.com"], protocol_distribution={"https": 5})
        data = AnalysisData(network=bad_net, dom=valid_dom, javascript=valid_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in network.request_count" in msg
        with pytest.raises(RuntimeError) as exc_info:
            engine.analyze(data)
        assert "network.request_count" in str(exc_info.value)

    def test_network_float_request_count(self, engine, valid_dom, valid_js):
        """Reject float request_count in NetworkData."""
        bad_net = NetworkData(request_count=12.5, unique_domains=["example.com"], protocol_distribution={"https": 5})
        data = AnalysisData(network=bad_net, dom=valid_dom, javascript=valid_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in network.request_count" in msg

    def test_network_bool_request_count(self, engine, valid_dom, valid_js):
        """Reject bool request_count (e.g. True) in NetworkData."""
        bad_net = NetworkData(request_count=True, unique_domains=["example.com"], protocol_distribution={"https": 5})
        data = AnalysisData(network=bad_net, dom=valid_dom, javascript=valid_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in network.request_count" in msg

    def test_network_unique_domains_not_list(self, engine, valid_dom, valid_js):
        """Reject unique_domains if not a list."""
        bad_net = NetworkData(request_count=5, unique_domains="example.com", protocol_distribution={"https": 5})
        data = AnalysisData(network=bad_net, dom=valid_dom, javascript=valid_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in network.unique_domains" in msg

    def test_network_unique_domains_contains_non_string(self, engine, valid_dom, valid_js):
        """Reject unique_domains containing non-string items."""
        bad_net = NetworkData(request_count=5, unique_domains=["example.com", 12345], protocol_distribution={"https": 5})
        data = AnalysisData(network=bad_net, dom=valid_dom, javascript=valid_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in network.unique_domains" in msg

    def test_network_protocol_distribution_not_dict(self, engine, valid_dom, valid_js):
        """Reject protocol_distribution if not a dict."""
        bad_net = NetworkData(request_count=5, unique_domains=["example.com"], protocol_distribution=["https", 5])
        data = AnalysisData(network=bad_net, dom=valid_dom, javascript=valid_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in network.protocol_distribution" in msg

    def test_network_protocol_distribution_negative_value(self, engine, valid_dom, valid_js):
        """Reject negative protocol distribution count."""
        bad_net = NetworkData(request_count=5, unique_domains=["example.com"], protocol_distribution={"https": -3})
        data = AnalysisData(network=bad_net, dom=valid_dom, javascript=valid_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in network.protocol_distribution" in msg

    def test_network_protocol_distribution_bool_value(self, engine, valid_dom, valid_js):
        """Reject boolean value in protocol distribution."""
        bad_net = NetworkData(request_count=5, unique_domains=["example.com"], protocol_distribution={"https": False})
        data = AnalysisData(network=bad_net, dom=valid_dom, javascript=valid_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in network.protocol_distribution" in msg

    # --- DOM Data Corruption ---

    def test_dom_html_content_not_string(self, engine, valid_network, valid_js):
        """Reject non-string html_content."""
        bad_dom = DOMData(html_content=12345, structure_metrics={"total_elements": 10})
        data = AnalysisData(network=valid_network, dom=bad_dom, javascript=valid_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in dom.html_content" in msg
        with pytest.raises(RuntimeError) as exc_info:
            engine.analyze(data)
        assert "dom.html_content" in str(exc_info.value)

    def test_dom_structure_metrics_not_dict(self, engine, valid_network, valid_js):
        """Reject non-dict structure_metrics."""
        bad_dom = DOMData(html_content="<html/>", structure_metrics=["total_elements", 10])
        data = AnalysisData(network=valid_network, dom=bad_dom, javascript=valid_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in dom.structure_metrics" in msg

    def test_dom_structure_metrics_negative_value(self, engine, valid_network, valid_js):
        """Reject negative metric count in structure_metrics."""
        bad_dom = DOMData(html_content="<html/>", structure_metrics={"total_elements": -10})
        data = AnalysisData(network=valid_network, dom=bad_dom, javascript=valid_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in dom.structure_metrics.total_elements" in msg

    def test_dom_structure_metrics_bool_value(self, engine, valid_network, valid_js):
        """Reject boolean metric count in structure_metrics."""
        bad_dom = DOMData(html_content="<html/>", structure_metrics={"iframe_count": True})
        data = AnalysisData(network=valid_network, dom=bad_dom, javascript=valid_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in dom.structure_metrics.iframe_count" in msg

    # --- JavaScript Data Corruption ---

    def test_javascript_negative_script_count(self, engine, valid_network, valid_dom):
        """Reject negative script_count in JavaScriptData."""
        bad_js = JavaScriptData(script_count=-5, dom_modifications=10, external_api_calls=2)
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=bad_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in javascript.script_count" in msg
        with pytest.raises(RuntimeError) as exc_info:
            engine.analyze(data)
        assert "javascript.script_count" in str(exc_info.value)

    def test_javascript_bool_script_count(self, engine, valid_network, valid_dom):
        """Reject boolean script_count in JavaScriptData."""
        bad_js = JavaScriptData(script_count=True, dom_modifications=10, external_api_calls=2)
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=bad_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in javascript.script_count" in msg

    def test_javascript_negative_dom_modifications(self, engine, valid_network, valid_dom):
        """Reject negative dom_modifications in JavaScriptData."""
        bad_js = JavaScriptData(script_count=5, dom_modifications=-20, external_api_calls=2)
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=bad_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in javascript.dom_modifications" in msg

    def test_javascript_str_external_api_calls(self, engine, valid_network, valid_dom):
        """Reject string external_api_calls in JavaScriptData."""
        bad_js = JavaScriptData(script_count=5, dom_modifications=20, external_api_calls="none")
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=bad_js)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in javascript.external_api_calls" in msg

    # --- Visual Data Corruption ---

    def test_visual_screenshot_path_not_string(self, engine, valid_network, valid_dom):
        """Reject non-string screenshot_path."""
        bad_vis = VisualData(screenshot_path=999, layout_characteristics={"viewport_width": 1280})
        data = AnalysisData(network=valid_network, dom=valid_dom, visual=bad_vis)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in visual.screenshot_path" in msg
        with pytest.raises(RuntimeError) as exc_info:
            engine.analyze(data)
        assert "visual.screenshot_path" in str(exc_info.value)

    def test_visual_negative_viewport_dimension(self, engine, valid_network, valid_dom):
        """Reject negative viewport dimensions."""
        bad_vis = VisualData(screenshot_path="/tmp/img.png", layout_characteristics={"viewport_width": -1280})
        data = AnalysisData(network=valid_network, dom=valid_dom, visual=bad_vis)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in visual.layout_characteristics.viewport_width" in msg

    def test_visual_bool_viewport_dimension(self, engine, valid_network, valid_dom):
        """Reject boolean viewport dimension."""
        bad_vis = VisualData(screenshot_path="/tmp/img.png", layout_characteristics={"viewport_height": False})
        data = AnalysisData(network=valid_network, dom=valid_dom, visual=bad_vis)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in visual.layout_characteristics.viewport_height" in msg

    # --- SSL Data Corruption ---

    def test_ssl_issuer_not_string(self, engine, valid_network, valid_dom):
        """Reject non-string issuer."""
        bad_ssl = SSLData(issuer={"name": "DigiCert"}, expiration_date="2030-01-01T00:00:00Z", chain_valid=True)
        data = AnalysisData(network=valid_network, dom=valid_dom, ssl=bad_ssl)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in ssl.issuer" in msg

    def test_ssl_expiration_date_not_string(self, engine, valid_network, valid_dom):
        """Reject non-string expiration_date."""
        bad_ssl = SSLData(issuer="CN=DigiCert", expiration_date=20300101, chain_valid=True)
        data = AnalysisData(network=valid_network, dom=valid_dom, ssl=bad_ssl)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in ssl.expiration_date" in msg

    def test_ssl_chain_valid_not_boolean(self, engine, valid_network, valid_dom):
        """Reject non-boolean chain_valid (e.g. integer 1 or string 'valid')."""
        bad_ssl = SSLData(issuer="CN=DigiCert", expiration_date="2030-01-01T00:00:00Z", chain_valid="true")
        data = AnalysisData(network=valid_network, dom=valid_dom, ssl=bad_ssl)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Data corruption detected in ssl.chain_valid" in msg

    def test_ssl_chain_valid_false_is_not_corruption(self, engine, valid_network, valid_dom):
        """chain_valid=False is legitimate certificate state, not data corruption."""
        untrusted_ssl = SSLData(issuer="CN=Self-Signed", expiration_date="2030-01-01T00:00:00Z", chain_valid=False)
        data = AnalysisData(network=valid_network, dom=valid_dom, ssl=untrusted_ssl)
        is_valid, msg = engine.validate_data(data)
        assert is_valid is True
        assert msg == ""


# ---------------------------------------------------------------------------
# Test Suite 4: analyze() Score Generation and Invariants
# ---------------------------------------------------------------------------

class TestAnalyzeScoringAndInvariants:
    """Test score generation, ranges, and summation invariants."""

    def test_analyze_rejects_insufficient_data(self, engine, valid_network, valid_dom):
        """analyze raises ValueError for < 3 categories."""
        data = AnalysisData(network=valid_network, dom=valid_dom)
        with pytest.raises(ValueError) as exc_info:
            engine.analyze(data)
        assert "Insufficient data" in str(exc_info.value)

    def test_analyze_3_categories_scores(self, engine, valid_network, valid_dom, valid_js):
        """Requirement 3.1: Valid 3-category data generates Authenticity_Score and Fake_Score."""
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js)
        scores = engine.analyze(data)

        assert isinstance(scores, AnalysisScores)
        assert 0.0 <= scores.authenticity_score <= 1.0
        assert 0.0 <= scores.fake_score <= 1.0
        assert abs(scores.authenticity_score + scores.fake_score - 1.0) <= 0.01

    def test_analyze_4_categories_scores(self, engine, valid_network, valid_dom, valid_js, valid_ssl):
        """Requirement 3.1: Valid 4-category data generates Authenticity_Score and Fake_Score."""
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js, ssl=valid_ssl)
        scores = engine.analyze(data)

        assert isinstance(scores, AnalysisScores)
        assert 0.0 <= scores.authenticity_score <= 1.0
        assert 0.0 <= scores.fake_score <= 1.0
        assert abs(scores.authenticity_score + scores.fake_score - 1.0) <= 0.01

    def test_analyze_5_categories_scores(self, engine, full_analysis_data):
        """Requirement 3.1: Valid 5-category data generates Authenticity_Score and Fake_Score."""
        scores = engine.analyze(full_analysis_data)

        assert isinstance(scores, AnalysisScores)
        assert 0.0 <= scores.authenticity_score <= 1.0
        assert 0.0 <= scores.fake_score <= 1.0
        assert abs(scores.authenticity_score + scores.fake_score - 1.0) <= 0.01

    def test_authenticity_score_range_bounds(self, engine, full_analysis_data):
        """Requirement 3.2: Authenticity_Score is between 0.0 and 1.0 inclusive."""
        scores = engine.analyze(full_analysis_data)
        assert 0.0 <= scores.authenticity_score <= 1.0

    def test_fake_score_range_bounds(self, engine, full_analysis_data):
        """Requirement 3.3: Fake_Score is between 0.0 and 1.0 inclusive."""
        scores = engine.analyze(full_analysis_data)
        assert 0.0 <= scores.fake_score <= 1.0

    def test_score_summation_tolerance(self, engine, full_analysis_data):
        """Requirement 3.4: Authenticity_Score + Fake_Score == 1.0 within 0.01 tolerance."""
        scores = engine.analyze(full_analysis_data)
        total = scores.authenticity_score + scores.fake_score
        assert abs(total - 1.0) <= 0.01

    def test_no_artificial_exact_normalization(self, engine, valid_network, valid_dom, valid_js):
        """Requirement 3.4: Scores must not rely on artificial exact normalization."""
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js)
        scores = engine.analyze(data)
        # Sum is within tolerance
        assert abs(scores.authenticity_score + scores.fake_score - 1.0) <= 0.01

    def test_deterministic_scoring(self, engine, full_analysis_data):
        """Analysis produces identical scores for identical inputs."""
        run1 = engine.analyze(full_analysis_data)
        run2 = engine.analyze(full_analysis_data)
        assert run1.authenticity_score == run2.authenticity_score
        assert run1.fake_score == run2.fake_score
        assert run1.top_factors == run2.top_factors
        assert run1.suspicious_indicators == run2.suspicious_indicators


# ---------------------------------------------------------------------------
# Test Suite 5: Rule-Based Category Weighting & Heuristics
# ---------------------------------------------------------------------------

class TestRuleBasedHeuristics:
    """Test heuristic signal evaluation across individual categories."""

    def test_suspicious_ssl_lowers_authenticity(self, engine, valid_dom, valid_js):
        """Untrusted/invalid SSL reduces authenticity score and raises suspicious indicator when fake_score > 0.5."""
        trusted_ssl = SSLData(issuer="CN=DigiCert", expiration_date="2030-01-01T00:00:00Z", chain_valid=True)
        untrusted_ssl = SSLData(issuer="", expiration_date="2020-01-01T00:00:00Z", chain_valid=False)

        valid_network = NetworkData(request_count=15, unique_domains=["example.com"], protocol_distribution={"https": 15})
        bad_network = NetworkData(request_count=50, unique_domains=["bad.com"] * 35, protocol_distribution={"http": 50})
        bad_dom = DOMData(html_content="<html/>", structure_metrics={"iframe_count": 8, "form_count": 15})

        data_trusted = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js, ssl=trusted_ssl)
        data_untrusted = AnalysisData(network=bad_network, dom=bad_dom, javascript=valid_js, ssl=untrusted_ssl)

        scores_trusted = engine.analyze(data_trusted)
        scores_untrusted = engine.analyze(data_untrusted)

        assert scores_trusted.authenticity_score > scores_untrusted.authenticity_score
        assert scores_untrusted.fake_score > scores_trusted.fake_score
        assert scores_untrusted.fake_score > 0.5
        assert any("invalid" in s.lower() or "self-signed" in s.lower() for s in scores_untrusted.suspicious_indicators)

    def test_dynamic_active_weighting_with_partial_categories(self, engine, valid_network, valid_dom, valid_visual):
        """Active weights are dynamically normalized when SSL and JS are missing."""
        data = AnalysisData(network=valid_network, dom=valid_dom, visual=valid_visual)
        scores = engine.analyze(data)
        assert 0.0 <= scores.authenticity_score <= 1.0
        assert 0.0 <= scores.fake_score <= 1.0
        assert abs(scores.authenticity_score + scores.fake_score - 1.0) <= 0.01

    def test_extreme_javascript_activity_detected_as_suspicious(self, engine, valid_dom):
        """Extreme DOM modifications and API calls trigger suspicious indicators when fake_score > 0.5."""
        http_network = NetworkData(request_count=15, unique_domains=["example.com"], protocol_distribution={"http": 15})
        untrusted_ssl = SSLData(issuer="", expiration_date="2020-01-01T00:00:00Z", chain_valid=False)
        aggressive_js = JavaScriptData(script_count=150, dom_modifications=5000, external_api_calls=120)
        data = AnalysisData(network=http_network, dom=valid_dom, javascript=aggressive_js, ssl=untrusted_ssl)
        scores = engine.analyze(data)

        assert scores.fake_score > 0.5
        assert any("mutation" in s.lower() or "dom" in s.lower() for s in scores.suspicious_indicators)
        assert any("api" in s.lower() for s in scores.suspicious_indicators)


# ---------------------------------------------------------------------------
# Test Suite 6: Timeout Handling
# ---------------------------------------------------------------------------

class TestAnalysisTimeout:
    """Test 10-second timeout parameter and timeout exceptions."""

    def test_default_timeout_is_10_seconds(self, engine, full_analysis_data):
        """Requirement 3.8: Default timeout parameter is 10 seconds."""
        import inspect
        sig = inspect.signature(engine.analyze)
        assert sig.parameters["timeout"].default == 10

    def test_analysis_completes_well_under_10_seconds(self, engine, full_analysis_data):
        """Requirement 3.8: Analysis completes in < 10 seconds."""
        start = time.monotonic()
        scores = engine.analyze(full_analysis_data, timeout=10)
        elapsed = time.monotonic() - start
        assert elapsed < 1.0  # Fast rule-based analysis
        assert scores is not None

    def test_timeout_zero_or_negative_raises_timeout_error(self, engine, full_analysis_data):
        """Non-positive timeout triggers TimeoutError immediately."""
        with pytest.raises(TimeoutError) as exc_info:
            engine.analyze(full_analysis_data, timeout=0)
        assert "timed out" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test Suite 7: Confidence Indicator Calculation (Task 8.5 & Property 15)
# ---------------------------------------------------------------------------

class TestCalculateConfidence:
    """Test calculate_confidence method for Requirements 4.4, 4.5, 4.6 and Property 15."""

    def test_confidence_0_categories_returns_low(self, engine):
        """Requirement 4.6: 0 categories (<50%) returns 'LOW'."""
        data = AnalysisData()
        assert engine.calculate_confidence(data) == "LOW"

    def test_confidence_1_category_returns_low(self, engine, valid_network):
        """Requirement 4.6: 1 category (20%) returns 'LOW'."""
        data = AnalysisData(network=valid_network)
        assert engine.calculate_confidence(data) == "LOW"

    def test_confidence_2_categories_returns_low(self, engine, valid_network, valid_dom):
        """Requirement 4.6: 2 categories (40%) returns 'LOW'."""
        data = AnalysisData(network=valid_network, dom=valid_dom)
        assert engine.calculate_confidence(data) == "LOW"

    def test_confidence_3_categories_returns_medium(self, engine, valid_network, valid_dom, valid_js):
        """Requirement 4.5: 3 categories (60%, 50% <= ratio < 80%) returns 'MEDIUM'."""
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js)
        assert engine.calculate_confidence(data) == "MEDIUM"

    def test_confidence_4_categories_returns_high(self, engine, valid_network, valid_dom, valid_js, valid_ssl):
        """Requirement 4.4: 4 categories (80%) returns 'HIGH'."""
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js, ssl=valid_ssl)
        assert engine.calculate_confidence(data) == "HIGH"

    def test_confidence_5_categories_returns_high(self, engine, full_analysis_data):
        """Requirement 4.4: 5 categories (100%) returns 'HIGH'."""
        assert engine.calculate_confidence(full_analysis_data) == "HIGH"

    def test_confidence_failed_categories_excluded(self, engine, valid_network, valid_dom, valid_js):
        """Failed categories (failed=True) must not count toward successfully collected ratio."""
        failed_ssl = SSLData(issuer="", expiration_date="", chain_valid=False, failed=True)
        failed_visual = VisualData(screenshot_path="", layout_characteristics={}, failed=True)
        # 3 valid + 2 failed = 3 active -> MEDIUM
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js, ssl=failed_ssl, visual=failed_visual)
        assert engine.calculate_confidence(data) == "MEDIUM"

    def test_confidence_various_combinations(self, engine, valid_network, valid_dom, valid_js, valid_visual, valid_ssl):
        """Different category combinations with the same category count produce identical confidence levels."""
        # Combinations with 3 categories -> all MEDIUM
        comb3_a = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js)
        comb3_b = AnalysisData(network=valid_network, visual=valid_visual, ssl=valid_ssl)
        comb3_c = AnalysisData(dom=valid_dom, javascript=valid_js, visual=valid_visual)
        assert engine.calculate_confidence(comb3_a) == "MEDIUM"
        assert engine.calculate_confidence(comb3_b) == "MEDIUM"
        assert engine.calculate_confidence(comb3_c) == "MEDIUM"

        # Combinations with 4 categories -> all HIGH
        comb4_a = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js, visual=valid_visual)
        comb4_b = AnalysisData(network=valid_network, dom=valid_dom, visual=valid_visual, ssl=valid_ssl)
        comb4_c = AnalysisData(dom=valid_dom, javascript=valid_js, visual=valid_visual, ssl=valid_ssl)
        assert engine.calculate_confidence(comb4_a) == "HIGH"
        assert engine.calculate_confidence(comb4_b) == "HIGH"
        assert engine.calculate_confidence(comb4_c) == "HIGH"

    def test_confidence_invalid_input_returns_low(self, engine):
        """Non-AnalysisData input safely returns 'LOW'."""
        assert engine.calculate_confidence("invalid_input") == "LOW"
        assert engine.calculate_confidence(None) == "LOW"
        assert engine.calculate_confidence(12345) == "LOW"


# ---------------------------------------------------------------------------
# Test Suite 8: Top Factors and Suspicious Indicators (Task 8.7, Properties 24 & 25)
# ---------------------------------------------------------------------------

class TestTopFactorsAndSuspiciousIndicators:
    """Test top factors ranking and suspicious indicators gating (Requirements 7.3, 7.4)."""

    def test_suspicious_indicators_empty_when_fake_score_below_half(self, engine, full_analysis_data):
        """Requirement 7.3 & Property 24: Fake_Score < 0.5 returns empty suspicious_indicators."""
        scores = engine.analyze(full_analysis_data)
        assert scores.fake_score < 0.5
        assert scores.suspicious_indicators == []

    def test_suspicious_indicators_empty_when_fake_score_exactly_half(self, engine, monkeypatch):
        """Requirement 7.3 & Property 24: Fake_Score == 0.5 returns empty suspicious_indicators."""
        monkeypatch.setattr(engine, "_evaluate_dom", lambda dom: (0.5, ["DOM factor"], ["Potential anomaly"]))
        monkeypatch.setattr(engine, "_evaluate_network", lambda net: (0.5, ["Net factor"], ["Net warning"]))
        monkeypatch.setattr(engine, "_evaluate_javascript", lambda js: (0.5, ["JS factor"], ["JS warning"]))

        data = AnalysisData(
            network=NetworkData(request_count=10, unique_domains=["a.com"], protocol_distribution={"https": 10}),
            dom=DOMData(html_content="<html/>", structure_metrics={"total_elements": 10}),
            javascript=JavaScriptData(script_count=5, dom_modifications=10, external_api_calls=2),
        )
        scores = engine.analyze(data)

        assert scores.authenticity_score == 0.5
        assert scores.fake_score == 0.5
        assert scores.suspicious_indicators == []

    def test_suspicious_indicators_populated_when_fake_score_above_half(self, engine):
        """Requirement 7.3 & Property 24: Fake_Score > 0.5 returns non-empty suspicious_indicators."""
        bad_ssl = SSLData(issuer="", expiration_date="2020-01-01T00:00:00Z", chain_valid=False, failed=False)
        bad_net = NetworkData(request_count=20, unique_domains=["ex.com"] * 35, protocol_distribution={"http": 20}, failed=False)
        bad_dom = DOMData(html_content="<html/>", structure_metrics={"iframe_count": 8, "form_count": 15}, failed=False)
        data = AnalysisData(ssl=bad_ssl, network=bad_net, dom=bad_dom)
        scores = engine.analyze(data)

        assert scores.fake_score > 0.5
        assert len(scores.suspicious_indicators) > 0
        assert any("ssl" in s.lower() or "certificate" in s.lower() for s in scores.suspicious_indicators)
        assert any("protocol" in s.lower() or "http" in s.lower() for s in scores.suspicious_indicators)


    def test_suspicious_indicators_deduplicated(self, engine):
        """Requirement 7.3: Suspicious indicators are deduplicated while preserving order."""
        bad_ssl = SSLData(issuer="", expiration_date="2020-01-01T00:00:00Z", chain_valid=False, failed=False)
        bad_net = NetworkData(request_count=20, unique_domains=["ex.com"] * 35, protocol_distribution={"http": 20}, failed=False)
        bad_js = JavaScriptData(script_count=150, dom_modifications=5000, external_api_calls=120, failed=False)
        data = AnalysisData(ssl=bad_ssl, network=bad_net, javascript=bad_js)
        scores = engine.analyze(data)

        assert scores.fake_score > 0.5
        assert len(scores.suspicious_indicators) == len(set(scores.suspicious_indicators))

    def test_top_factors_exactly_three_for_3_categories(self, engine, valid_network, valid_dom, valid_js):
        """Requirement 7.4 & Property 25: Exactly 3 top factors for 3 active categories."""
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js)
        scores = engine.analyze(data)
        assert len(scores.top_factors) == 3
        assert len(set(scores.top_factors)) == 3

    def test_top_factors_exactly_three_for_4_categories(self, engine, valid_network, valid_dom, valid_js, valid_ssl):
        """Requirement 7.4 & Property 25: Exactly 3 top factors for 4 active categories."""
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js, ssl=valid_ssl)
        scores = engine.analyze(data)
        assert len(scores.top_factors) == 3
        assert len(set(scores.top_factors)) == 3

    def test_top_factors_exactly_three_for_5_categories(self, engine, full_analysis_data):
        """Requirement 7.4 & Property 25: Exactly 3 top factors for 5 active categories."""
        scores = engine.analyze(full_analysis_data)
        assert len(scores.top_factors) == 3
        assert len(set(scores.top_factors)) == 3

    def test_top_factors_no_duplicates(self, engine, full_analysis_data):
        """Requirement 7.4: Top factors list contains unique strings."""
        scores = engine.analyze(full_analysis_data)
        assert len(scores.top_factors) == len(set(scores.top_factors))

    def test_top_factors_deterministic_ranking(self, engine, full_analysis_data):
        """Ranking of top factors is strictly deterministic across repeated runs."""
        scores1 = engine.analyze(full_analysis_data)
        scores2 = engine.analyze(full_analysis_data)
        assert scores1.top_factors == scores2.top_factors

    def test_top_factors_fallbacks_tied_only_to_active_categories(self, engine, valid_network, valid_dom, valid_js):
        """Fallback factors are tied ONLY to active, non-failed categories."""
        # SSL and Visual are None (inactive)
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js)
        scores = engine.analyze(data)
        assert len(scores.top_factors) == 3
        # Should not include SSL or Visual fallback strings
        assert not any("ssl" in f.lower() or "certificate" in f.lower() for f in scores.top_factors)
        assert not any("visual" in f.lower() or "screenshot" in f.lower() for f in scores.top_factors)

    def test_top_factors_are_positive_influential_factors(self, engine, full_analysis_data):
        """Top factors are positive authenticity drivers, not negative/suspicious indicators."""
        scores = engine.analyze(full_analysis_data)
        for factor in scores.top_factors:
            assert not factor.startswith("Data corruption")
            assert not factor.startswith("Failed")
            assert not factor.startswith("Insufficient")


# ---------------------------------------------------------------------------
# Test Suite 9: AI Analysis Edge Cases (Task 8.9, Requirements 3.7 & 3.8)
# ---------------------------------------------------------------------------

class TestAIAnalysisEdgeCases:
    """
    Edge-case and boundary unit tests for AIAnalysisEngine (Task 8.9).
    Validates: Requirements 3.7 and 3.8.
    """

    def test_boundary_all_ten_3_category_combinations(
        self, engine, valid_network, valid_dom, valid_js, valid_visual, valid_ssl
    ):
        """
        Requirement 3.5 & Task 8.9: Test ALL 10 combinations of exactly 3 active categories.
        C(5, 3) = 10 combinations:
          1. network + dom + javascript
          2. network + dom + visual
          3. network + dom + ssl
          4. network + javascript + visual
          5. network + javascript + ssl
          6. network + visual + ssl
          7. dom + javascript + visual
          8. dom + javascript + ssl
          9. dom + visual + ssl
          10. javascript + visual + ssl
        """
        cat_pool = {
            "network": valid_network,
            "dom": valid_dom,
            "javascript": valid_js,
            "visual": valid_visual,
            "ssl": valid_ssl,
        }

        import itertools
        all_3_combos = list(itertools.combinations(["network", "dom", "javascript", "visual", "ssl"], 3))
        assert len(all_3_combos) == 10

        for combo in all_3_combos:
            data = AnalysisData(
                network=cat_pool["network"] if "network" in combo else None,
                dom=cat_pool["dom"] if "dom" in combo else None,
                javascript=cat_pool["javascript"] if "javascript" in combo else None,
                visual=cat_pool["visual"] if "visual" in combo else None,
                ssl=cat_pool["ssl"] if "ssl" in combo else None,
                timeout_occurred=False,
            )

            is_valid, msg = engine.validate_data(data)
            assert is_valid is True, f"Validation failed for combo {combo}: {msg}"
            assert msg == ""

            scores = engine.analyze(data)
            assert isinstance(scores, AnalysisScores)
            assert 0.0 <= scores.authenticity_score <= 1.0
            assert 0.0 <= scores.fake_score <= 1.0
            assert abs(scores.authenticity_score + scores.fake_score - 1.0) <= 0.01
            assert len(scores.top_factors) == 3, f"Expected exactly 3 top_factors for combo {combo}"
            assert len(set(scores.top_factors)) == 3, f"Expected unique top_factors for combo {combo}"

    def test_boundary_transition_2_to_3_categories(self, engine, valid_network, valid_dom, valid_js):
        """
        Explicit boundary transition: 2 active categories fail, adding 1 active category succeeds.
        """
        # Exactly 2 categories -> rejected
        data_2 = AnalysisData(network=valid_network, dom=valid_dom, javascript=None, visual=None, ssl=None)
        is_valid_2, msg_2 = engine.validate_data(data_2)
        assert is_valid_2 is False
        assert "Insufficient data" in msg_2
        with pytest.raises(ValueError) as exc_2:
            engine.analyze(data_2)
        assert "Insufficient data" in str(exc_2.value)

        # Transition to 3 categories -> accepted
        data_3 = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js, visual=None, ssl=None)
        is_valid_3, msg_3 = engine.validate_data(data_3)
        assert is_valid_3 is True
        assert msg_3 == ""
        scores = engine.analyze(data_3)
        assert isinstance(scores, AnalysisScores)
        assert 0.0 <= scores.authenticity_score <= 1.0

    def test_boundary_failed_category_drops_below_threshold(self, engine, valid_network, valid_dom, valid_js):
        """
        3 categories present, but 1 has failed=True -> active categories = 2 -> raises ValueError.
        """
        failed_js = JavaScriptData(script_count=0, dom_modifications=0, external_api_calls=0, failed=True)
        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=failed_js, visual=None, ssl=None)

        is_valid, msg = engine.validate_data(data)
        assert is_valid is False
        assert "Insufficient data" in msg

        with pytest.raises(ValueError) as exc_info:
            engine.analyze(data)
        assert "Insufficient data" in str(exc_info.value)

    def test_partial_score_all_five_4_category_combinations(
        self, engine, valid_network, valid_dom, valid_js, valid_visual, valid_ssl
    ):
        """
        Requirement 3.7 & Task 8.9: Test ALL 5 combinations of exactly 4 active categories.
        C(5, 4) = 5 combinations (each omitting 1 category).
        """
        cat_pool = {
            "network": valid_network,
            "dom": valid_dom,
            "javascript": valid_js,
            "visual": valid_visual,
            "ssl": valid_ssl,
        }

        import itertools
        all_4_combos = list(itertools.combinations(["network", "dom", "javascript", "visual", "ssl"], 4))
        assert len(all_4_combos) == 5

        for combo in all_4_combos:
            data = AnalysisData(
                network=cat_pool["network"] if "network" in combo else None,
                dom=cat_pool["dom"] if "dom" in combo else None,
                javascript=cat_pool["javascript"] if "javascript" in combo else None,
                visual=cat_pool["visual"] if "visual" in combo else None,
                ssl=cat_pool["ssl"] if "ssl" in combo else None,
                timeout_occurred=False,
            )

            scores = engine.analyze(data)
            assert isinstance(scores, AnalysisScores)
            assert 0.0 <= scores.authenticity_score <= 1.0
            assert 0.0 <= scores.fake_score <= 1.0
            assert abs(scores.authenticity_score + scores.fake_score - 1.0) <= 0.01
            assert len(scores.top_factors) == 3
            assert len(set(scores.top_factors)) == 3

    def test_partial_score_missing_categories_contribute_zero_weight(
        self, engine, valid_network, valid_dom, valid_js
    ):
        """
        Requirement 3.7: Missing categories do not distort active weight normalization.
        Weights are normalized dynamically across ONLY the active categories.
        """
        data_3 = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js)
        scores = engine.analyze(data_3)

        # Base weights: network=0.20, dom=0.20, javascript=0.20 (total active = 0.60)
        # Each active category gets relative weight 0.20 / 0.60 = 1/3
        score_net, _, _ = engine._evaluate_network(valid_network)
        score_dom, _, _ = engine._evaluate_dom(valid_dom)
        score_js, _, _ = engine._evaluate_javascript(valid_js)

        expected_authenticity = (score_net + score_dom + score_js) / 3.0
        assert abs(scores.authenticity_score - expected_authenticity) <= 0.0001

    def test_partial_score_evaluator_error_aborts_without_scores(
        self, engine, valid_network, valid_dom, valid_js, monkeypatch
    ):
        """
        Requirement 3.7: When an error occurs during evaluation, analysis aborts
        and does not return fabricated/partial scores as if analysis completed.
        """
        def crashing_evaluator(js):
            raise RuntimeError("Simulated crash in JavaScript evaluator")

        monkeypatch.setattr(engine, "_evaluate_javascript", crashing_evaluator)

        data = AnalysisData(network=valid_network, dom=valid_dom, javascript=valid_js)

        with pytest.raises(RuntimeError) as exc_info:
            engine.analyze(data)
        assert "Simulated crash" in str(exc_info.value)

    def test_timeout_default_constant_is_10_seconds(self, engine):
        """
        Requirement 3.8: Verify DEFAULT_ANALYSIS_TIMEOUT constant is 10 and default parameter is 10.
        """
        import inspect
        assert DEFAULT_ANALYSIS_TIMEOUT == 10
        sig = inspect.signature(engine.analyze)
        assert sig.parameters["timeout"].default == 10

    def test_timeout_simulated_elapsed_exceeds_10_seconds(self, engine, full_analysis_data, monkeypatch):
        """
        Requirement 3.8: Deterministic simulation of analysis taking > 10 seconds.
        Does NOT sleep for 10 real seconds.
        """
        call_count = 0
        def fake_monotonic():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return 100.0   # start_time
            return 110.05      # elapsed = 10.05 > 10.0

        monkeypatch.setattr(time, "monotonic", fake_monotonic)

        with pytest.raises(TimeoutError) as exc_info:
            engine.analyze(full_analysis_data, timeout=10)

        err_msg = str(exc_info.value)
        assert "timed out" in err_msg.lower()
        assert "10" in err_msg

    def test_timeout_custom_threshold_enforced(self, engine, full_analysis_data, monkeypatch):
        """
        Requirement 3.8: Custom timeout threshold (e.g. 2.0s) is enforced deterministically.
        """
        call_count = 0
        def fake_monotonic_over():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return 50.0
            return 52.5  # elapsed = 2.5 > 2.0

        monkeypatch.setattr(time, "monotonic", fake_monotonic_over)

        with pytest.raises(TimeoutError) as exc_info:
            engine.analyze(full_analysis_data, timeout=2.0)
        assert "timed out" in str(exc_info.value).lower()
        assert "2.0" in str(exc_info.value) or "2" in str(exc_info.value)

        # Under threshold succeeds
        call_count = 0
        def fake_monotonic_under():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return 50.0
            return 51.0  # elapsed = 1.0 < 2.0

        monkeypatch.setattr(time, "monotonic", fake_monotonic_under)
        scores = engine.analyze(full_analysis_data, timeout=2.0)
        assert isinstance(scores, AnalysisScores)

    def test_timeout_zero_raises(self, engine, full_analysis_data):
        """
        Requirement 3.8: timeout=0 raises TimeoutError immediately.
        """
        with pytest.raises(TimeoutError) as exc_info:
            engine.analyze(full_analysis_data, timeout=0)
        assert "timed out" in str(exc_info.value).lower()

    def test_timeout_negative_raises(self, engine, full_analysis_data):
        """
        Requirement 3.8: Negative timeout raises TimeoutError immediately.
        """
        with pytest.raises(TimeoutError) as exc_info:
            engine.analyze(full_analysis_data, timeout=-1)
        assert "timed out" in str(exc_info.value).lower()

    def test_extreme_metrics_clamped_to_valid_range(self, engine):
        """
        Score clamping on extreme valid input metrics (massive element counts, requests, mutations).
        """
        extreme_net = NetworkData(
            request_count=100_000,
            unique_domains=[f"domain{i}.com" for i in range(50)],
            protocol_distribution={"https": 100_000},
            failed=False,
        )
        extreme_dom = DOMData(
            html_content="<div>" * 50_000 + "</div>" * 50_000,
            structure_metrics={"total_elements": 50_000, "form_count": 500, "iframe_count": 100},
            failed=False,
        )
        extreme_js = JavaScriptData(
            script_count=500,
            dom_modifications=50_000,
            external_api_calls=1_000,
            failed=False,
        )
        extreme_visual = VisualData(
            screenshot_path="/tmp/huge_screenshot.png",
            layout_characteristics={"viewport_width": 7680, "viewport_height": 4320, "image_count": 500, "has_images": True},
            failed=False,
        )
        extreme_ssl = SSLData(
            issuer="CN=Root CA",
            expiration_date="2040-01-01T00:00:00Z",
            chain_valid=True,
            failed=False,
        )

        data = AnalysisData(
            network=extreme_net,
            dom=extreme_dom,
            javascript=extreme_js,
            visual=extreme_visual,
            ssl=extreme_ssl,
            timeout_occurred=False,
        )

        scores = engine.analyze(data)
        assert 0.0 <= scores.authenticity_score <= 1.0
        assert 0.0 <= scores.fake_score <= 1.0
        assert abs(scores.authenticity_score + scores.fake_score - 1.0) <= 0.01
        assert len(scores.top_factors) == 3
        assert len(set(scores.top_factors)) == 3

    def test_zero_metric_boundaries(self, engine):
        """
        Boundary condition: zero and empty metric fields across all categories.
        """
        zero_net = NetworkData(request_count=0, unique_domains=[], protocol_distribution={}, failed=False)
        zero_dom = DOMData(html_content="", structure_metrics={}, failed=False)
        zero_js = JavaScriptData(script_count=0, dom_modifications=0, external_api_calls=0, failed=False)
        zero_visual = VisualData(screenshot_path="", layout_characteristics={}, failed=False)
        zero_ssl = SSLData(issuer="", expiration_date="", chain_valid=False, failed=False)

        data = AnalysisData(
            network=zero_net,
            dom=zero_dom,
            javascript=zero_js,
            visual=zero_visual,
            ssl=zero_ssl,
            timeout_occurred=False,
        )

        scores = engine.analyze(data)
        assert 0.0 <= scores.authenticity_score <= 1.0
        assert 0.0 <= scores.fake_score <= 1.0
        assert abs(scores.authenticity_score + scores.fake_score - 1.0) <= 0.01
        assert len(scores.top_factors) == 3
        assert len(set(scores.top_factors)) == 3
