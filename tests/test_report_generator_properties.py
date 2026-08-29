"""
Property-based tests for Report Generator formatting, structure, schema conformance, and partial report generation (Tasks 10.2, 10.4, & 10.6).

Properties covered:
- Property 13: Score Formatting
- Property 14: Result Structure Completeness
- Property 16: URL Inclusion in Results
- Property 22: Report Structure Generation
- Property 23: ISO 8601 Timestamp Formatting
- Property 26: JSON Schema Conformance
- Property 27: Partial Report Generation

Validates Requirements: 4.1, 4.2, 4.3, 4.7, 7.1, 7.2, 7.5, 7.6
"""

from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict

import jsonschema
import pytest
from hypothesis import given, settings, strategies as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.models import (
    AnalysisData,
    AnalysisResult,
    DOMData,
    JavaScriptData,
    NetworkData,
    SSLData,
    VisualData,
)
from src.report_generator import ReportGenerator


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def generator() -> ReportGenerator:
    """Shared ReportGenerator instance for property tests."""
    return ReportGenerator()


# ---------------------------------------------------------------------------
# Hypothesis Strategies
# ---------------------------------------------------------------------------

score_strategy = st.floats(
    min_value=0.0,
    max_value=1.0,
    allow_nan=False,
    allow_infinity=False,
)

url_strategy = st.from_regex(
    r"https?://[a-z0-9\-]+(\.[a-z0-9\-]+)*(:\d+)?(/.*)?",
    fullmatch=True,
)

timestamp_strategy = st.datetimes(
    min_value=datetime(2000, 1, 1),
    max_value=datetime(2099, 12, 31),
)

valid_network_strategy = st.builds(
    NetworkData,
    request_count=st.integers(min_value=0, max_value=500),
    unique_domains=st.lists(st.text(min_size=1, max_size=20), max_size=10),
    protocol_distribution=st.dictionaries(st.sampled_from(["http", "https", "ws", "wss"]), st.integers(0, 100), max_size=4),
    failed=st.booleans(),
)

valid_dom_strategy = st.builds(
    DOMData,
    html_content=st.text(max_size=200),
    structure_metrics=st.dictionaries(st.text(min_size=1, max_size=10), st.integers(0, 50), max_size=5),
    failed=st.booleans(),
)

valid_js_strategy = st.builds(
    JavaScriptData,
    script_count=st.integers(min_value=0, max_value=50),
    dom_modifications=st.integers(min_value=0, max_value=100),
    external_api_calls=st.integers(min_value=0, max_value=20),
    failed=st.booleans(),
)

valid_visual_strategy = st.builds(
    VisualData,
    screenshot_path=st.text(max_size=50),
    layout_characteristics=st.fixed_dictionaries({
        "viewport_width": st.integers(min_value=320, max_value=2560),
        "viewport_height": st.integers(min_value=240, max_value=1440),
        "has_images": st.booleans(),
    }),
    failed=st.booleans(),
)

valid_ssl_strategy = st.builds(
    SSLData,
    issuer=st.text(max_size=50),
    expiration_date=st.text(max_size=30),
    chain_valid=st.booleans(),
    failed=st.booleans(),
)

valid_analysis_data_strategy = st.builds(
    AnalysisData,
    network=st.one_of(st.none(), valid_network_strategy),
    dom=st.one_of(st.none(), valid_dom_strategy),
    javascript=st.one_of(st.none(), valid_js_strategy),
    visual=st.one_of(st.none(), valid_visual_strategy),
    ssl=st.one_of(st.none(), valid_ssl_strategy),
    timeout_occurred=st.booleans(),
)

valid_analysis_result_strategy = st.builds(
    AnalysisResult,
    authenticity_score=score_strategy,
    fake_score=score_strategy,
    confidence_indicator=st.sampled_from(["HIGH", "MEDIUM", "LOW"]),
    url=url_strategy,
    analysis_data=valid_analysis_data_strategy,
    timestamps=st.fixed_dictionaries({
        "analysis_start": st.sampled_from(["2026-08-28T20:30:00Z", "2026-01-01T00:00:00Z"]),
        "analysis_completion": st.sampled_from(["2026-08-28T20:30:05Z", "2026-01-01T00:00:10Z"]),
    }),
    top_factors=st.lists(st.text(min_size=1, max_size=30), max_size=3),
    suspicious_indicators=st.lists(st.text(min_size=1, max_size=30), max_size=5),
    error_message=st.one_of(st.none(), st.text(max_size=50)),
)


# ---------------------------------------------------------------------------
# Property 13: Score Formatting
# ---------------------------------------------------------------------------

class TestProperty13ScoreFormatting:
    """
    Property-based tests for Property 13: Score Formatting.
    Validates Requirements 4.1, 4.2.
    """

    @given(score=score_strategy)
    @settings(max_examples=100)
    def test_property_13_score_formatting_range_and_decimals(self, generator: ReportGenerator, score: float):
        """Property 13: format_score converts score [0.0, 1.0] to percentage with exactly 2 decimal places."""
        formatted = generator.format_score(score)

        assert isinstance(formatted, str)
        assert formatted.endswith("%")
        assert re.match(r"^\d+\.\d{2}%$", formatted) is not None

        # Verify mathematical equivalence to score * 100 rounded to 2 decimal places
        parsed_val = float(formatted[:-1])
        expected_val = round(score * 100, 2)
        assert math.isclose(parsed_val, expected_val, abs_tol=1e-2)

    @given(auth_score=score_strategy, fake_score=score_strategy)
    @settings(max_examples=100)
    def test_property_13_format_scores_dictionary(
        self, generator: ReportGenerator, auth_score: float, fake_score: float
    ):
        """Property 13: format_scores returns dict with both formatted scores matching percentage format."""
        scores = generator.format_scores(auth_score, fake_score)

        assert isinstance(scores, dict)
        assert "authenticity_score" in scores
        assert "fake_score" in scores
        assert scores["authenticity_score"] == f"{auth_score * 100:.2f}%"
        assert scores["fake_score"] == f"{fake_score * 100:.2f}%"


# ---------------------------------------------------------------------------
# Property 14: Result Structure Completeness
# ---------------------------------------------------------------------------

class TestProperty14ResultStructureCompleteness:
    """
    Property-based tests for Property 14: Result Structure Completeness.
    Validates Requirement 4.3.
    """

    @given(result=valid_analysis_result_strategy)
    @settings(max_examples=100)
    def test_property_14_result_contains_both_scores(self, generator: ReportGenerator, result: AnalysisResult):
        """Property 14: Output report contains both authenticity_score and fake_score simultaneously."""
        report = generator.generate_report(result)

        assert isinstance(report, dict)
        assert "authenticity_score" in report
        assert "fake_score" in report
        assert report["authenticity_score"] is not None
        assert report["fake_score"] is not None
        assert re.match(r"^\d+\.\d{2}%$", report["authenticity_score"])
        assert re.match(r"^\d+\.\d{2}%$", report["fake_score"])


# ---------------------------------------------------------------------------
# Property 16: URL Inclusion in Results
# ---------------------------------------------------------------------------

class TestProperty16URLInclusion:
    """
    Property-based tests for Property 16: URL Inclusion in Results.
    Validates Requirement 4.7.
    """

    @given(result=valid_analysis_result_strategy)
    @settings(max_examples=100)
    def test_property_16_url_inclusion(self, generator: ReportGenerator, result: AnalysisResult):
        """Property 16: Report structure includes the target website URL alongside scores."""
        report = generator.generate_report(result)

        assert "url" in report
        assert report["url"] == str(result.url)


# ---------------------------------------------------------------------------
# Property 22: Report Structure Generation
# ---------------------------------------------------------------------------

class TestProperty22ReportStructureGeneration:
    """
    Property-based tests for Property 22: Report Structure Generation.
    Validates Requirement 7.1.
    """

    @given(result=valid_analysis_result_strategy)
    @settings(max_examples=100)
    def test_property_22_report_structure_all_required_fields(
        self, generator: ReportGenerator, result: AnalysisResult
    ):
        """Property 22: Structured report contains all required fields with expected types."""
        report = generator.generate_report(result)

        required_keys = {
            "authenticity_score",
            "fake_score",
            "confidence_indicator",
            "url",
            "analysis_data",
            "timestamps",
            "top_factors",
            "suspicious_indicators",
            "error_message",
        }

        assert required_keys.issubset(report.keys())

        # Type checks
        assert isinstance(report["authenticity_score"], str)
        assert isinstance(report["fake_score"], str)
        assert isinstance(report["confidence_indicator"], str)
        assert isinstance(report["url"], str)
        assert isinstance(report["analysis_data"], dict)
        assert isinstance(report["timestamps"], dict)
        assert isinstance(report["top_factors"], list)
        assert isinstance(report["suspicious_indicators"], list)

        # Check analysis_data categories key presence
        ad_keys = {"network", "dom", "javascript", "visual", "ssl"}
        assert ad_keys.issubset(report["analysis_data"].keys())


# ---------------------------------------------------------------------------
# Property 23: ISO 8601 Timestamp Formatting
# ---------------------------------------------------------------------------

class TestProperty23TimestampFormatting:
    """
    Property-based tests for Property 23: ISO 8601 Timestamp Formatting.
    Validates Requirement 7.2.
    """

    @given(dt=timestamp_strategy)
    @settings(max_examples=100)
    def test_property_23_iso8601_utc_timestamp_format(self, generator: ReportGenerator, dt: datetime):
        """Property 23: format_timestamp returns ISO 8601 UTC format ending with Z for any datetime."""
        formatted = generator.format_timestamp(dt)

        assert isinstance(formatted, str)
        assert formatted.endswith("Z")
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", formatted) is not None


# ---------------------------------------------------------------------------
# Property 26: JSON Schema Conformance
# ---------------------------------------------------------------------------

class TestProperty26JSONSchemaConformance:
    """
    Property-based tests for Property 26: JSON Schema Conformance (Task 10.4).
    Validates Requirement 7.5.
    """

    @given(result=valid_analysis_result_strategy)
    @settings(max_examples=100)
    def test_property_26_json_schema_conformance(self, generator: ReportGenerator, result: AnalysisResult):
        """Property 26: Exported JSON from any valid AnalysisResult validates against report_schema.json."""
        json_str = generator.export_json(result)

        assert isinstance(json_str, str)
        parsed = json.loads(json_str)

        schema_path = Path(__file__).parent.parent / "src" / "report_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        format_checker = jsonschema.FormatChecker()
        if "uri" not in format_checker.checkers:
            @format_checker.checks("uri")
            def _check_uri(val: Any) -> bool:
                if not isinstance(val, str):
                    return True
                from urllib.parse import urlparse
                parsed_url = urlparse(val)
                return bool(parsed_url.scheme and (parsed_url.netloc or parsed_url.path))

        jsonschema.validate(instance=parsed, schema=schema, format_checker=format_checker)

    @given(result=valid_analysis_result_strategy)
    @settings(max_examples=100)
    def test_property_26_json_parse_validity(self, generator: ReportGenerator, result: AnalysisResult):
        """Property 26: Exported JSON string from any valid AnalysisResult is valid parseable JSON."""
        json_str = generator.export_json(result)
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# Strategies for Partial Report Generation (Task 10.6)
# ---------------------------------------------------------------------------

valid_score_st = st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)
invalid_score_st = st.sampled_from([None, "invalid_score", [0.8], {"score": 0.5}, True])

valid_conf_st = st.sampled_from(["HIGH", "MEDIUM", "LOW"])
invalid_conf_st = st.sampled_from([None, "", "   "])

valid_url_st = st.from_regex(r"https?://[a-z0-9\-]+(\.[a-z0-9\-]+)*(:\d+)?(/.*)?", fullmatch=True)
invalid_url_st = st.sampled_from([None, "", "   "])

valid_timestamps_st = st.fixed_dictionaries({
    "analysis_start": st.sampled_from(["2026-08-28T20:30:00Z", "2026-01-01T00:00:00Z"]),
    "analysis_completion": st.sampled_from(["2026-08-28T20:30:05Z", "2026-01-01T00:00:10Z"]),
})
invalid_timestamps_st = st.sampled_from([
    None,
    "not_a_dict",
    12345,
])


class CorruptedDict(dict):
    def keys(self):
        raise RuntimeError("Corrupted analysis_data dict")


invalid_analysis_data_st = st.sampled_from([
    CorruptedDict(),
])


class NonIterable:
    pass


valid_top_factors_st = st.lists(st.text(min_size=1, max_size=30), max_size=3)
invalid_top_factors_st = st.sampled_from([
    NonIterable(),
])

valid_susp_st = st.lists(st.text(min_size=1, max_size=30), max_size=5)
invalid_susp_st = st.sampled_from([
    NonIterable(),
])


@st.composite
def partially_valid_result_strategy(draw):
    valid_scores = draw(st.booleans())
    valid_conf = draw(st.booleans())
    valid_url = draw(st.booleans())
    valid_ad = draw(st.booleans())
    valid_ts = draw(st.booleans())
    valid_tf = draw(st.booleans())
    valid_si = draw(st.booleans())
    has_prior_err = draw(st.booleans())

    class DynamicResult:
        pass

    res = DynamicResult()

    if valid_scores:
        res.authenticity_score = draw(valid_score_st)
        res.fake_score = draw(valid_score_st)
    else:
        res.authenticity_score = draw(invalid_score_st)
        res.fake_score = draw(invalid_score_st)

    if valid_conf:
        res.confidence_indicator = draw(valid_conf_st)
    else:
        res.confidence_indicator = draw(invalid_conf_st)

    if valid_url:
        res.url = draw(valid_url_st)
    else:
        res.url = draw(invalid_url_st)

    if valid_ad:
        res.analysis_data = draw(valid_analysis_data_strategy)

    if valid_ts:
        res.timestamps = draw(valid_timestamps_st)
    else:
        res.timestamps = draw(invalid_timestamps_st)

    if valid_tf:
        res.top_factors = draw(valid_top_factors_st)
    else:
        res.top_factors = draw(invalid_top_factors_st)

    if valid_si:
        res.suspicious_indicators = draw(valid_susp_st)
    else:
        res.suspicious_indicators = draw(invalid_susp_st)

    res.error_message = draw(st.text(min_size=1, max_size=30)) if has_prior_err else None

    flags = {
        "scores": valid_scores,
        "confidence_indicator": valid_conf,
        "url": valid_url,
        "analysis_data": valid_ad,
        "timestamps": valid_ts,
        "top_factors": valid_tf,
        "suspicious_indicators": valid_si,
        "prior_error": res.error_message,
    }

    return res, flags


# ---------------------------------------------------------------------------
# Property 27: Partial Report Generation
# ---------------------------------------------------------------------------

class TestProperty27PartialReportGeneration:
    """
    Property-based tests for Property 27: Partial Report Generation (Task 10.6).
    Validates Requirement 7.6.
    """

    @given(sample=partially_valid_result_strategy())
    @settings(max_examples=100)
    def test_property_27_partial_report_preserves_valid_fields(self, generator: ReportGenerator, sample):
        """Property 27: Partial report preserves all valid fields accurately."""
        res, flags = sample
        report = generator.generate_partial_report(res)

        if flags["scores"]:
            assert report["authenticity_score"] == f"{float(res.authenticity_score) * 100:.2f}%"
            assert report["fake_score"] == f"{float(res.fake_score) * 100:.2f}%"
        if flags["confidence_indicator"]:
            assert report["confidence_indicator"] == str(res.confidence_indicator).strip().upper()
        if flags["url"]:
            assert report["url"] == str(res.url).strip()
        if flags["analysis_data"]:
            assert isinstance(report["analysis_data"], dict)
            assert {"network", "dom", "javascript", "visual", "ssl"}.issubset(report["analysis_data"].keys())
        if flags["timestamps"]:
            assert report["timestamps"] == res.timestamps
        if flags["top_factors"]:
            assert report["top_factors"] == list(res.top_factors)
        if flags["suspicious_indicators"]:
            assert report["suspicious_indicators"] == list(res.suspicious_indicators)

    @given(sample=partially_valid_result_strategy())
    @settings(max_examples=100)
    def test_property_27_partial_report_marks_invalid_fields(self, generator: ReportGenerator, sample):
        """Property 27: Partial report marks missing/invalid scalar fields as None and list fields as []."""
        res, flags = sample
        report = generator.generate_partial_report(res)

        if not flags["scores"]:
            assert report["authenticity_score"] is None
            assert report["fake_score"] is None
        if not flags["confidence_indicator"]:
            assert report["confidence_indicator"] is None
        if not flags["url"]:
            assert report["url"] is None
        if not flags["analysis_data"]:
            assert report["analysis_data"] == {
                "network": None,
                "dom": None,
                "javascript": None,
                "visual": None,
                "ssl": None,
            }
        if not flags["timestamps"]:
            assert report["timestamps"] is None
        if not flags["top_factors"]:
            assert report["top_factors"] == []
        if not flags["suspicious_indicators"]:
            assert report["suspicious_indicators"] == []

    @given(sample=partially_valid_result_strategy())
    @settings(max_examples=100)
    def test_property_27_partial_report_lists_failed_fields(self, generator: ReportGenerator, sample):
        """Property 27: Partial report includes failed field names in error_message iff any field failed."""
        res, flags = sample
        report = generator.generate_partial_report(res)

        failed_keys = [k for k, v in flags.items() if not v and k != "prior_error"]
        if failed_keys:
            assert isinstance(report["error_message"], str)
            assert "Partial report generated. Failed fields:" in report["error_message"]
            for f_key in failed_keys:
                if f_key == "scores":
                    assert "authenticity_score" in report["error_message"]
                    assert "fake_score" in report["error_message"]
                else:
                    assert f_key in report["error_message"]
        else:
            assert report["error_message"] == flags["prior_error"]

    @given(sample=partially_valid_result_strategy())
    @settings(max_examples=100)
    def test_property_27_partial_report_multiple_failures(self, generator: ReportGenerator, sample):
        """Property 27: Multiple simultaneous failures are listed without duplicate names."""
        res, flags = sample
        report = generator.generate_partial_report(res)

        failed_keys = [k for k, v in flags.items() if not v and k != "prior_error"]
        if len(failed_keys) > 1:
            err_msg = report["error_message"]
            assert isinstance(err_msg, str)
            assert "Partial report generated. Failed fields:" in err_msg

    @given(sample=partially_valid_result_strategy())
    @settings(max_examples=100)
    def test_property_27_partial_report_structure_keys(self, generator: ReportGenerator, sample):
        """Property 27: Partial report always contains all 9 required top-level keys."""
        res, _ = sample
        report = generator.generate_partial_report(res)

        required_keys = {
            "authenticity_score",
            "fake_score",
            "confidence_indicator",
            "url",
            "analysis_data",
            "timestamps",
            "top_factors",
            "suspicious_indicators",
            "error_message",
        }
        assert required_keys == report.keys()

    def test_property_27_partial_report_none_result(self, generator: ReportGenerator):
        """Property 27: generate_partial_report(None) handles null input without crashing."""
        report = generator.generate_partial_report(None)

        assert isinstance(report, dict)
        assert report["authenticity_score"] is None
        assert report["fake_score"] is None
        assert report["confidence_indicator"] is None
        assert report["url"] is None
        assert report["analysis_data"] == {
            "network": None,
            "dom": None,
            "javascript": None,
            "visual": None,
            "ssl": None,
        }
        assert report["timestamps"] is None
        assert report["top_factors"] == []
        assert report["suspicious_indicators"] == []
        assert isinstance(report["error_message"], str)
        assert "Partial report generated. Failed fields:" in report["error_message"]

    @given(
        score=score_strategy,
        url=url_strategy,
        categories=st.fixed_dictionaries({
            "has_net": st.booleans(),
            "has_dom": st.booleans(),
            "has_js": st.booleans(),
            "has_vis": st.booleans(),
            "has_ssl": st.booleans(),
        }),
    )
    @settings(max_examples=100)
    def test_property_27_partial_report_missing_analysis_categories(
        self, generator: ReportGenerator, score: float, url: str, categories: dict
    ):
        """Property 27: Missing category dataclasses within AnalysisData preserve top-level analysis_data as valid dictionary with None categories."""
        net = NetworkData(request_count=5, unique_domains=[], protocol_distribution={}, failed=False) if categories["has_net"] else None
        dom = DOMData(html_content="", structure_metrics={}, failed=False) if categories["has_dom"] else None
        js = JavaScriptData(script_count=1, dom_modifications=0, external_api_calls=0, failed=False) if categories["has_js"] else None
        vis = VisualData(screenshot_path="", layout_characteristics={}, failed=False) if categories["has_vis"] else None
        ssl = SSLData(issuer="", expiration_date="", chain_valid=True, failed=False) if categories["has_ssl"] else None

        ad = AnalysisData(network=net, dom=dom, javascript=js, visual=vis, ssl=ssl, timeout_occurred=False)
        result = AnalysisResult(
            authenticity_score=score,
            fake_score=1.0 - score,
            confidence_indicator="HIGH",
            url=url,
            analysis_data=ad,
            timestamps={"analysis_start": "2026-08-28T20:30:00Z", "analysis_completion": "2026-08-28T20:30:05Z"},
            top_factors=["SSL verified"],
            suspicious_indicators=[],
            error_message=None,
        )

        report = generator.generate_partial_report(result)

        assert isinstance(report["analysis_data"], dict)
        assert (report["analysis_data"]["network"] is not None) == categories["has_net"]
        assert (report["analysis_data"]["dom"] is not None) == categories["has_dom"]
        assert (report["analysis_data"]["javascript"] is not None) == categories["has_js"]
        assert (report["analysis_data"]["visual"] is not None) == categories["has_vis"]
        assert (report["analysis_data"]["ssl"] is not None) == categories["has_ssl"]

        if report["error_message"] is not None:
            assert "analysis_data" not in report["error_message"]
