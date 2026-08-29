"""
Unit tests for ReportGenerator (Task 10.1).

Validates:
- ReportGenerator instantiation and interface
- format_scores and format_score percentage calculations (Requirements 4.1, 4.2)
- Simultaneous score display (Requirement 4.3)
- URL inclusion alongside scores (Requirement 4.7)
- Structured report with all Analysis_Data elements (Requirement 7.1)
- ISO 8601 UTC timestamp formatting (Requirement 7.2)
- Top 3 factors and suspicious indicators inclusion
- JSON serializability of generated report
"""

import json
import re
from datetime import datetime, timezone
from typing import Dict

import pytest

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

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


@pytest.fixture
def generator() -> ReportGenerator:
    """Fixture providing a ReportGenerator instance."""
    return ReportGenerator()


@pytest.fixture
def sample_analysis_data() -> AnalysisData:
    """Fixture providing a complete AnalysisData instance."""
    return AnalysisData(
        network=NetworkData(
            request_count=15,
            unique_domains=["example.com", "cdn.example.com"],
            protocol_distribution={"https": 15},
            failed=False,
        ),
        dom=DOMData(
            html_content="<html><body><h1>Test</h1></body></html>",
            structure_metrics={"total_elements": 20, "form_count": 1, "iframe_count": 0},
            failed=False,
        ),
        javascript=JavaScriptData(
            script_count=3,
            dom_modifications=10,
            external_api_calls=1,
            failed=False,
        ),
        visual=VisualData(
            screenshot_path="/tmp/screenshot.png",
            layout_characteristics={"viewport_width": 1280, "viewport_height": 800, "has_images": True},
            failed=False,
        ),
        ssl=SSLData(
            issuer="CN=DigiCert Global Root CA",
            expiration_date="2030-01-01T00:00:00Z",
            chain_valid=True,
            failed=False,
        ),
        timeout_occurred=False,
    )


@pytest.fixture
def sample_analysis_result(sample_analysis_data) -> AnalysisResult:
    """Fixture providing a complete AnalysisResult instance."""
    return AnalysisResult(
        authenticity_score=0.855,
        fake_score=0.145,
        confidence_indicator="HIGH",
        url="https://example.com",
        analysis_data=sample_analysis_data,
        timestamps={
            "analysis_start": "2026-08-28T20:30:00Z",
            "analysis_completion": "2026-08-28T20:30:05Z",
        },
        top_factors=[
            "Valid SSL certificate chain verified",
            "All network traffic encrypted over HTTPS",
            "Clean DOM hierarchy without iframes",
        ],
        suspicious_indicators=[],
        error_message=None,
    )


class TestReportGeneratorFormatting:
    """Unit tests for ReportGenerator formatting methods."""

    def test_report_generator_instantiation(self, generator):
        """Test that ReportGenerator can be instantiated cleanly."""
        assert isinstance(generator, ReportGenerator)

    def test_format_score_two_decimals(self, generator):
        """Requirement 4.1 & 4.2: format_score multiplies by 100 with 2 decimals."""
        assert generator.format_score(0.855) == "85.50%"
        assert generator.format_score(0.145) == "14.50%"
        assert generator.format_score(0.0) == "0.00%"
        assert generator.format_score(1.0) == "100.00%"
        assert generator.format_score(0.5) == "50.00%"
        assert generator.format_score(0.333333) == "33.33%"
        assert generator.format_score(0.666667) == "66.67%"

    def test_format_scores_dictionary(self, generator):
        """Requirement 4.3: format_scores returns dictionary with both scores."""
        scores = generator.format_scores(0.855, 0.145)
        assert isinstance(scores, dict)
        assert "authenticity_score" in scores
        assert "fake_score" in scores
        assert scores["authenticity_score"] == "85.50%"
        assert scores["fake_score"] == "14.50%"

    def test_format_scores_boundary_values(self, generator):
        """Test format_scores with boundary score values."""
        # Exact 0.0 and 1.0
        bounds = generator.format_scores(0.0, 1.0)
        assert bounds["authenticity_score"] == "0.00%"
        assert bounds["fake_score"] == "100.00%"

        # Exact 0.5 and 0.5
        half = generator.format_scores(0.5, 0.5)
        assert half["authenticity_score"] == "50.00%"
        assert half["fake_score"] == "50.00%"

    def test_format_timestamp_iso8601_utc(self, generator):
        """Requirement 7.2: format_timestamp returns ISO 8601 UTC timestamp ending with Z."""
        dt = datetime(2026, 8, 28, 20, 30, 45, tzinfo=timezone.utc)
        formatted = generator.format_timestamp(dt)
        assert formatted == "2026-08-28T20:30:45Z"

        # Pattern validation
        iso_pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
        assert re.match(iso_pattern, formatted) is not None

        # Default argument uses current UTC time
        current_formatted = generator.format_timestamp()
        assert re.match(iso_pattern, current_formatted) is not None
        assert current_formatted.endswith("Z")


class TestReportGeneratorReportStructure:
    """Unit tests for generate_report and output structure."""

    def test_generate_report_contains_all_required_fields(self, generator, sample_analysis_result):
        """Requirement 7.1 & Schema: generate_report contains all required report keys."""
        report = generator.generate_report(sample_analysis_result)

        required_keys = [
            "authenticity_score",
            "fake_score",
            "confidence_indicator",
            "url",
            "analysis_data",
            "timestamps",
            "top_factors",
            "suspicious_indicators",
            "error_message",
        ]

        for key in required_keys:
            assert key in report, f"Missing required report field: {key}"

    def test_generate_report_scores_formatted_as_percentages(self, generator, sample_analysis_result):
        """Requirement 4.1 & 4.2: Scores in report are percentage strings."""
        report = generator.generate_report(sample_analysis_result)

        assert report["authenticity_score"] == "85.50%"
        assert report["fake_score"] == "14.50%"
        assert re.match(r"^\d+\.\d{2}%$", report["authenticity_score"])
        assert re.match(r"^\d+\.\d{2}%$", report["fake_score"])

    def test_generate_report_confidence_indicator(self, generator, sample_analysis_result):
        """Requirement 4.4-4.6: Confidence indicator is preserved in report."""
        report = generator.generate_report(sample_analysis_result)
        assert report["confidence_indicator"] == "HIGH"

        # Test MEDIUM and LOW preservation
        sample_analysis_result.confidence_indicator = "MEDIUM"
        assert generator.generate_report(sample_analysis_result)["confidence_indicator"] == "MEDIUM"

        sample_analysis_result.confidence_indicator = "LOW"
        assert generator.generate_report(sample_analysis_result)["confidence_indicator"] == "LOW"

    def test_generate_report_url(self, generator, sample_analysis_result):
        """Requirement 4.7: URL is preserved in report."""
        report = generator.generate_report(sample_analysis_result)
        assert report["url"] == "https://example.com"

    def test_generate_report_timestamps_structure(self, generator, sample_analysis_result):
        """Requirement 7.2: Timestamps dictionary contains start and completion in ISO 8601 UTC."""
        report = generator.generate_report(sample_analysis_result)
        timestamps = report["timestamps"]

        assert isinstance(timestamps, dict)
        assert "analysis_start" in timestamps
        assert "analysis_completion" in timestamps
        assert timestamps["analysis_start"] == "2026-08-28T20:30:00Z"
        assert timestamps["analysis_completion"] == "2026-08-28T20:30:05Z"

    def test_generate_report_analysis_data_serialized(self, generator, sample_analysis_result):
        """Requirement 7.1: AnalysisData is serialized to a dictionary of 5 categories."""
        report = generator.generate_report(sample_analysis_result)
        data = report["analysis_data"]

        assert isinstance(data, dict)
        assert "network" in data
        assert "dom" in data
        assert "javascript" in data
        assert "visual" in data
        assert "ssl" in data

        # Check nested structures are standard dicts, not dataclasses
        assert isinstance(data["network"], dict)
        assert data["network"]["request_count"] == 15
        assert data["network"]["unique_domains"] == ["example.com", "cdn.example.com"]
        assert data["network"]["failed"] is False

        assert isinstance(data["dom"], dict)
        assert data["dom"]["structure_metrics"]["total_elements"] == 20

        assert isinstance(data["ssl"], dict)
        assert data["ssl"]["chain_valid"] is True

    def test_generate_report_top_factors(self, generator, sample_analysis_result):
        """Requirement 7.4: top_factors list is preserved in report."""
        report = generator.generate_report(sample_analysis_result)

        assert isinstance(report["top_factors"], list)
        assert len(report["top_factors"]) == 3
        assert report["top_factors"] == sample_analysis_result.top_factors

    def test_generate_report_suspicious_indicators(self, generator, sample_analysis_result):
        """Requirement 7.3: suspicious_indicators list is preserved in report."""
        # Empty when fake_score <= 0.5
        report = generator.generate_report(sample_analysis_result)
        assert report["suspicious_indicators"] == []

        # Populated when fake_score > 0.5
        adversarial_result = AnalysisResult(
            authenticity_score=0.20,
            fake_score=0.80,
            confidence_indicator="HIGH",
            url="https://phishing.bad",
            analysis_data=sample_analysis_result.analysis_data,
            timestamps=sample_analysis_result.timestamps,
            top_factors=["Self-signed certificate", "Excessive domains", "Obfuscated JS"],
            suspicious_indicators=["SSL chain invalid", "Excessive external requests (50)"],
            error_message=None,
        )
        adv_report = generator.generate_report(adversarial_result)
        assert adv_report["suspicious_indicators"] == [
            "SSL chain invalid",
            "Excessive external requests (50)",
        ]

    def test_generate_report_with_error_message(self, generator, sample_analysis_data):
        """Requirement 7.1: Error message is included in report when error occurred."""
        error_result = AnalysisResult(
            authenticity_score=0.0,
            fake_score=0.0,
            confidence_indicator="LOW",
            url="https://broken.example",
            analysis_data=sample_analysis_data,
            timestamps={"analysis_start": "2026-08-28T20:30:00Z", "analysis_completion": "2026-08-28T20:30:01Z"},
            top_factors=[],
            suspicious_indicators=[],
            error_message="Insufficient data: collection timed out",
        )
        report = generator.generate_report(error_result)
        assert report["error_message"] == "Insufficient data: collection timed out"

    def test_generate_report_with_none_categories(self, generator):
        """Report generator handles AnalysisData with None categories without crashing."""
        partial_data = AnalysisData(
            network=None,
            dom=None,
            javascript=None,
            visual=None,
            ssl=None,
        )
        result = AnalysisResult(
            authenticity_score=0.0,
            fake_score=0.0,
            confidence_indicator="LOW",
            url="https://empty.example",
            analysis_data=partial_data,
            timestamps={},
            top_factors=[],
            suspicious_indicators=[],
            error_message=None,
        )
        report = generator.generate_report(result)
        assert report["analysis_data"]["network"] is None
        assert report["analysis_data"]["dom"] is None
        assert report["analysis_data"]["javascript"] is None
        assert report["analysis_data"]["visual"] is None
        assert report["analysis_data"]["ssl"] is None

    def test_generate_report_json_serializability(self, generator, sample_analysis_result):
        """Report dictionary must be cleanly JSON serializable via json.dumps without TypeError."""
        report = generator.generate_report(sample_analysis_result)

        # Must not raise TypeError
        json_str = json.dumps(report)
        assert isinstance(json_str, str)
        assert len(json_str) > 0

        # Reloading matches dictionary
        reloaded = json.loads(json_str)
        assert reloaded["authenticity_score"] == "85.50%"
        assert reloaded["url"] == "https://example.com"
        assert reloaded["confidence_indicator"] == "HIGH"
