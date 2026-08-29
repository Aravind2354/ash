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
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

import jsonschema
import pytest

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


class TestTask10_3_JSONExport:
    """
    Unit tests for Task 10.3: JSON export with schema validation (Requirement 7.5).
    """

    def test_export_json_returns_string(self, generator, sample_analysis_result):
        """Task 10.3-1: export_json returns a string instance."""
        exported = generator.export_json(sample_analysis_result)
        assert isinstance(exported, str)
        assert len(exported) > 0

    def test_export_json_returns_valid_json(self, generator, sample_analysis_result):
        """Task 10.3-2: export_json returns valid JSON that parses cleanly via json.loads."""
        exported = generator.export_json(sample_analysis_result)
        parsed = json.loads(exported)
        assert isinstance(parsed, dict)
        assert parsed["authenticity_score"] == "85.50%"

    def test_export_json_validates_against_report_schema_json(self, generator, sample_analysis_result):
        """Task 10.3-3 & Requirement 10: Exported JSON validates directly against report_schema.json."""
        exported_json = generator.export_json(sample_analysis_result)
        report_dict = json.loads(exported_json)

        schema_path = Path(__file__).parent.parent / "src" / "report_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        # Must pass without raising ValidationError
        jsonschema.validate(instance=report_dict, schema=schema)

    def test_export_json_contains_all_required_fields(self, generator, sample_analysis_result):
        """Task 10.3-4: Exported JSON contains all top-level required fields."""
        exported_json = generator.export_json(sample_analysis_result)
        parsed = json.loads(exported_json)

        required_keys = [
            "authenticity_score",
            "fake_score",
            "confidence_indicator",
            "url",
            "timestamps",
        ]
        for key in required_keys:
            assert key in parsed, f"Missing required top-level key: {key}"

    def test_schema_validation_accepts_valid_report(self, generator, sample_analysis_result):
        """Task 10.3-5: Schema validation accepts a complete valid analysis report."""
        exported_json = generator.export_json(sample_analysis_result)
        parsed = json.loads(exported_json)
        assert parsed["confidence_indicator"] == "HIGH"
        assert parsed["url"] == "https://example.com"
        assert parsed["timestamps"]["analysis_start"] == "2026-08-28T20:30:00Z"
        assert parsed["timestamps"]["analysis_completion"] == "2026-08-28T20:30:05Z"

    def test_schema_validation_rejects_invalid_score_format(self, generator, sample_analysis_result):
        """Task 10.3-6: Schema validation rejects score not matching ^\\d+\\.\\d{2}%$ pattern."""
        schema_path = Path(__file__).parent.parent / "src" / "report_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        invalid_report = generator.generate_report(sample_analysis_result)
        invalid_report["authenticity_score"] = "85.5%"  # invalid: missing trailing 0

        with pytest.raises(jsonschema.exceptions.ValidationError):
            jsonschema.validate(instance=invalid_report, schema=schema)

    def test_schema_validation_rejects_invalid_confidence_value(self, generator, sample_analysis_result):
        """Task 10.3-7: Schema validation rejects confidence_indicator not in enum [HIGH, MEDIUM, LOW]."""
        invalid_result = AnalysisResult(
            authenticity_score=0.855,
            fake_score=0.145,
            confidence_indicator="VERY_HIGH",  # Invalid enum value
            url="https://example.com",
            analysis_data=sample_analysis_result.analysis_data,
            timestamps=sample_analysis_result.timestamps,
            top_factors=[],
            suspicious_indicators=[],
            error_message=None,
        )

        with pytest.raises(jsonschema.exceptions.ValidationError):
            generator.export_json(invalid_result)

    def test_schema_validation_rejects_missing_required_fields(self, generator, sample_analysis_result):
        """Task 10.3-8: Schema validation rejects report missing required fields (e.g. timestamps)."""
        schema_path = Path(__file__).parent.parent / "src" / "report_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        report = generator.generate_report(sample_analysis_result)
        del report["timestamps"]

        with pytest.raises(jsonschema.exceptions.ValidationError):
            jsonschema.validate(instance=report, schema=schema)

    def test_schema_validation_rejects_invalid_timestamp_structure(self, generator, sample_analysis_result):
        """Task 10.3-9: Schema validation rejects timestamps missing required analysis_completion field."""
        invalid_result = AnalysisResult(
            authenticity_score=0.855,
            fake_score=0.145,
            confidence_indicator="HIGH",
            url="https://example.com",
            analysis_data=sample_analysis_result.analysis_data,
            timestamps={"analysis_start": "2026-08-28T20:30:00Z"},  # Missing analysis_completion
            top_factors=[],
            suspicious_indicators=[],
            error_message=None,
        )

        with pytest.raises(jsonschema.exceptions.ValidationError):
            generator.export_json(invalid_result)

    def test_schema_validation_rejects_invalid_url(self, generator, sample_analysis_result):
        """Task 10.3-10: Schema validation rejects invalid URL string that fails URI format."""
        invalid_result = AnalysisResult(
            authenticity_score=0.855,
            fake_score=0.145,
            confidence_indicator="HIGH",
            url="not_a_valid_uri",  # Missing scheme/host structure
            analysis_data=sample_analysis_result.analysis_data,
            timestamps=sample_analysis_result.timestamps,
            top_factors=[],
            suspicious_indicators=[],
            error_message=None,
        )

        with pytest.raises(jsonschema.exceptions.ValidationError):
            generator.export_json(invalid_result)

    def test_json_serialization_handles_analysis_data(self, generator, sample_analysis_result):
        """Task 10.3-11: export_json correctly serializes nested AnalysisData structure."""
        exported_json = generator.export_json(sample_analysis_result)
        parsed = json.loads(exported_json)

        analysis_data = parsed["analysis_data"]
        assert isinstance(analysis_data, dict)
        assert analysis_data["network"]["request_count"] == 15
        assert analysis_data["dom"]["structure_metrics"]["total_elements"] == 20
        assert analysis_data["ssl"]["chain_valid"] is True

    def test_validation_error_raised_for_schema_invalid_generated_data(self, generator, sample_analysis_result):
        """Task 10.3-12 & Requirement 9: Verify export_json raises ValidationError for schema-invalid generated data."""
        invalid_result = AnalysisResult(
            authenticity_score=0.855,
            fake_score=0.145,
            confidence_indicator="UNKNOWN_CONFIDENCE",
            url="https://example.com",
            analysis_data=sample_analysis_result.analysis_data,
            timestamps=sample_analysis_result.timestamps,
            top_factors=[],
            suspicious_indicators=[],
            error_message=None,
        )

        with pytest.raises(jsonschema.exceptions.ValidationError):
            generator.export_json(invalid_result)


class TestTask10_5_PartialReportGeneration:
    """
    Unit tests for Task 10.5: Partial report generation (Requirement 7.6).

    Validates:
    - Preserving valid report fields when other fields fail
    - Setting ungeneratable/invalid fields to None or empty lists
    - Listing failed field names in error_message
    - Representation of missing/failed AnalysisData categories
    """

    def test_partial_report_all_valid(self, generator, sample_analysis_result):
        """Task 10.5-1: generate_partial_report with all valid fields returns complete report with error_message=None."""
        report = generator.generate_partial_report(sample_analysis_result)

        assert report["authenticity_score"] == "85.50%"
        assert report["fake_score"] == "14.50%"
        assert report["confidence_indicator"] == "HIGH"
        assert report["url"] == "https://example.com"
        assert report["analysis_data"]["network"]["request_count"] == 15
        assert report["timestamps"]["analysis_start"] == "2026-08-28T20:30:00Z"
        assert len(report["top_factors"]) == 3
        assert report["error_message"] is None

    def test_partial_report_missing_scores(self, generator, sample_analysis_result):
        """Task 10.5-2: generate_partial_report with invalid score formats scores as None and lists them in error_message."""
        invalid_result = AnalysisResult(
            authenticity_score=None,  # Invalid type for float score
            fake_score=None,
            confidence_indicator="HIGH",
            url="https://example.com",
            analysis_data=sample_analysis_result.analysis_data,
            timestamps=sample_analysis_result.timestamps,
            top_factors=[],
            suspicious_indicators=[],
            error_message=None,
        )

        report = generator.generate_partial_report(invalid_result)

        assert report["authenticity_score"] is None
        assert report["fake_score"] is None
        assert report["url"] == "https://example.com"  # Preserved
        assert report["confidence_indicator"] == "HIGH"  # Preserved
        assert "authenticity_score" in report["error_message"]
        assert "fake_score" in report["error_message"]

    def test_partial_report_invalid_url(self, generator, sample_analysis_result):
        """Task 10.5-3: generate_partial_report with invalid/empty url marks url as None and lists 'url' in error_message."""
        invalid_result = AnalysisResult(
            authenticity_score=0.855,
            fake_score=0.145,
            confidence_indicator="HIGH",
            url="",  # Empty string URL
            analysis_data=sample_analysis_result.analysis_data,
            timestamps=sample_analysis_result.timestamps,
            top_factors=[],
            suspicious_indicators=[],
            error_message=None,
        )

        report = generator.generate_partial_report(invalid_result)

        assert report["url"] is None
        assert report["authenticity_score"] == "85.50%"  # Preserved
        assert report["fake_score"] == "14.50%"  # Preserved
        assert "url" in report["error_message"]

    def test_partial_report_missing_timestamps(self, generator, sample_analysis_result):
        """Task 10.5-4: generate_partial_report with missing timestamps marks timestamps as None and lists in error_message."""
        invalid_result = AnalysisResult(
            authenticity_score=0.855,
            fake_score=0.145,
            confidence_indicator="HIGH",
            url="https://example.com",
            analysis_data=sample_analysis_result.analysis_data,
            timestamps=None,  # Missing timestamps dict
            top_factors=[],
            suspicious_indicators=[],
            error_message=None,
        )

        report = generator.generate_partial_report(invalid_result)

        assert report["timestamps"] is None
        assert "timestamps" in report["error_message"]

    def test_partial_report_preserves_valid_fields(self, generator, sample_analysis_result):
        """Task 10.5-5: Partial report preserves all valid fields even when multiple other fields fail."""
        invalid_result = AnalysisResult(
            authenticity_score=None,
            fake_score=None,
            confidence_indicator="HIGH",
            url="https://example.com",
            analysis_data=sample_analysis_result.analysis_data,
            timestamps=None,
            top_factors=["Valid factor"],
            suspicious_indicators=[],
            error_message=None,
        )

        report = generator.generate_partial_report(invalid_result)

        assert report["url"] == "https://example.com"
        assert report["confidence_indicator"] == "HIGH"
        assert report["analysis_data"]["network"]["request_count"] == 15
        assert report["top_factors"] == ["Valid factor"]
        assert report["authenticity_score"] is None
        assert report["timestamps"] is None

    def test_partial_report_error_message_lists_failed_fields(self, generator, sample_analysis_result):
        """Task 10.5-6: error_message contains a descriptive message naming every failed field."""
        invalid_result = AnalysisResult(
            authenticity_score=None,
            fake_score=None,
            confidence_indicator="HIGH",
            url="https://example.com",
            analysis_data=sample_analysis_result.analysis_data,
            timestamps=sample_analysis_result.timestamps,
            top_factors=[],
            suspicious_indicators=[],
            error_message=None,
        )

        report = generator.generate_partial_report(invalid_result)

        assert report["error_message"].startswith("Partial report generated. Failed fields:")
        assert "authenticity_score" in report["error_message"]
        assert "fake_score" in report["error_message"]

    def test_partial_report_multiple_failed_fields(self, generator, sample_analysis_result):
        """Task 10.5-7: Multiple failed fields (scores + URL + timestamps) are all explicitly enumerated in error_message."""
        invalid_result = AnalysisResult(
            authenticity_score=None,
            fake_score=None,
            confidence_indicator=None,
            url="",
            analysis_data=sample_analysis_result.analysis_data,
            timestamps=None,
            top_factors=[],
            suspicious_indicators=[],
            error_message=None,
        )

        report = generator.generate_partial_report(invalid_result)

        err = report["error_message"]
        assert "authenticity_score" in err
        assert "fake_score" in err
        assert "confidence_indicator" in err
        assert "url" in err
        assert "timestamps" in err

    def test_partial_report_missing_analysis_data_categories(self, generator, sample_analysis_result):
        """Task 10.5-8: Missing AnalysisData categories are serialized as None without declaring analysis_data failed."""
        partial_data = AnalysisData(
            network=None,  # Missing network category
            dom=sample_analysis_result.analysis_data.dom,
            javascript=None,
            visual=None,
            ssl=None,
        )
        partial_result = AnalysisResult(
            authenticity_score=0.855,
            fake_score=0.145,
            confidence_indicator="LOW",
            url="https://example.com",
            analysis_data=partial_data,
            timestamps=sample_analysis_result.timestamps,
            top_factors=[],
            suspicious_indicators=[],
            error_message=None,
        )

        report = generator.generate_partial_report(partial_result)

        assert report["analysis_data"]["network"] is None
        assert report["analysis_data"]["javascript"] is None
        assert report["analysis_data"]["dom"]["structure_metrics"]["total_elements"] == 20
        assert report["error_message"] is None

    def test_partial_report_failed_analysis_data_categories(self, generator, sample_analysis_result):
        """Task 10.5-9: Failed AnalysisData categories preserve failed=True flag and object payload."""
        failed_dom = DOMData(
            html_content="",
            structure_metrics={},
            failed=True,
        )
        partial_data = AnalysisData(
            network=sample_analysis_result.analysis_data.network,
            dom=failed_dom,
            javascript=None,
            visual=None,
            ssl=None,
        )
        partial_result = AnalysisResult(
            authenticity_score=0.5,
            fake_score=0.5,
            confidence_indicator="LOW",
            url="https://example.com",
            analysis_data=partial_data,
            timestamps=sample_analysis_result.timestamps,
            top_factors=[],
            suspicious_indicators=[],
            error_message=None,
        )

        report = generator.generate_partial_report(partial_result)

        assert report["analysis_data"]["dom"]["failed"] is True
        assert report["analysis_data"]["network"]["failed"] is False
        assert report["error_message"] is None

    def test_partial_report_does_not_crash_on_none_result(self, generator):
        """Task 10.5-10: Calling generate_partial_report(None) returns partial report dict with all fields marked missing."""
        report = generator.generate_partial_report(None)

        assert isinstance(report, dict)
        assert report["authenticity_score"] is None
        assert report["fake_score"] is None
        assert report["confidence_indicator"] is None
        assert report["url"] is None
        assert report["timestamps"] is None
        assert report["top_factors"] == []
        assert report["suspicious_indicators"] == []
        assert "authenticity_score" in report["error_message"]
        assert "url" in report["error_message"]

    def test_partial_report_valid_fields_unchanged(self, generator, sample_analysis_result):
        """Task 10.5-11: Valid fields maintain exact standard formatting in partial reports."""
        report = generator.generate_partial_report(sample_analysis_result)

        assert report["authenticity_score"] == "85.50%"
        assert report["fake_score"] == "14.50%"
        assert report["url"] == "https://example.com"
        assert report["confidence_indicator"] == "HIGH"

    def test_partial_report_error_message_none_when_all_succeed(self, generator, sample_analysis_result):
        """Task 10.5-12: error_message is None when all report fields generate cleanly."""
        report = generator.generate_partial_report(sample_analysis_result)
        assert report["error_message"] is None


class TestTask10_7_ReportGenerationEdgeCases:
    """
    Unit tests for Task 10.7: Report generation edge cases.

    Validates Requirements: 7.1, 7.2, 7.6
    """

    def test_report_with_all_five_data_categories_present(self, generator):
        """Task 10.7-1 & Requirement 7.1: Verify generate_report serializes all 5 populated AnalysisData categories."""
        all_categories_data = AnalysisData(
            network=NetworkData(
                request_count=25,
                unique_domains=["example.com", "cdn.example.com", "api.example.com"],
                protocol_distribution={"https": 25},
                failed=False,
            ),
            dom=DOMData(
                html_content="<html><body><main><h1>Title</h1></main></body></html>",
                structure_metrics={"total_elements": 45, "form_count": 2, "iframe_count": 0},
                failed=False,
            ),
            javascript=JavaScriptData(
                script_count=5,
                dom_modifications=12,
                external_api_calls=2,
                failed=False,
            ),
            visual=VisualData(
                screenshot_path="/var/screenshots/shot.png",
                layout_characteristics={"viewport_width": 1920, "viewport_height": 1080, "has_images": True},
                failed=False,
            ),
            ssl=SSLData(
                issuer="CN=DigiCert Global Root CA, O=DigiCert Inc",
                expiration_date="2030-12-31T23:59:59Z",
                chain_valid=True,
                failed=False,
            ),
            timeout_occurred=False,
        )

        result = AnalysisResult(
            authenticity_score=0.92,
            fake_score=0.08,
            confidence_indicator="HIGH",
            url="https://complete.example.org",
            analysis_data=all_categories_data,
            timestamps={
                "analysis_start": "2026-08-29T10:00:00Z",
                "analysis_completion": "2026-08-29T10:00:05Z",
            },
            top_factors=["Valid SSL certificate", "Clean DOM structure", "Encrypted HTTPS traffic"],
            suspicious_indicators=[],
            error_message=None,
        )

        report = generator.generate_report(result)

        ad = report["analysis_data"]
        assert isinstance(ad, dict)
        assert set(ad.keys()) == {"network", "dom", "javascript", "visual", "ssl"}

        # Verify exact nested category properties
        assert ad["network"]["request_count"] == 25
        assert ad["network"]["unique_domains"] == ["example.com", "cdn.example.com", "api.example.com"]
        assert ad["dom"]["structure_metrics"]["total_elements"] == 45
        assert ad["javascript"]["script_count"] == 5
        assert ad["visual"]["screenshot_path"] == "/var/screenshots/shot.png"
        assert ad["ssl"]["issuer"] == "CN=DigiCert Global Root CA, O=DigiCert Inc"
        assert ad["ssl"]["chain_valid"] is True

    def test_report_with_partial_data_categories(self, generator):
        """Task 10.7-2 & Requirement 7.1: Verify generate_report handles partial data categories (network & ssl present, dom, js, visual None)."""
        partial_data = AnalysisData(
            network=NetworkData(
                request_count=10,
                unique_domains=["example.org"],
                protocol_distribution={"https": 10},
                failed=False,
            ),
            dom=None,
            javascript=None,
            visual=None,
            ssl=SSLData(
                issuer="Let's Encrypt Authority X3",
                expiration_date="2027-01-01T00:00:00Z",
                chain_valid=True,
                failed=False,
            ),
            timeout_occurred=False,
        )

        result = AnalysisResult(
            authenticity_score=0.75,
            fake_score=0.25,
            confidence_indicator="MEDIUM",
            url="https://partial.example.org",
            analysis_data=partial_data,
            timestamps={
                "analysis_start": "2026-08-29T11:00:00Z",
                "analysis_completion": "2026-08-29T11:00:02Z",
            },
            top_factors=["Valid SSL issuer"],
            suspicious_indicators=[],
            error_message=None,
        )

        report = generator.generate_report(result)

        ad = report["analysis_data"]
        assert isinstance(ad, dict)
        assert ad["network"]["request_count"] == 10
        assert ad["ssl"]["issuer"] == "Let's Encrypt Authority X3"
        assert ad["dom"] is None
        assert ad["javascript"] is None
        assert ad["visual"] is None

    def test_report_with_missing_timestamps(self, generator, sample_analysis_data):
        """Task 10.7-3 & Requirement 7.2: Verify generate_report handles empty or missing timestamps dict without crashing."""
        result_empty_ts = AnalysisResult(
            authenticity_score=0.80,
            fake_score=0.20,
            confidence_indicator="HIGH",
            url="https://notimestamp.example",
            analysis_data=sample_analysis_data,
            timestamps={},
            top_factors=[],
            suspicious_indicators=[],
            error_message=None,
        )

        report = generator.generate_report(result_empty_ts)
        assert isinstance(report["timestamps"], dict)
        assert report["timestamps"] == {}

    def test_partial_report_combines_prior_error_message(self, generator, sample_analysis_data):
        """Task 10.7-4 & Requirement 7.6: Verify generate_partial_report appends prior error message when fields fail."""
        invalid_result_with_prior_err = AnalysisResult(
            authenticity_score=None,  # Causing score failure
            fake_score=None,
            confidence_indicator="HIGH",
            url="https://error.example",
            analysis_data=sample_analysis_data,
            timestamps={"analysis_start": "2026-08-29T12:00:00Z", "analysis_completion": "2026-08-29T12:00:01Z"},
            top_factors=[],
            suspicious_indicators=[],
            error_message="Network fetch socket reset by peer",
        )

        report = generator.generate_partial_report(invalid_result_with_prior_err)

        err_msg = report["error_message"]
        assert isinstance(err_msg, str)
        assert err_msg.startswith("Partial report generated. Failed fields:")
        assert "authenticity_score" in err_msg
        assert "fake_score" in err_msg
        assert "Prior error: Network fetch socket reset by peer" in err_msg

    def test_format_timestamp_naive_datetime(self, generator):
        """Task 10.7-5 & Requirement 7.2: Verify format_timestamp converts naive datetime to UTC ISO 8601 string ending in Z."""
        naive_dt = datetime(2026, 8, 29, 14, 30, 45)
        formatted = generator.format_timestamp(naive_dt)

        assert formatted == "2026-08-29T14:30:45Z"
        assert formatted.endswith("Z")
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", formatted) is not None
