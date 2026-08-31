"""Tests for the public API module (src.analyzer) and package exports."""

import pytest
from unittest.mock import MagicMock, patch

from src.analyzer import (
    analyze_website,
    AuthenticityDetector,
    AnalysisResult,
    AnalysisData,
    InputValidator,
    ReportGenerator,
)
import src


class TestAnalyzerModuleExports:
    """Test exports from src.analyzer and src root."""

    def test_analyzer_module_all_exports_present(self):
        """Verify all expected symbols are accessible from src.analyzer."""
        from src.analyzer import (
            analyze_website,
            AuthenticityDetector,
            AnalysisResult,
            AnalysisData,
            InputValidator,
            ReportGenerator,
        )
        assert callable(analyze_website)
        assert AuthenticityDetector is not None
        assert AnalysisResult is not None
        assert AnalysisData is not None
        assert InputValidator is not None
        assert ReportGenerator is not None

    def test_src_package_root_exports(self):
        """Verify all expected symbols are accessible from src directly."""
        assert hasattr(src, "analyze_website")
        assert hasattr(src, "AuthenticityDetector")
        assert hasattr(src, "AnalysisResult")
        assert hasattr(src, "AnalysisData")
        assert hasattr(src, "InputValidator")
        assert hasattr(src, "ReportGenerator")
        assert hasattr(src, "__version__")
        assert src.__version__ == "0.1.0"


class TestAnalyzerPublicFunctions:
    """Test public API functions in src.analyzer."""

    def test_analyze_website_invalid_url_fast_rejection(self):
        """Test analyze_website rejects invalid URL without starting sandbox."""
        result = analyze_website("invalid://bad-url")
        assert isinstance(result, dict)
        assert result["authenticity_score"] is None
        assert result["fake_score"] is None
        assert result["confidence_indicator"] == "LOW"
        assert result["error_message"] is not None

    def test_analyze_website_with_custom_detector_injection(self):
        """Test analyze_website accepts custom AuthenticityDetector instance."""
        mock_detector = MagicMock(spec=AuthenticityDetector)
        expected_report = {
            "authenticity_score": "95.00%",
            "fake_score": "5.00%",
            "confidence_indicator": "HIGH",
            "url": "https://example.com",
            "top_factors": ["Valid SSL certificate"],
            "suspicious_indicators": [],
            "error_message": None,
        }
        mock_detector.analyze_website.return_value = expected_report

        result = analyze_website("https://example.com", detector=mock_detector)
        mock_detector.analyze_website.assert_called_once_with("https://example.com")
        assert result == expected_report

    def test_format_text_summary_rendering(self):
        """Test ReportGenerator.format_text_summary generates complete output."""
        sample_report = {
            "url": "https://example.com",
            "authenticity_score": "88.50%",
            "fake_score": "11.50%",
            "confidence_indicator": "HIGH",
            "top_factors": ["Valid SSL certificate", "Clean DNS resolution"],
            "suspicious_indicators": [],
            "timestamps": {
                "analysis_start": "2026-08-31T06:00:00Z",
                "analysis_completion": "2026-08-31T06:00:05Z",
            },
            "error_message": None,
        }
        summary = ReportGenerator.format_text_summary(sample_report)
        assert "WEBSITE AUTHENTICITY ANALYSIS REPORT" in summary
        assert "https://example.com" in summary
        assert "88.50%" in summary
        assert "11.50%" in summary
        assert "Valid SSL certificate" in summary
        assert "2026-08-31T06:00:00Z" in summary

    def test_format_text_summary_with_suspicious_indicators(self):
        """Test ReportGenerator.format_text_summary renders suspicious indicators."""
        suspicious_report = {
            "url": "https://phishing-site.example",
            "authenticity_score": "20.00%",
            "fake_score": "80.00%",
            "confidence_indicator": "HIGH",
            "top_factors": ["Page loaded"],
            "suspicious_indicators": [
                "Expired SSL certificate",
                "Password field on HTTP domain",
            ],
            "timestamps": {},
            "error_message": None,
        }
        summary = ReportGenerator.format_text_summary(suspicious_report)
        assert "Suspicious Risk Indicators:" in summary
        assert "Expired SSL certificate" in summary
        assert "Password field on HTTP domain" in summary
