"""Public API entry point for Website Authenticity Detector.

This module provides the primary user-facing functions and classes for
analyzing website authenticity, as documented in README.md.

Example:
    >>> from src.analyzer import analyze_website
    >>> result = analyze_website("https://example.com")
    >>> print(result["authenticity_score"])
    >>> print(result["fake_score"])
    >>> print(result["confidence_indicator"])
"""

from typing import Any, Dict, Optional

from src.authenticity_detector import AuthenticityDetector, analyze_website
from src.models import AnalysisResult, AnalysisData
from src.input_validator import InputValidator
from src.report_generator import ReportGenerator

__all__ = [
    "analyze_website",
    "AuthenticityDetector",
    "AnalysisResult",
    "AnalysisData",
    "InputValidator",
    "ReportGenerator",
]
