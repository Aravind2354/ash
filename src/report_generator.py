"""
ReportGenerator class for formatting and generating website authenticity analysis reports.

Implements:
- ReportGenerator class with generate_report method
- format_scores / format_score methods (percentage string with 2 decimals)
- format_timestamp method (ISO 8601 UTC string ending in 'Z')
- AnalysisData serialization to JSON-compatible dictionary
- Assembly of all required fields: scores, confidence, url, analysis_data, timestamps, factors, suspicious indicators, error_message

Validates Requirements: 4.1, 4.2, 4.3, 4.7, 7.1, 7.2
"""

from datetime import datetime, timezone
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List, Optional

from src.models import AnalysisData, AnalysisResult


class ReportGenerator:
    """
    Generates structured, JSON-compatible analysis reports from AnalysisResult.
    """

    @staticmethod
    def format_score(score: float) -> str:
        """
        Format a single score value [0.0, 1.0] as a percentage string with 2 decimal places.

        Formula: f"{score * 100:.2f}%"
        Examples:
            0.855 -> "85.50%"
            0.145 -> "14.50%"
            0.0   -> "0.00%"
            1.0   -> "100.00%"
            0.5   -> "50.00%"

        Args:
            score: Score value between 0.0 and 1.0.

        Returns:
            Formatted percentage string.
        """
        return f"{score * 100:.2f}%"

    def format_scores(self, auth_score: float, fake_score: float) -> Dict[str, str]:
        """
        Format authenticity and fake scores as a dictionary of percentage strings.

        Args:
            auth_score: Authenticity score between 0.0 and 1.0.
            fake_score: Fake probability score between 0.0 and 1.0.

        Returns:
            Dictionary with 'authenticity_score' and 'fake_score' formatted strings.
        """
        return {
            "authenticity_score": self.format_score(auth_score),
            "fake_score": self.format_score(fake_score),
        }

    @staticmethod
    def format_timestamp(dt: Optional[datetime] = None) -> str:
        """
        Format a datetime as an ISO 8601 UTC timestamp string ending with 'Z'.

        Format: YYYY-MM-DDTHH:MM:SSZ (e.g. 2026-08-28T20:30:45Z)

        Args:
            dt: Optional datetime object. If None, current UTC time is used.

        Returns:
            ISO 8601 UTC timestamp string.
        """
        if dt is None:
            dt = datetime.now(timezone.utc)
        elif dt.tzinfo is None:
            # Assume UTC if naive datetime
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            # Convert to UTC
            dt = dt.astimezone(timezone.utc)

        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _serialize_analysis_data(self, data: Any) -> Dict[str, Any]:
        """
        Serialize AnalysisData or arbitrary category dict to a JSON-compatible dictionary.

        Args:
            data: AnalysisData instance or dictionary.

        Returns:
            JSON-compatible dictionary representation of collected categories.
        """
        if data is None:
            return {
                "network": None,
                "dom": None,
                "javascript": None,
                "visual": None,
                "ssl": None,
            }

        if is_dataclass(data):
            raw_dict = asdict(data)
        elif isinstance(data, dict):
            raw_dict = dict(data)
        else:
            raw_dict = {}

        return {
            "network": raw_dict.get("network"),
            "dom": raw_dict.get("dom"),
            "javascript": raw_dict.get("javascript"),
            "visual": raw_dict.get("visual"),
            "ssl": raw_dict.get("ssl"),
        }

    def generate_report(self, result: AnalysisResult) -> Dict[str, Any]:
        """
        Generate a structured, JSON-compatible report dictionary from AnalysisResult.

        Args:
            result: AnalysisResult instance.

        Returns:
            Dictionary containing all required report fields per the specification:
            - authenticity_score: Percentage string (e.g., "85.50%")
            - fake_score: Percentage string (e.g., "14.50%")
            - confidence_indicator: "HIGH", "MEDIUM", or "LOW"
            - url: Target website URL
            - analysis_data: Serialized data dictionary
            - timestamps: Dict containing 'analysis_start' and 'analysis_completion'
            - top_factors: List of top 3 authenticity factors
            - suspicious_indicators: List of suspicious factors if fake_score > 0.5
            - error_message: Error string or None
        """
        scores_formatted = self.format_scores(result.authenticity_score, result.fake_score)

        return {
            "authenticity_score": scores_formatted["authenticity_score"],
            "fake_score": scores_formatted["fake_score"],
            "confidence_indicator": str(result.confidence_indicator),
            "url": str(result.url),
            "analysis_data": self._serialize_analysis_data(result.analysis_data),
            "timestamps": dict(result.timestamps) if result.timestamps is not None else {},
            "top_factors": list(result.top_factors) if result.top_factors is not None else [],
            "suspicious_indicators": (
                list(result.suspicious_indicators) if result.suspicious_indicators is not None else []
            ),
            "error_message": result.error_message,
        }
