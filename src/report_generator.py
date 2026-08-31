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

import json
from datetime import datetime, timezone
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import jsonschema

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

    def export_json(self, result: AnalysisResult) -> str:
        """
        Export analysis report as a formatted JSON string validated against report_schema.json.

        Task 10.3 (Requirement 7.5, Property 26):
        1. Generates report dictionary via generate_report(result)
        2. Loads src/report_schema.json
        3. Validates report dictionary against JSON Schema using jsonschema.validate()
        4. Serializes validated report into a JSON string using json.dumps()

        Args:
            result: AnalysisResult object to export.

        Returns:
            Validated JSON string representation of the analysis report.

        Raises:
            jsonschema.exceptions.ValidationError: If report dictionary violates report_schema.json.
        """
        report_dict = self.generate_report(result)

        schema_path = Path(__file__).parent / "report_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        format_checker = jsonschema.FormatChecker()
        if "uri" not in format_checker.checkers:
            @format_checker.checks("uri")
            def _check_uri(val: Any) -> bool:
                if not isinstance(val, str):
                    return True
                from urllib.parse import urlparse
                parsed = urlparse(val)
                return bool(parsed.scheme and (parsed.netloc or parsed.path))

        jsonschema.validate(instance=report_dict, schema=schema, format_checker=format_checker)

        return json.dumps(report_dict, indent=2)

    def generate_partial_report(
        self,
        result: Optional[AnalysisResult] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate a partial structured report dictionary preserving valid fields and marking missing/failed fields.

        Task 10.5 (Requirement 7.6, Property 27):
        - Preserves all valid report fields
        - Marks missing or ungeneratable fields as None (or empty lists for factor lists)
        - Returns a descriptive error_message listing every field that could not be generated

        Args:
            result: Optional AnalysisResult instance (may have missing/invalid fields).
            **kwargs: Additional parameters for customization or fallback.

        Returns:
            Dictionary containing partial report fields and failure tracking in error_message.
        """
        failed_fields: List[str] = []

        # 1. Scores (authenticity_score, fake_score)
        auth_score_val = None
        fake_score_val = None
        if result is not None and hasattr(result, "authenticity_score") and hasattr(result, "fake_score"):
            try:
                auth = result.authenticity_score
                fake = result.fake_score
                if (
                    isinstance(auth, (int, float))
                    and isinstance(fake, (int, float))
                    and not isinstance(auth, bool)
                    and not isinstance(fake, bool)
                ):
                    scores_formatted = self.format_scores(float(auth), float(fake))
                    auth_score_val = scores_formatted["authenticity_score"]
                    fake_score_val = scores_formatted["fake_score"]
                else:
                    failed_fields.extend(["authenticity_score", "fake_score"])
            except Exception:
                failed_fields.extend(["authenticity_score", "fake_score"])
        else:
            failed_fields.extend(["authenticity_score", "fake_score"])

        # 2. Confidence Indicator
        conf_val = None
        if result is not None and getattr(result, "confidence_indicator", None) is not None:
            try:
                ci_str = str(result.confidence_indicator).strip()
                if ci_str and ci_str.upper() in ("HIGH", "MEDIUM", "LOW"):
                    conf_val = ci_str.upper()
                elif ci_str:
                    conf_val = ci_str
                else:
                    failed_fields.append("confidence_indicator")
            except Exception:
                failed_fields.append("confidence_indicator")
        else:
            failed_fields.append("confidence_indicator")

        # 3. Target URL
        url_val = None
        if result is not None and getattr(result, "url", None) is not None:
            try:
                u_str = str(result.url).strip()
                if u_str:
                    url_val = u_str
                else:
                    failed_fields.append("url")
            except Exception:
                failed_fields.append("url")
        else:
            failed_fields.append("url")

        # 4. Analysis Data
        analysis_data_val = None
        if result is not None and getattr(result, "analysis_data", None) is not None:
            try:
                analysis_data_val = self._serialize_analysis_data(result.analysis_data)
            except Exception:
                analysis_data_val = {
                    "network": None,
                    "dom": None,
                    "javascript": None,
                    "visual": None,
                    "ssl": None,
                }
                failed_fields.append("analysis_data")
        else:
            analysis_data_val = {
                "network": None,
                "dom": None,
                "javascript": None,
                "visual": None,
                "ssl": None,
            }
            if result is None or not hasattr(result, "analysis_data"):
                failed_fields.append("analysis_data")

        # 5. Timestamps
        timestamps_val = None
        if result is not None and getattr(result, "timestamps", None) is not None:
            try:
                if isinstance(result.timestamps, dict):
                    timestamps_val = dict(result.timestamps)
                    if not timestamps_val or "analysis_start" not in timestamps_val or "analysis_completion" not in timestamps_val:
                        failed_fields.append("timestamps")
                else:
                    failed_fields.append("timestamps")
            except Exception:
                failed_fields.append("timestamps")
        else:
            failed_fields.append("timestamps")

        # 6. Top Factors
        top_factors_val: List[str] = []
        if result is not None and getattr(result, "top_factors", None) is not None:
            try:
                top_factors_val = list(result.top_factors)
            except Exception:
                top_factors_val = []
                failed_fields.append("top_factors")
        else:
            top_factors_val = []

        # 7. Suspicious Indicators
        susp_val: List[str] = []
        if result is not None and getattr(result, "suspicious_indicators", None) is not None:
            try:
                susp_val = list(result.suspicious_indicators)
            except Exception:
                susp_val = []
                failed_fields.append("suspicious_indicators")
        else:
            susp_val = []

        # 8. Error Message Construction
        if failed_fields:
            seen = set()
            dedup_failed = [f for f in failed_fields if not (f in seen or seen.add(f))]
            msg = f"Partial report generated. Failed fields: {dedup_failed}"
            if result is not None and getattr(result, "error_message", None):
                msg += f". Prior error: {result.error_message}"
            err_msg = msg
        else:
            err_msg = getattr(result, "error_message", None) if result is not None else None

        return {
            "authenticity_score": auth_score_val,
            "fake_score": fake_score_val,
            "confidence_indicator": conf_val,
            "url": url_val,
            "analysis_data": analysis_data_val,
            "timestamps": timestamps_val,
            "top_factors": top_factors_val,
            "suspicious_indicators": susp_val,
            "error_message": err_msg,
        }

    @staticmethod
    def format_text_summary(report_dict: Dict[str, Any]) -> str:
        """
        Generate a human-readable text summary from an analysis report dictionary.

        Args:
            report_dict: Analysis report dictionary.

        Returns:
            Formatted multi-line text summary string suitable for console output.
        """
        lines = []
        url = report_dict.get("url", "N/A")
        auth_score = report_dict.get("authenticity_score", "N/A")
        fake_score = report_dict.get("fake_score", "N/A")
        confidence = report_dict.get("confidence_indicator", "N/A")
        error = report_dict.get("error_message")

        lines.append("=" * 60)
        lines.append("        WEBSITE AUTHENTICITY ANALYSIS REPORT")
        lines.append("=" * 60)
        lines.append(f"Target URL:            {url}")
        lines.append(f"Authenticity Score:    {auth_score}")
        lines.append(f"Fake Probability:      {fake_score}")
        lines.append(f"Confidence Indicator:  {confidence}")

        if error:
            lines.append(f"Status / Error:        {error}")

        top_factors = report_dict.get("top_factors") or []
        if top_factors:
            lines.append("-" * 60)
            lines.append("Top Authenticity Factors:")
            for factor in top_factors:
                lines.append(f"  [+] {factor}")

        suspicious = report_dict.get("suspicious_indicators") or []
        if suspicious:
            lines.append("-" * 60)
            lines.append("Suspicious Risk Indicators:")
            for ind in suspicious:
                lines.append(f"  [!] {ind}")

        timestamps = report_dict.get("timestamps") or {}
        if isinstance(timestamps, dict) and timestamps:
            start = timestamps.get("analysis_start", "")
            end = timestamps.get("analysis_completion", "")
            if start or end:
                lines.append("-" * 60)
                if start:
                    lines.append(f"Started:               {start}")
                if end:
                    lines.append(f"Completed:             {end}")

        lines.append("=" * 60)
        return "\n".join(lines)

