"""Website Authenticity Detection System - Main Orchestration.

This module provides the main orchestration logic for analyzing website authenticity.
It coordinates input validation, sandbox execution, data collection, AI analysis,
and report generation.

Requirements: 5.3, 5.4, 5.5, 7.2, 8.3, 9.3
"""

import asyncio
import inspect
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from src.input_validator import InputValidator
from src.sandbox import SandboxManager, Sandbox
from src.data_collector import DataCollector
from src.ai_analyzer import AIAnalysisEngine
from src.report_generator import ReportGenerator
from src.models import AnalysisResult
from config.logging_config import get_logger


# Collection Timeout Constants (Requirements 8.1, 8.3)
INITIAL_COLLECTION_TIMEOUT = 60
RETRY_COLLECTION_TIMEOUT = INITIAL_COLLECTION_TIMEOUT + 30


class AuthenticityDetector:
    """Orchestrates website authenticity analysis pipeline."""

    def __init__(
        self,
        validator: Optional[InputValidator] = None,
        sandbox_manager: Optional[SandboxManager] = None,
        data_collector: Optional[DataCollector] = None,
        ai_engine: Optional[AIAnalysisEngine] = None,
        report_generator: Optional[ReportGenerator] = None,
    ):
        """Initialize AuthenticityDetector with components.

        Args:
            validator: Optional InputValidator instance.
            sandbox_manager: Optional SandboxManager instance.
            data_collector: Optional DataCollector instance.
            ai_engine: Optional AIAnalysisEngine instance.
            report_generator: Optional ReportGenerator instance.
        """
        self.validator = validator or InputValidator()
        self.sandbox_manager = sandbox_manager
        self.data_collector = data_collector or DataCollector()
        self.ai_engine = ai_engine or AIAnalysisEngine()
        self.report_generator = report_generator or ReportGenerator()
        self.logger = get_logger(__name__)

    def analyze_website(self, url: str) -> Dict[str, Any]:
        """Synchronous wrapper for website authenticity analysis (Requirement 5.3).

        Args:
            url: Target website URL string.

        Returns:
            Dictionary containing report keys: authenticity_score, fake_score,
            confidence_indicator, url, timestamps, analysis_data, top_factors,
            suspicious_indicators, error_message.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Running inside existing event loop
                try:
                    import nest_asyncio
                    nest_asyncio.apply()
                    return loop.run_until_complete(self.analyze_website_async(url))
                except Exception:
                    future = asyncio.run_coroutine_threadsafe(
                        self.analyze_website_async(url), loop
                    )
                    return future.result()
            else:
                return loop.run_until_complete(self.analyze_website_async(url))
        except RuntimeError:
            return asyncio.run(self.analyze_website_async(url))
        except Exception as exc:
            # Synchronous wrapper emergency fallback
            return self._build_emergency_fallback(url, "synchronous wrapper", exc)

    async def analyze_website_async(self, url: str) -> Dict[str, Any]:
        """Asynchronously orchestrates website authenticity analysis.

        Execution Flow:
        1. Validate URL BEFORE sandbox creation. If invalid -> return error dict fast (<500ms).
        2. Record analysis_start timestamp in ISO 8601 UTC format.
        3. Create & initialize sandbox context.
        4. Validate isolation boundary.
        5. Load target URL in sandbox.
        6. Collect AnalysisData via DataCollector.
        7. Evaluate categories collected. If < 3: perform ONE retry with +30s timeout extension.
        8. Send AnalysisData to AIAnalysisEngine.analyze().
        9. Calculate confidence via AIAnalysisEngine.calculate_confidence().
        10. Build AnalysisResult dataclass.
        11. Generate final report via ReportGenerator.
        12. Record analysis_completion timestamp in ISO 8601 UTC format.
        13. Always cleanup/terminate sandbox in a finally block.
        """
        current_operation = "URL validation"

        # Step 1: Input Validation BEFORE Sandbox Creation (Requirement 9.3)
        try:
            is_valid, validation_error = self.validator.validate_url(url)
            if not is_valid:
                self.logger.warning(f"URL validation failed for {url}: {validation_error}")
                return {
                    "authenticity_score": None,
                    "fake_score": None,
                    "confidence_indicator": "LOW",
                    "url": url,
                    "timestamps": {},
                    "analysis_data": None,
                    "top_factors": [],
                    "suspicious_indicators": [],
                    "error_message": f"URL validation failed: {validation_error}",
                }
        except Exception as exc:
            return self._handle_exception(exc, current_operation, url, {})

        start_dt = datetime.now(timezone.utc)
        start_str = start_dt.isoformat().replace("+00:00", "Z")
        timestamps = {"analysis_start": start_str}

        sandbox: Optional[Sandbox] = None
        sb_manager = self.sandbox_manager or SandboxManager()

        try:
            # Top-level try block wrapping execution pipeline (Requirement 5.4)
            try:
                # Step 4: Create Sandbox
                current_operation = "sandbox initialization"
                create_res = sb_manager.create_sandbox()
                if inspect.isawaitable(create_res):
                    sandbox = await create_res
                else:
                    sandbox = create_res

                # Step 5: Validate Isolation Boundary
                current_operation = "isolation validation"
                try:
                    iso_res = sb_manager.validate_isolation()
                    if inspect.isawaitable(iso_res):
                        is_isolated, iso_msg = await iso_res
                    else:
                        is_isolated, iso_msg = iso_res

                    if not is_isolated:
                        self.logger.error(f"Isolation check failed: {iso_msg}")
                        result = AnalysisResult(
                            authenticity_score=None,
                            fake_score=None,
                            confidence_indicator="LOW",
                            url=url,
                            analysis_data=None,
                            timestamps=timestamps,
                            top_factors=[],
                            suspicious_indicators=[],
                            error_message=f"Isolation boundary check failed: {iso_msg}",
                        )
                        return self.report_generator.generate_partial_report(result)
                except Exception as e:
                    self.logger.warning(f"Isolation validation check exception: {e}")

                # Step 6: Load Target URL
                current_operation = "URL loading"
                load_res = sandbox.load_url(url, timeout=30)
                if inspect.isawaitable(load_res):
                    loaded = await load_res
                else:
                    loaded = load_res

                if not loaded:
                    result = AnalysisResult(
                        authenticity_score=None,
                        fake_score=None,
                        confidence_indicator="LOW",
                        url=url,
                        analysis_data=None,
                        timestamps=timestamps,
                        top_factors=[],
                        suspicious_indicators=[],
                        error_message=f"Failed to load URL: {url}",
                    )
                    return self.report_generator.generate_partial_report(result)

                # Step 7: Collect AnalysisData
                current_operation = "data collection"
                collect_res = self.data_collector.collect_all(sandbox, timeout=INITIAL_COLLECTION_TIMEOUT)
                if inspect.isawaitable(collect_res):
                    analysis_data = await collect_res
                else:
                    analysis_data = collect_res

                # SSL Data Collection
                try:
                    ssl_res = self.data_collector.collect_ssl_data(url)
                    if inspect.isawaitable(ssl_res):
                        ssl_data = await ssl_res
                    else:
                        ssl_data = ssl_res
                    if analysis_data is not None:
                        analysis_data.ssl = ssl_data
                except Exception:
                    pass

                categories_count = 0
                if analysis_data is not None:
                    categories_count = sum(
                        1 for cat in [
                            analysis_data.network,
                            analysis_data.dom,
                            analysis_data.javascript,
                            analysis_data.visual,
                            analysis_data.ssl,
                        ] if cat is not None and getattr(cat, "failed", False) is False
                    )
                    analysis_data.categories_collected = categories_count

                # Step 8-9: Insufficient Data Retry (Requirement 8.3)
                if categories_count < 3:
                    current_operation = "data collection retry"
                    self.logger.warning(
                        f"Insufficient categories collected ({categories_count}/5). Initiating ONE retry with +30s extended timeout ({RETRY_COLLECTION_TIMEOUT}s)."
                    )
                    retry_res = self.data_collector.collect_all(sandbox, timeout=RETRY_COLLECTION_TIMEOUT)
                    if inspect.isawaitable(retry_res):
                        retry_data = await retry_res
                    else:
                        retry_data = retry_res

                    if analysis_data is not None and getattr(analysis_data, "ssl", None) is not None:
                        retry_data.ssl = analysis_data.ssl

                    retry_count = sum(
                        1 for cat in [
                            retry_data.network,
                            retry_data.dom,
                            retry_data.javascript,
                            retry_data.visual,
                            retry_data.ssl,
                        ] if cat is not None and getattr(cat, "failed", False) is False
                    )
                    retry_data.categories_collected = retry_count
                    analysis_data = retry_data
                    categories_count = retry_count

                # Step 10: AI Analysis
                current_operation = "AI analysis"
                scores = self.ai_engine.analyze(analysis_data)
                confidence = self.ai_engine.calculate_confidence(analysis_data)
                auth_score = scores.authenticity_score
                fake_score = scores.fake_score
                top_factors = scores.top_factors
                suspicious_indicators = scores.suspicious_indicators
                error_msg = None

                end_dt = datetime.now(timezone.utc)
                end_str = end_dt.isoformat().replace("+00:00", "Z")
                timestamps["analysis_completion"] = end_str

                # Step 11: Report Generation
                current_operation = "report generation"
                result = AnalysisResult(
                    authenticity_score=auth_score,
                    fake_score=fake_score,
                    confidence_indicator=confidence,
                    url=url,
                    analysis_data=analysis_data,
                    timestamps=timestamps,
                    top_factors=top_factors,
                    suspicious_indicators=suspicious_indicators,
                    error_message=error_msg,
                )

                if error_msg or auth_score is None:
                    return self.report_generator.generate_partial_report(result)
                else:
                    return self.report_generator.generate_report(result)

            except Exception as exc:
                # Top-level exception handler (Requirement 5.4, Property 18)
                return self._handle_exception(exc, current_operation, url, timestamps)

        finally:
            # Step 15: Always Cleanup Sandbox
            current_operation = "sandbox cleanup"
            if sandbox is not None or self.sandbox_manager is not None:
                try:
                    term_res = sb_manager.terminate_sandbox(sandbox)
                    if inspect.isawaitable(term_res):
                        await term_res
                except Exception as e:
                    self.logger.error(f"Error during sandbox termination: {e}")

    def _handle_exception(
        self,
        exc: Exception,
        operation: str,
        url: str,
        timestamps: Dict[str, str],
    ) -> Dict[str, Any]:
        """Catches and logs exception information, returning structured error dict with fallback.

        Validates: Requirements 5.4, 5.5, Property 18
        """
        try:
            exc_type = type(exc).__name__
            exc_msg = str(exc)

            # Log exception type, message, and failed operation (Requirement 5.4)
            self.logger.error(
                f"Exception during '{operation}' for URL '{url}': [{exc_type}] {exc_msg}",
                extra={
                    "extra_fields": {
                        "exception_type": exc_type,
                        "exception_message": exc_msg,
                        "failed_operation": operation,
                        "url": url,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                },
            )

            err_summary = f"Operation '{operation}' failed with {exc_type}: {exc_msg}" if exc_msg else f"Operation '{operation}' failed with {exc_type}"

            result = AnalysisResult(
                authenticity_score=None,
                fake_score=None,
                confidence_indicator="LOW",
                url=url,
                analysis_data=None,
                timestamps=timestamps,
                top_factors=[],
                suspicious_indicators=[],
                error_message=err_summary,
            )

            report = self.report_generator.generate_partial_report(result)
            report["exception_type"] = exc_type
            report["failed_operation"] = operation
            return report

        except Exception as fallback_exc:
            # Fallback mechanism if error handling code itself fails (Requirement 5.4)
            return self._build_emergency_fallback(url, operation, exc, fallback_exc)

    def _build_emergency_fallback(
        self,
        url: str,
        operation: str,
        exc: Exception,
        fallback_exc: Optional[Exception] = None,
    ) -> Dict[str, Any]:
        """Emergency fallback response when normal error dictionary generation fails.

        Validates Requirement 5.4 fallback mechanism.
        """
        exc_type = type(exc).__name__
        try:
            self.logger.critical(
                f"Emergency fallback triggered for '{operation}' due to secondary exception: {fallback_exc}"
            )
        except Exception:
            pass

        return {
            "authenticity_score": None,
            "fake_score": None,
            "confidence_indicator": "LOW",
            "url": str(url),
            "timestamps": {},
            "analysis_data": None,
            "top_factors": [],
            "suspicious_indicators": [],
            "error_message": f"Critical error during '{operation}' [{exc_type}]",
            "exception_type": exc_type,
            "failed_operation": operation,
        }


def analyze_website(url: str, detector: Optional[AuthenticityDetector] = None) -> Dict[str, Any]:
    """Public API function for website authenticity analysis (Requirement 5.3).

    Args:
        url: Target website URL string.
        detector: Optional AuthenticityDetector instance for injection/testing.

    Returns:
        Dictionary containing authenticity_score, fake_score, confidence_indicator,
        error_message, and all report fields.
    """
    det = detector or AuthenticityDetector()
    return det.analyze_website(url)
