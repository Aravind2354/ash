"""Unit tests for main analysis orchestration in src/authenticity_detector.py.

Validates Task 12.1 and Requirements: 5.3, 7.2, 8.3, 9.3
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from src.authenticity_detector import AuthenticityDetector, analyze_website
from src.models import (
    AnalysisData,
    AnalysisResult,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
)


@pytest.fixture
def sample_analysis_data():
    return AnalysisData(
        network=NetworkData(request_count=10, unique_domains=["example.com"], protocol_distribution={"https": 10}, failed=False),
        dom=DOMData(html_content="<html></html>", structure_metrics={"total_elements": 10}, failed=False),
        javascript=JavaScriptData(script_count=2, dom_modifications=1, external_api_calls=0, failed=False),
        visual=VisualData(screenshot_path="/tmp/shot.png", layout_characteristics={}, failed=False),
        ssl=SSLData(issuer="DigiCert", expiration_date="2030-01-01T00:00:00Z", chain_valid=True, failed=False),
        timeout_occurred=False,
        categories_collected=5,
    )


@pytest.fixture
def mock_validator():
    val = MagicMock()
    val.validate_url.return_value = (True, None)
    return val


@pytest.fixture
def mock_sandbox():
    sb = MagicMock()
    sb.load_url = AsyncMock(return_value=True)
    return sb


@pytest.fixture
def mock_sandbox_manager(mock_sandbox):
    mgr = MagicMock()
    mgr.create_sandbox = AsyncMock(return_value=mock_sandbox)
    mgr.validate_isolation = AsyncMock(return_value=(True, ""))
    mgr.terminate_sandbox = AsyncMock()
    return mgr


@pytest.fixture
def mock_data_collector(sample_analysis_data):
    dc = MagicMock()
    dc.collect_all = AsyncMock(return_value=sample_analysis_data)
    dc.collect_ssl_data = AsyncMock(return_value=sample_analysis_data.ssl)
    return dc


@pytest.fixture
def mock_ai_engine():
    ai = MagicMock()
    scores = MagicMock()
    scores.authenticity_score = 0.85
    scores.fake_score = 0.15
    scores.top_factors = ["Factor 1", "Factor 2"]
    scores.suspicious_indicators = []
    ai.analyze.return_value = scores
    ai.calculate_confidence.return_value = "HIGH"
    return ai


@pytest.fixture
def mock_report_generator():
    rg = MagicMock()
    rg.generate_report.return_value = {
        "authenticity_score": "85.00%",
        "fake_score": "15.00%",
        "confidence_indicator": "HIGH",
        "url": "https://example.com",
        "timestamps": {"analysis_start": "2026-08-29T10:00:00Z", "analysis_completion": "2026-08-29T10:00:05Z"},
        "analysis_data": {},
        "top_factors": ["Factor 1", "Factor 2"],
        "suspicious_indicators": [],
        "error_message": None,
    }

    def _generate_partial_report(res=None, **kwargs):
        err_msg = getattr(res, "error_message", "Partial error") if res is not None else "Partial error"
        return {
            "authenticity_score": None,
            "fake_score": None,
            "confidence_indicator": getattr(res, "confidence_indicator", "LOW") if res is not None else "LOW",
            "url": getattr(res, "url", "https://example.com") if res is not None else "https://example.com",
            "timestamps": getattr(res, "timestamps", {}) if res is not None else {},
            "analysis_data": getattr(res, "analysis_data", None) if res is not None else None,
            "top_factors": getattr(res, "top_factors", []) if res is not None else [],
            "suspicious_indicators": getattr(res, "suspicious_indicators", []) if res is not None else [],
            "error_message": err_msg,
        }

    rg.generate_partial_report.side_effect = _generate_partial_report
    return rg


class TestTask12_1_MainAnalysisOrchestration:
    """Unit tests for Task 12.1 main analysis orchestration."""

    def test_valid_url_follows_orchestration_path(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """1. Valid URL follows complete orchestration path in correct order."""
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website("https://example.com")

        mock_validator.validate_url.assert_called_once_with("https://example.com")
        mock_sandbox_manager.create_sandbox.assert_called_once()
        mock_sandbox_manager.validate_isolation.assert_called_once()
        mock_data_collector.collect_all.assert_called_once()
        mock_ai_engine.analyze.assert_called_once()
        mock_report_generator.generate_report.assert_called_once()
        assert isinstance(res, dict)
        assert res["authenticity_score"] == "85.00%"

    def test_invalid_url_rejected_before_sandbox_initialization(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """2. Invalid URL is rejected before sandbox initialization."""
        mock_validator.validate_url.return_value = (False, "Invalid URL scheme")
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website("ftp://invalid.example")

        mock_validator.validate_url.assert_called_once_with("ftp://invalid.example")
        mock_sandbox_manager.create_sandbox.assert_not_called()
        assert isinstance(res, dict)
        assert res["authenticity_score"] is None
        assert "Invalid URL scheme" in res["error_message"]

    def test_sandbox_created_for_valid_url(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """3. Sandbox is created for a valid URL."""
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website("https://valid.example")

        mock_sandbox_manager.create_sandbox.assert_called_once()

    def test_url_loaded_into_sandbox(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_sandbox,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """4. URL is loaded into sandbox context."""
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website("https://target.example")

        mock_sandbox.load_url.assert_called_once_with("https://target.example", timeout=30)

    def test_data_collector_invoked(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_sandbox,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """5. DataCollector is invoked with the sandbox."""
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website("https://example.com")

        mock_data_collector.collect_all.assert_called_once_with(mock_sandbox, timeout=60)

    def test_ai_engine_invoked_with_collected_data(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        sample_analysis_data,
        mock_ai_engine,
        mock_report_generator,
    ):
        """6. AIAnalysisEngine is invoked with collected AnalysisData."""
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website("https://example.com")

        mock_ai_engine.analyze.assert_called_once_with(sample_analysis_data)

    def test_report_generator_invoked(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """7. ReportGenerator is invoked with AnalysisResult."""
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website("https://example.com")

        mock_report_generator.generate_report.assert_called_once()
        arg = mock_report_generator.generate_report.call_args[0][0]
        assert isinstance(arg, AnalysisResult)
        assert arg.url == "https://example.com"
        assert arg.authenticity_score == 0.85

    def test_returned_value_is_dictionary(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """8. Returned value is a dictionary."""
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = analyze_website("https://example.com", detector=detector)

        assert isinstance(res, dict)

    def test_required_result_fields_present(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """9. Required result fields (Requirement 5.3) are present."""
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website("https://example.com")

        required = ["authenticity_score", "fake_score", "confidence_indicator", "error_message"]
        for key in required:
            assert key in res, f"Missing required key: {key}"

    def test_sandbox_cleanup_occurs_after_successful_execution(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_sandbox,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """10. Sandbox cleanup occurs after successful execution."""
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website("https://example.com")

        mock_sandbox_manager.terminate_sandbox.assert_called_once_with(mock_sandbox)

    def test_sandbox_cleanup_occurs_after_failure(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_sandbox,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """11. Sandbox cleanup occurs in finally block after load URL failure."""
        mock_sandbox.load_url.side_effect = RuntimeError("Navigation timeout")
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website("https://timeout.example")

        mock_sandbox_manager.terminate_sandbox.assert_called_once_with(mock_sandbox)
        mock_report_generator.generate_partial_report.assert_called_once()
        assert isinstance(res, dict)


class TestTask12_3_ExceptionHandlingAndLogging:
    """Unit tests for Task 12.3: Exception handling and logging (Requirements 5.4, 5.5, Property 18)."""

    def test_unhandled_exception_caught_and_logged(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """Task 12.3-1: Unhandled exception during sandbox creation is caught, logged, and returns structured error dict."""
        mock_sandbox_manager.create_sandbox.side_effect = TypeError("Unexpected null context")
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        with patch.object(detector.logger, "error") as mock_log_error:
            res = detector.analyze_website("https://example.com")

        mock_log_error.assert_called()
        assert res["exception_type"] == "TypeError"
        assert res["failed_operation"] == "sandbox initialization"
        assert "TypeError" in res["error_message"]
        assert "sandbox initialization" in res["error_message"]

    def test_exception_during_ai_analysis(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """Task 12.3-2: Exception during AI analysis sets failed_operation='AI analysis' and exception_type='RuntimeError'."""
        mock_ai_engine.analyze.side_effect = RuntimeError("XGBoost prediction failure")
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        with patch.object(detector.logger, "error") as mock_log_error:
            res = detector.analyze_website("https://example.com")

        mock_log_error.assert_called()
        assert res["exception_type"] == "RuntimeError"
        assert res["failed_operation"] == "AI analysis"
        assert "AI analysis" in res["error_message"]

    def test_exception_response_contains_exception_type(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """Task 12.3-3 & Property 18: Returned error dictionary explicitly contains exception_type key matching type name."""
        mock_data_collector.collect_all.side_effect = ValueError("Corrupted memory buffer")
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website("https://example.com")

        assert "exception_type" in res
        assert res["exception_type"] == "ValueError"

    def test_exception_response_contains_failed_operation(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """Task 12.3-4 & Property 18: Returned error dictionary explicitly contains failed_operation key matching operation phase."""
        mock_data_collector.collect_all.side_effect = AttributeError("Missing network probe")
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website("https://example.com")

        assert "failed_operation" in res
        assert res["failed_operation"] == "data collection"

    def test_fallback_handler_when_error_handling_fails(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """Task 12.3-5 & Requirement 5.4: Fallback mechanism returns emergency error dict if error handler itself raises exception."""
        mock_data_collector.collect_all.side_effect = RuntimeError("Primary collection failure")
        mock_report_generator.generate_partial_report.side_effect = MemoryError("Report generator OOM")

        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website("https://example.com")

        assert isinstance(res, dict)
        assert res["authenticity_score"] is None
        assert res["fake_score"] is None
        assert res["confidence_indicator"] == "LOW"
        assert res["exception_type"] == "RuntimeError"
        assert res["failed_operation"] == "data collection"
        assert "Critical error" in res["error_message"]

    def test_error_response_latency_under_500ms(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """Task 12.3-6 & Requirement 5.5: Exception handling path returns error dictionary in under 500 milliseconds (0.5s)."""
        import time

        mock_sandbox_manager.create_sandbox.side_effect = RuntimeError("Sandbox failure")
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        start = time.perf_counter()
        res = detector.analyze_website("https://example.com")
        elapsed = time.perf_counter() - start

        assert elapsed < 0.5, f"Error response took {elapsed:.4f}s, exceeding 0.5s limit"
        assert isinstance(res, dict)

    def test_cleanup_still_occurs_after_exception(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_sandbox,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """Task 12.3-7: Sandbox cleanup occurs in finally block even when AI analysis raises an unhandled exception."""
        mock_ai_engine.analyze.side_effect = Exception("Fatal AI crash")
        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website("https://example.com")

        mock_sandbox_manager.terminate_sandbox.assert_called_once_with(mock_sandbox)
        assert res["exception_type"] == "Exception"
        assert res["failed_operation"] == "AI analysis"


class TestTask12_5_InsufficientDataRetry:
    """Unit tests for Task 12.5: Retry logic for insufficient data (Requirement 8.3)."""

    def test_retry_triggered_when_fewer_than_three_categories(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """1. Retry is triggered when initial collection yields fewer than 3 categories (<3)."""
        insufficient_data = AnalysisData(
            network=NetworkData(10, ["example.com"], {"https": 10}, failed=False),
            dom=None,
            javascript=None,
            visual=None,
            ssl=None,
            categories_collected=1,
        )
        sufficient_data = AnalysisData(
            network=NetworkData(10, ["example.com"], {"https": 10}, failed=False),
            dom=DOMData(html_content="<html></html>", structure_metrics={"total_elements": 10}, failed=False),
            javascript=JavaScriptData(script_count=2, dom_modifications=1, external_api_calls=0, failed=False),
            visual=None,
            ssl=None,
            categories_collected=3,
        )
        mock_data_collector.collect_all.side_effect = [insufficient_data, sufficient_data]

        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website("https://example.com")

        assert mock_data_collector.collect_all.call_count == 2

    def test_no_retry_when_three_or_more_categories(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """2. No retry is initiated when initial collection yields 3 or more categories (>=3)."""
        sufficient_data = AnalysisData(
            network=NetworkData(10, ["example.com"], {"https": 10}, failed=False),
            dom=DOMData(html_content="<html></html>", structure_metrics={"total_elements": 10}, failed=False),
            javascript=JavaScriptData(script_count=2, dom_modifications=1, external_api_calls=0, failed=False),
            visual=None,
            ssl=None,
            categories_collected=3,
        )
        mock_data_collector.collect_all.return_value = sufficient_data

        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website("https://example.com")

        assert mock_data_collector.collect_all.call_count == 1

    def test_retry_uses_90_second_timeout(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """3. Retry extends collection timeout by +30s (60s -> 90s)."""
        insufficient_data = AnalysisData(
            network=NetworkData(10, ["example.com"], {"https": 10}, failed=False),
            dom=None,
            javascript=None,
            visual=None,
            ssl=None,
            categories_collected=1,
        )
        mock_data_collector.collect_all.return_value = insufficient_data

        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website("https://example.com")

        calls = mock_data_collector.collect_all.call_args_list
        assert len(calls) == 2
        assert calls[0].kwargs.get("timeout") == 60
        assert calls[1].kwargs.get("timeout") == 90

    def test_retry_happens_exactly_once(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """4. Retry happens exactly once even if retry attempt still returns < 3 categories."""
        insufficient_data = AnalysisData(
            network=NetworkData(10, ["example.com"], {"https": 10}, failed=False),
            dom=None,
            javascript=None,
            visual=None,
            ssl=None,
            categories_collected=1,
        )
        mock_data_collector.collect_all.return_value = insufficient_data

        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website("https://example.com")

        assert mock_data_collector.collect_all.call_count == 2

    def test_retry_reuses_same_sandbox(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_sandbox,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """5. Retry reuses the already created sandbox context (no second sandbox creation)."""
        insufficient_data = AnalysisData(
            network=NetworkData(10, ["example.com"], {"https": 10}, failed=False),
            dom=None,
            javascript=None,
            visual=None,
            ssl=None,
            categories_collected=1,
        )
        mock_data_collector.collect_all.return_value = insufficient_data

        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website("https://example.com")

        mock_sandbox_manager.create_sandbox.assert_called_once()
        calls = mock_data_collector.collect_all.call_args_list
        assert calls[0].args[0] is mock_sandbox
        assert calls[1].args[0] is mock_sandbox

    def test_retry_result_used_for_analysis(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """6. The retry result (not the initial result) is passed to AIAnalysisEngine.analyze()."""
        initial_data = AnalysisData(network=NetworkData(10, ["example.com"], {"https": 10}, failed=False), categories_collected=1)
        retry_data = AnalysisData(
            network=NetworkData(10, ["example.com"], {"https": 10}, failed=False),
            dom=DOMData(html_content="<html></html>", structure_metrics={"total_elements": 10}, failed=False),
            javascript=JavaScriptData(script_count=2, dom_modifications=1, external_api_calls=0, failed=False),
            categories_collected=3,
        )
        mock_data_collector.collect_all.side_effect = [initial_data, retry_data]

        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website("https://example.com")

        mock_ai_engine.analyze.assert_called_once_with(retry_data)

    def test_retry_still_insufficient_proceeds_with_low_confidence(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """7. If retry still returns < 3 categories, analysis proceeds and confidence is calculated as LOW."""
        insufficient_data = AnalysisData(
            network=NetworkData(10, ["example.com"], {"https": 10}, failed=False),
            categories_collected=1,
        )
        mock_data_collector.collect_all.return_value = insufficient_data
        mock_ai_engine.calculate_confidence.return_value = "LOW"

        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website("https://example.com")

        mock_ai_engine.calculate_confidence.assert_called_once_with(insufficient_data)

    def test_retry_exception_uses_correct_operation_context(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """8. If retry attempt raises an exception, failed_operation is set to 'data collection retry'."""
        initial_data = AnalysisData(network=NetworkData(10, ["example.com"], {"https": 10}, failed=False), categories_collected=1)
        mock_data_collector.collect_all.side_effect = [initial_data, RuntimeError("Retry network timeout")]

        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website("https://example.com")

        assert res["exception_type"] == "RuntimeError"
        assert res["failed_operation"] == "data collection retry"

    def test_sandbox_cleanup_after_retry_failure(
        self,
        mock_validator,
        mock_sandbox_manager,
        mock_sandbox,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """9. Sandbox cleanup occurs in finally block after a retry failure."""
        initial_data = AnalysisData(network=NetworkData(10, ["example.com"], {"https": 10}, failed=False), categories_collected=1)
        mock_data_collector.collect_all.side_effect = [initial_data, Exception("Fatal retry failure")]

        detector = AuthenticityDetector(
            validator=mock_validator,
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website("https://example.com")

        mock_sandbox_manager.terminate_sandbox.assert_called_once_with(mock_sandbox)


class TestTask12_7_ValidationErrorResponses:
    """Unit tests for Task 12.7: Validation Error Responses (Requirement 9.3, Property 32)."""

    def test_validation_error_missing_scheme_response(
        self,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """1. Missing scheme returns structured validation error response and prevents sandbox creation."""
        url = "example.com/path"
        detector = AuthenticityDetector(
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website(url)

        assert isinstance(res, dict)
        assert res["authenticity_score"] is None
        assert res["fake_score"] is None
        assert res["confidence_indicator"] == "LOW"
        assert res["url"] == url
        assert res["timestamps"] == {}
        assert res["analysis_data"] is None
        assert res["top_factors"] == []
        assert res["suspicious_indicators"] == []
        assert "URL validation failed" in res["error_message"]
        assert "scheme" in res["error_message"].lower()
        mock_sandbox_manager.create_sandbox.assert_not_called()

    def test_validation_error_missing_host_response(
        self,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """2. Missing host returns structured validation error response and prevents sandbox creation."""
        url = "https://"
        detector = AuthenticityDetector(
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website(url)

        assert isinstance(res, dict)
        assert res["authenticity_score"] is None
        assert res["fake_score"] is None
        assert res["confidence_indicator"] == "LOW"
        assert res["url"] == url
        assert res["timestamps"] == {}
        assert res["analysis_data"] is None
        assert res["top_factors"] == []
        assert res["suspicious_indicators"] == []
        assert "URL validation failed" in res["error_message"]
        assert "missing host component" in res["error_message"].lower()
        mock_sandbox_manager.create_sandbox.assert_not_called()

    @pytest.mark.parametrize(
        "url,expected_proto",
        [
            ("ftp://example.com", "ftp"),
            ("file:///etc/passwd", "file"),
            ("javascript:alert(1)", "javascript"),
        ],
    )
    def test_validation_error_unsupported_protocol_response(
        self,
        url,
        expected_proto,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """3. Unsupported protocols return structured validation error and prevent sandbox creation."""
        detector = AuthenticityDetector(
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website(url)

        assert isinstance(res, dict)
        assert res["authenticity_score"] is None
        assert res["fake_score"] is None
        assert res["confidence_indicator"] == "LOW"
        assert res["url"] == url
        assert res["timestamps"] == {}
        assert res["analysis_data"] is None
        assert res["top_factors"] == []
        assert res["suspicious_indicators"] == []
        assert "URL validation failed" in res["error_message"]
        assert "scheme must be http or https" in res["error_message"].lower()
        assert expected_proto in res["error_message"].lower()
        mock_sandbox_manager.create_sandbox.assert_not_called()

    def test_validation_error_localhost_rejection_response(
        self,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """4. Localhost URL returns structured validation error and prevents sandbox creation."""
        url = "http://localhost"
        detector = AuthenticityDetector(
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website(url)

        assert isinstance(res, dict)
        assert res["authenticity_score"] is None
        assert res["fake_score"] is None
        assert res["confidence_indicator"] == "LOW"
        assert res["url"] == url
        assert res["timestamps"] == {}
        assert res["analysis_data"] is None
        assert res["top_factors"] == []
        assert res["suspicious_indicators"] == []
        assert "URL validation failed" in res["error_message"]
        assert "localhost" in res["error_message"].lower()
        mock_sandbox_manager.create_sandbox.assert_not_called()

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://192.168.1.1",
        ],
    )
    def test_validation_error_private_ipv4_rejection_response(
        self,
        url,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """5. Private IPv4 URLs return structured validation error and prevent sandbox creation."""
        detector = AuthenticityDetector(
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website(url)

        assert isinstance(res, dict)
        assert res["authenticity_score"] is None
        assert res["fake_score"] is None
        assert res["confidence_indicator"] == "LOW"
        assert res["url"] == url
        assert res["timestamps"] == {}
        assert res["analysis_data"] is None
        assert res["top_factors"] == []
        assert res["suspicious_indicators"] == []
        assert "URL validation failed" in res["error_message"]
        assert "private ip address" in res["error_message"].lower()
        mock_sandbox_manager.create_sandbox.assert_not_called()

    @pytest.mark.parametrize(
        "url",
        [
            "http://[::1]",
            "http://[fc00::1]",
        ],
    )
    def test_validation_error_private_ipv6_rejection_response(
        self,
        url,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """6. Private IPv6 URLs return structured validation error and prevent sandbox creation."""
        detector = AuthenticityDetector(
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website(url)

        assert isinstance(res, dict)
        assert res["authenticity_score"] is None
        assert res["fake_score"] is None
        assert res["confidence_indicator"] == "LOW"
        assert res["url"] == url
        assert res["timestamps"] == {}
        assert res["analysis_data"] is None
        assert res["top_factors"] == []
        assert res["suspicious_indicators"] == []
        assert "URL validation failed" in res["error_message"]
        assert "private ip address" in res["error_message"].lower()
        mock_sandbox_manager.create_sandbox.assert_not_called()

    def test_validation_error_overly_long_url_response(
        self,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """7. URLs exceeding 2048 characters return structured validation error and prevent sandbox creation."""
        url = "https://example.com/" + ("a" * 2050)
        detector = AuthenticityDetector(
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        res = detector.analyze_website(url)

        assert isinstance(res, dict)
        assert res["authenticity_score"] is None
        assert res["fake_score"] is None
        assert res["confidence_indicator"] == "LOW"
        assert res["url"] == url
        assert res["timestamps"] == {}
        assert res["analysis_data"] is None
        assert res["top_factors"] == []
        assert res["suspicious_indicators"] == []
        assert "URL validation failed" in res["error_message"]
        assert "2048" in res["error_message"]
        mock_sandbox_manager.create_sandbox.assert_not_called()

    @pytest.mark.parametrize(
        "invalid_url",
        [
            "example.com/path",
            "https://",
            "ftp://example.com",
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "https://example.com/" + ("a" * 2050),
        ],
    )
    def test_validation_error_prevents_sandbox_creation(
        self,
        invalid_url,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """8. Core Property 32 check: Sandbox creation is explicitly prevented for all representative invalid URLs."""
        detector = AuthenticityDetector(
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        detector.analyze_website(invalid_url)

        mock_sandbox_manager.create_sandbox.assert_not_called()

    def test_validation_error_response_latency_under_500ms(
        self,
        mock_sandbox_manager,
        mock_data_collector,
        mock_ai_engine,
        mock_report_generator,
    ):
        """9. Requirement 5.5: Validation error response is returned in under 500 milliseconds (0.5s)."""
        import time

        url = "ftp://invalid-fast-fail.example"
        detector = AuthenticityDetector(
            sandbox_manager=mock_sandbox_manager,
            data_collector=mock_data_collector,
            ai_engine=mock_ai_engine,
            report_generator=mock_report_generator,
        )

        start = time.perf_counter()
        res = detector.analyze_website(url)
        elapsed = time.perf_counter() - start

        assert elapsed < 0.5, f"Validation error response took {elapsed:.4f}s, exceeding 0.5s limit"
        assert isinstance(res, dict)
        assert res["authenticity_score"] is None
        mock_sandbox_manager.create_sandbox.assert_not_called()
