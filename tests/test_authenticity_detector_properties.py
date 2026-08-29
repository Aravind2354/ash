"""Property-based tests for website authenticity detector API contract compliance.

Validates Task 12.2, 12.4 and Requirements: 5.3, 5.4, Property 17, Property 18
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from hypothesis import given, settings, HealthCheck, strategies as st

from src.authenticity_detector import AuthenticityDetector, analyze_website
from src.models import (
    AnalysisData,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
)


REQUIRED_CONTRACT_KEYS = {
    "authenticity_score",
    "fake_score",
    "confidence_indicator",
    "error_message",
}


def _make_mock_detector(fail_collection: bool = False) -> AuthenticityDetector:
    """Helper to construct an AuthenticityDetector with fresh mock components."""
    validator = MagicMock()
    validator.validate_url.return_value = (True, None)

    sandbox = MagicMock()
    sandbox.load_url = AsyncMock(return_value=True)

    sb_manager = MagicMock()
    sb_manager.create_sandbox = AsyncMock(return_value=sandbox)
    sb_manager.validate_isolation = AsyncMock(return_value=(True, ""))
    sb_manager.terminate_sandbox = AsyncMock()

    sample_data = AnalysisData(
        network=NetworkData(10, ["example.com"], {"https": 10}, failed=False),
        dom=DOMData("<html></html>", {"total_elements": 10}, failed=False),
        javascript=JavaScriptData(2, 1, 0, failed=False),
        visual=VisualData("/tmp/shot.png", {}, failed=False),
        ssl=SSLData("DigiCert", "2030-01-01T00:00:00Z", True, failed=False),
        categories_collected=5,
    )

    data_collector = MagicMock()
    if fail_collection:
        data_collector.collect_all = AsyncMock(side_effect=RuntimeError("Mocked collection pipeline crash"))
    else:
        data_collector.collect_all = AsyncMock(return_value=sample_data)
    data_collector.collect_ssl_data = AsyncMock(return_value=sample_data.ssl)

    ai_engine = MagicMock()
    scores = MagicMock()
    scores.authenticity_score = 0.85
    scores.fake_score = 0.15
    scores.top_factors = ["Factor 1"]
    scores.suspicious_indicators = []
    ai_engine.analyze.return_value = scores
    ai_engine.calculate_confidence.return_value = "HIGH"

    report_generator = MagicMock()
    report_generator.generate_report.side_effect = lambda res, **kwargs: {
        "authenticity_score": "85.00%" if res.authenticity_score is not None else None,
        "fake_score": "15.00%" if res.fake_score is not None else None,
        "confidence_indicator": getattr(res, "confidence_indicator", "HIGH"),
        "url": getattr(res, "url", "https://example.com"),
        "timestamps": getattr(res, "timestamps", {}),
        "analysis_data": {},
        "top_factors": getattr(res, "top_factors", []),
        "suspicious_indicators": getattr(res, "suspicious_indicators", []),
        "error_message": getattr(res, "error_message", None),
        "exception_type": getattr(res, "exception_type", None),
        "failed_operation": getattr(res, "failed_operation", None),
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
            "exception_type": getattr(res, "exception_type", None) if res is not None else None,
            "failed_operation": getattr(res, "failed_operation", None) if res is not None else None,
        }

    report_generator.generate_partial_report.side_effect = _generate_partial_report

    detector = AuthenticityDetector(
        validator=validator,
        sandbox_manager=sb_manager,
        data_collector=data_collector,
        ai_engine=ai_engine,
        report_generator=report_generator,
    )
    detector.sandbox = sandbox
    return detector


# Hypothesis Strategies
valid_url_strategy = st.from_regex(
    r"^https?://[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(/.*)?$",
    fullmatch=True,
)

arbitrary_text_strategy = st.text()


class TestProperty17APIContractCompliance:
    """Property 17: API Contract Compliance (Requirement 5.3).

    For any URL input to analyze_website(), the returned dictionary SHALL contain:
    authenticity_score, fake_score, confidence_indicator, and error_message.
    """

    @given(url=arbitrary_text_strategy)
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_17_api_contract_for_any_url(self, url):
        """Property 17-1: For ANY arbitrary text input, analyze_website(url) returns a dict with all 4 required keys."""
        res = analyze_website(url)

        assert isinstance(res, dict), f"Expected dict, got {type(res)}"
        for key in REQUIRED_CONTRACT_KEYS:
            assert key in res, f"Missing required contract key '{key}' in result for URL input '{url[:30]}...'"

    @given(url=valid_url_strategy)
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_17_valid_url_contract(self, url):
        """Property 17-2: For valid URL format, analyze_website(url) with mocked components returns a dict with all 4 required keys."""
        detector = _make_mock_detector(fail_collection=False)

        res = analyze_website(url, detector=detector)

        assert isinstance(res, dict)
        for key in REQUIRED_CONTRACT_KEYS:
            assert key in res, f"Missing required contract key '{key}' for valid URL '{url}'"

    @given(url=st.one_of(st.just(""), st.just("   "), st.from_regex(r"^ftp://[a-z0-9\.]+$")))
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_17_invalid_url_contract(self, url):
        """Property 17-3: For invalid/malformed URL inputs, analyze_website(url) returns a dict with all 4 required keys."""
        res = analyze_website(url)

        assert isinstance(res, dict)
        for key in REQUIRED_CONTRACT_KEYS:
            assert key in res, f"Missing required contract key '{key}' for invalid URL '{url}'"
        assert res["authenticity_score"] is None
        assert res["fake_score"] is None
        assert res["confidence_indicator"] == "LOW"
        assert res["error_message"] is not None

    @given(url=valid_url_strategy)
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_17_error_path_contract(self, url):
        """Property 17-4: When internal pipeline raises an exception, analyze_website(url) returns a dict with all 4 required keys."""
        detector = _make_mock_detector(fail_collection=True)

        res = analyze_website(url, detector=detector)

        assert isinstance(res, dict)
        for key in REQUIRED_CONTRACT_KEYS:
            assert key in res, f"Missing required contract key '{key}' during error path for URL '{url}'"


# Hypothesis exception strategies for Property 18
exception_classes_strategy = st.sampled_from([
    RuntimeError,
    TypeError,
    ValueError,
    AttributeError,
    KeyError,
    TimeoutError,
    MemoryError,
    Exception,
])

exception_messages_strategy = st.text(min_size=1, max_size=100)

operation_stages_strategy = st.sampled_from([
    "sandbox initialization",
    "URL loading",
    "data collection",
    "data collection retry",
    "AI analysis",
    "report generation",
])


class TestProperty18ExceptionHandling:
    """Property 18: Exception Handling (Requirement 5.4).

    For any Python exception that occurs during execution, the system SHALL:
    - catch the exception
    - log its type and message
    - return an error dictionary
    - include exception type name
    - include operation description
    """

    @given(
        exc_cls=exception_classes_strategy,
        msg=exception_messages_strategy,
        op_stage=operation_stages_strategy,
        url=valid_url_strategy,
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_18_randomized_exception_handling_across_operations(
        self, exc_cls, msg, op_stage, url
    ):
        """Property 18-1: For any randomized Python exception class and message injected at any operation stage, the detector catches the exception and returns structured metadata."""
        exc_instance = exc_cls(msg)
        detector = _make_mock_detector(fail_collection=False)

        insufficient_data = AnalysisData(
            network=NetworkData(10, ["example.com"], {"https": 10}, failed=False),
            categories_collected=1,
        )

        # Inject exception based on operation stage
        if op_stage == "sandbox initialization":
            detector.sandbox_manager.create_sandbox = AsyncMock(side_effect=exc_instance)
        elif op_stage == "isolation validation":
            detector.sandbox_manager.validate_isolation = AsyncMock(side_effect=exc_instance)
        elif op_stage == "URL loading":
            detector.sandbox.load_url = AsyncMock(side_effect=exc_instance)
        elif op_stage == "data collection":
            detector.data_collector.collect_all = AsyncMock(side_effect=exc_instance)
        elif op_stage == "data collection retry":
            detector.data_collector.collect_all = AsyncMock(side_effect=[insufficient_data, exc_instance])
        elif op_stage == "AI analysis":
            detector.ai_engine.analyze.side_effect = exc_instance
        elif op_stage == "report generation":
            detector.report_generator.generate_report.side_effect = exc_instance

        res = analyze_website(url, detector=detector)

        # Core Property 18 Assertions
        assert isinstance(res, dict), f"Expected dict response for {exc_cls.__name__} in '{op_stage}'"
        assert res["exception_type"] == exc_cls.__name__, f"Expected exception_type {exc_cls.__name__}, got {res.get('exception_type')}"
        assert res["failed_operation"] == op_stage, f"Expected failed_operation {op_stage}, got {res.get('failed_operation')}"
        assert "error_message" in res
        assert res["authenticity_score"] is None
        assert res["fake_score"] is None
        assert res["confidence_indicator"] == "LOW"

    @given(
        exc_cls=exception_classes_strategy,
        msg=exception_messages_strategy,
        url=valid_url_strategy,
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_18_exception_logging(self, exc_cls, msg, url):
        """Property 18-2: For any exception during execution, the detector logger receives error information with exception type, message, and operation."""
        exc_instance = exc_cls(msg)
        detector = _make_mock_detector(fail_collection=False)
        detector.data_collector.collect_all = AsyncMock(side_effect=exc_instance)

        with patch.object(detector.logger, "error") as mock_logger_error:
            analyze_website(url, detector=detector)

        mock_logger_error.assert_called()
        call_args = mock_logger_error.call_args
        log_msg = call_args[0][0]
        assert exc_cls.__name__ in log_msg
        assert "data collection" in log_msg

    @given(
        exc_cls=exception_classes_strategy,
        msg=exception_messages_strategy,
        url=valid_url_strategy,
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_18_error_response_contains_exception_metadata(self, exc_cls, msg, url):
        """Property 18-3: The returned error response dictionary structurally contains exception_type and failed_operation metadata."""
        exc_instance = exc_cls(msg)
        detector = _make_mock_detector(fail_collection=False)
        detector.ai_engine.analyze.side_effect = exc_instance

        res = analyze_website(url, detector=detector)

        assert isinstance(res, dict)
        assert res["exception_type"] == exc_cls.__name__
        assert res["failed_operation"] == "AI analysis"
        assert "error_message" in res

    @given(
        exc_cls=exception_classes_strategy,
        op_stage=st.sampled_from(["URL loading", "data collection", "AI analysis"]),
        url=valid_url_strategy,
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_18_cleanup_after_exception(self, exc_cls, op_stage, url):
        """Property 18-4: After any exception occurring after sandbox creation, sandbox termination is guaranteed in finally block."""
        exc_instance = exc_cls("Post-creation failure")
        detector = _make_mock_detector(fail_collection=False)

        if op_stage == "URL loading":
            detector.sandbox.load_url = AsyncMock(side_effect=exc_instance)
        elif op_stage == "data collection":
            detector.data_collector.collect_all = AsyncMock(side_effect=exc_instance)
        elif op_stage == "AI analysis":
            detector.ai_engine.analyze.side_effect = exc_instance

        analyze_website(url, detector=detector)

        detector.sandbox_manager.terminate_sandbox.assert_called_once_with(detector.sandbox)

    @given(
        exc_cls=exception_classes_strategy,
        secondary_exc_cls=st.sampled_from([RuntimeError, MemoryError, TypeError, ValueError]),
        url=valid_url_strategy,
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_18_fallback_handler_property(self, exc_cls, secondary_exc_cls, url):
        """Property 18-5: When normal error response generation itself raises a secondary exception, the fallback handler returns an emergency dict cleanly."""
        exc_instance = exc_cls("Primary pipeline crash")
        secondary_exc = secondary_exc_cls("Secondary error handler crash")

        detector = _make_mock_detector(fail_collection=False)
        detector.data_collector.collect_all = AsyncMock(side_effect=exc_instance)
        detector.report_generator.generate_partial_report.side_effect = secondary_exc

        res = analyze_website(url, detector=detector)

        assert isinstance(res, dict)
        assert res["authenticity_score"] is None
        assert res["fake_score"] is None
        assert res["confidence_indicator"] == "LOW"
        assert res["exception_type"] == exc_cls.__name__
        assert res["failed_operation"] == "data collection"
        assert "Critical error" in res["error_message"]


def _make_analysis_data_with_categories(count: int) -> AnalysisData:
    """Helper to construct an AnalysisData object with exactly `count` successful categories (0..5)."""
    categories = [
        NetworkData(10, ["example.com"], {"https": 10}, failed=False),
        DOMData("<html></html>", {"total_elements": 10}, failed=False),
        JavaScriptData(2, 1, 0, failed=False),
        VisualData("/tmp/shot.png", {}, failed=False),
        SSLData("DigiCert", "2030-01-01T00:00:00Z", True, failed=False),
    ]

    selected = categories[:count]
    return AnalysisData(
        network=selected[0] if len(selected) > 0 else None,
        dom=selected[1] if len(selected) > 1 else None,
        javascript=selected[2] if len(selected) > 2 else None,
        visual=selected[3] if len(selected) > 3 else None,
        ssl=selected[4] if len(selected) > 4 else None,
        categories_collected=count,
    )


# Hypothesis strategies for Property 28
insufficient_count_strategy = st.integers(min_value=0, max_value=2)
sufficient_count_strategy = st.integers(min_value=3, max_value=5)
any_category_count_strategy = st.integers(min_value=0, max_value=5)


class TestProperty28RetryLogicForInsufficientData:
    """Property 28: Retry Logic for Insufficient Data (Requirement 8.3).

    For any website analysis where initial data collection yields fewer than 3 categories,
    the Authenticity_Detector SHALL:
    - initiate exactly ONE retry attempt
    - use an extended timeout of +30 seconds (90s total when initial is 60s)
    - reuse the same sandbox
    - perform analysis with whatever data is collected after the retry
    """

    @given(
        initial_count=insufficient_count_strategy,
        retry_count=any_category_count_strategy,
        url=valid_url_strategy,
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_28_retry_triggered_for_any_insufficient_initial_data(
        self, initial_count, retry_count, url
    ):
        """Property 28-1: For any initial category count < 3, exactly one retry is initiated."""
        initial_data = _make_analysis_data_with_categories(initial_count)
        retry_data = _make_analysis_data_with_categories(retry_count)

        detector = _make_mock_detector(fail_collection=False)
        detector.data_collector.collect_ssl_data = AsyncMock(return_value=None)
        detector.data_collector.collect_all = AsyncMock(side_effect=[initial_data, retry_data])

        analyze_website(url, detector=detector)

        assert detector.data_collector.collect_all.call_count == 2, (
            f"Expected exactly 2 collect_all calls for initial_count={initial_count}, "
            f"got {detector.data_collector.collect_all.call_count}"
        )

    @given(
        initial_count=sufficient_count_strategy,
        url=valid_url_strategy,
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_28_no_retry_for_any_sufficient_initial_data(
        self, initial_count, url
    ):
        """Property 28-2: For any initial category count >= 3, no retry attempt is initiated."""
        initial_data = _make_analysis_data_with_categories(initial_count)

        detector = _make_mock_detector(fail_collection=False)
        detector.data_collector.collect_ssl_data = AsyncMock(return_value=None)
        detector.data_collector.collect_all = AsyncMock(return_value=initial_data)

        analyze_website(url, detector=detector)

        assert detector.data_collector.collect_all.call_count == 1, (
            f"Expected exactly 1 collect_all call for initial_count={initial_count}, "
            f"got {detector.data_collector.collect_all.call_count}"
        )

    @given(
        initial_count=insufficient_count_strategy,
        retry_count=any_category_count_strategy,
        url=valid_url_strategy,
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_28_retry_uses_extended_timeout(
        self, initial_count, retry_count, url
    ):
        """Property 28-3: The retry attempt uses an extended timeout equal to initial_timeout + 30 (60s -> 90s)."""
        initial_data = _make_analysis_data_with_categories(initial_count)
        retry_data = _make_analysis_data_with_categories(retry_count)

        detector = _make_mock_detector(fail_collection=False)
        detector.data_collector.collect_ssl_data = AsyncMock(return_value=None)
        detector.data_collector.collect_all = AsyncMock(side_effect=[initial_data, retry_data])

        analyze_website(url, detector=detector)

        calls = detector.data_collector.collect_all.call_args_list
        initial_timeout = calls[0].kwargs["timeout"]
        retry_timeout = calls[1].kwargs["timeout"]

        assert initial_timeout == 60
        assert retry_timeout == 90
        assert retry_timeout == initial_timeout + 30

    @given(
        initial_count=insufficient_count_strategy,
        retry_count=any_category_count_strategy,
        url=valid_url_strategy,
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_28_reuses_same_sandbox(
        self, initial_count, retry_count, url
    ):
        """Property 28-4: The retry attempt reuses the exact same sandbox instance without creating a new one."""
        initial_data = _make_analysis_data_with_categories(initial_count)
        retry_data = _make_analysis_data_with_categories(retry_count)

        detector = _make_mock_detector(fail_collection=False)
        detector.data_collector.collect_ssl_data = AsyncMock(return_value=None)
        detector.data_collector.collect_all = AsyncMock(side_effect=[initial_data, retry_data])

        analyze_website(url, detector=detector)

        calls = detector.data_collector.collect_all.call_args_list
        first_sandbox = calls[0].args[0]
        second_sandbox = calls[1].args[0]

        assert first_sandbox is detector.sandbox
        assert second_sandbox is first_sandbox
        assert detector.sandbox_manager.create_sandbox.call_count == 1

    @given(
        initial_count=insufficient_count_strategy,
        retry_count=any_category_count_strategy,
        url=valid_url_strategy,
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_28_uses_retry_result_for_analysis(
        self, initial_count, retry_count, url
    ):
        """Property 28-5: The AI analysis engine receives the retry AnalysisData object as input for analysis."""
        initial_data = _make_analysis_data_with_categories(initial_count)
        retry_data = _make_analysis_data_with_categories(retry_count)

        detector = _make_mock_detector(fail_collection=False)
        detector.data_collector.collect_ssl_data = AsyncMock(return_value=None)
        detector.data_collector.collect_all = AsyncMock(side_effect=[initial_data, retry_data])

        analyze_website(url, detector=detector)

        passed_data = detector.ai_engine.analyze.call_args[0][0]
        assert passed_data is retry_data, "AI analysis must be performed using the retry data"

    @given(
        initial_count=insufficient_count_strategy,
        retry_count=insufficient_count_strategy,
        url=valid_url_strategy,
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_28_persistent_insufficiency_still_proceeds(
        self, initial_count, retry_count, url
    ):
        """Property 28-6: When retry also produces <3 categories, execution proceeds with whatever data was collected."""
        initial_data = _make_analysis_data_with_categories(initial_count)
        retry_data = _make_analysis_data_with_categories(retry_count)

        detector = _make_mock_detector(fail_collection=False)
        detector.data_collector.collect_ssl_data = AsyncMock(return_value=None)
        detector.data_collector.collect_all = AsyncMock(side_effect=[initial_data, retry_data])

        res = analyze_website(url, detector=detector)

        assert detector.data_collector.collect_all.call_count == 2
        assert detector.ai_engine.analyze.call_count == 1
        assert detector.ai_engine.analyze.call_args[0][0] is retry_data
        assert isinstance(res, dict)

    @given(
        initial_count=insufficient_count_strategy,
        exc_cls=exception_classes_strategy,
        msg=exception_messages_strategy,
        url=valid_url_strategy,
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_28_retry_exception_operation_context(
        self, initial_count, exc_cls, msg, url
    ):
        """Property 28-7: An exception occurring during retry collection sets failed_operation to 'data collection retry'."""
        initial_data = _make_analysis_data_with_categories(initial_count)
        exc_instance = exc_cls(msg)

        detector = _make_mock_detector(fail_collection=False)
        detector.data_collector.collect_ssl_data = AsyncMock(return_value=None)
        detector.data_collector.collect_all = AsyncMock(side_effect=[initial_data, exc_instance])

        res = analyze_website(url, detector=detector)

        assert isinstance(res, dict)
        assert res["exception_type"] == exc_cls.__name__
        assert res["failed_operation"] == "data collection retry"
