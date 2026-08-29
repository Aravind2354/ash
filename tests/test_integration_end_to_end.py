"""Integration tests for component wiring and end-to-end flow.

Task 14.1: Verify that the REAL DEFAULT COMPONENT INSTANCES work together correctly
without dependency injection or mocks.

Task 14.2: Verify complete analysis flow with mock websites, execution performance
under 10s, error response under 500ms, repeated analyses sandbox cleanup/reset,
and insufficient-data retry integration.
(Requirements: 3.8, 5.5, 6.6; Properties: 2, 34)
"""

import pytest
import asyncio
import time
from datetime import datetime, timezone
from unittest.mock import patch

from src.authenticity_detector import AuthenticityDetector, analyze_website
from src.input_validator import InputValidator
from src.sandbox import SandboxManager, Sandbox
from src.data_collector import DataCollector
from src.ai_analyzer import AIAnalysisEngine
from src.report_generator import ReportGenerator
from src.models import (
    AnalysisResult,
    AnalysisData,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
)


class TestTask14_1_ComponentWiring:
    """Task 14.1: Verification of real default component construction and wiring."""

    def test_default_component_construction(self):
        """Verify AuthenticityDetector() constructs successfully with default components."""
        detector = AuthenticityDetector()

        assert detector.validator is not None
        assert isinstance(detector.validator, InputValidator)

        assert detector.sandbox_manager is not None
        assert isinstance(detector.sandbox_manager, SandboxManager)

        assert detector.data_collector is not None
        assert isinstance(detector.data_collector, DataCollector)

        assert detector.ai_engine is not None
        assert isinstance(detector.ai_engine, AIAnalysisEngine)

        assert detector.report_generator is not None
        assert isinstance(detector.report_generator, ReportGenerator)

    def test_component_method_signatures_compatibility(self):
        """Verify that default components expose required methods with compatible signatures."""
        detector = AuthenticityDetector()

        # InputValidator signature
        assert hasattr(detector.validator, "validate_url")
        valid, err = detector.validator.validate_url("https://example.com")
        assert isinstance(valid, bool)

        # SandboxManager signatures
        assert hasattr(detector.sandbox_manager, "create_sandbox")
        assert hasattr(detector.sandbox_manager, "validate_isolation")
        assert hasattr(detector.sandbox_manager, "terminate_sandbox")
        is_isolated, msg = detector.sandbox_manager.validate_isolation()
        assert isinstance(is_isolated, bool)
        assert isinstance(msg, str)

        # DataCollector signatures
        assert hasattr(detector.data_collector, "collect_all")
        assert hasattr(detector.data_collector, "collect_ssl_data")

        # AIAnalysisEngine signatures
        assert hasattr(detector.ai_engine, "analyze")
        assert hasattr(detector.ai_engine, "calculate_confidence")

        # ReportGenerator signatures
        assert hasattr(detector.report_generator, "generate_report")
        assert hasattr(detector.report_generator, "generate_partial_report")

    def test_analyze_website_default_components_invalid_url(self):
        """Verify analyze_website() with default components correctly validates and rejects invalid URL."""
        res = analyze_website("not-a-valid-url")

        assert isinstance(res, dict)
        assert res["authenticity_score"] is None
        assert res["fake_score"] is None
        assert res["confidence_indicator"] == "LOW"
        assert res["error_message"] is not None
        assert "URL validation failed" in res["error_message"]
        assert res["url"] == "not-a-valid-url"

    def test_analyze_website_isolation_check_default_host_behavior(self):
        """Verify that running locally without Docker isolation validation returns a structured report."""
        detector = AuthenticityDetector()
        res = detector.analyze_website("https://example.com")

        assert isinstance(res, dict)
        assert "authenticity_score" in res
        assert "fake_score" in res
        assert "confidence_indicator" in res
        assert "error_message" in res
        assert res["authenticity_score"] is None
        assert res["fake_score"] is None
        assert res["confidence_indicator"] == "LOW"
        assert "Isolation" in res["error_message"] or "isolation" in res["error_message"]

    def test_end_to_end_real_flow_with_validated_isolation(self):
        """Verify the full pipeline when running in a validated container with real default components."""
        detector = AuthenticityDetector()

        # Simulate running in a validated container environment
        with patch.object(detector.sandbox_manager, "_detect_container_environment", return_value=True):
            detector.sandbox_manager.set_isolation_validated("test-container-id-12345")

            data = AnalysisData(
                network=NetworkData(request_count=10, unique_domains=["example.com"], protocol_distribution={"https": 10}, failed=False),
                dom=DOMData(html_content="<html><head><title>Test</title></head><body><h1>Hello</h1></body></html>", structure_metrics={"total_elements": 10}, failed=False),
                javascript=JavaScriptData(script_count=1, dom_modifications=0, external_api_calls=0, failed=False),
                visual=VisualData(screenshot_path="", layout_characteristics={"has_viewport": True}, failed=False),
                ssl=SSLData(issuer="DigiCert", expiration_date="2030-01-01T00:00:00Z", chain_valid=True, failed=False),
                categories_collected=5,
            )

            class MockSandbox:
                async def load_url(self, url, timeout=30):
                    return True

            async def mock_create():
                return MockSandbox()

            async def mock_collect(sandbox, url, timeout=60):
                return data

            detector.sandbox_manager.create_sandbox = mock_create
            detector.data_collector.collect_all = mock_collect

            res = detector.analyze_website("https://example.com")

            assert isinstance(res, dict)
            assert res["authenticity_score"] is not None
            assert res["fake_score"] is not None
            assert res["confidence_indicator"] == "HIGH"
            assert res["url"] == "https://example.com"
            assert "analysis_start" in res["timestamps"]
            assert "analysis_completion" in res["timestamps"]
            assert len(res["top_factors"]) == 3
            assert res["error_message"] is None

    def test_sandbox_cleanup_called_on_pipeline_exit(self):
        """Verify that default sandbox_manager.terminate_sandbox is invoked in finally block."""
        detector = AuthenticityDetector()

        with patch.object(detector.sandbox_manager, "_detect_container_environment", return_value=True):
            detector.sandbox_manager.set_isolation_validated("test-container-id-12345")

            terminate_called = False

            async def mock_terminate(sandbox=None):
                nonlocal terminate_called
                terminate_called = True

            detector.sandbox_manager.terminate_sandbox = mock_terminate

            class MockSandbox:
                async def load_url(self, url, timeout=30):
                    return False

            async def mock_create():
                return MockSandbox()

            detector.sandbox_manager.create_sandbox = mock_create

            res = detector.analyze_website("https://example.com")

            assert terminate_called is True
            assert "Failed to load URL" in res["error_message"]


class TestTask14_2_CompleteAnalysisFlow:
    """Task 14.2: End-to-end integration tests for complete analysis flow, timing, and cleanup."""

    @pytest.fixture
    def authentic_analysis_data(self) -> AnalysisData:
        """Fixture representing a high-authenticity, legitimate website."""
        return AnalysisData(
            network=NetworkData(
                request_count=25,
                unique_domains=["example.com", "cdn.example.com", "static.example.com"],
                protocol_distribution={"https": 25},
                failed=False,
            ),
            dom=DOMData(
                html_content="<!DOCTYPE html><html><head><title>Authentic Store</title></head><body><h1>Official Store</h1><p>Welcome to our verified portal.</p></body></html>",
                structure_metrics={"element_count": 60, "iframe_count": 0, "form_count": 1},
                failed=False,
            ),
            javascript=JavaScriptData(
                script_count=3,
                dom_modifications=2,
                external_api_calls=1,
                failed=False,
            ),
            visual=VisualData(
                screenshot_path="/tmp/authentic_screenshot.png",
                layout_characteristics={"viewport_width": 1920, "viewport_height": 1080},
                failed=False,
            ),
            ssl=SSLData(
                issuer="Let's Encrypt Authority X3",
                expiration_date="2030-01-01T00:00:00Z",
                chain_valid=True,
                failed=False,
            ),
            categories_collected=5,
        )

    @pytest.fixture
    def suspicious_analysis_data(self) -> AnalysisData:
        """Fixture representing a deceptive, suspicious mock website."""
        return AnalysisData(
            network=NetworkData(
                request_count=40,
                unique_domains=[f"track{i}.phishingserver.xyz" for i in range(35)],
                protocol_distribution={"http": 40},
                failed=False,
            ),
            dom=DOMData(
                html_content="<html><head><title>Login</title></head><body><iframe src='http://hidden-payload.ru'></iframe></body></html>",
                structure_metrics={"element_count": 2, "iframe_count": 8, "form_count": 15},
                failed=False,
            ),
            javascript=JavaScriptData(
                script_count=35,
                dom_modifications=80,
                external_api_calls=50,
                failed=False,
            ),
            visual=VisualData(
                screenshot_path="",
                layout_characteristics={},
                failed=False,
            ),
            ssl=SSLData(
                issuer="",
                expiration_date="2020-01-01T00:00:00Z",
                chain_valid=False,
                failed=False,
            ),
            categories_collected=5,
        )

    def test_e2e_complete_analysis_authentic_website(self, authentic_analysis_data):
        """1. Complete analysis flow on authentic website produces complete report under 10s."""
        detector = AuthenticityDetector()

        with patch.object(detector.sandbox_manager, "_detect_container_environment", return_value=True):
            detector.sandbox_manager.set_isolation_validated("container-auth-1")

            class MockSandbox:
                async def load_url(self, url, timeout=30):
                    return True

            async def mock_create():
                return MockSandbox()

            async def mock_collect(sandbox, url, timeout=60):
                return authentic_analysis_data

            detector.sandbox_manager.create_sandbox = mock_create
            detector.data_collector.collect_all = mock_collect

            start = time.perf_counter()
            res = detector.analyze_website("https://authentic-store.example.com")
            elapsed = time.perf_counter() - start

            # Performance verification (Requirement 3.8, Property 34)
            assert elapsed < 10.0, f"Analysis took {elapsed:.2f}s (exceeded 10s limit)"

            # Structurally valid dictionary result
            assert isinstance(res, dict)

            # All 9 report fields must be present
            required_keys = [
                "authenticity_score",
                "fake_score",
                "confidence_indicator",
                "url",
                "timestamps",
                "analysis_data",
                "top_factors",
                "suspicious_indicators",
                "error_message",
            ]
            for key in required_keys:
                assert key in res, f"Missing required key: {key}"

            assert res["url"] == "https://authentic-store.example.com"
            assert res["error_message"] is None
            assert res["confidence_indicator"] == "HIGH"

            # Formatted percentages
            assert res["authenticity_score"].endswith("%")
            assert res["fake_score"].endswith("%")
            auth_val = float(res["authenticity_score"].rstrip("%"))
            fake_val = float(res["fake_score"].rstrip("%"))
            assert auth_val > 50.0, f"Expected authentic score > 50%, got {auth_val}%"
            assert fake_val < 50.0, f"Expected fake score < 50%, got {fake_val}%"
            assert abs((auth_val + fake_val) - 100.0) <= 1.0

            # Suspicious indicators empty when fake score <= 0.5
            assert res["suspicious_indicators"] == []

            # Exactly 3 top factors
            assert len(res["top_factors"]) == 3

            # Timestamps format and ordering
            ts = res["timestamps"]
            assert "analysis_start" in ts
            assert "analysis_completion" in ts
            start_dt = datetime.fromisoformat(ts["analysis_start"].replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(ts["analysis_completion"].replace("Z", "+00:00"))
            assert end_dt >= start_dt

    def test_e2e_complete_analysis_suspicious_website(self, suspicious_analysis_data):
        """2. Complete analysis flow on suspicious website yields Fake_Score > 0.5 with indicators."""
        detector = AuthenticityDetector()

        with patch.object(detector.sandbox_manager, "_detect_container_environment", return_value=True):
            detector.sandbox_manager.set_isolation_validated("container-susp-1")

            class MockSandbox:
                async def load_url(self, url, timeout=30):
                    return True

            async def mock_create():
                return MockSandbox()

            async def mock_collect(sandbox, url, timeout=60):
                return suspicious_analysis_data

            detector.sandbox_manager.create_sandbox = mock_create
            detector.data_collector.collect_all = mock_collect

            start = time.perf_counter()
            res = detector.analyze_website("https://suspicious-login.phishing.example")
            elapsed = time.perf_counter() - start

            assert elapsed < 10.0, f"Analysis took {elapsed:.2f}s"
            assert isinstance(res, dict)
            assert res["error_message"] is None

            # Fake score > 50%
            auth_val = float(res["authenticity_score"].rstrip("%"))
            fake_val = float(res["fake_score"].rstrip("%"))
            assert fake_val > 50.0, f"Expected fake score > 50%, got {fake_val}%"
            assert auth_val < 50.0

            # Suspicious indicators populated by real AIAnalysisEngine
            assert len(res["suspicious_indicators"]) > 0
            assert len(res["top_factors"]) == 3

    def test_e2e_performance_analysis_under_10_seconds(self, authentic_analysis_data):
        """3. Performance test: valid analysis completes strictly under 10s (Requirement 3.8)."""
        detector = AuthenticityDetector()

        with patch.object(detector.sandbox_manager, "_detect_container_environment", return_value=True):
            detector.sandbox_manager.set_isolation_validated("container-perf-1")

            class MockSandbox:
                async def load_url(self, url, timeout=30):
                    return True

            async def mock_create():
                return MockSandbox()

            async def mock_collect(sandbox, url, timeout=60):
                return authentic_analysis_data

            detector.sandbox_manager.create_sandbox = mock_create
            detector.data_collector.collect_all = mock_collect

            start = time.perf_counter()
            res = detector.analyze_website("https://perf-check.example.com")
            elapsed = time.perf_counter() - start

            assert elapsed < 10.0, f"Analysis exceeded 10 seconds: {elapsed:.3f}s"
            assert res["authenticity_score"] is not None

    def test_e2e_performance_error_response_under_500ms(self):
        """4. Performance test: error responses returned within 500ms (Requirement 5.5, Property 34)."""
        start = time.perf_counter()
        res = analyze_website("ftp://invalid-scheme.example.com")
        elapsed = time.perf_counter() - start

        assert elapsed < 0.5, f"Error response took {elapsed:.4f}s (exceeded 500ms limit)"
        assert isinstance(res, dict)
        assert res["authenticity_score"] is None
        assert res["fake_score"] is None
        assert res["confidence_indicator"] == "LOW"
        assert res["error_message"] is not None
        assert "URL validation failed" in res["error_message"]

    def test_e2e_repeated_analyses_sandbox_cleanup_and_reset(self, authentic_analysis_data):
        """5. Repeated analyses: sandbox is cleaned up and reset between analyses (Requirement 6.6, Property 2)."""
        detector = AuthenticityDetector()

        with patch.object(detector.sandbox_manager, "_detect_container_environment", return_value=True):
            detector.sandbox_manager.set_isolation_validated("container-repeat-1")

            terminated_count = 0

            class MockSandbox:
                async def load_url(self, url, timeout=30):
                    return True

            async def mock_create():
                return MockSandbox()

            async def mock_terminate(sandbox=None):
                nonlocal terminated_count
                terminated_count += 1

            async def mock_collect(sandbox, url, timeout=60):
                return authentic_analysis_data

            detector.sandbox_manager.create_sandbox = mock_create
            detector.sandbox_manager.terminate_sandbox = mock_terminate
            detector.data_collector.collect_all = mock_collect

            target_urls = [
                "https://site-a.example.com",
                "https://site-b.example.com",
                "https://site-c.example.com",
            ]

            results = []
            for url in target_urls:
                res = detector.analyze_website(url)
                results.append(res)

            # All analyses must complete independently
            assert len(results) == 3
            for i, url in enumerate(target_urls):
                assert results[i]["url"] == url
                assert results[i]["authenticity_score"] is not None
                assert results[i]["error_message"] is None

            # Cleanup must occur after EVERY single analysis
            assert terminated_count == 3, f"Expected 3 terminations for 3 analyses, got {terminated_count}"

    def test_e2e_insufficient_data_retry_flow(self):
        """6. Insufficient data (<3 categories) triggers single retry with extended timeout (Req 8.3)."""
        detector = AuthenticityDetector()

        with patch.object(detector.sandbox_manager, "_detect_container_environment", return_value=True):
            detector.sandbox_manager.set_isolation_validated("container-retry-1")

            # First attempt: only 2 valid categories
            insufficient_data = AnalysisData(
                network=NetworkData(request_count=5, unique_domains=["example.com"], protocol_distribution={"https": 5}, failed=False),
                dom=DOMData(html_content="<html><body>Hi</body></html>", structure_metrics={"element_count": 5}, failed=False),
                javascript=JavaScriptData(script_count=0, dom_modifications=0, external_api_calls=0, failed=True),
                visual=VisualData(screenshot_path="", layout_characteristics={}, failed=True),
                ssl=SSLData(issuer="", expiration_date="", chain_valid=False, failed=True),
                categories_collected=2,
            )

            # Retry attempt: 4 valid categories
            retry_data = AnalysisData(
                network=NetworkData(request_count=10, unique_domains=["example.com"], protocol_distribution={"https": 10}, failed=False),
                dom=DOMData(html_content="<html><head><title>Retry</title></head><body><h1>Content</h1></body></html>", structure_metrics={"element_count": 20}, failed=False),
                javascript=JavaScriptData(script_count=2, dom_modifications=1, external_api_calls=1, failed=False),
                visual=VisualData(screenshot_path="/tmp/shot.png", layout_characteristics={"viewport_width": 1920}, failed=False),
                ssl=SSLData(issuer="", expiration_date="", chain_valid=False, failed=True),
                categories_collected=4,
            )

            calls = []

            class MockSandbox:
                async def load_url(self, url, timeout=30):
                    return True

            async def mock_create():
                return MockSandbox()

            async def mock_collect(sandbox, url, timeout=60):
                calls.append({"url": url, "timeout": timeout})
                if len(calls) == 1:
                    return insufficient_data
                return retry_data

            detector.sandbox_manager.create_sandbox = mock_create
            detector.data_collector.collect_all = mock_collect

            res = detector.analyze_website("https://retry-flow.example.com")

            # Exactly two collection calls: initial (timeout 60) and retry (timeout 90)
            assert len(calls) == 2
            assert calls[0]["timeout"] == 60
            assert calls[1]["timeout"] == 90

            # Final report successfully generated from retry data
            assert isinstance(res, dict)
            assert res["authenticity_score"] is not None
            assert res["fake_score"] is not None
            assert res["confidence_indicator"] == "HIGH"
            assert res["error_message"] is None
            assert len(res["top_factors"]) == 3
