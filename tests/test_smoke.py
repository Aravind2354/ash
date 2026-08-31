"""Deployment Smoke Tests for Website Authenticity Detector (Task 14.4).

Verifies environment readiness, system/python requirements, runtime dependencies,
Playwright Chromium browser availability, core API callable signature, basic pipeline
invocation, and Docker daemon connectivity (gated).

Requirements: 5.1, 5.2, 5.3
"""

import sys
import os
import importlib
import pytest
from unittest.mock import patch, MagicMock

from src.authenticity_detector import analyze_website, AuthenticityDetector
from src.models import (
    AnalysisData,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
)


def test_python_version_within_specification():
    """Verify Python version is 3.8 <= version < 4.0 (Requirement 5.1)."""
    version = sys.version_info
    assert (
        version.major == 3 and version.minor >= 8
    ), f"Python version must be >= 3.8, found {version.major}.{version.minor}.{version.micro}"
    assert (
        version.major < 4
    ), f"Python version must be < 4.0, found {version.major}.{version.minor}.{version.micro}"


def test_virtual_environment_is_active():
    """Verify virtual environment isolation (Requirement 5.2)."""
    is_venv = sys.prefix != sys.base_prefix
    assert (
        is_venv
    ), f"Virtual environment is not active. sys.prefix ({sys.prefix}) == sys.base_prefix ({sys.base_prefix})"


def test_all_dependencies_installed_and_importable():
    """Verify all 17 runtime and development dependencies can be imported."""
    audited_dependencies = [
        ("playwright", "playwright"),
        ("hypothesis", "hypothesis"),
        ("pytest", "pytest"),
        ("pytest_asyncio", "pytest-asyncio"),
        ("dateutil", "python-dateutil"),
        ("jsonschema", "jsonschema"),
        ("requests", "requests"),
        ("docker", "docker"),
        ("xgboost", "xgboost"),
        ("sklearn", "scikit-learn"),
        ("pandas", "pandas"),
        ("numpy", "numpy"),
        ("joblib", "joblib"),
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn"),
        ("pydantic", "pydantic"),
        ("httpx", "httpx"),
    ]

    failed_imports = []
    for module_name, package_name in audited_dependencies:
        try:
            importlib.import_module(module_name)
        except ImportError as e:
            failed_imports.append(f"{package_name} (module: {module_name}, error: {e})")

    assert not failed_imports, (
        "The following required project dependencies failed to import:\n"
        + "\n".join(failed_imports)
    )


@pytest.mark.asyncio
async def test_playwright_browser_binary_available_and_functional():
    """Verify Playwright Chromium browser binary exists, launches headless, renders local HTML, and closes cleanly."""
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        try:
            executable_path = p.chromium.executable_path
        except Exception as e:
            pytest.fail(f"Playwright Chromium executable path resolution failed: {e}")

        assert executable_path, "Chromium executable path is empty"
        assert os.path.exists(executable_path), (
            f"Chromium browser binary missing at expected path: {executable_path}"
        )

        try:
            browser = await p.chromium.launch(headless=True)
        except Exception as e:
            pytest.fail(f"Failed to launch Playwright Chromium browser: {e}")

        try:
            page = await browser.new_page()
            html_content = "<html><body><h1 id='smoke-target'>Smoke Test OK</h1></body></html>"
            await page.set_content(html_content)

            heading_text = await page.inner_text("#smoke-target")
            assert heading_text == "Smoke Test OK", f"Unexpected rendered text: {heading_text}"
        finally:
            await browser.close()


def test_analyze_website_api_function_signature_and_keys():
    """Verify analyze_website API function signature and returned dictionary keys (Requirement 5.3)."""
    assert callable(analyze_website), "analyze_website is not callable"

    # Test with invalid URL to verify API contract dictionary structure without starting browser sandbox
    result = analyze_website("invalid-url-smoke-test")

    assert isinstance(result, dict), f"Expected dict, got {type(result)}"

    required_keys = [
        "authenticity_score",
        "fake_score",
        "confidence_indicator",
        "error_message",
    ]
    for key in required_keys:
        assert key in result, f"Required API key '{key}' missing from analyze_website return dict"


def test_analyze_website_basic_pipeline_invocation():
    """Verify basic analyze_website pipeline invocation completes using controlled mock data without external network calls."""
    detector = AuthenticityDetector()

    mock_analysis_data = AnalysisData(
        network=NetworkData(
            request_count=5,
            unique_domains=["localhost"],
            protocol_distribution={"https": 5},
            failed=False,
        ),
        dom=DOMData(
            html_content="<html><body><h1>Test</h1></body></html>",
            structure_metrics={"total_elements": 5},
            failed=False,
        ),
        javascript=JavaScriptData(
            script_count=1, dom_modifications=0, external_api_calls=0, failed=False
        ),
        visual=VisualData(
            screenshot_path="", layout_characteristics={"has_images": False}, failed=False
        ),
        ssl=SSLData(
            issuer="Test CA",
            expiration_date="2030-01-01T00:00:00Z",
            chain_valid=True,
            failed=False,
        ),
        timeout_occurred=False,
        categories_collected=5,
    )

    with patch.object(
        detector.sandbox_manager, "validate_isolation", return_value=(True, "")
    ), patch.object(
        detector.sandbox_manager, "create_sandbox"
    ) as mock_create_sb, patch.object(
        detector.data_collector, "collect_all", return_value=mock_analysis_data
    ), patch.object(
        detector.data_collector, "collect_ssl_data", return_value=mock_analysis_data.ssl
    ):
        mock_sb = MagicMock()
        mock_sb.load_url.return_value = True
        mock_create_sb.return_value = mock_sb

        res = detector.analyze_website("https://example.org/smoke-test")

        assert isinstance(res, dict)
        assert res["authenticity_score"] is not None
        assert res["fake_score"] is not None
        assert res["confidence_indicator"] in ["HIGH", "MEDIUM", "LOW"]
        assert res["error_message"] is None


def test_docker_environment_connectivity():
    """Verify Docker client connectivity if Docker daemon is available, otherwise skip."""
    try:
        import docker

        client = docker.from_env(timeout=2)
        client.ping()
    except Exception as e:
        pytest.skip(f"Docker daemon not reachable/available: {e}")

    # Docker is available - run minimal connectivity container
    container = None
    try:
        container = client.containers.create(
            "python:3.11-slim",
            command="echo smoke_ok",
            detach=False,
        )
        container.start()
        container.wait(timeout=10)
        logs = container.logs().decode("utf-8").strip()
        assert "smoke_ok" in logs, f"Unexpected container output: {logs}"
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass
