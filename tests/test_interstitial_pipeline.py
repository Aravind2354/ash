"""Comprehensive unit & integration tests for anti-bot / verification interstitial pipeline.

Validates the 4 core cases:
- TEST 1: Normal accessible website (features extracted, XGBoost executed, probability generated).
- TEST 2: Website showing Cloudflare/anti-bot/verification challenge (target not reached, XGBoost NOT executed, scores null, INCONCLUSIVE, HTTP 200, no partial report error).
- TEST 3: Explicit security/phishing interstitial (security signal preserved, XGBoost bypassed, classification = PHISHING).
- TEST 4: Known legitimate accessible website (e.g. amazon.in, target page reached, XGBoost executes, no false INCONCLUSIVE).
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from src.authenticity_detector import AuthenticityDetector
from src.ai_analyzer import AIAnalysisEngine
from src.models import (
    AnalysisData,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
    AnalysisScores,
)
from web.app import app
from web.tasks import task_manager, run_analysis_task


@pytest.fixture
def api_client():
    return TestClient(app)


class TestInterstitialPipelineScenarios:
    """Test suite validating all 4 scenarios specified in requirements."""

    @pytest.mark.asyncio
    async def test_1_normal_accessible_website(self):
        """TEST 1: Normal accessible website must reach target, extract features, execute XGBoost and produce normal classification."""
        normal_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Legitimate Web Service</title></head>
        <body>
            <h1>Welcome to Legitimate Service</h1>
            <p>Our secure platform provides verified cloud utilities.</p>
        </body>
        </html>
        """
        mock_data = AnalysisData(
            network=NetworkData(request_count=15, unique_domains=["legitservice.example.com"], protocol_distribution={"https": 15}, failed=False),
            dom=DOMData(html_content=normal_html, structure_metrics={"total_elements": 60, "password_input_count": 0}, failed=False),
            javascript=JavaScriptData(script_count=5, dom_modifications=2, external_api_calls=1, failed=False),
            visual=VisualData(screenshot_path="/tmp/screen.png", layout_characteristics={}, failed=False),
            ssl=SSLData(issuer="Let's Encrypt", expiration_date="2027-01-01", chain_valid=True, failed=False),
            categories_collected=5,
        )

        mock_sandbox = AsyncMock()
        mock_sandbox.load_url.return_value = True
        mock_sandbox.page = AsyncMock()
        mock_sandbox.page.url = "https://legitservice.example.com/"
        mock_sandbox.page.title.return_value = "Legitimate Web Service"

        mock_sb_manager = AsyncMock()
        mock_sb_manager.create_sandbox.return_value = mock_sandbox
        mock_sb_manager.validate_isolation.return_value = (True, "")

        mock_collector = AsyncMock()
        mock_collector.collect_all.return_value = mock_data

        detector = AuthenticityDetector(
            sandbox_manager=mock_sb_manager,
            data_collector=mock_collector
        )

        report = await detector.analyze_website_async("https://legitservice.example.com/")

        # Verify Test 1 expectations
        assert report["status"] == "completed"
        assert report["classification"] in ["SAFE", "SUSPICIOUS", "HIGH_RISK", "PHISHING"]
        assert report["risk_level"] in ["SAFE", "SUSPICIOUS", "HIGH_RISK", "PHISHING"]
        assert report["risk_level"] != "INCONCLUSIVE"
        assert report["authenticity_score"] is not None
        assert report["fake_score"] is not None
        assert report["xgboost_executed"] is True
        assert report["xgboost_probability"] is not None
        assert report["error_message"] is None
        assert "analysis_start" in report["timestamps"]
        assert "analysis_completion" in report["timestamps"]

    @pytest.mark.asyncio
    async def test_2_antibot_verification_challenge_inconclusive(self):
        """TEST 2: Anti-bot / Cloudflare verification challenge must produce INCONCLUSIVE with XGBoost not executed and null scores."""
        challenge_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Just a moment...</title></head>
        <body>
            <div id="challenge-stage">
                <p>Checking your browser before accessing the website</p>
                <div class="cf-browser-verification">Verify you are human</div>
            </div>
        </body>
        </html>
        """
        mock_data = AnalysisData(
            network=NetworkData(request_count=3, unique_domains=["challenges.cloudflare.com"], protocol_distribution={"https": 3}, failed=False),
            dom=DOMData(html_content=challenge_html, structure_metrics={"total_elements": 6}, failed=False),
            javascript=JavaScriptData(script_count=1, dom_modifications=0, external_api_calls=0, failed=False),
            visual=VisualData(screenshot_path="/tmp/screen.png", layout_characteristics={}, failed=False),
            ssl=SSLData(issuer="Cloudflare", expiration_date="2026-12-31", chain_valid=True, failed=False),
            categories_collected=5,
        )

        mock_sandbox = AsyncMock()
        mock_sandbox.load_url.return_value = True
        mock_sandbox.page = AsyncMock()
        mock_sandbox.page.url = "https://chatgpt.com/"
        mock_sandbox.page.title.return_value = "Just a moment..."

        mock_sb_manager = AsyncMock()
        mock_sb_manager.create_sandbox.return_value = mock_sandbox
        mock_sb_manager.validate_isolation.return_value = (True, "")

        mock_collector = AsyncMock()
        mock_collector.collect_all.return_value = mock_data

        # Spy on ai_engine and ml_model
        ai_engine = AIAnalysisEngine()
        predict_mock = MagicMock()
        ai_engine.ml_model.predict_phishing_probability = predict_mock

        detector = AuthenticityDetector(
            sandbox_manager=mock_sb_manager,
            data_collector=mock_collector,
            ai_engine=ai_engine
        )

        report = await detector.analyze_website_async("https://chatgpt.com/")

        # Verify Test 2 expectations:
        # 1. XGBoost was NOT executed
        predict_mock.assert_not_called()
        assert report["xgboost_executed"] is False
        assert report["xgboost_probability"] is None

        # 2. Authenticity / Fake scores are null
        assert report["authenticity_score"] is None
        assert report["fake_score"] is None

        # 3. Status and classification are completed INCONCLUSIVE
        assert report["status"] == "completed"
        assert report["classification"] == "INCONCLUSIVE"
        assert report["risk_level"] == "INCONCLUSIVE"
        assert report["confidence_indicator"] == "LOW"

        # 4. Error message is None (no "Partial report generated" error)
        assert report["error_message"] is None
        assert "Partial report generated" not in str(report.get("error_message"))

        # 5. Reason and recommendation are present
        assert "reason" in report and report["reason"]
        assert "recommendation" in report and report["recommendation"]

        # 6. Timestamps properly generated
        assert "analysis_start" in report["timestamps"]
        assert "analysis_completion" in report["timestamps"]

    @pytest.mark.asyncio
    async def test_3_explicit_security_phishing_interstitial(self):
        """TEST 3: Explicit security/phishing warning interstitial must preserve security detection and classify as PHISHING."""
        phishing_warning_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Deceptive site ahead</title></head>
        <body>
            <h1>Deceptive site ahead</h1>
            <p>Attackers on this site might trick you into doing something dangerous like installing software or revealing your personal information.</p>
        </body>
        </html>
        """
        mock_data = AnalysisData(
            network=NetworkData(request_count=2, unique_domains=["safebrowsing.google.com"], protocol_distribution={"https": 2}, failed=False),
            dom=DOMData(html_content=phishing_warning_html, structure_metrics={"total_elements": 10}, failed=False),
            javascript=JavaScriptData(script_count=1, dom_modifications=0, external_api_calls=0, failed=False),
            visual=VisualData(screenshot_path="/tmp/screen.png", layout_characteristics={}, failed=False),
            ssl=SSLData(issuer="Google Trust Services", expiration_date="2026-12-31", chain_valid=True, failed=False),
            categories_collected=5,
        )

        mock_sandbox = AsyncMock()
        mock_sandbox.load_url.return_value = True
        mock_sandbox.page = AsyncMock()
        mock_sandbox.page.url = "https://phishing-site.example/"
        mock_sandbox.page.title.return_value = "Deceptive site ahead"

        mock_sb_manager = AsyncMock()
        mock_sb_manager.create_sandbox.return_value = mock_sandbox
        mock_sb_manager.validate_isolation.return_value = (True, "")

        mock_collector = AsyncMock()
        mock_collector.collect_all.return_value = mock_data

        detector = AuthenticityDetector(
            sandbox_manager=mock_sb_manager,
            data_collector=mock_collector
        )

        report = await detector.analyze_website_async("https://phishing-site.example/")

        # Verify Test 3 expectations
        assert report["status"] == "completed"
        assert report["classification"] == "PHISHING"
        assert report["risk_level"] == "PHISHING"
        assert float(report["authenticity_score"].replace("%", "")) <= 10.0
        assert float(report["fake_score"].replace("%", "")) >= 90.0
        assert report["confidence_indicator"] == "HIGH"
        assert len(report["critical_indicators"]) > 0

    @pytest.mark.asyncio
    async def test_4_known_legitimate_website_amazon_in(self):
        """TEST 4: Known legitimate website amazon.in executes XGBoost and returns normal verdict without false INCONCLUSIVE."""
        amazon_html = """
        <!DOCTYPE html>
        <html lang="en">
        <head><title>Online Shopping site in India: Shop Online for Mobiles, Books, Watches, Shoes and More - Amazon.in</title></head>
        <body>
            <div id="navbar"><a href="/ref=nav_logo">Amazon.in</a></div>
            <div class="nav-search-field"><input type="text" name="field-keywords" placeholder="Search Amazon.in"></div>
            <div id="desktop-grid"><p>Great Indian Festival Deals</p></div>
        </body>
        </html>
        """
        mock_data = AnalysisData(
            network=NetworkData(request_count=30, unique_domains=["amazon.in", "images-amazon.com"], protocol_distribution={"https": 30}, failed=False),
            dom=DOMData(html_content=amazon_html, structure_metrics={"total_elements": 200, "password_input_count": 0}, failed=False),
            javascript=JavaScriptData(script_count=12, dom_modifications=8, external_api_calls=4, failed=False),
            visual=VisualData(screenshot_path="/tmp/screen.png", layout_characteristics={}, failed=False),
            ssl=SSLData(issuer="DigiCert Global Root CA", expiration_date="2027-12-31", chain_valid=True, failed=False),
            categories_collected=5,
        )

        mock_sandbox = AsyncMock()
        mock_sandbox.load_url.return_value = True
        mock_sandbox.page = AsyncMock()
        mock_sandbox.page.url = "https://www.amazon.in/"
        mock_sandbox.page.title.return_value = "Online Shopping site in India: Shop Online for Mobiles, Books, Watches, Shoes and More - Amazon.in"

        mock_sb_manager = AsyncMock()
        mock_sb_manager.create_sandbox.return_value = mock_sandbox
        mock_sb_manager.validate_isolation.return_value = (True, "")

        mock_collector = AsyncMock()
        mock_collector.collect_all.return_value = mock_data

        detector = AuthenticityDetector(
            sandbox_manager=mock_sb_manager,
            data_collector=mock_collector
        )

        report = await detector.analyze_website_async("https://www.amazon.in/")

        # Verify Test 4 expectations
        assert report["status"] == "completed"
        assert report["risk_level"] != "INCONCLUSIVE"
        assert report["classification"] != "INCONCLUSIVE"
        assert report["authenticity_score"] is not None
        assert report["fake_score"] is not None
        assert report["xgboost_executed"] is True
        assert report["xgboost_probability"] is not None
        assert report["error_message"] is None

    def test_ai_analyzer_direct_call_skips_xgboost_on_interstitial(self):
        """Verify AIAnalysisEngine.analyze directly skips predict_phishing_probability on challenge data."""
        challenge_html = """
        <html>
        <head><title>Just a moment...</title></head>
        <body>
            <div id="challenge-stage">
                <p>Checking if the site connection is secure</p>
                <form id="challenge-form"></form>
            </div>
        </body>
        </html>
        """
        data = AnalysisData(
            network=NetworkData(request_count=2, unique_domains=["challenges.cloudflare.com"], protocol_distribution={"https": 2}, failed=False),
            dom=DOMData(html_content=challenge_html, structure_metrics={"total_elements": 6}, failed=False),
            javascript=JavaScriptData(script_count=1, dom_modifications=0, external_api_calls=0, failed=False),
            visual=VisualData(screenshot_path="/tmp/screen.png", layout_characteristics={}, failed=False),
            ssl=SSLData(issuer="Cloudflare", expiration_date="2026-12-31", chain_valid=True, failed=False),
            categories_collected=5,
        )

        ai_engine = AIAnalysisEngine()
        predict_mock = MagicMock()
        ai_engine.ml_model.predict_phishing_probability = predict_mock

        scores = ai_engine.analyze(data, url="https://protected.example.com")

        # predict_phishing_probability MUST NOT be called
        predict_mock.assert_not_called()
        assert scores.risk_level == "INCONCLUSIVE"
        assert scores.authenticity_score is None
        assert scores.fake_score is None

    @pytest.mark.asyncio
    async def test_web_task_manager_inconclusive_api_response(self, api_client):
        """Verify web task runner marks INCONCLUSIVE as completed with HTTP 200 and expected result object."""
        inconclusive_result = {
            "status": "completed",
            "classification": "INCONCLUSIVE",
            "risk_level": "INCONCLUSIVE",
            "authenticity_score": None,
            "fake_score": None,
            "confidence": "LOW",
            "confidence_indicator": "LOW",
            "xgboost_executed": False,
            "xgboost_probability": None,
            "reason": "Target website was not reached due to an anti-bot or verification challenge",
            "recommendation": "Try again with a website that can be reached by the analysis browser",
            "timestamps": {"analysis_start": "2026-08-31T12:00:00Z", "analysis_completion": "2026-08-31T12:00:05Z"},
            "analysis_data": None,
            "top_factors": ["Target website was intercepted by a security challenge / interstitial"],
            "suspicious_indicators": [],
            "error_message": None,
        }

        task = task_manager.create_task("https://target-with-challenge.com")

        with patch.object(AuthenticityDetector, "analyze_website_async", return_value=inconclusive_result):
            await run_analysis_task(task.task_id, "https://target-with-challenge.com")

        # Query GET /api/task/{task_id}
        response = api_client.get(f"/api/task/{task.task_id}")
        assert response.status_code == 200
        resp_json = response.json()

        assert resp_json["status"] == "completed"
        assert resp_json["error"] is None
        result = resp_json["result"]
        assert result["classification"] == "INCONCLUSIVE"
        assert result["risk_level"] == "INCONCLUSIVE"
        assert result["authenticity_score"] is None
        assert result["fake_score"] is None
        assert result["confidence"] == "LOW"
        assert result["xgboost_executed"] is False
        assert result["xgboost_probability"] is None
        assert "anti-bot" in result["reason"].lower() or "challenge" in result["reason"].lower() or "verification" in result["reason"].lower()
        assert "Try again" in result["recommendation"]

