"""Unit tests for generic security interstitial and block-page detection."""

import pytest
from unittest.mock import AsyncMock, patch
from src.interstitial_detector import detect_interstitial, InterstitialDetectionResult
from src.authenticity_detector import AuthenticityDetector
from src.models import AnalysisData, NetworkData, DOMData, JavaScriptData, VisualData, SSLData


class TestInterstitialDetector:
    """Test suite for interstitial detection regex, titles, and DOM signatures."""

    def test_phishing_interstitial_cloudflare_warning(self):
        """Detect Cloudflare phishing warning interstitial page."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Suspected Phishing</title></head>
        <body>
            <h1>Warning: Suspected Phishing</h1>
            <p>This website has been reported for potential phishing.</p>
            <p>Verify you are human to proceed.</p>
        </body>
        </html>
        """
        result = detect_interstitial(
            requested_url="https://lottoonz.example.com/",
            final_url="https://lottoonz.example.com/",
            page_title="Suspected Phishing",
            html_content=html,
            structure_metrics={"total_elements": 12}
        )

        assert result.is_interstitial is True
        assert result.interstitial_type == "PHISHING_WARNING"
        assert result.is_phishing_signal is True
        assert result.target_domain_reached is False
        assert len(result.indicators) > 0
        assert any("phishing" in ind.lower() for ind in result.indicators)

    def test_deceptive_site_ahead_browser_warning(self):
        """Detect browser/SafeBrowsing deceptive site warning."""
        html = """
        <html>
        <head><title>Security Warning</title></head>
        <body>
            <h1>Deceptive site ahead</h1>
            <p>Attackers on this site may trick you into doing something dangerous like installing software or revealing personal info.</p>
        </body>
        </html>
        """
        result = detect_interstitial(
            requested_url="https://fake-login.example.org/",
            final_url="https://fake-login.example.org/",
            page_title="Security Warning",
            html_content=html,
            structure_metrics={"total_elements": 10}
        )

        assert result.is_interstitial is True
        assert result.interstitial_type == "PHISHING_WARNING"
        assert result.is_phishing_signal is True
        assert result.target_domain_reached is False

    def test_cloudflare_turnstile_bot_challenge(self):
        """Detect Cloudflare Turnstile anti-bot verification challenge."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Just a moment...</title></head>
        <body>
            <div id="challenge-stage">
                <form id="challenge-form" action="/cdn-cgi/challenge-platform/h/g/turnstile">
                    <p>Verify you are human</p>
                </form>
            </div>
        </body>
        </html>
        """
        result = detect_interstitial(
            requested_url="https://target-site.example.com/",
            final_url="https://target-site.example.com/",
            page_title="Just a moment...",
            html_content=html,
            structure_metrics={"total_elements": 14}
        )

        assert result.is_interstitial is True
        assert result.interstitial_type == "BOT_CHALLENGE"
        assert result.is_phishing_signal is False
        assert result.target_domain_reached is False

    def test_normal_google_website_not_interstitial(self):
        """Legitimate Google search page must not be flagged as an interstitial."""
        html = """
        <!doctype html>
        <html>
        <head><title>Google</title></head>
        <body>
            <div id="main">
                <form action="/search">
                    <input type="text" name="q" />
                    <input type="submit" value="Google Search" />
                </form>
                <div>About Store Gmail Images</div>
            </div>
        </body>
        </html>
        """
        result = detect_interstitial(
            requested_url="https://www.google.com/",
            final_url="https://www.google.com/",
            page_title="Google",
            html_content=html,
            structure_metrics={"total_elements": 120}
        )

        assert result.is_interstitial is False
        assert result.interstitial_type == "NONE"
        assert result.target_domain_reached is True
        assert result.is_phishing_signal is False

    def test_normal_microsoft_website_not_interstitial(self):
        """Legitimate Microsoft page must not be flagged as an interstitial."""
        html = """
        <!doctype html>
        <html>
        <head><title>Microsoft – Cloud, Computers, Apps & Gaming</title></head>
        <body>
            <nav>Microsoft 365, Teams, Windows, Surface</nav>
            <h1>Explore Microsoft products and services</h1>
        </body>
        </html>
        """
        result = detect_interstitial(
            requested_url="https://www.microsoft.com/en-us",
            final_url="https://www.microsoft.com/en-us",
            page_title="Microsoft – Cloud, Computers, Apps & Gaming",
            html_content=html,
            structure_metrics={"total_elements": 250}
        )

        assert result.is_interstitial is False
        assert result.target_domain_reached is True

    def test_external_security_domain_redirection(self):
        """Detect redirection to an external security provider block domain."""
        result = detect_interstitial(
            requested_url="https://malicious-site.example/",
            final_url="https://safebrowsing.google.com/safebrowsing/diagnostic?site=malicious-site.example",
            page_title="Safe Browsing Warning",
            html_content="<html><body>Site blocked</body></html>",
        )

        assert result.is_interstitial is True
        assert result.target_domain_reached is False


class TestAuthenticityDetectorInterstitialIntegration:
    """Integration tests for AuthenticityDetector handling of interstitials."""

    @pytest.mark.asyncio
    async def test_phishing_interstitial_produces_high_risk_phishing_report(self):
        """Phishing warning interstitial must produce a PHISHING result rather than false SAFE."""
        interstitial_html = """
        <html>
        <head><title>Warning: Suspected Phishing</title></head>
        <body>
            <h1>This website has been reported for potential phishing.</h1>
            <p>Verify you are human</p>
        </body>
        </html>
        """
        mock_data = AnalysisData(
            network=NetworkData(request_count=2, unique_domains=["cloudflare.com"], protocol_distribution={"https": 2}, failed=False),
            dom=DOMData(html_content=interstitial_html, structure_metrics={"total_elements": 10}, failed=False),
            javascript=JavaScriptData(script_count=1, dom_modifications=0, external_api_calls=0, failed=False),
            visual=VisualData(screenshot_path="/tmp/screen.png", layout_characteristics={}, failed=False),
            ssl=SSLData(issuer="Cloudflare", expiration_date="2026-12-31", chain_valid=True, failed=False),
            categories_collected=5,
        )

        mock_sandbox = AsyncMock()
        mock_sandbox.load_url.return_value = True
        mock_sandbox.page = AsyncMock()
        mock_sandbox.page.url = "https://lottoonz.example.com/"
        mock_sandbox.page.title.return_value = "Warning: Suspected Phishing"

        mock_sb_manager = AsyncMock()
        mock_sb_manager.create_sandbox.return_value = mock_sandbox
        mock_sb_manager.validate_isolation.return_value = (True, "")

        mock_collector = AsyncMock()
        mock_collector.collect_all.return_value = mock_data

        detector = AuthenticityDetector(
            sandbox_manager=mock_sb_manager,
            data_collector=mock_collector
        )

        report = await detector.analyze_website_async("https://lottoonz.example.com/")

        # Verify not false SAFE
        assert report["risk_level"] in ["PHISHING", "HIGH_RISK"]
        assert float(report["authenticity_score"].replace("%", "")) < 20.0
        assert float(report["fake_score"].replace("%", "")) > 80.0
        assert len(report["critical_indicators"]) > 0
        assert any("SECURITY_INTERSTITIAL" in ind for ind in report["critical_indicators"])

    @pytest.mark.asyncio
    async def test_challenge_page_produces_inconclusive_result(self):
        """Bot challenge page must produce inconclusive result with low confidence rather than high-confidence SAFE."""
        challenge_html = """
        <html>
        <head><title>Just a moment...</title></head>
        <body>
            <div id="challenge-stage">
                <p>Checking if the site connection is secure</p>
                <form id="challenge-form" action="/cdn-cgi/challenge-platform/"></form>
            </div>
        </body>
        </html>
        """
        mock_data = AnalysisData(
            network=NetworkData(request_count=2, unique_domains=["cloudflare.com"], protocol_distribution={"https": 2}, failed=False),
            dom=DOMData(html_content=challenge_html, structure_metrics={"total_elements": 8}, failed=False),
            javascript=JavaScriptData(script_count=1, dom_modifications=0, external_api_calls=0, failed=False),
            visual=VisualData(screenshot_path="/tmp/screen.png", layout_characteristics={}, failed=False),
            ssl=SSLData(issuer="Cloudflare", expiration_date="2026-12-31", chain_valid=True, failed=False),
            categories_collected=5,
        )

        mock_sandbox = AsyncMock()
        mock_sandbox.load_url.return_value = True
        mock_sandbox.page = AsyncMock()
        mock_sandbox.page.url = "https://protected-site.example.com/"
        mock_sandbox.page.title.return_value = "Just a moment..."

        mock_sb_manager = AsyncMock()
        mock_sb_manager.create_sandbox.return_value = mock_sandbox
        mock_sb_manager.validate_isolation.return_value = (True, "")

        mock_collector = AsyncMock()
        mock_collector.collect_all.return_value = mock_data

        detector = AuthenticityDetector(
            sandbox_manager=mock_sb_manager,
            data_collector=mock_collector
        )

        report = await detector.analyze_website_async("https://protected-site.example.com/")

        # Verify not false SAFE
        assert report["risk_level"] == "INCONCLUSIVE"
        assert report["confidence_indicator"] == "LOW"
        assert report["authenticity_score"] is None
        assert "interstitial challenge" in report["error_message"]
