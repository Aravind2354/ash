"""
Deterministic Test Suite for Multi-Layer Phishing & Fake Website Detection.

Tests Scenarios A through N covering:
- Legitimate websites (Google, Microsoft, Amazon)
- Brand impersonation (subdomain, prefix, title)
- Complex deceptive subdomains (allegro.oferta7678678564.pl)
- Credential harvesting
- Cross-domain form submission
- Excessive hidden inputs
- Excessive iframes
- Punycode & IP-based URLs
- Valid SSL on phishing sites
- Legitimate authentication pages (must remain SAFE)
- URL normalization & FQDN validation
"""

import pytest
from src.ai_analyzer import AIAnalysisEngine
from src.domain_analyzer import DomainAnalyzer
from src.brand_detector import BrandDetector
from src.input_validator import InputValidator
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
    return AIAnalysisEngine()


def create_mock_analysis_data(
    password_count: int = 0,
    email_count: int = 0,
    hidden_count: int = 0,
    iframe_count: int = 0,
    external_form_action_count: int = 0,
    cross_domain_form_action_count: int = 0,
    html_title: str = "Welcome",
    html_body: str = "<p>Standard page content</p>",
    ssl_valid: bool = True,
) -> AnalysisData:
    """Helper to build controlled AnalysisData instances."""
    html_content = f"<html><head><title>{html_title}</title></head><body><h1>{html_title}</h1>{html_body}</body></html>"
    return AnalysisData(
        network=NetworkData(
            request_count=10,
            unique_domains=["example.com"],
            protocol_distribution={"https": 10},
        ),
        dom=DOMData(
            html_content=html_content,
            structure_metrics={
                "element_count": 150,
                "form_count": 1 if password_count or email_count else 0,
                "iframe_count": iframe_count,
                "script_count": 5,
                "password_input_count": password_count,
                "email_input_count": email_count,
                "hidden_input_count": hidden_count,
                "login_keyword_count": 1 if password_count else 0,
                "external_form_action_count": external_form_action_count,
                "cross_domain_form_action_count": cross_domain_form_action_count,
            },
        ),
        javascript=JavaScriptData(
            script_count=5,
            dom_modifications=2,
            external_api_calls=0,
        ),
        visual=VisualData(
            screenshot_path="/tmp/screenshot.png",
            layout_characteristics={
                "viewport_width": 1280,
                "viewport_height": 800,
                "image_count": 4,
            },
        ),
        ssl=SSLData(
            issuer="Let's Encrypt Authority X3" if ssl_valid else "Untrusted CA",
            expiration_date="2027-01-01T00:00:00Z",
            chain_valid=ssl_valid,
        ),
    )


# ==============================================================================
# Scenario A: Legitimate Public Domains
# ==============================================================================
@pytest.mark.parametrize("url,brand", [
    ("https://www.google.com", "Google"),
    ("https://www.microsoft.com", "Microsoft"),
    ("https://www.amazon.com", "Amazon"),
])
def test_scenario_a_legitimate_websites(ai_engine, url, brand):
    data = create_mock_analysis_data(html_title=f"{brand} Official Homepage")
    scores = ai_engine.analyze(data, url=url)
    assert scores.authenticity_score >= 0.80, f"Expected high authenticity for {url}, got {scores.authenticity_score}"
    assert scores.risk_level == "SAFE"
    assert len(scores.critical_indicators) == 0


# ==============================================================================
# Scenario B: Brand Impersonation (Subdomains / Prefixes)
# ==============================================================================
@pytest.mark.parametrize("url", [
    "https://google.example.com",
    "https://microsoft-login.example.com",
    "https://allegro.example.com",
])
def test_scenario_b_brand_impersonation(ai_engine, url):
    data = create_mock_analysis_data(html_title="Sign in to your account")
    scores = ai_engine.analyze(data, url=url)
    assert scores.authenticity_score <= 0.25
    assert scores.risk_level in ["PHISHING", "HIGH_RISK"]
    assert any("BRAND_DOMAIN_MISMATCH" in ind for ind in scores.critical_indicators)


# ==============================================================================
# Scenario C: Suspicious Subdomain with Numeric Heavy Hostname
# ==============================================================================
def test_scenario_c_allegro_oferta_suspicious_subdomain(ai_engine):
    url = "http://allegro.oferta7678678564.pl"
    data = create_mock_analysis_data(
        password_count=1,
        email_count=1,
        html_title="Allegro - Logowanie do serwisu",
    )
    scores = ai_engine.analyze(data, url=url)
    assert scores.authenticity_score <= 0.15, f"Authenticity score was {scores.authenticity_score}, expected <= 0.15"
    assert scores.fake_score >= 0.85
    assert scores.risk_level == "PHISHING"
    assert any("Allegro" in ind for ind in scores.critical_indicators)


# ==============================================================================
# Scenario D: Credential Phishing on Unauthorized Domain
# ==============================================================================
def test_scenario_d_credential_phishing_form(ai_engine):
    url = "http://paypal-verification.secure-account-9283.com"
    data = create_mock_analysis_data(
        password_count=1,
        email_count=1,
        html_title="PayPal - Security Verification Required",
    )
    scores = ai_engine.analyze(data, url=url)
    assert scores.risk_level == "PHISHING"
    assert scores.authenticity_score <= 0.10
    assert any("CREDENTIAL_HARVESTING" in ind for ind in scores.critical_indicators)


# ==============================================================================
# Scenario E: Cross-Domain Credential Submission
# ==============================================================================
def test_scenario_e_cross_domain_credential_submission(ai_engine):
    url = "https://legit-looking-portal.com/login"
    data = create_mock_analysis_data(
        password_count=1,
        email_count=1,
        external_form_action_count=1,
        cross_domain_form_action_count=1,
    )
    scores = ai_engine.analyze(data, url=url)
    assert scores.risk_level == "PHISHING"
    assert any("CROSS_DOMAIN_EXFILTRATION" in ind for ind in scores.critical_indicators)


# ==============================================================================
# Scenario F: Excessive Hidden Inputs
# ==============================================================================
def test_scenario_f_excessive_hidden_inputs(ai_engine):
    url = "https://some-service.com/checkout"
    data = create_mock_analysis_data(hidden_count=8)
    scores = ai_engine.analyze(data, url=url)
    assert scores.authenticity_score <= 0.60
    assert any("hidden form inputs" in ind for ind in scores.suspicious_indicators)


# ==============================================================================
# Scenario G: Excessive Iframes
# ==============================================================================
def test_scenario_g_excessive_iframes(ai_engine):
    url = "https://some-service.com/ad-portal"
    data = create_mock_analysis_data(iframe_count=7)
    scores = ai_engine.analyze(data, url=url)
    assert scores.authenticity_score <= 0.65
    assert any("iframe" in ind for ind in scores.suspicious_indicators)


# ==============================================================================
# Scenario H: Punycode / Homograph Domain
# ==============================================================================
def test_scenario_h_punycode_homograph_domain(ai_engine):
    url = "https://xn--gogle-pua.com"
    data = create_mock_analysis_data()
    scores = ai_engine.analyze(data, url=url)
    assert any("Punycode" in ind for ind in scores.suspicious_indicators)


# ==============================================================================
# Scenario I: Direct IP Address URL
# ==============================================================================
def test_scenario_i_ip_address_url(ai_engine):
    url = "http://45.33.32.156/portal"
    data = create_mock_analysis_data()
    scores = ai_engine.analyze(data, url=url)
    assert any("IP address" in ind for ind in scores.suspicious_indicators)


# ==============================================================================
# Scenario J: Numeric Heavy Random Hostname
# ==============================================================================
def test_scenario_j_numeric_random_hostname(ai_engine):
    url = "http://account-update-9482710385.xyz"
    data = create_mock_analysis_data()
    scores = ai_engine.analyze(data, url=url)
    assert scores.risk_level in ["HIGH_RISK", "SUSPICIOUS"]
    assert scores.authenticity_score <= 0.35


# ==============================================================================
# Scenario K: Confirmed Threat Intelligence
# ==============================================================================
def test_scenario_k_threat_intelligence_flag(ai_engine):
    url = "https://known-bad-phish.com"
    data = create_mock_analysis_data()
    reputation = {"status": "available", "provider": "Google Safe Browsing", "threat_detected": True}
    scores = ai_engine.analyze(data, url=url, reputation=reputation)
    assert scores.authenticity_score == 0.0
    assert scores.fake_score == 1.0
    assert scores.risk_level == "PHISHING"
    assert any("CONFIRMED_THREAT" in ind for ind in scores.critical_indicators)


# ==============================================================================
# Scenario L: Valid SSL Certificate on Phishing Domain (SSL must NOT mask phishing)
# ==============================================================================
def test_scenario_l_valid_ssl_on_phishing_site(ai_engine):
    url = "https://allegro.oferta7678678564.pl"
    data = create_mock_analysis_data(
        password_count=1,
        email_count=1,
        ssl_valid=True,  # Valid SSL Certificate
        html_title="Allegro - Bezpieczne Logowanie",
    )
    scores = ai_engine.analyze(data, url=url)
    # Valid SSL must NOT cause this to be rated as authentic
    assert scores.authenticity_score <= 0.15, f"Valid SSL falsely inflated phishing score: {scores.authenticity_score}"
    assert scores.risk_level == "PHISHING"


# ==============================================================================
# Scenario M: Legitimate Login Page (Must NOT be falsely classified as phishing)
# ==============================================================================
@pytest.mark.parametrize("url,title", [
    ("https://accounts.google.com/signin", "Google Sign In"),
    ("https://login.microsoftonline.com", "Microsoft Sign In"),
    ("https://allegro.pl/logowanie", "Allegro - Logowanie"),
])
def test_scenario_m_legitimate_login_pages(ai_engine, url, title):
    data = create_mock_analysis_data(
        password_count=1,
        email_count=1,
        html_title=title,
        ssl_valid=True,
    )
    scores = ai_engine.analyze(data, url=url)
    # Legitimate login pages on authorized domains must remain SAFE
    assert scores.authenticity_score >= 0.80, f"Legitimate login portal {url} received low score: {scores.authenticity_score}"
    assert scores.risk_level == "SAFE"
    assert len(scores.critical_indicators) == 0


# ==============================================================================
# Scenario N: URL Validation and FQDN Rejection
# ==============================================================================
def test_scenario_n_url_validation_rejections():
    validator = InputValidator()
    
    # Single-word hostname without TLD must be rejected with INVALID_URL
    is_valid, err = validator.validate_url("https://google")
    assert not is_valid
    assert "INVALID_URL" in err

    # Normal URL with valid TLD passes
    is_valid, err = validator.validate_url("https://google.com")
    assert is_valid
    assert err is None

    # Normalization handles scheme-less and case
    norm = InputValidator.normalize_url("www.Google.com/path?q=1")
    assert norm == "http://www.google.com/path?q=1"
