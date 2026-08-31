"""
Feature Extraction Module for Website Authenticity & Phishing Detection.

Converts collected website analysis data (URL, DOM, SSL, Network, JavaScript, Visual, Brand)
into a fixed, ordered numerical feature vector for XGBoost model training and inference.
"""

import math
import re
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse

import numpy as np

from src.models import (
    AnalysisData,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
)
from src.domain_analyzer import DomainAnalyzer, DomainIdentity, SUSPICIOUS_TLDS
from src.brand_detector import BrandDetector, BrandAnalysisResult


# Fixed list of 48 feature names in deterministic canonical order
FEATURE_NAMES: List[str] = [
    # Domain & URL Features (16)
    "url_length",
    "is_https",
    "subdomain_count",
    "has_ip_address",
    "hyphen_count",
    "dot_count",
    "is_suspicious_tld",
    "domain_length",
    "longest_numeric_sequence",
    "numeric_ratio",
    "domain_entropy",
    "is_punycode",
    "suspicious_keyword_count",
    "path_length",
    "query_length",
    "non_standard_port",
    # Brand & Impersonation Features (3)
    "brand_detected",
    "brand_domain_match",
    "brand_domain_mismatch",
    # SSL/TLS Features (4)
    "ssl_chain_valid",
    "ssl_expired",
    "ssl_self_signed",
    "ssl_recognized_ca",
    # DOM Structure & Forms Features (13)
    "dom_element_count",
    "dom_form_count",
    "dom_iframe_count",
    "dom_script_count",
    "password_input_count",
    "email_input_count",
    "card_input_count",
    "otp_input_count",
    "hidden_input_count",
    "login_keyword_count",
    "external_form_action_count",
    "cross_domain_form_action_count",
    "has_credential_harvesting_form",
    # Network Features (4)
    "network_request_count",
    "network_https_ratio",
    "network_unique_domains_count",
    "network_external_domains_count",
    # JavaScript Features (3)
    "js_script_count",
    "js_dom_modifications",
    "js_external_api_calls",
    # Visual Features (4)
    "has_screenshot",
    "viewport_width",
    "viewport_height",
    "image_count",
    # Threat Intelligence (1)
    "threat_intelligence_flag",
]

# Trusted Public Certificate Authorities keywords for CA recognition feature
TRUSTED_CA_KEYWORDS = {
    "digicert", "let's encrypt", "letsencrypt", "sectigo", "comodo",
    "godaddy", "google trust services", "amazon", "cloudflare",
    "geotrust", "thawte", "verisign", "identrust", "globalsign",
    "entrust", "baltimore", "usertrust", "zerossl", "buypass"
}


class FeatureExtractor:
    """Extracts numeric feature vectors from raw website data for XGBoost ML inference and training."""

    def __init__(
        self,
        domain_analyzer: Optional[DomainAnalyzer] = None,
        brand_detector: Optional[BrandDetector] = None,
    ):
        self.domain_analyzer = domain_analyzer or DomainAnalyzer()
        self.brand_detector = brand_detector or BrandDetector()

    def extract_features_dict(
        self,
        data: Optional[AnalysisData] = None,
        url: Optional[str] = None,
        reputation: Optional[Dict[str, Any]] = None,
        domain_info: Optional[DomainIdentity] = None,
        brand_result: Optional[BrandAnalysisResult] = None,
    ) -> Dict[str, float]:
        """
        Extract a dictionary of numerical feature values from collected website data.

        Args:
            data: AnalysisData instance with network, DOM, JS, visual, and SSL telemetry.
            url: Target website URL.
            reputation: External threat intelligence result (if any).
            domain_info: Pre-computed DomainIdentity (optional).
            brand_result: Pre-computed BrandAnalysisResult (optional).

        Returns:
            Dictionary mapping feature name to numerical float value.
        """
        target_url = (url or "").strip()
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")

        # Compute DomainIdentity if not provided
        if domain_info is None and target_url:
            domain_info = self.domain_analyzer.analyze_domain(target_url)

        # Extract HTML and headings for brand detection if needed
        html = ""
        headings: List[str] = []
        page_title = ""
        dom_metrics: Dict[str, Any] = {}

        if data is not None and data.dom is not None and not data.dom.failed:
            html = data.dom.html_content if isinstance(data.dom.html_content, str) else ""
            dom_metrics = data.dom.structure_metrics if isinstance(data.dom.structure_metrics, dict) else {}
            if html:
                title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
                if title_match:
                    page_title = title_match.group(1).strip()
                h_matches = re.findall(r"<h[1-3][^>]*>(.*?)</h[1-3]>", html, re.IGNORECASE | re.DOTALL)
                headings = [re.sub(r"<[^>]+>", "", h).strip() for h in h_matches if h]

        # Compute BrandAnalysisResult if not provided
        if brand_result is None and target_url:
            brand_result = self.brand_detector.detect_brand_impersonation(
                target_url, page_title=page_title, html_content=html, headings=headings
            )

        features: Dict[str, float] = {}

        # -------------------------------------------------------------
        # 1. Domain & URL Features
        # -------------------------------------------------------------
        features["url_length"] = float(len(target_url))
        features["is_https"] = 1.0 if parsed.scheme.lower() == "https" else 0.0

        if domain_info is not None:
            features["subdomain_count"] = float(domain_info.subdomain_count)
            features["has_ip_address"] = 1.0 if domain_info.is_ip_address else 0.0
            features["hyphen_count"] = float(domain_info.hyphen_count)
            features["dot_count"] = float(domain_info.hostname.count("."))
            tld_root = domain_info.public_suffix.split(".")[-1].lower() if domain_info.public_suffix else ""
            features["is_suspicious_tld"] = 1.0 if tld_root in SUSPICIOUS_TLDS else 0.0
            features["domain_length"] = float(len(domain_info.registrable_domain))
            features["longest_numeric_sequence"] = float(domain_info.longest_numeric_sequence)
            features["numeric_ratio"] = float(domain_info.numeric_ratio)
            features["domain_entropy"] = float(domain_info.entropy)
            features["is_punycode"] = 1.0 if domain_info.punycode_detected else 0.0
            features["suspicious_keyword_count"] = float(len(domain_info.matched_suspicious_words))
            features["non_standard_port"] = 1.0 if (domain_info.port and domain_info.port not in {80, 443, 8080, 8443}) else 0.0
        else:
            features["subdomain_count"] = 0.0
            features["has_ip_address"] = 0.0
            features["hyphen_count"] = float(target_url.count("-"))
            features["dot_count"] = float(target_url.count("."))
            features["is_suspicious_tld"] = 0.0
            features["domain_length"] = float(len(parsed.netloc))
            features["longest_numeric_sequence"] = 0.0
            features["numeric_ratio"] = 0.0
            features["domain_entropy"] = 0.0
            features["is_punycode"] = 0.0
            features["suspicious_keyword_count"] = 0.0
            features["non_standard_port"] = 0.0

        features["path_length"] = float(len(parsed.path or ""))
        features["query_length"] = float(len(parsed.query or ""))

        # -------------------------------------------------------------
        # 2. Brand & Impersonation Features
        # -------------------------------------------------------------
        if brand_result is not None:
            features["brand_detected"] = 1.0 if brand_result.brand_detected else 0.0
            features["brand_domain_match"] = 1.0 if (brand_result.brand_detected and brand_result.brand_domain_match) else 0.0
            features["brand_domain_mismatch"] = 1.0 if brand_result.is_impersonation else 0.0
        else:
            features["brand_detected"] = 0.0
            features["brand_domain_match"] = 0.0
            features["brand_domain_mismatch"] = 0.0

        # -------------------------------------------------------------
        # 3. SSL / TLS Features
        # -------------------------------------------------------------
        ssl_data = data.ssl if (data is not None and data.ssl is not None and not data.ssl.failed) else None
        if ssl_data is not None:
            features["ssl_chain_valid"] = 1.0 if getattr(ssl_data, "chain_valid", False) else 0.0
            
            # Expiration check
            exp_date_str = getattr(ssl_data, "expiration_date", "") or ""
            is_expired = 0.0
            if exp_date_str:
                try:
                    exp_dt = datetime.fromisoformat(exp_date_str.replace("Z", "+00:00"))
                    if exp_dt < datetime.now(timezone.utc):
                        is_expired = 1.0
                except Exception:
                    pass
            features["ssl_expired"] = is_expired

            # Issuer / CA checks
            issuer = (getattr(ssl_data, "issuer", "") or "").lower()
            if not issuer:
                features["ssl_self_signed"] = 1.0
                features["ssl_recognized_ca"] = 0.0
            else:
                features["ssl_self_signed"] = 1.0 if ("self" in issuer or "untrusted" in issuer) else 0.0
                features["ssl_recognized_ca"] = 1.0 if any(ca in issuer for ca in TRUSTED_CA_KEYWORDS) else 0.0
        else:
            features["ssl_chain_valid"] = 0.0
            features["ssl_expired"] = 0.0
            features["ssl_self_signed"] = 0.0
            features["ssl_recognized_ca"] = 0.0

        # -------------------------------------------------------------
        # 4. DOM Structure & Form Features
        # -------------------------------------------------------------
        features["dom_element_count"] = float(dom_metrics.get("element_count", 0))
        features["dom_form_count"] = float(dom_metrics.get("form_count", 0))
        features["dom_iframe_count"] = float(dom_metrics.get("iframe_count", 0))
        features["dom_script_count"] = float(dom_metrics.get("script_count", 0))
        pwd_c = float(dom_metrics.get("password_input_count", 0))
        email_c = float(dom_metrics.get("email_input_count", 0))
        card_c = float(dom_metrics.get("card_input_count", 0))
        otp_c = float(dom_metrics.get("otp_input_count", 0))
        features["password_input_count"] = pwd_c
        features["email_input_count"] = email_c
        features["card_input_count"] = card_c
        features["otp_input_count"] = otp_c
        features["hidden_input_count"] = float(dom_metrics.get("hidden_input_count", 0))
        features["login_keyword_count"] = float(dom_metrics.get("login_keyword_count", 0))
        features["external_form_action_count"] = float(dom_metrics.get("external_form_action_count", 0))
        features["cross_domain_form_action_count"] = float(dom_metrics.get("cross_domain_form_action_count", 0))
        features["has_credential_harvesting_form"] = 1.0 if (pwd_c > 0 or email_c > 0 or card_c > 0 or otp_c > 0) else 0.0

        # -------------------------------------------------------------
        # 5. Network Features
        # -------------------------------------------------------------
        net_data = data.network if (data is not None and data.network is not None and not data.network.failed) else None
        if net_data is not None:
            req_c = float(getattr(net_data, "request_count", 0))
            features["network_request_count"] = req_c
            proto_dist = getattr(net_data, "protocol_distribution", {}) or {}
            secure_reqs = proto_dist.get("https", 0) + proto_dist.get("wss", 0)
            features["network_https_ratio"] = (float(secure_reqs) / req_c) if req_c > 0 else (1.0 if features["is_https"] > 0 else 0.0)
            u_domains = getattr(net_data, "unique_domains", []) or []
            features["network_unique_domains_count"] = float(len(u_domains))
            
            # External domains (domains different from current page domain)
            page_host = (parsed.hostname or "").lower()
            ext_domains = [d for d in u_domains if d.lower() != page_host]
            features["network_external_domains_count"] = float(len(ext_domains))
        else:
            features["network_request_count"] = 0.0
            features["network_https_ratio"] = 1.0 if features["is_https"] > 0 else 0.0
            features["network_unique_domains_count"] = 0.0
            features["network_external_domains_count"] = 0.0

        # -------------------------------------------------------------
        # 6. JavaScript Telemetry Features
        # -------------------------------------------------------------
        js_data = data.javascript if (data is not None and data.javascript is not None and not data.javascript.failed) else None
        if js_data is not None:
            features["js_script_count"] = float(getattr(js_data, "script_count", 0))
            features["js_dom_modifications"] = float(getattr(js_data, "dom_modifications", 0))
            features["js_external_api_calls"] = float(getattr(js_data, "external_api_calls", 0))
        else:
            features["js_script_count"] = 0.0
            features["js_dom_modifications"] = 0.0
            features["js_external_api_calls"] = 0.0

        # -------------------------------------------------------------
        # 7. Visual Features
        # -------------------------------------------------------------
        vis_data = data.visual if (data is not None and data.visual is not None and not data.visual.failed) else None
        if vis_data is not None:
            s_path = getattr(vis_data, "screenshot_path", "") or ""
            features["has_screenshot"] = 1.0 if s_path else 0.0
            layout = getattr(vis_data, "layout_characteristics", {}) or {}
            features["viewport_width"] = float(layout.get("viewport_width", 1280))
            features["viewport_height"] = float(layout.get("viewport_height", 800))
            features["image_count"] = float(layout.get("image_count", 0))
        else:
            features["has_screenshot"] = 0.0
            features["viewport_width"] = 1280.0
            features["viewport_height"] = 800.0
            features["image_count"] = 0.0

        # -------------------------------------------------------------
        # 8. Threat Intelligence Features
        # -------------------------------------------------------------
        if reputation is not None and isinstance(reputation, dict):
            features["threat_intelligence_flag"] = 1.0 if reputation.get("threat_detected") else 0.0
        else:
            features["threat_intelligence_flag"] = 0.0

        return features

    def extract_feature_vector(
        self,
        data: Optional[AnalysisData] = None,
        url: Optional[str] = None,
        reputation: Optional[Dict[str, Any]] = None,
        domain_info: Optional[DomainIdentity] = None,
        brand_result: Optional[BrandAnalysisResult] = None,
    ) -> np.ndarray:
        """
        Extract numerical feature vector as a 1D numpy array in deterministic feature order.

        Returns:
            1D numpy array with length equal to len(FEATURE_NAMES) (38 features).
        """
        f_dict = self.extract_features_dict(
            data=data,
            url=url,
            reputation=reputation,
            domain_info=domain_info,
            brand_result=brand_result,
        )
        return np.array([f_dict.get(name, 0.0) for name in FEATURE_NAMES], dtype=np.float32)
