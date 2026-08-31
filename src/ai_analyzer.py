"""
AI Analysis Engine for Website Authenticity Detector.

This module processes collected AnalysisData (network, DOM, JavaScript, visual, SSL)
to generate authenticity and fraud probability scores using rule-based heuristics.

Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8
"""

import logging
import time
import re
from datetime import datetime, timezone
from typing import Optional, Dict, List, Tuple, Any

from src.models import (
    AnalysisData,
    AnalysisScores,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
)
from src.domain_analyzer import DomainAnalyzer, DomainIdentity
from src.brand_detector import BrandDetector, BrandAnalysisResult
from src.feature_extractor import FeatureExtractor, FEATURE_NAMES
from src.ml_model import MLPhishingModel


# Default base weights across the 5 categories (sum = 1.0)
CATEGORY_BASE_WEIGHTS: Dict[str, float] = {
    "ssl": 0.25,
    "network": 0.20,
    "dom": 0.20,
    "javascript": 0.20,
    "visual": 0.15,
}

DEFAULT_ANALYSIS_TIMEOUT: int = 10  # Requirement 3.8 (10-second timeout)


class AIAnalysisEngine:
    """
    AI Analysis Engine that evaluates website authenticity from collected data.

    Combines XGBoost-based machine learning probability prediction with domain identity,
    brand impersonation detection, and non-linear safety risk gates.
    """

    def __init__(
        self,
        logger: Optional[logging.Logger] = None,
        ml_model: Optional[MLPhishingModel] = None,
        feature_extractor: Optional[FeatureExtractor] = None,
    ):
        """Initialize the AI Analysis Engine."""
        self.logger = logger or logging.getLogger(__name__)
        self.domain_analyzer = DomainAnalyzer()
        self.brand_detector = BrandDetector()
        self.feature_extractor = feature_extractor or FeatureExtractor(
            domain_analyzer=self.domain_analyzer,
            brand_detector=self.brand_detector,
        )
        self.ml_model = ml_model or MLPhishingModel(logger=self.logger)

    def _is_exact_non_negative_int(self, val: Any) -> bool:
        """Check if a value is an exact integer and >= 0 (excluding bool)."""
        return isinstance(val, int) and not isinstance(val, bool) and val >= 0

    def validate_data(self, data: AnalysisData) -> Tuple[bool, str]:
        """
        Validate data completeness and integrity.

        Performs:
        1. Input type validation (must be AnalysisData instance).
        2. Data corruption detection (type checks and non-negative range checks) (Requirement 3.6).
        3. Minimum category requirement (requires >= 3 active categories) (Requirement 3.5).

        Args:
            data: The AnalysisData instance to validate.

        Returns:
            Tuple of (is_valid: bool, error_message: str).
        """
        if not isinstance(data, AnalysisData):
            return False, "Invalid input: expected an AnalysisData instance"

        # 1. Check for data corruption across all present categories (Req 3.6)
        is_uncorrupted, corruption_msg = self._check_corruption(data)
        if not is_uncorrupted:
            return False, corruption_msg

        # 2. Check for sufficient active categories (Req 3.5)
        active_categories = self._get_active_categories(data)
        count = len(active_categories)

        if count < 3:
            return False, f"Insufficient data: at least 3 categories required (found {count})"

        return True, ""

    def calculate_confidence(self, data: AnalysisData) -> str:
        """
        Calculate confidence indicator based on category collection ratio.

        Thresholds (Requirements 4.4, 4.5, 4.6 & Property 15):
        - HIGH: 4-5 categories (80%+ successfully collected)
        - MEDIUM: 3 categories (60% successfully collected)
        - LOW: 0-2 categories (<60% successfully collected)

        Args:
            data: AnalysisData instance to evaluate.

        Returns:
            "HIGH", "MEDIUM", or "LOW".
        """
        if not isinstance(data, AnalysisData):
            return "LOW"

        active_categories = self._get_active_categories(data)
        count = len(active_categories)

        if count >= 4:
            return "HIGH"
        elif count == 3:
            return "MEDIUM"
        else:
            return "LOW"

    def _check_corruption(self, data: AnalysisData) -> Tuple[bool, str]:
        """Validate internal field types and ranges for all present categories."""
        if data.network is not None:
            valid, err = self._validate_network_integrity(data.network)
            if not valid:
                return False, err

        if data.dom is not None:
            valid, err = self._validate_dom_integrity(data.dom)
            if not valid:
                return False, err

        if data.javascript is not None:
            valid, err = self._validate_javascript_integrity(data.javascript)
            if not valid:
                return False, err

        if data.visual is not None:
            valid, err = self._validate_visual_integrity(data.visual)
            if not valid:
                return False, err

        if data.ssl is not None:
            valid, err = self._validate_ssl_integrity(data.ssl)
            if not valid:
                return False, err

        return True, ""

    def _validate_network_integrity(self, net: NetworkData) -> Tuple[bool, str]:
        """Validate NetworkData types and ranges."""
        if not isinstance(net, NetworkData):
            return False, "Data corruption detected in network: expected NetworkData instance"

        if not self._is_exact_non_negative_int(net.request_count):
            return False, "Data corruption detected in network.request_count: expected non-negative int"

        if not isinstance(net.unique_domains, list) or not all(isinstance(d, str) for d in net.unique_domains):
            return False, "Data corruption detected in network.unique_domains: expected list of strings"

        if not isinstance(net.protocol_distribution, dict):
            return False, "Data corruption detected in network.protocol_distribution: expected dict"

        for k, v in net.protocol_distribution.items():
            if not isinstance(k, str) or not self._is_exact_non_negative_int(v):
                return False, "Data corruption detected in network.protocol_distribution: expected dict of string to non-negative int"

        if not isinstance(net.failed, bool):
            return False, "Data corruption detected in network.failed: expected boolean"

        return True, ""

    def _validate_dom_integrity(self, dom: DOMData) -> Tuple[bool, str]:
        """Validate DOMData types and ranges."""
        if not isinstance(dom, DOMData):
            return False, "Data corruption detected in dom: expected DOMData instance"

        if not isinstance(dom.html_content, str):
            return False, "Data corruption detected in dom.html_content: expected string"

        if not isinstance(dom.structure_metrics, dict):
            return False, "Data corruption detected in dom.structure_metrics: expected dict"

        for k, v in dom.structure_metrics.items():
            if not isinstance(k, str) or not self._is_exact_non_negative_int(v):
                return False, f"Data corruption detected in dom.structure_metrics.{k}: expected non-negative int"

        if not isinstance(dom.failed, bool):
            return False, "Data corruption detected in dom.failed: expected boolean"

        return True, ""

    def _validate_javascript_integrity(self, js: JavaScriptData) -> Tuple[bool, str]:
        """Validate JavaScriptData types and ranges."""
        if not isinstance(js, JavaScriptData):
            return False, "Data corruption detected in javascript: expected JavaScriptData instance"

        if not self._is_exact_non_negative_int(js.script_count):
            return False, "Data corruption detected in javascript.script_count: expected non-negative int"

        if not self._is_exact_non_negative_int(js.dom_modifications):
            return False, "Data corruption detected in javascript.dom_modifications: expected non-negative int"

        if not self._is_exact_non_negative_int(js.external_api_calls):
            return False, "Data corruption detected in javascript.external_api_calls: expected non-negative int"

        if not isinstance(js.failed, bool):
            return False, "Data corruption detected in javascript.failed: expected boolean"

        return True, ""

    def _validate_visual_integrity(self, visual: VisualData) -> Tuple[bool, str]:
        """Validate VisualData types and ranges."""
        if not isinstance(visual, VisualData):
            return False, "Data corruption detected in visual: expected VisualData instance"

        if not isinstance(visual.screenshot_path, str):
            return False, "Data corruption detected in visual.screenshot_path: expected string"

        if not isinstance(visual.layout_characteristics, dict):
            return False, "Data corruption detected in visual.layout_characteristics: expected dict"

        for dim in ["viewport_width", "viewport_height", "image_count", "width", "height"]:
            if dim in visual.layout_characteristics and visual.layout_characteristics[dim] is not None:
                val = visual.layout_characteristics[dim]
                if not self._is_exact_non_negative_int(val):
                    return False, f"Data corruption detected in visual.layout_characteristics.{dim}: expected non-negative int"

        if not isinstance(visual.failed, bool):
            return False, "Data corruption detected in visual.failed: expected boolean"

        return True, ""

    def _validate_ssl_integrity(self, ssl: SSLData) -> Tuple[bool, str]:
        """Validate SSLData types and ranges."""
        if not isinstance(ssl, SSLData):
            return False, "Data corruption detected in ssl: expected SSLData instance"

        if not isinstance(ssl.issuer, str):
            return False, "Data corruption detected in ssl.issuer: expected string"

        if not isinstance(ssl.expiration_date, str):
            return False, "Data corruption detected in ssl.expiration_date: expected string"

        if not isinstance(ssl.chain_valid, bool):
            return False, "Data corruption detected in ssl.chain_valid: expected boolean"

        if not isinstance(ssl.failed, bool):
            return False, "Data corruption detected in ssl.failed: expected boolean"

        return True, ""

    def analyze(
        self,
        data: AnalysisData,
        url: Optional[str] = None,
        reputation: Optional[Dict[str, Any]] = None,
        timeout: int = DEFAULT_ANALYSIS_TIMEOUT,
        progress_callback: Optional[Any] = None,
    ) -> AnalysisScores:
        """
        Analyze collected website data and generate authenticity scores with risk gating.

        Args:
            data: AnalysisData containing collected categories.
            url: Optional analyzed website URL for domain and brand analysis.
            reputation: Optional threat intelligence reputation result.
            timeout: Maximum execution time in seconds (default 10s per Requirement 3.8).
            progress_callback: Optional callback for reporting analysis progress stages.

        Returns:
            AnalysisScores with authenticity_score, fake_score, top_factors, suspicious_indicators, risk_level, and critical_indicators.

        Raises:
            ValueError: If input is not AnalysisData or has fewer than 3 collected categories (Req 3.5).
            RuntimeError: If data corruption is detected in category fields (Req 3.6).
            TimeoutError: If analysis exceeds the specified timeout (Req 3.8).
        """
        start_time = time.monotonic()

        # Check for non-positive timeout
        if timeout <= 0:
            raise TimeoutError(f"Analysis timed out: exceeded {timeout}s limit")

        # Validate minimum category requirements and data corruption (Req 3.5, 3.6)
        is_valid, error_msg = self.validate_data(data)
        if not is_valid:
            self.logger.warning(f"Data validation failed: {error_msg}")
            if error_msg.startswith("Data corruption detected"):
                raise RuntimeError(error_msg)
            raise ValueError(error_msg)

        active_categories = self._get_active_categories(data)
        category_scores: Dict[str, float] = {}
        category_factors: Dict[str, List[str]] = {}
        all_suspicious_indicators: List[str] = []

        # Evaluate each active category
        if "ssl" in active_categories and data.ssl is not None:
            score, factors, suspicious = self._evaluate_ssl(data.ssl)
            category_scores["ssl"] = score
            category_factors["ssl"] = factors
            all_suspicious_indicators.extend(suspicious)

        if "network" in active_categories and data.network is not None:
            score, factors, suspicious = self._evaluate_network(data.network)
            category_scores["network"] = score
            category_factors["network"] = factors
            all_suspicious_indicators.extend(suspicious)

        if "dom" in active_categories and data.dom is not None:
            score, factors, suspicious = self._evaluate_dom(data.dom)
            category_scores["dom"] = score
            category_factors["dom"] = factors
            all_suspicious_indicators.extend(suspicious)

        if "javascript" in active_categories and data.javascript is not None:
            score, factors, suspicious = self._evaluate_javascript(data.javascript)
            category_scores["javascript"] = score
            category_factors["javascript"] = factors
            all_suspicious_indicators.extend(suspicious)

        if "visual" in active_categories and data.visual is not None:
            score, factors, suspicious = self._evaluate_visual(data.visual)
            category_scores["visual"] = score
            category_factors["visual"] = factors
            all_suspicious_indicators.extend(suspicious)

        # Check elapsed time before aggregation
        elapsed = time.monotonic() - start_time
        if elapsed > timeout:
            raise TimeoutError(f"Analysis timed out: took {elapsed:.2f}s, exceeded {timeout}s limit")

        # Dynamically normalize weights over ACTIVE categories only
        total_active_weight = sum(CATEGORY_BASE_WEIGHTS[cat] for cat in active_categories)
        if total_active_weight == 0:
            raise RuntimeError("No active category weights available for scoring")

        category_heuristic_authenticity = sum(
            (CATEGORY_BASE_WEIGHTS[cat] / total_active_weight) * category_scores[cat]
            for cat in active_categories
        )

        # Extract DOM metrics and content for phishing detection
        html = data.dom.html_content if data.dom and isinstance(data.dom.html_content, str) else ""
        dom_metrics = data.dom.structure_metrics if data.dom and isinstance(data.dom.structure_metrics, dict) else {}
        pwd_count = dom_metrics.get('password_input_count', 0)
        email_count = dom_metrics.get('email_input_count', 0)
        card_count = dom_metrics.get('card_input_count', 0)
        otp_count = dom_metrics.get('otp_input_count', 0)
        hidden_count = dom_metrics.get('hidden_input_count', 0)
        iframe_count = dom_metrics.get('iframe_count', 0)
        ext_action_count = dom_metrics.get('external_form_action_count', 0)
        cross_domain_action_count = dom_metrics.get('cross_domain_form_action_count', 0)
        login_kw_count = dom_metrics.get('login_keyword_count', 0)

        # Extract page title and headings for brand detection
        page_title = ""
        headings = []
        if html:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if title_match:
                page_title = title_match.group(1).strip()
            h_matches = re.findall(r'<h[1-3][^>]*>(.*?)</h[1-3]>', html, re.IGNORECASE | re.DOTALL)
            headings = [re.sub(r'<[^>]+>', '', h).strip() for h in h_matches if h]

        # Domain Identity & Brand Impersonation Analysis
        critical_indicators: List[str] = []
        suspicious_indicators: List[str] = []
        risk_level = "SAFE"

        domain_info: Optional[DomainIdentity] = None
        brand_result: Optional[BrandAnalysisResult] = None

        if url:
            domain_info = self.domain_analyzer.analyze_domain(url)
            brand_result = self.brand_detector.detect_brand_impersonation(
                url, page_title=page_title, html_content=html, headings=headings
            )

        # -------------------------------------------------------------
        # [5] Feature Extraction, [6] XGBoost Inference & [7] Heuristics
        # -------------------------------------------------------------
        if progress_callback and callable(progress_callback):
            try:
                progress_callback("extracting features")
            except Exception:
                pass

        features_dict = self.feature_extractor.extract_features_dict(
            data=data,
            url=url,
            reputation=reputation,
            domain_info=domain_info,
            brand_result=brand_result,
        )
        self.logger.info(f"[5] FEATURE EXTRACTION: {len(features_dict)} canonical features extracted")
        print(f"[5] FEATURE EXTRACTION: {len(features_dict)} canonical features extracted", flush=True)

        if progress_callback and callable(progress_callback):
            try:
                progress_callback("running XGBoost")
            except Exception:
                pass

        ml_phishing_prob = self.ml_model.predict_phishing_probability(features_dict)
        ml_authenticity_prob = 1.0 - ml_phishing_prob

        if progress_callback and callable(progress_callback):
            try:
                progress_callback("running AI/hybrid analysis")
            except Exception:
                pass

        if url and self.ml_model.is_trained:
            # Blend ML probability with heuristic baseline (70% ML model, 30% categories)
            weighted_authenticity = (ml_authenticity_prob * 0.70) + (category_heuristic_authenticity * 0.30)
        else:
            weighted_authenticity = category_heuristic_authenticity

        ml_diag = [
            f"[6] XGBOOST INFERENCE",
            f"[ML]",
            f"Feature extraction executed: YES",
            f"XGBoost executed: {'YES' if self.ml_model.is_trained else 'NO'}",
            f"XGBoost phishing probability: {ml_phishing_prob*100:.2f}%",
            f"XGBoost authenticity probability: {ml_authenticity_prob*100:.2f}%",
            f"",
            f"[7] HEURISTIC ANALYSIS",
            f"[HYBRID]",
            f"ML contribution: {ml_authenticity_prob * 0.70 * 100:.2f}% (70% weight)",
            f"Heuristic contribution: {category_heuristic_authenticity * 0.30 * 100:.2f}% (30% weight)",
            f"Final weighted score: {weighted_authenticity*100:.2f}%",
        ]
        for line in ml_diag:
            self.logger.info(line)
            print(line, flush=True)

        # -------------------------------------------------------------
        # [9] RISK GATES: Strong Phishing & Impersonation Gating Logic
        # -------------------------------------------------------------
        triggered_gates: List[str] = []
        triggered_reasons: List[str] = []

        def log_override(gate_name: str, reason: str, prev_auth: float, new_auth: float, r_level: str):
            triggered_gates.append(gate_name)
            triggered_reasons.append(reason)
            prev_fake = round(1.0 - prev_auth, 4)
            new_fake = round(1.0 - new_auth, 4)
            override_lines = [
                f"[OVERRIDE]",
                f"gate={gate_name}",
                f"reason={reason}",
                f"previous_authenticity={prev_auth:.4f}",
                f"new_authenticity={new_auth:.4f}",
                f"previous_fake={prev_fake:.4f}",
                f"new_fake={new_fake:.4f}",
                f"risk_level={r_level}"
            ]
            for o_line in override_lines:
                self.logger.info(o_line)
                print(o_line, flush=True)

        self.logger.info("[9] RISK GATES EVALUATION")
        print("[9] RISK GATES EVALUATION", flush=True)

        # Gate 0: Explicit Phishing / Security Interstitial Warning in HTML
        if html and re.search(r"this\s+(?:website|site|page)\s+has\s+been\s+reported\s+(?:for|as)(?:\s+potential)?\s+phishing|suspected\s+phishing|deceptive\s+site\s+ahead", html, re.IGNORECASE):
            critical_indicators.append(
                "SECURITY_INTERSTITIAL: Interstitial page content explicitly flagged target website for suspected phishing / security threat"
            )
            prev_a = weighted_authenticity
            weighted_authenticity = min(weighted_authenticity, 0.05)
            risk_level = "PHISHING"
            log_override("Gate 0 (Security Interstitial Warning)", "Explicit phishing warning text found in HTML", prev_a, weighted_authenticity, risk_level)

        # Gate 1: Brand Impersonation Mismatch
        if brand_result and brand_result.is_impersonation:
            critical_indicators.extend(brand_result.indicators)
            prev_a = weighted_authenticity
            if pwd_count > 0 or email_count > 0 or card_count > 0 or otp_count > 0:
                critical_indicators.append(
                    "CREDENTIAL_HARVESTING: Login/security input fields on unauthorized brand impersonation domain"
                )
                weighted_authenticity = min(weighted_authenticity, 0.08)
                risk_level = "PHISHING"
                log_override("Gate 1 (Brand Impersonation + Credentials)", f"Impersonating {brand_result.brand_detected} with input fields", prev_a, weighted_authenticity, risk_level)
            else:
                weighted_authenticity = min(weighted_authenticity, 0.18)
                risk_level = "HIGH_RISK"
                log_override("Gate 1 (Brand Impersonation)", f"Impersonating {brand_result.brand_detected} on unauthorized root domain", prev_a, weighted_authenticity, risk_level)

        # Gate 2: Cross-Domain Credential Exfiltration
        if cross_domain_action_count > 0 and (pwd_count > 0 or email_count > 0 or card_count > 0):
            critical_indicators.append(
                "CROSS_DOMAIN_EXFILTRATION: Sensitive credentials submitted to an external third-party domain"
            )
            prev_a = weighted_authenticity
            weighted_authenticity = min(weighted_authenticity, 0.10)
            risk_level = "PHISHING"
            log_override("Gate 2 (Cross-Domain Exfiltration)", "Credentials submitted to external third-party domain", prev_a, weighted_authenticity, risk_level)

        # Gate 3: Payment / OTP Harvesting on Unverified / Unknown Domain
        if (card_count > 0 or otp_count > 0) and not (brand_result and brand_result.brand_detected and brand_result.brand_domain_match):
            if card_count > 0:
                critical_indicators.append("CREDENTIAL_HARVESTING: Payment / credit card details entry on unverified domain")
            if otp_count > 0:
                critical_indicators.append("CREDENTIAL_HARVESTING: One-Time Passcode (OTP) / PIN entry requested on unverified domain")
            prev_a = weighted_authenticity
            weighted_authenticity = min(weighted_authenticity, 0.10)
            risk_level = "PHISHING"
            log_override("Gate 3 (Payment/OTP Harvesting)", "Financial or OTP entry fields on unverified domain", prev_a, weighted_authenticity, risk_level)

        # Gate 4: Confirmed Malicious Threat Intelligence
        if reputation and reputation.get("threat_detected"):
            provider_name = reputation.get("provider", "Threat Intelligence")
            critical_indicators.append(f"CONFIRMED_THREAT: Flagged as malicious by {provider_name}")
            prev_a = weighted_authenticity
            weighted_authenticity = 0.0
            risk_level = "PHISHING"
            log_override("Gate 4 (Threat Intelligence)", f"Confirmed malicious by {provider_name}", prev_a, weighted_authenticity, risk_level)

        # Gate 5: Suspicious Domain & High Numeric Density
        if domain_info and domain_info.suspicious_hostname:
            is_verified_brand = bool(brand_result and brand_result.brand_detected and brand_result.brand_domain_match)
            if not is_verified_brand:
                suspicious_indicators.extend(domain_info.risk_factors)
                prev_a = weighted_authenticity
                if domain_info.longest_numeric_sequence >= 6 or domain_info.numeric_ratio > 0.35:
                    weighted_authenticity = min(weighted_authenticity, 0.25)
                    if risk_level not in ["PHISHING", "HIGH_RISK"]:
                        risk_level = "HIGH_RISK"
                    log_override("Gate 5 (Suspicious TLD/Numeric)", "High numeric sequence / suspicious hostname", prev_a, weighted_authenticity, risk_level)
                elif domain_info.is_ip_address:
                    weighted_authenticity = min(weighted_authenticity, 0.45)
                    if risk_level == "SAFE":
                        risk_level = "SUSPICIOUS"
                    log_override("Gate 5 (Raw IP Address)", "Raw IP address used in place of domain", prev_a, weighted_authenticity, risk_level)
                elif domain_info.punycode_detected:
                    weighted_authenticity = min(weighted_authenticity, 0.45)
                    if risk_level == "SAFE":
                        risk_level = "SUSPICIOUS"
                    log_override("Gate 5 (Punycode)", "Punycode internationalized homograph indicator", prev_a, weighted_authenticity, risk_level)
                else:
                    weighted_authenticity = min(weighted_authenticity, 0.45)
                    if risk_level == "SAFE":
                        risk_level = "SUSPICIOUS"
                    log_override("Gate 5 (Suspicious Hostname/TLD)", f"Risk factor: {', '.join(domain_info.risk_factors)}", prev_a, weighted_authenticity, risk_level)

        # Gate 6: Structural Deception Signals
        if hidden_count > 5:
            suspicious_indicators.append(f"Excessive hidden form inputs ({hidden_count} hidden fields)")
            prev_a = weighted_authenticity
            weighted_authenticity = min(weighted_authenticity, 0.55)
            if risk_level == "SAFE":
                risk_level = "SUSPICIOUS"
            log_override("Gate 6 (Hidden Inputs)", f"{hidden_count} hidden input fields", prev_a, weighted_authenticity, risk_level)

        if iframe_count > 5:
            suspicious_indicators.append(f"Excessive embedded iframe elements ({iframe_count} iframes)")
            prev_a = weighted_authenticity
            weighted_authenticity = min(weighted_authenticity, 0.60)
            if risk_level == "SAFE":
                risk_level = "SUSPICIOUS"
            log_override("Gate 6 (Iframes)", f"{iframe_count} embedded iframes", prev_a, weighted_authenticity, risk_level)

        # Gate 7: Legitimate Domain Verification
        if brand_result and brand_result.brand_detected and brand_result.brand_domain_match:
            prev_a = weighted_authenticity
            weighted_authenticity = max(weighted_authenticity, 0.85)
            risk_level = "SAFE"
            suspicious_indicators = [ind for ind in suspicious_indicators if "Suspicious authentication keywords" not in ind]
            if prev_a < 0.85:
                log_override("Gate 7 (Verified Brand Match)", f"Official verified domain for {brand_result.brand_detected}", prev_a, weighted_authenticity, risk_level)
        elif domain_info and domain_info.domain_identity_score >= 0.90 and not (brand_result and brand_result.is_impersonation) and cross_domain_action_count == 0:
            if weighted_authenticity >= 0.70:
                risk_level = "SAFE"

        # Clamp authenticity score strictly to [0.0, 1.0] (Req 3.2)
        authenticity_score = max(0.0, min(1.0, weighted_authenticity))

        # Calculate fake score naturally as complementary probability (Req 3.3, 3.4)
        fake_score = round(1.0 - authenticity_score, 4)
        fake_score = max(0.0, min(1.0, fake_score))

        # Standardize Risk Level
        if risk_level not in ["PHISHING", "HIGH_RISK", "SAFE"]:
            if fake_score >= 0.70 or critical_indicators:
                risk_level = "HIGH_RISK"
            elif fake_score >= 0.45 or suspicious_indicators:
                risk_level = "SUSPICIOUS"
            else:
                risk_level = "SAFE"
        elif risk_level == "SAFE":
            if critical_indicators:
                risk_level = "HIGH_RISK"
            elif fake_score >= 0.50:
                risk_level = "SUSPICIOUS"

        # Generate ML model feature explanations for this prediction
        model_explanations = self.ml_model.explain_prediction(features_dict, fake_score, top_k=3)

        # Select exactly 3 deterministic top factors ranked by weighted influence (Req 7.4 & Property 25)
        top_factors = self._select_top_factors(
            active_categories,
            category_scores,
            category_factors,
            risk_level=risk_level,
            critical_indicators=critical_indicators,
            suspicious_indicators=suspicious_indicators + all_suspicious_indicators,
            model_explanations=model_explanations,
        )

        # Gate suspicious indicators on Fake_Score > 0.5 or critical indicators (Req 7.3 & Property 24)
        combined_suspicious = critical_indicators + suspicious_indicators + all_suspicious_indicators
        if fake_score > 0.5 or critical_indicators or suspicious_indicators:
            final_suspicious = list(dict.fromkeys(combined_suspicious))
        else:
            final_suspicious = []

        # [10] FINAL RESULT
        gate_summary = ", ".join(triggered_gates) if triggered_gates else "NONE"
        gate_reason = ", ".join(triggered_reasons) if triggered_reasons else "NONE"
        final_logs = [
            f"[10] FINAL RESULT",
            f"[RISK GATES]",
            f"Which gate triggered: {gate_summary}",
            f"Why it triggered: {gate_reason}",
            f"",
            f"[FINAL]",
            f"Authentication score: {authenticity_score*100:.2f}%",
            f"Fake score: {fake_score*100:.2f}%",
            f"Risk level: {risk_level}",
            f"Confidence: {self.calculate_confidence(data)}",
            f"Reason: {top_factors[0] if top_factors else 'Analysis completed'}"
        ]
        for line in final_logs:
            self.logger.info(line)
            print(line, flush=True)

        return AnalysisScores(
            authenticity_score=authenticity_score,
            fake_score=fake_score,
            top_factors=top_factors,
            suspicious_indicators=final_suspicious,
            risk_level=risk_level,
            critical_indicators=critical_indicators,
        )

    def _select_top_factors(
        self,
        active_categories: List[str],
        category_scores: Dict[str, float],
        category_factors: Dict[str, List[str]],
        risk_level: str = "SAFE",
        critical_indicators: Optional[List[str]] = None,
        suspicious_indicators: Optional[List[str]] = None,
        model_explanations: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Deterministically select and rank the top 3 data factors.
        Prioritizes top risk factors for threats, suppressing misleading positive SSL factors.
        """
        critical = critical_indicators or []
        suspicious = suspicious_indicators or []
        explanations = model_explanations or []
        selected_factors: List[str] = []

        # If high risk or phishing: pick top risk indicators first
        if risk_level in ["PHISHING", "HIGH_RISK"]:
            for ind in critical + suspicious + explanations:
                if ind and ind not in selected_factors:
                    if "Valid trusted SSL" in ind or "Recognized trusted Certificate" in ind:
                        continue
                    selected_factors.append(ind)
                    if len(selected_factors) == 3:
                        return selected_factors

        category_priority = ["ssl", "network", "dom", "javascript", "visual"]
        if risk_level in ["PHISHING", "HIGH_RISK", "SUSPICIOUS"]:
            category_priority = ["dom", "network", "javascript", "visual", "ssl"]

        scored_categories = []
        for cat in active_categories:
            weight = CATEGORY_BASE_WEIGHTS.get(cat, 0.0)
            score = category_scores.get(cat, 0.0)
            influence = weight * score
            prio_idx = category_priority.index(cat) if cat in category_priority else 99
            scored_categories.append((influence, weight, -prio_idx, cat))

        scored_categories.sort(reverse=True)

        # Phase 1: Round-robin across distinct scored categories to ensure diverse factors
        for _, _, _, cat in scored_categories:
            factors = category_factors.get(cat, [])
            for f in factors:
                if f and f not in selected_factors:
                    if risk_level in ["PHISHING", "HIGH_RISK"] and ("Valid trusted SSL" in f or "Recognized trusted Certificate" in f):
                        continue
                    selected_factors.append(f)
                    break
            if len(selected_factors) == 3:
                break

        # Phase 2: If fewer than 3 factors, add remaining factors
        if len(selected_factors) < 3:
            for _, _, _, cat in scored_categories:
                factors = category_factors.get(cat, [])
                for f in factors:
                    if f and f not in selected_factors:
                        if risk_level in ["PHISHING", "HIGH_RISK"] and ("Valid trusted SSL" in f or "Recognized trusted Certificate" in f):
                            continue
                        selected_factors.append(f)
                        if len(selected_factors) == 3:
                            break
                if len(selected_factors) == 3:
                    break

        if len(selected_factors) < 3:
            fallbacks = {
                "ssl": "SSL certificate information evaluated",
                "network": "Network protocol distribution verified",
                "dom": "DOM structure analysis completed",
                "javascript": "JavaScript behavior analysis completed",
                "visual": "Visual rendering characteristics captured",
            }
            for _, _, _, cat in scored_categories:
                fb = fallbacks.get(cat)
                if fb and fb not in selected_factors:
                    selected_factors.append(fb)
                    if len(selected_factors) == 3:
                        break

        return selected_factors[:3]

    def _get_active_categories(self, data: AnalysisData) -> List[str]:
        """Get list of successfully collected, non-failed categories."""
        active = []
        if data.network is not None and not data.network.failed:
            active.append("network")
        if data.dom is not None and not data.dom.failed:
            active.append("dom")
        if data.javascript is not None and not data.javascript.failed:
            active.append("javascript")
        if data.visual is not None and not data.visual.failed:
            active.append("visual")
        if data.ssl is not None and not data.ssl.failed:
            active.append("ssl")
        return active

    def _evaluate_ssl(self, ssl: SSLData) -> Tuple[float, List[str], List[str]]:
        """
        Evaluate SSL certificate signals.

        Base weight: 0.25
        Signals: chain validity, issuer presence, expiration status.
        """
        score = 0.5
        factors: List[str] = []
        suspicious: List[str] = []

        if ssl.chain_valid:
            score += 0.3
            factors.append("Valid trusted SSL certificate chain")
        else:
            score -= 0.4
            suspicious.append("SSL certificate chain is invalid or self-signed")

        if ssl.issuer and ssl.issuer.strip():
            score += 0.1
            factors.append(f"Recognized certificate authority: {ssl.issuer.split(',')[0]}")
        else:
            score -= 0.2
            suspicious.append("SSL certificate missing issuer distinguished name")

        if ssl.expiration_date:
            try:
                # ISO-8601 UTC parse check
                exp_dt = datetime.fromisoformat(ssl.expiration_date.replace("Z", "+00:00"))
                if exp_dt > datetime.now(timezone.utc):
                    score += 0.1
                    factors.append("Non-expired SSL certificate")
                else:
                    score -= 0.3
                    suspicious.append("SSL certificate has expired")
            except Exception:
                score -= 0.1
                suspicious.append("Invalid SSL certificate expiration timestamp format")

        return max(0.0, min(1.0, score)), factors, suspicious

    def _evaluate_network(self, network: NetworkData) -> Tuple[float, List[str], List[str]]:
        """
        Evaluate network request pattern signals.

        Base weight: 0.20
        Signals: HTTPS/secure protocol ratio, domain fan-out, request volume.
        """
        score = 0.5
        factors: List[str] = []
        suspicious: List[str] = []

        total_requests = network.request_count or sum(network.protocol_distribution.values())
        https_count = network.protocol_distribution.get("https", 0) + network.protocol_distribution.get("wss", 0)
        http_count = network.protocol_distribution.get("http", 0) + network.protocol_distribution.get("ws", 0)

        if total_requests > 0:
            https_ratio = https_count / total_requests
            if https_ratio >= 0.8:
                score += 0.25
                factors.append(f"High secure protocol adoption ({https_ratio * 100:.1f}% HTTPS/WSS)")
            elif https_ratio < 0.5:
                score -= 0.25
                suspicious.append(f"Majority of network requests use unencrypted protocols ({http_count} HTTP)")
        else:
            score += 0.1

        unique_domain_count = len(network.unique_domains)
        if 1 <= unique_domain_count <= 15:
            score += 0.15
            factors.append(f"Moderate external domain contact count ({unique_domain_count} domains)")
        elif unique_domain_count > 30:
            score -= 0.2
            suspicious.append(f"Excessive unique external domains contacted ({unique_domain_count} domains)")

        if total_requests > 500:
            score -= 0.1
            suspicious.append(f"Abnormally high network request volume ({total_requests} requests)")
        elif total_requests > 0:
            score += 0.1

        return max(0.0, min(1.0, score)), factors, suspicious

    def _evaluate_dom(self, dom: DOMData) -> Tuple[float, List[str], List[str]]:
        """
        Evaluate DOM structure and phishing-related HTML signals.
        """

        score = 0.5
        factors: List[str] = []
        suspicious: List[str] = []

        metrics = dom.structure_metrics or {}

        element_count = (
            metrics.get("element_count")
            or metrics.get("total_elements")
            or len(dom.html_content) // 50
        )

        iframe_count = metrics.get("iframe_count", 0)
        form_count = metrics.get("form_count", 0)

        password_input_count = metrics.get("password_input_count", 0)
        email_input_count = metrics.get("email_input_count", 0)
        hidden_input_count = metrics.get("hidden_input_count", 0)
        login_keyword_count = metrics.get("login_keyword_count", 0)

        # General DOM structure
        if element_count >= 10:
            score += 0.15
            factors.append(
                f"Rich DOM element hierarchy ({element_count} elements)"
            )
        elif element_count < 3 and len(dom.html_content) < 50:
            score -= 0.25
            suspicious.append(
                "Sparse or placeholder DOM structure"
            )

        # Iframes
        if iframe_count == 0:
            score += 0.10
            factors.append("No embedded iframes detected")
        elif iframe_count > 5:
            score -= 0.20
            suspicious.append(
                f"High number of embedded iframes ({iframe_count} iframes)"
            )

        # Forms
        if 0 < form_count <= 5:
            score += 0.10
            factors.append(
                f"Standard form input structure ({form_count} forms)"
            )
        elif form_count > 10:
            score -= 0.15
            suspicious.append(
                f"Suspiciously high number of input forms ({form_count} forms)"
            )

        # Phishing-specific signals
        if password_input_count > 0:
            score -= 0.15
            suspicious.append(
                f"Password input detected ({password_input_count} password fields)"
            )

        if email_input_count > 0 and password_input_count > 0:
            score -= 0.20
            suspicious.append(
                "Email and password fields detected together"
            )

        if login_keyword_count >= 2 and password_input_count > 0:
            score -= 0.20
            suspicious.append(
                "Login/account verification language combined with password input"
            )

        external_form_action_count = metrics.get("external_form_action_count", 0)
        if external_form_action_count > 0:
            score -= 0.25
            suspicious.append(
                f"Form submits data to an external third-party domain ({external_form_action_count} external form actions)"
            )

        if hidden_input_count > 5:
            score -= 0.10
            suspicious.append(
                f"Multiple hidden input fields detected ({hidden_input_count})"
            )

        if login_keyword_count >= 2:
            score -= 0.05
            suspicious.append(
                f"Multiple account/login related keywords detected ({login_keyword_count})"
            )

        # Positive signal
        if (
            password_input_count == 0
            and email_input_count == 0
            and login_keyword_count == 0
            and external_form_action_count == 0
        ):
            factors.append(
                "No obvious login credential collection signals detected"
            )

        return max(0.0, min(1.0, score)), factors, suspicious

    def _evaluate_javascript(self, js: JavaScriptData) -> Tuple[float, List[str], List[str]]:
        """
        Evaluate JavaScript execution metrics.

        Base weight: 0.20
        Signals: script volume, dynamic mutation rate, external API invocations.
        """
        score = 0.5
        factors: List[str] = []
        suspicious: List[str] = []

        if 1 <= js.script_count <= 40:
            score += 0.2
            factors.append(f"Standard script execution profile ({js.script_count} scripts)")
        elif js.script_count > 80:
            score -= 0.2
            suspicious.append(f"Excessive number of executed scripts ({js.script_count} scripts)")

        if js.dom_modifications <= 200:
            score += 0.15
            factors.append("Controlled dynamic DOM modification rate")
        elif js.dom_modifications > 1000:
            score -= 0.3
            suspicious.append(f"Extreme dynamic DOM modification frequency ({js.dom_modifications} mutations)")

        if js.external_api_calls <= 20:
            score += 0.15
            factors.append("Normal external API invocation volume")
        elif js.external_api_calls > 50:
            score -= 0.2
            suspicious.append(f"High frequency of external API calls ({js.external_api_calls} calls)")

        return max(0.0, min(1.0, score)), factors, suspicious

    def _evaluate_visual(self, visual: VisualData) -> Tuple[float, List[str], List[str]]:
        """
        Evaluate visual rendering characteristics.

        Base weight: 0.15
        Signals: screenshot presence, viewport dimensions, layout properties.
        """
        score = 0.5
        factors: List[str] = []
        suspicious: List[str] = []

        if visual.screenshot_path and visual.screenshot_path.strip():
            score += 0.25
            factors.append("Valid rendered layout screenshot captured")
        else:
            score -= 0.3
            suspicious.append("Failed or missing layout screenshot")

        layout = visual.layout_characteristics or {}
        width = layout.get("viewport_width") or layout.get("width", 0)
        height = layout.get("viewport_height") or layout.get("height", 0)

        if width > 0 and height > 0:
            score += 0.15
            factors.append(f"Standard viewport rendering ({width}x{height})")
        else:
            score -= 0.1

        if layout.get("has_images") or layout.get("image_count", 0) > 0:
            score += 0.1
            factors.append("Visual image assets present")

        return max(0.0, min(1.0, score)), factors, suspicious
