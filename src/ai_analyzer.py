"""
AI Analysis Engine for Website Authenticity Detector.

This module processes collected AnalysisData (network, DOM, JavaScript, visual, SSL)
to generate authenticity and fraud probability scores using rule-based heuristics.

Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8
"""

import logging
import time
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

    Evaluates structural, behavioral, cryptographic, and visual signals
    across all available data categories using normalized rule-based heuristics.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the AI Analysis Engine."""
        self.logger = logger or logging.getLogger(__name__)

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

    def analyze(self, data: AnalysisData, timeout: int = DEFAULT_ANALYSIS_TIMEOUT) -> AnalysisScores:
        """
        Analyze collected website data and generate authenticity scores.

        Args:
            data: AnalysisData containing collected categories.
            timeout: Maximum execution time in seconds (default 10s per Requirement 3.8).

        Returns:
            AnalysisScores with authenticity_score, fake_score, top_factors, and suspicious_indicators.

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

        weighted_authenticity = sum(
            (CATEGORY_BASE_WEIGHTS[cat] / total_active_weight) * category_scores[cat]
            for cat in active_categories
        )

        # Clamp authenticity score strictly to [0.0, 1.0] (Req 3.2)
        authenticity_score = max(0.0, min(1.0, weighted_authenticity))

        # Calculate fake score naturally as complementary probability (Req 3.3, 3.4)
        # Using 4 decimal places preserving natural float sum within tolerance of 0.01
        fake_score = round(1.0 - authenticity_score, 4)
        fake_score = max(0.0, min(1.0, fake_score))

        # Select exactly 3 deterministic top factors ranked by weighted influence (Req 7.4 & Property 25)
        top_factors = self._select_top_factors(active_categories, category_scores, category_factors)

        # Gate suspicious indicators on Fake_Score > 0.5 (Req 7.3 & Property 24)
        if fake_score > 0.5:
            final_suspicious = list(dict.fromkeys(all_suspicious_indicators))
        else:
            final_suspicious = []

        self.logger.info(
            f"AI analysis completed: authenticity={authenticity_score:.4f}, fake={fake_score:.4f}, "
            f"{len(top_factors)} top factors, {len(final_suspicious)} suspicious indicators"
        )

        return AnalysisScores(
            authenticity_score=authenticity_score,
            fake_score=fake_score,
            top_factors=top_factors,
            suspicious_indicators=final_suspicious,
        )

    def _select_top_factors(
        self,
        active_categories: List[str],
        category_scores: Dict[str, float],
        category_factors: Dict[str, List[str]],
    ) -> List[str]:
        """
        Deterministically select and rank the top 3 data factors influencing Authenticity_Score.

        Requirement 7.4 & Property 25:
        - Exactly 3 factors must be returned for any successful analysis result.
        - Factors are ranked by category weighted influence (base_weight * category_score).
        - Unique strings only (deduplicated).
        - Inactive/failed categories are NEVER included.
        - If fewer than 3 factors exist, deterministic fallback factors from active categories are added.
        """
        category_priority = ["ssl", "network", "dom", "javascript", "visual"]

        scored_categories = []
        for cat in active_categories:
            weight = CATEGORY_BASE_WEIGHTS.get(cat, 0.0)
            score = category_scores.get(cat, 0.0)
            influence = weight * score
            prio_idx = category_priority.index(cat) if cat in category_priority else 99
            scored_categories.append((influence, weight, -prio_idx, cat))

        scored_categories.sort(reverse=True)

        selected_factors: List[str] = []
        for _, _, _, cat in scored_categories:
            factors = category_factors.get(cat, [])
            for f in factors:
                if f and f not in selected_factors:
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
        Evaluate DOM structure and HTML content signals.

        Base weight: 0.20
        Signals: total elements, iframe count, form count.
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

        if element_count >= 10:
            score += 0.2
            factors.append(f"Rich DOM element hierarchy ({element_count} elements)")
        elif element_count < 3 and len(dom.html_content) < 50:
            score -= 0.25
            suspicious.append("Sparse or placeholder DOM structure")

        if iframe_count == 0:
            score += 0.15
            factors.append("No embedded iframes detected")
        elif iframe_count > 5:
            score -= 0.3
            suspicious.append(f"High number of embedded iframes ({iframe_count} iframes)")

        if 0 < form_count <= 5:
            score += 0.15
            factors.append(f"Standard form input structure ({form_count} forms)")
        elif form_count > 10:
            score -= 0.15
            suspicious.append(f"Suspiciously high number of input forms ({form_count} forms)")

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
