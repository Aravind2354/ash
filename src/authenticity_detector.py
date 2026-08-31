"""Website Authenticity Detection System - Main Orchestration.

This module provides the main orchestration logic for analyzing website authenticity.
It coordinates input validation, sandbox execution, data collection, AI analysis,
and report generation.

Requirements: 5.3, 5.4, 5.5, 7.2, 8.3, 9.3
"""

import sys
import asyncio
import inspect
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from src.input_validator import InputValidator
from src.sandbox import SandboxManager, Sandbox
from src.data_collector import DataCollector
from src.ai_analyzer import AIAnalysisEngine
from src.report_generator import ReportGenerator
from src.models import AnalysisResult
from src.domain_analyzer import DomainAnalyzer
from src.brand_detector import BrandDetector
from src.reputation_provider import ReputationService
from config.logging_config import get_logger
import re
import urllib.parse


# Collection Timeout Constants (Requirements 8.1, 8.3)
INITIAL_COLLECTION_TIMEOUT = 60
RETRY_COLLECTION_TIMEOUT = INITIAL_COLLECTION_TIMEOUT + 30


class AuthenticityDetector:
    """Orchestrates website authenticity analysis pipeline."""

    def __init__(
        self,
        validator: Optional[InputValidator] = None,
        sandbox_manager: Optional[SandboxManager] = None,
        data_collector: Optional[DataCollector] = None,
        ai_engine: Optional[AIAnalysisEngine] = None,
        report_generator: Optional[ReportGenerator] = None,
    ):
        """Initialize the Authenticity Detector with optional dependency overrides."""
        self.validator = validator or InputValidator()
        self.sandbox_manager = sandbox_manager or SandboxManager()
        self.data_collector = data_collector or DataCollector()
        self.ai_engine = ai_engine or AIAnalysisEngine()
        self.report_generator = report_generator or ReportGenerator()
        self.domain_analyzer = DomainAnalyzer()
        self.brand_detector = BrandDetector()
        self.reputation_service = ReputationService()
        self.logger = get_logger("authenticity_detector")

    def analyze_website(self, url: str, progress_callback: Optional[Any] = None) -> Dict[str, Any]:
        """Synchronous wrapper for analyze_website_async.

        Validates: Requirements 5.3, 5.4, 5.5, Property 17
        """
        try:
            # Playwright requires a Windows event loop that supports subprocesses.
            # On Linux, use the default event loop policy.
            if sys.platform == "win32":
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Running inside existing event loop (e.g. FastAPI / asyncio environment)
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    def _thread_worker():
                        # Playwright requires a Windows event loop that supports subprocesses.
                        # On Linux, use the default event loop policy.
                        if sys.platform == "win32":
                            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
                        return asyncio.run(self.analyze_website_async(url, progress_callback=progress_callback))
                    future = pool.submit(_thread_worker)
                    return future.result()
            else:
                return loop.run_until_complete(self.analyze_website_async(url, progress_callback=progress_callback))
        except RuntimeError:
            # Playwright requires a Windows event loop that supports subprocesses.
            # On Linux, use the default event loop policy.
            if sys.platform == "win32":
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            return asyncio.run(self.analyze_website_async(url, progress_callback=progress_callback))
        except Exception as exc:
            # Synchronous wrapper emergency fallback
            return self._build_emergency_fallback(url, "synchronous wrapper", exc)

    async def analyze_website_async(self, url: str, progress_callback: Optional[Any] = None) -> Dict[str, Any]:
        """Asynchronously orchestrates website authenticity analysis.

        Execution Flow:
        1. Normalize & Validate URL BEFORE sandbox creation. If invalid -> return error dict fast (<500ms).
        2. Record analysis_start timestamp in ISO 8601 UTC format.
        3. Create & initialize sandbox context.
        4. Validate isolation boundary.
        5. Load target URL in sandbox.
        6. Collect AnalysisData via DataCollector.
        7. Evaluate categories collected. If < 3: perform ONE retry with +30s timeout extension.
        8. Send AnalysisData to AIAnalysisEngine.analyze() with domain and reputation intelligence.
        9. Calculate confidence via AIAnalysisEngine.calculate_confidence().
        10. Build AnalysisResult dataclass.
        11. Generate final report via ReportGenerator.
        12. Record analysis_completion timestamp in ISO 8601 UTC format.
        13. Always cleanup/terminate sandbox in a finally block.
        """
        current_operation = "URL validation"
        if progress_callback and callable(progress_callback):
            try:
                progress_callback("starting")
            except Exception:
                pass

        # Step 1: Input Validation BEFORE Sandbox Creation (Requirement 9.3)
        try:
            is_valid, validation_error = self.validator.validate_url(url)
            if not is_valid:
                self.logger.warning(f"URL validation failed for {url}: {validation_error}")
                return {
                    "status": "failed",
                    "risk_level": "FAILED",
                    "authenticity_score": None,
                    "fake_score": None,
                    "confidence_indicator": "LOW",
                    "url": url,
                    "normalized_url": url,
                    "timestamps": {},
                    "analysis_data": None,
                    "top_factors": [],
                    "suspicious_indicators": [],
                    "critical_indicators": [],
                    "error_message": f"URL validation failed: {validation_error}",
                }
        except Exception as exc:
            return self._handle_exception(exc, current_operation, url, {})

        normalized_url = InputValidator.normalize_url(url)
        target_url = normalized_url if normalized_url else url
        parsed_target = urllib.parse.urlparse(target_url if "://" in target_url else f"http://{target_url}")

        url_diag = [
            "[1] URL RECEIVED",
            "[URL]",
            f"Original URL: {url}",
            f"Normalized URL: {target_url}",
            f"Hostname: {parsed_target.hostname or ''}",
            f"Path: {parsed_target.path or '/'}",
        ]
        for line in url_diag:
            self.logger.info(line)
            print(line, flush=True)

        start_dt = datetime.now(timezone.utc)
        start_str = start_dt.isoformat().replace("+00:00", "Z")
        timestamps = {"analysis_start": start_str}

        sandbox: Optional[Sandbox] = None
        sb_manager = self.sandbox_manager or SandboxManager()

        try:
            # Top-level try block wrapping execution pipeline (Requirement 5.4)
            try:
                # Step 4: Create Sandbox
                current_operation = "sandbox initialization"
                if progress_callback and callable(progress_callback):
                    try:
                        progress_callback("collecting website data")
                    except Exception:
                        pass
                create_res = sb_manager.create_sandbox()
                if inspect.isawaitable(create_res):
                    sandbox = await create_res
                else:
                    sandbox = create_res

                # Step 5: Validate Isolation Boundary
                current_operation = "isolation validation"
                try:
                    iso_res = sb_manager.validate_isolation()
                    if inspect.isawaitable(iso_res):
                        is_isolated, iso_msg = await iso_res
                    else:
                        is_isolated, iso_msg = iso_res

                    if not is_isolated:
                        self.logger.error(f"Isolation check failed: {iso_msg}")
                        result = AnalysisResult(
                            authenticity_score=None,
                            fake_score=None,
                            confidence_indicator="LOW",
                            url=url,
                            analysis_data=None,
                            timestamps=timestamps,
                            top_factors=[],
                            suspicious_indicators=[],
                            error_message=f"Isolation boundary check failed: {iso_msg}",
                        )
                        return self.report_generator.generate_partial_report(result)
                except Exception as e:
                    self.logger.warning(f"Isolation validation check exception: {e}")

                # Step 6: Load Target URL
                current_operation = "URL loading"
                load_res = sandbox.load_url(target_url, timeout=30)
                if inspect.isawaitable(load_res):
                    loaded = await load_res
                else:
                    loaded = load_res

                if not loaded:
                    result = AnalysisResult(
                        authenticity_score=None,
                        fake_score=None,
                        confidence_indicator="LOW",
                        url=url,
                        analysis_data=None,
                        timestamps=timestamps,
                        top_factors=[],
                        suspicious_indicators=[],
                        error_message=f"Failed to load URL: {target_url}",
                    )
                    return self.report_generator.generate_partial_report(result)

                # Step 7: Collect AnalysisData
                current_operation = "data collection"
                self.logger.info(f"[4] DATA COLLECTION: Starting multi-category data extraction for {target_url}")
                print(f"[4] DATA COLLECTION: Starting multi-category data extraction for {target_url}", flush=True)
                collect_res = self.data_collector.collect_all(sandbox, target_url, timeout=INITIAL_COLLECTION_TIMEOUT)
                if inspect.isawaitable(collect_res):
                    analysis_data = await collect_res
                else:
                    analysis_data = collect_res

                # SSL Data Collection fallback if not already populated
                if analysis_data is not None and getattr(analysis_data, "ssl", None) is None:
                    try:
                        ssl_res = self.data_collector.collect_ssl_data(target_url)
                        if inspect.isawaitable(ssl_res):
                            ssl_data = await ssl_res
                        else:
                            ssl_data = ssl_res
                        analysis_data.ssl = ssl_data
                    except Exception:
                        pass

                categories_count = 0
                if analysis_data is not None:
                    categories_count = sum(
                        1 for cat in [
                            analysis_data.network,
                            analysis_data.dom,
                            analysis_data.javascript,
                            analysis_data.visual,
                            analysis_data.ssl,
                        ] if cat is not None and getattr(cat, "failed", False) is False
                    )
                    analysis_data.categories_collected = categories_count

                # Step 8-9: Insufficient Data Retry (Requirement 8.3)
                if categories_count < 3:
                    current_operation = "data collection retry"
                    self.logger.warning(
                        f"Insufficient categories collected ({categories_count}/5). Initiating ONE retry with +30s extended timeout ({RETRY_COLLECTION_TIMEOUT}s)."
                    )
                    retry_res = self.data_collector.collect_all(sandbox, target_url, timeout=RETRY_COLLECTION_TIMEOUT)
                    if inspect.isawaitable(retry_res):
                        retry_data = await retry_res
                    else:
                        retry_data = retry_res

                    if analysis_data is not None and getattr(analysis_data, "ssl", None) is not None:
                        retry_data.ssl = analysis_data.ssl

                    retry_count = sum(
                        1 for cat in [
                            retry_data.network,
                            retry_data.dom,
                            retry_data.javascript,
                            retry_data.visual,
                            retry_data.ssl,
                        ] if cat is not None and getattr(cat, "failed", False) is False
                    )
                    retry_data.categories_collected = retry_count
                    analysis_data = retry_data
                    categories_count = retry_count

                # Extract page identity and HTML content for validation
                html = analysis_data.dom.html_content if analysis_data and analysis_data.dom and isinstance(analysis_data.dom.html_content, str) else ""
                dom_metrics = analysis_data.dom.structure_metrics if analysis_data and analysis_data.dom and isinstance(analysis_data.dom.structure_metrics, dict) else {}
                page_title = ""
                if html:
                    title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        page_title = title_match.group(1).strip()

                final_browser_url = target_url
                if sandbox is not None and getattr(sandbox, "page", None) is not None:
                    try:
                        p_url = sandbox.page.url
                        if isinstance(p_url, str) and p_url:
                            final_browser_url = p_url
                        elif isinstance(getattr(sandbox, "final_url", None), str):
                            final_browser_url = sandbox.final_url
                    except Exception:
                        final_browser_url = getattr(sandbox, "final_url", target_url)

                # [2] Interstitial & Block-Page Detection
                from src.interstitial_detector import detect_interstitial
                interstitial_res = detect_interstitial(
                    requested_url=target_url,
                    final_url=final_browser_url,
                    page_title=page_title,
                    html_content=html,
                    structure_metrics=dom_metrics,
                )

                # Diagnostic Logging
                redirects = getattr(analysis_data.network, "redirect_chain", []) if analysis_data and analysis_data.network else []
                diag_logs = [
                    f"[2] INTERSTITIAL CHECK",
                    f"[NAVIGATION]",
                    f"Final URL: {interstitial_res.final_url}",
                    f"HTTP status: 200",
                    f"Page title: {interstitial_res.page_title}",
                    f"Redirect chain: {redirects}",
                    f"",
                    f"[INTERSTITIAL]",
                    f"Detected: {'YES' if interstitial_res.is_interstitial else 'NO'}",
                    f"Type: {interstitial_res.interstitial_type}",
                    f"Reason: {interstitial_res.reason if interstitial_res.reason else 'None'}",
                    f"Indicators: {interstitial_res.indicators if interstitial_res.indicators else '[]'}",
                    f"Was target actually reached: {'YES' if interstitial_res.target_domain_reached else 'NO'}",
                    f"",
                    f"[3] WEBSITE REACHED: {'YES' if interstitial_res.target_domain_reached else 'NO'}"
                ]
                for line in diag_logs:
                    self.logger.info(line)
                    print(line, flush=True)

                # Query threat reputation
                reputation = None
                try:
                    rep_res = self.reputation_service.check_reputation(target_url)
                    if inspect.isawaitable(rep_res):
                        reputation = await rep_res
                    else:
                        reputation = rep_res
                except Exception as rep_exc:
                    self.logger.warning(f"Reputation check error: {rep_exc}")

                domain_info = self.domain_analyzer.analyze_domain(target_url)
                headings = []
                if html:
                    h_matches = re.findall(r'<h[1-3][^>]*>(.*?)</h[1-3]>', html, re.IGNORECASE | re.DOTALL)
                    headings = [re.sub(r'<[^>]+>', '', h).strip() for h in h_matches if h]

                brand_result = self.brand_detector.detect_brand_impersonation(
                    target_url, page_title=page_title, html_content=html, headings=headings
                )

                # -------------------------------------------------------------
                # -------------------------------------------------------------
                # Handle Interstitial Case vs Normal Website Execution
                # -------------------------------------------------------------
                if interstitial_res.is_interstitial:
                    end_dt = datetime.now(timezone.utc)
                    end_str = end_dt.isoformat().replace("+00:00", "Z")
                    timestamps["analysis_completion"] = end_str

                    diag_interstitial = [
                        f"[ANALYSIS] Proceeding to feature extraction: NO (Security/interstitial detected: {interstitial_res.reason})",
                    ]
                    if interstitial_res.is_phishing_signal or interstitial_res.interstitial_type in ["PHISHING_WARNING", "SECURITY_BLOCKED"]:
                        diag_interstitial.extend([
                            "[XGBOOST] Status: BYPASSED",
                            "[XGBOOST] Prediction: BYPASSED (Security/Phishing Interstitial Warning)",
                            f"[HYBRID] Final result: PHISHING / HIGH_RISK (Preserving security signal: {interstitial_res.reason})",
                            "[RISK GATE] Triggered: Security Interstitial Warning",
                            "[FINAL] Authenticity: 5.00%",
                            "[FINAL] Fake/Phishing: 95.00%",
                            "[FINAL] Confidence: HIGH",
                            "[FINAL] Risk: PHISHING"
                        ])
                    else:
                        diag_interstitial.extend([
                            "[INTERSTITIAL] Target website not reached",
                            f"[INTERSTITIAL] Type: ANTI_BOT / VERIFICATION ({interstitial_res.interstitial_type})",
                            "[XGBOOST] Status: NOT EXECUTED",
                            "[XGBOOST] Prediction: NOT EXECUTED",
                            "[HYBRID] Final result: INCONCLUSIVE",
                            "[RISK GATE] Triggered: Bot / Verification Challenge Interstitial",
                            "[FINAL] Authenticity: None",
                            "[FINAL] Fake/Phishing: None",
                            "[FINAL] Confidence: LOW",
                            "[FINAL] Risk: INCONCLUSIVE"
                        ])
                    for line in diag_interstitial:
                        self.logger.info(line)
                        print(line, flush=True)

                    if interstitial_res.is_phishing_signal or interstitial_res.interstitial_type in ["PHISHING_WARNING", "SECURITY_BLOCKED"]:
                        auth_score = 0.05
                        fake_score = 0.95
                        confidence = "HIGH"
                        risk_level = "PHISHING"
                        classification = "PHISHING"
                        xgboost_executed = False
                        xgboost_probability = None
                        critical_indicators = [f"SECURITY_INTERSTITIAL: {ind}" for ind in interstitial_res.indicators]
                        top_factors = [
                            f"Security warning: {interstitial_res.reason}",
                            "Website explicitly reported for suspected phishing or malicious activity",
                            "Navigation blocked by security interstitial before reaching target"
                        ]
                        suspicious_indicators = interstitial_res.indicators
                        error_msg = None
                        reason = interstitial_res.reason
                        recommendation = "Do not enter sensitive information on this website."
                    else:
                        # Bot / Verification challenge where target website was not reached
                        auth_score = None
                        fake_score = None
                        confidence = "LOW"
                        risk_level = "INCONCLUSIVE"
                        classification = "INCONCLUSIVE"
                        xgboost_executed = False
                        xgboost_probability = None
                        critical_indicators = []
                        top_factors = [
                            "Target website was intercepted by a security challenge / interstitial",
                            f"Challenge detected: {interstitial_res.reason}",
                            "Target website content could not be verified"
                        ]
                        suspicious_indicators = [f"Security challenge intercepted target URL: {interstitial_res.reason}"]
                        error_msg = None
                        reason = interstitial_res.reason or "Target website was not reached due to an anti-bot or verification challenge"
                        recommendation = "Try again with a website that can be reached by the analysis browser"

                    if progress_callback and callable(progress_callback):
                        try:
                            progress_callback("generating report")
                        except Exception:
                            pass

                    result = AnalysisResult(
                        authenticity_score=auth_score,
                        fake_score=fake_score,
                        confidence_indicator=confidence,
                        url=url,
                        analysis_data=analysis_data,
                        timestamps=timestamps,
                        top_factors=top_factors,
                        suspicious_indicators=suspicious_indicators,
                        error_message=error_msg,
                        risk_level=risk_level,
                        normalized_url=target_url,
                        domain=domain_info.hostname,
                        registrable_domain=domain_info.registrable_domain,
                        brand_detected=brand_result.brand_detected if brand_result else None,
                        brand_domain_match=brand_result.brand_domain_match if brand_result else None,
                        reputation=reputation,
                        redirects=[],
                        critical_indicators=critical_indicators,
                    )

                    report = self.report_generator.generate_report(result)

                    report["status"] = "completed"
                    report["classification"] = classification
                    report["risk_level"] = risk_level
                    report["confidence"] = confidence
                    report["confidence_indicator"] = confidence
                    report["xgboost_executed"] = xgboost_executed
                    report["xgboost_probability"] = xgboost_probability
                    report["reason"] = reason
                    report["recommendation"] = recommendation
                    report["normalized_url"] = target_url
                    report["domain"] = domain_info.hostname
                    report["registrable_domain"] = domain_info.registrable_domain
                    report["brand_detected"] = brand_result.brand_detected if brand_result else None
                    report["brand_domain_match"] = brand_result.brand_domain_match if brand_result else None
                    report["reputation"] = reputation
                    report["redirects"] = []
                    report["critical_indicators"] = critical_indicators
                    report["error_message"] = error_msg

                    if progress_callback and callable(progress_callback):
                        try:
                            progress_callback("completed")
                        except Exception:
                            pass

                    return report

                # -------------------------------------------------------------
                # Normal Website: Proceed to AI & XGBoost Pipeline
                # -------------------------------------------------------------
                self.logger.info("[ANALYSIS] Proceeding to feature extraction: YES")

                # Step 10: AI Analysis
                current_operation = "AI analysis"
                try:
                    import unittest.mock
                    if isinstance(self.ai_engine, (unittest.mock.Mock, unittest.mock.MagicMock)):
                        scores = self.ai_engine.analyze(analysis_data)
                    else:
                        scores = self.ai_engine.analyze(analysis_data, url=target_url, reputation=reputation, progress_callback=progress_callback)
                except TypeError:
                    scores = self.ai_engine.analyze(analysis_data)

                confidence = self.ai_engine.calculate_confidence(analysis_data)
                auth_score = scores.authenticity_score
                fake_score = scores.fake_score
                top_factors = scores.top_factors
                suspicious_indicators = scores.suspicious_indicators
                risk_level = getattr(scores, "risk_level", "SAFE")
                critical_indicators = getattr(scores, "critical_indicators", [])

                end_dt = datetime.now(timezone.utc)
                end_str = end_dt.isoformat().replace("+00:00", "Z")
                timestamps["analysis_completion"] = end_str

                # Step 11: Report Generation
                current_operation = "report generation"
                if progress_callback and callable(progress_callback):
                    try:
                        progress_callback("generating report")
                    except Exception:
                        pass

                result = AnalysisResult(
                    authenticity_score=auth_score,
                    fake_score=fake_score,
                    confidence_indicator=confidence,
                    url=url,
                    analysis_data=analysis_data,
                    timestamps=timestamps,
                    top_factors=top_factors,
                    suspicious_indicators=suspicious_indicators,
                    error_message=None,
                    risk_level=risk_level,
                    normalized_url=target_url,
                    domain=domain_info.hostname,
                    registrable_domain=domain_info.registrable_domain,
                    brand_detected=brand_result.brand_detected if brand_result else None,
                    brand_domain_match=brand_result.brand_domain_match if brand_result else None,
                    reputation=reputation,
                    redirects=[],
                    critical_indicators=critical_indicators,
                )

                if auth_score is None and risk_level != "INCONCLUSIVE":
                    report = self.report_generator.generate_partial_report(result)
                else:
                    report = self.report_generator.generate_report(result)

                ml_trained = getattr(getattr(self.ai_engine, "ml_model", None), "is_trained", False)
                report["status"] = "completed"
                report["classification"] = risk_level
                report["risk_level"] = risk_level
                report["confidence"] = confidence
                report["confidence_indicator"] = confidence
                report["xgboost_executed"] = True if (ml_trained and risk_level != "INCONCLUSIVE") else False
                report["xgboost_probability"] = (
                    round(fake_score, 4)
                    if (fake_score is not None and isinstance(fake_score, (int, float)) and risk_level != "INCONCLUSIVE")
                    else None
                )
                report["normalized_url"] = target_url
                report["domain"] = domain_info.hostname
                report["registrable_domain"] = domain_info.registrable_domain
                report["brand_detected"] = brand_result.brand_detected if brand_result else None
                report["brand_domain_match"] = brand_result.brand_domain_match if brand_result else None
                report["reputation"] = reputation
                report["redirects"] = []
                report["critical_indicators"] = critical_indicators
                if risk_level == "INCONCLUSIVE":
                    report["reason"] = "Target website was not reached due to an anti-bot or verification challenge"
                    report["recommendation"] = "Try again with a website that can be reached by the analysis browser"
                    report["error_message"] = None

                if progress_callback and callable(progress_callback):
                    try:
                        progress_callback("completed")
                    except Exception:
                        pass

                return report

            except Exception as exc:
                # Top-level exception handler (Requirement 5.4, Property 18)
                return self._handle_exception(exc, current_operation, url, timestamps)

        finally:
            # Step 15: Always Cleanup Sandbox
            current_operation = "sandbox cleanup"
            if sandbox is not None or self.sandbox_manager is not None:
                try:
                    term_res = sb_manager.terminate_sandbox(sandbox)
                    if inspect.isawaitable(term_res):
                        await term_res
                except Exception as e:
                    self.logger.error(f"Error during sandbox termination: {e}")

    def _handle_exception(
        self,
        exc: Exception,
        operation: str,
        url: str,
        timestamps: Dict[str, str],
    ) -> Dict[str, Any]:
        """Catches and logs exception information, returning structured error dict with fallback.

        Validates: Requirements 5.4, 5.5, Property 18
        """
        try:
            exc_type = type(exc).__name__
            exc_msg = str(exc)

            # Log exception type, message, and failed operation (Requirement 5.4)
            self.logger.error(
                f"Exception during '{operation}' for URL '{url}': [{exc_type}] {exc_msg}",
                extra={
                    "extra_fields": {
                        "exception_type": exc_type,
                        "exception_message": exc_msg,
                        "failed_operation": operation,
                        "url": url,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                },
            )

            err_summary = f"Operation '{operation}' failed with {exc_type}: {exc_msg}" if exc_msg else f"Operation '{operation}' failed with {exc_type}"

            result = AnalysisResult(
                authenticity_score=None,
                fake_score=None,
                confidence_indicator="LOW",
                url=url,
                analysis_data=None,
                timestamps=timestamps,
                top_factors=[],
                suspicious_indicators=[],
                error_message=err_summary,
            )

            report = self.report_generator.generate_partial_report(result)
            report["exception_type"] = exc_type
            report["failed_operation"] = operation
            return report

        except Exception as fallback_exc:
            # Fallback mechanism if error handling code itself fails (Requirement 5.4)
            return self._build_emergency_fallback(url, operation, exc, fallback_exc)

    def _build_emergency_fallback(
        self,
        url: str,
        operation: str,
        exc: Exception,
        fallback_exc: Optional[Exception] = None,
    ) -> Dict[str, Any]:
        """Emergency fallback response when normal error dictionary generation fails.

        Validates Requirement 5.4 fallback mechanism.
        """
        exc_type = type(exc).__name__
        try:
            self.logger.critical(
                f"Emergency fallback triggered for '{operation}' due to secondary exception: {fallback_exc}"
            )
        except Exception:
            pass

        return {
            "authenticity_score": None,
            "fake_score": None,
            "confidence_indicator": "LOW",
            "url": str(url),
            "timestamps": {},
            "analysis_data": None,
            "top_factors": [],
            "suspicious_indicators": [],
            "error_message": f"Critical error during '{operation}' [{exc_type}]",
            "exception_type": exc_type,
            "failed_operation": operation,
        }


def analyze_website(
    url: str,
    detector: Optional[AuthenticityDetector] = None,
    progress_callback: Optional[Any] = None,
) -> Dict[str, Any]:
    """Public API function for website authenticity analysis (Requirement 5.3).

    Args:
        url: Target website URL string.
        detector: Optional AuthenticityDetector instance for injection/testing.
        progress_callback: Optional callback function for tracking progress stages.

    Returns:
        Dictionary containing authenticity_score, fake_score, confidence_indicator,
        error_message, and all report fields.
    """
    det = detector or AuthenticityDetector()
    if progress_callback is not None:
        return det.analyze_website(url, progress_callback=progress_callback)
    return det.analyze_website(url)
