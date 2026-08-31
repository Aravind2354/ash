"""
Data models for Website Authenticity Detector.

This module contains all data structures used for collecting, aggregating,
and reporting website analysis data.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, List


@dataclass
class NetworkData:
    """
    Network request patterns collected during website execution.
    
    Attributes:
        request_count: Total number of network requests made
        unique_domains: List of unique domain names contacted
        protocol_distribution: Count of requests per protocol (http, https, ws, wss)
        failed: Indicates if collection of this category failed
    """
    request_count: int
    unique_domains: List[str]
    protocol_distribution: Dict[str, int]
    failed: bool = False


@dataclass
class DOMData:
    """
    DOM structure and HTML content collected from the website.
    
    Attributes:
        html_content: Raw HTML content of the page
        structure_metrics: Metrics about DOM structure including element counts
        failed: Indicates if collection of this category failed
    """
    html_content: str
    structure_metrics: Dict[str, int]
    failed: bool = False


@dataclass
class JavaScriptData:
    """
    JavaScript execution behavior metrics.
    
    Attributes:
        script_count: Number of JavaScript scripts executed
        dom_modifications: Number of dynamic DOM modifications performed
        external_api_calls: Number of calls to external APIs
        failed: Indicates if collection of this category failed
    """
    script_count: int
    dom_modifications: int
    external_api_calls: int
    failed: bool = False


@dataclass
class VisualData:
    """
    Visual rendering characteristics of the website.
    
    Attributes:
        screenshot_path: File path to the captured screenshot
        layout_characteristics: Visual layout metrics (viewport size, images, colors)
        failed: Indicates if collection of this category failed
    """
    screenshot_path: str
    layout_characteristics: Dict[str, any]
    failed: bool = False


@dataclass
class SSLData:
    """
    SSL/TLS certificate information.
    
    Attributes:
        issuer: Certificate issuer name
        expiration_date: Certificate expiration date in ISO 8601 format
        chain_valid: Whether the certificate chain validation passed
        failed: Indicates if collection of this category failed
    """
    issuer: str
    expiration_date: str
    chain_valid: bool
    failed: bool = False


@dataclass
class AnalysisData:
    """
    Container for all collected data categories.
    
    This aggregates data from all five collection categories and tracks
    collection success/failure status.
    
    Attributes:
        network: Network request patterns (None if not collected)
        dom: DOM structure and HTML content (None if not collected)
        javascript: JavaScript behavior metrics (None if not collected)
        visual: Visual rendering data (None if not collected)
        ssl: SSL certificate information (None if not collected)
        timeout_occurred: Whether a timeout occurred during collection
        categories_collected: Count of successfully collected categories (0-5)
    """
    network: Optional[NetworkData] = None
    dom: Optional[DOMData] = None
    javascript: Optional[JavaScriptData] = None
    visual: Optional[VisualData] = None
    ssl: Optional[SSLData] = None
    timeout_occurred: bool = False
    categories_collected: int = 0
    
    def __post_init__(self):
        """Calculate categories_collected after initialization."""
        self.categories_collected = sum([
            self.network is not None and not self.network.failed,
            self.dom is not None and not self.dom.failed,
            self.javascript is not None and not self.javascript.failed,
            self.visual is not None and not self.visual.failed,
            self.ssl is not None and not self.ssl.failed,
        ])


@dataclass
class AnalysisResult:
    """
    Complete result of website authenticity analysis.
    
    Attributes:
        authenticity_score: Probability that the website is authentic (0.0-1.0)
        fake_score: Probability that the website is fraudulent (0.0-1.0)
        confidence_indicator: Confidence level ("HIGH", "MEDIUM", "LOW")
        url: The analyzed website URL
        analysis_data: All collected data categories
        timestamps: Analysis start and completion timestamps (ISO 8601 UTC)
        top_factors: Top 3 factors that influenced the authenticity score
        suspicious_indicators: Data elements contributing to Fake_Score > 0.5
        error_message: Error message if analysis failed (None if successful)
        risk_level: Standardized verdict ("SAFE", "SUSPICIOUS", "HIGH_RISK", "PHISHING", "INCONCLUSIVE", "FAILED")
        normalized_url: Normalized target URL
        domain: Extracted hostname
        registrable_domain: Root/registrable domain
        brand_detected: Claimed or detected brand name
        brand_domain_match: Whether domain is authorized for detected brand
        reputation: Threat intelligence reputation status and provider data
        redirects: Redirect chain history
        critical_indicators: High-severity security threat indicators
    """
    authenticity_score: float
    fake_score: float
    confidence_indicator: str
    url: str
    analysis_data: AnalysisData
    timestamps: Dict[str, str]
    top_factors: List[str]
    suspicious_indicators: List[str]
    error_message: Optional[str] = None
    risk_level: str = "INCONCLUSIVE"
    normalized_url: Optional[str] = None
    domain: Optional[str] = None
    registrable_domain: Optional[str] = None
    brand_detected: Optional[str] = None
    brand_domain_match: Optional[bool] = None
    reputation: Optional[Dict[str, any]] = None
    redirects: Optional[List[Dict[str, any]]] = None
    critical_indicators: List[str] = field(default_factory=list)


@dataclass
class AnalysisScores:
    """
    Scores generated by AI analysis of website authenticity.

    Attributes:
        authenticity_score: Probability that the website is authentic (0.0-1.0)
        fake_score: Probability that the website is fraudulent (0.0-1.0)
        top_factors: List of top factors that influenced the score
        suspicious_indicators: List of elements contributing to Fake_Score > 0.5
        risk_level: Standardized verdict ("SAFE", "SUSPICIOUS", "HIGH_RISK", "PHISHING")
        critical_indicators: High-severity security threat indicators
    """
    authenticity_score: float
    fake_score: float
    top_factors: List[str] = field(default_factory=list)
    suspicious_indicators: List[str] = field(default_factory=list)
    risk_level: str = "SAFE"
    critical_indicators: List[str] = field(default_factory=list)

