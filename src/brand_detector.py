"""
Brand Intelligence and Domain Impersonation Detection Module.

This module detects claimed brand identities from URLs, page titles, headings,
and page content, and compares them against authorized registrable domains to
identify brand-domain mismatches and phishing impersonation attacks.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

from src.domain_analyzer import DomainAnalyzer


@dataclass
class BrandProfile:
    """Configuration profile for a recognizable organization or brand."""
    name: str
    primary_domain: str
    authorized_domains: List[str]
    keywords: List[str]
    high_value_target: bool = True


@dataclass
class BrandAnalysisResult:
    """Result of brand impersonation analysis."""
    brand_detected: Optional[str] = None
    brand_domain_match: bool = True
    claimed_brand: Optional[str] = None
    actual_registrable_domain: str = ""
    authorized_domains: List[str] = field(default_factory=list)
    detection_sources: List[str] = field(default_factory=list)
    is_impersonation: bool = False
    impersonation_severity: str = "NONE"  # "NONE", "MEDIUM", "HIGH", "CRITICAL"
    indicators: List[str] = field(default_factory=list)


# Comprehensive catalog of major technology, e-commerce, banking, and logistics brands
BRAND_CATALOG: List[BrandProfile] = [
    BrandProfile(
        name="Allegro",
        primary_domain="allegro.pl",
        authorized_domains=[
            "allegro.pl", "allegrolokalnie.pl", "allegrogroups.pl",
            "allegro.cz", "allegro.sk", "allegro.hu", "allegromail.pl"
        ],
        keywords=["allegro", "allegrolokalnie", "allegro pay"],
    ),
    BrandProfile(
        name="Google",
        primary_domain="google.com",
        authorized_domains=[
            "google.com", "google.co.in", "google.pl", "google.co.uk", "google.de", "google.fr",
            "google.it", "google.es", "google.ca", "google.com.au", "google.co.jp", "google.com.br",
            "google.nl", "google.co.za", "google.co.nz", "google.com.mx", "google.ch",
            "youtube.com", "gmail.com", "gstatic.com", "googleapis.com", "googleusercontent.com"
        ],
        keywords=["google", "gmail", "google drive", "google docs", "google workspace", "youtube"],
    ),
    BrandProfile(
        name="Microsoft",
        primary_domain="microsoft.com",
        authorized_domains=[
            "microsoft.com", "live.com", "office.com", "microsoftonline.com",
            "office365.com", "outlook.com", "bing.com", "azure.com", "msn.com",
            "xbox.com", "onedrive.com", "sharepoint.com", "windows.com",
            "microsoft.in", "microsoftstore.com"
        ],
        keywords=["microsoft", "office 365", "office365", "outlook", "onedrive", "azure", "windows"],
    ),
    BrandProfile(
        name="Apple",
        primary_domain="apple.com",
        authorized_domains=["apple.com", "icloud.com", "appleid.apple.com", "apple.co", "apple.in"],
        keywords=["apple", "icloud", "apple id", "app store"],
    ),
    BrandProfile(
        name="Amazon",
        primary_domain="amazon.com",
        authorized_domains=[
            "amazon.com", "amazon.in", "amazon.pl", "amazon.de", "amazon.co.uk", "amazon.fr",
            "amazon.it", "amazon.es", "amazon.co.jp", "amazon.ca", "amazon.com.au",
            "amazon.com.br", "amazon.com.mx", "amazon.nl", "amazon.se", "amazon.ae",
            "amazon.sa", "amazon.sg", "amazon.cn", "amazon.com.tr", "amazon.eg", "amazon.be",
            "aws.amazon.com", "primevideo.com", "media-amazon.com", "ssl-images-amazon.com",
            "amazon-adsystem.com"
        ],
        keywords=["amazon", "amazon prime", "aws", "prime video"],
    ),
    BrandProfile(
        name="PayPal",
        primary_domain="paypal.com",
        authorized_domains=["paypal.com", "paypal.me", "paypal-objects.com", "paypal.in"],
        keywords=["paypal", "paypal me"],
    ),
    BrandProfile(
        name="Netflix",
        primary_domain="netflix.com",
        authorized_domains=["netflix.com", "netflix.net", "nflxext.com", "nflximg.net"],
        keywords=["netflix"],
    ),
    BrandProfile(
        name="Facebook",
        primary_domain="facebook.com",
        authorized_domains=[
            "facebook.com", "meta.com", "instagram.com", "whatsapp.com",
            "messenger.com", "fb.com"
        ],
        keywords=["facebook", "meta", "instagram", "whatsapp", "messenger"],
    ),
    BrandProfile(
        name="Diners Club",
        primary_domain="dinersclub.com",
        authorized_domains=[
            "dinersclub.com", "dinersclubus.com", "dinersclubinternational.com",
            "dinersclub.co.uk", "dinersclub.de", "dinersclub.it", "dinersclub.es"
        ],
        keywords=["diners club", "dinersclub", "dinersclu", "diners-club"],
    ),
    BrandProfile(
        name="DHL",
        primary_domain="dhl.com",
        authorized_domains=["dhl.com", "dhl.pl", "dhl.de", "dhl-parcel.pl", "dhlparcel.pl"],
        keywords=["dhl", "dhl express", "dhl parcel"],
    ),
    BrandProfile(
        name="FedEx",
        primary_domain="fedex.com",
        authorized_domains=["fedex.com"],
        keywords=["fedex"],
    ),
    BrandProfile(
        name="UPS",
        primary_domain="ups.com",
        authorized_domains=["ups.com"],
        keywords=["ups tracking", "united parcel service"],
    ),
    BrandProfile(
        name="InPost",
        primary_domain="inpost.pl",
        authorized_domains=["inpost.pl", "paczkomaty.pl"],
        keywords=["inpost", "paczkomat", "paczkomaty"],
    ),
    BrandProfile(
        name="PKO Bank Polski",
        primary_domain="pkobp.pl",
        authorized_domains=["pkobp.pl", "ipko.pl", "inteligo.pl"],
        keywords=["pko bp", "pkobp", "ipko", "inteligo"],
    ),
    BrandProfile(
        name="mBank",
        primary_domain="mbank.pl",
        authorized_domains=["mbank.pl"],
        keywords=["mbank"],
    ),
    BrandProfile(
        name="Santander",
        primary_domain="santander.com",
        authorized_domains=["santander.com", "santander.pl", "santander.co.uk"],
        keywords=["santander", "bzwbk"],
    ),
    BrandProfile(
        name="ING Bank",
        primary_domain="ing.com",
        authorized_domains=["ing.com", "ing.pl", "ingbank.pl"],
        keywords=["ing bank", "ing direct", "moje ing"],
    ),
    BrandProfile(
        name="Chase",
        primary_domain="chase.com",
        authorized_domains=["chase.com", "jpmorgan.com"],
        keywords=["chase bank", "jpmorgan"],
    ),
    BrandProfile(
        name="Bank of America",
        primary_domain="bankofamerica.com",
        authorized_domains=["bankofamerica.com", "bofa.com"],
        keywords=["bank of america", "bofa"],
    ),
    BrandProfile(
        name="Wells Fargo",
        primary_domain="wellsfargo.com",
        authorized_domains=["wellsfargo.com"],
        keywords=["wells fargo"],
    ),
]


class BrandDetector:
    """Detects brand presence and validates domain authorization."""

    def __init__(self, catalog: Optional[List[BrandProfile]] = None):
        self.catalog = catalog or BRAND_CATALOG

    def detect_brand_impersonation(
        self,
        url: str,
        page_title: Optional[str] = None,
        html_content: Optional[str] = None,
        headings: Optional[List[str]] = None,
    ) -> BrandAnalysisResult:
        """
        Analyze whether a website is impersonating a recognized brand.

        Args:
            url: The analyzed URL.
            page_title: Captured <title> of the page.
            html_content: HTML source code or text.
            headings: List of <h1>, <h2> headings.

        Returns:
            BrandAnalysisResult with match details, severity, and indicators.
        """
        domain_info = DomainAnalyzer.analyze_domain(url)
        actual_reg_domain = domain_info.registrable_domain.lower()
        actual_domain_name = domain_info.domain_name.lower()
        subdomain = domain_info.subdomain.lower()
        hostname = domain_info.hostname.lower()

        detected_brand: Optional[BrandProfile] = None
        sources: List[str] = []

        # 1. Check Subdomain (highest signal for brand prepending e.g. allegro.oferta7678678564.pl)
        for brand in self.catalog:
            for kw in brand.keywords:
                clean_kw = kw.replace(" ", "")
                pattern = rf"(^|[\.\-_]){re.escape(clean_kw)}([\.\-_]|$)"
                if re.search(pattern, subdomain):
                    detected_brand = brand
                    sources.append(f"subdomain ('{subdomain}')")
                    break
            if detected_brand:
                break

        # 2. Check Hostname tokens if not found in subdomain
        if not detected_brand:
            for brand in self.catalog:
                for kw in brand.keywords:
                    clean_kw = kw.replace(" ", "")
                    # Matches hyphenated hostnames like "microsoft-login" or "dinersclu.bond"
                    if f"{clean_kw}-" in hostname or f"-{clean_kw}" in hostname or f"{clean_kw}." in hostname:
                        detected_brand = brand
                        sources.append(f"hostname prefix/suffix ('{hostname}')")
                        break
                if detected_brand:
                    break

        # 3. Check Domain Name typosquatting / brand substring token (e.g. dinersclu.bond)
        if not detected_brand:
            for brand in self.catalog:
                brand_primary_sld = brand.primary_domain.split(".")[0].lower()
                for kw in brand.keywords:
                    clean_kw = kw.replace(" ", "").replace("-", "")
                    if len(clean_kw) >= 5 and clean_kw in actual_domain_name:
                        detected_brand = brand
                        sources.append(f"domain token ('{actual_domain_name}')")
                        break
                if detected_brand:
                    break

        # 4. Check Page Title
        if not detected_brand and page_title:
            title_lower = page_title.lower()
            for brand in self.catalog:
                for kw in brand.keywords:
                    if re.search(rf"\b{re.escape(kw)}\b", title_lower):
                        detected_brand = brand
                        sources.append(f"page title ('{page_title[:40]}...')")
                        break
                if detected_brand:
                    break

        # 5. Check Headings / Content if still not found
        if not detected_brand and headings:
            combined_headings = " ".join(headings).lower()
            for brand in self.catalog:
                for kw in brand.keywords:
                    if re.search(rf"\b{re.escape(kw)}\b", combined_headings):
                        detected_brand = brand
                        sources.append(f"headings")
                        break
                if detected_brand:
                    break

        # If no brand detected: return clean result
        if not detected_brand:
            return BrandAnalysisResult(
                brand_detected=None,
                brand_domain_match=True,
                claimed_brand=None,
                actual_registrable_domain=actual_reg_domain,
                authorized_domains=[],
                detection_sources=[],
                is_impersonation=False,
                impersonation_severity="NONE",
                indicators=[],
            )

        # Validate whether actual_registrable_domain is authorized for the detected brand
        # 1. Exact match in authorized_domains list
        is_authorized = actual_reg_domain in [d.lower() for d in detected_brand.authorized_domains]

        # 2. Intelligent ccTLD/SLD matching:
        # If the brand's primary domain SLD matches the actual domain name (e.g. amazon.in, google.co.in)
        # under any legitimate public suffix NOT in SUSPICIOUS_TLDS, recognize it as an authorized brand domain.
        if not is_authorized and domain_info and not domain_info.is_ip_address:
            from src.domain_analyzer import SUSPICIOUS_TLDS
            brand_primary_sld = detected_brand.primary_domain.split(".")[0].lower()
            if actual_domain_name == brand_primary_sld and domain_info.public_suffix not in SUSPICIOUS_TLDS:
                is_authorized = True

        if is_authorized:
            return BrandAnalysisResult(
                brand_detected=detected_brand.name,
                brand_domain_match=True,
                claimed_brand=detected_brand.name,
                actual_registrable_domain=actual_reg_domain,
                authorized_domains=detected_brand.authorized_domains,
                detection_sources=sources,
                is_impersonation=False,
                impersonation_severity="NONE",
                indicators=[f"Official legitimate domain for {detected_brand.name}"],
            )

        # Mismatch detected: Brand Impersonation!
        indicators: List[str] = [
            f"BRAND_DOMAIN_MISMATCH: Page claims identity of '{detected_brand.name}' via {', '.join(sources)} but is hosted on unauthorized root domain '{actual_reg_domain}'",
            f"Expected authorized domains: {', '.join(detected_brand.authorized_domains[:3])}",
        ]

        # Determine severity
        if "subdomain" in "".join(sources) or "hostname" in "".join(sources) or "domain token" in "".join(sources):
            severity = "CRITICAL"
        else:
            severity = "HIGH"

        return BrandAnalysisResult(
            brand_detected=detected_brand.name,
            brand_domain_match=False,
            claimed_brand=detected_brand.name,
            actual_registrable_domain=actual_reg_domain,
            authorized_domains=detected_brand.authorized_domains,
            detection_sources=sources,
            is_impersonation=True,
            impersonation_severity=severity,
            indicators=indicators,
        )
