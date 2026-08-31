"""Generic Security Interstitial & Block-Page Detection.

Detects when browser navigation stops at a security warning, anti-bot challenge,
CAPTCHA, or vendor block page rather than the intended target website.
"""

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

from config.logging_config import get_logger

logger = get_logger("interstitial_detector")


@dataclass
class InterstitialDetectionResult:
    """Result of interstitial and page identity analysis."""

    is_interstitial: bool = False
    interstitial_type: str = "NONE"  # "NONE", "PHISHING_WARNING", "SECURITY_BLOCKED", "BOT_CHALLENGE", "CAPTCHA"
    reason: str = ""
    indicators: List[str] = field(default_factory=list)
    page_title: str = ""
    requested_url: str = ""
    final_url: str = ""
    target_domain_reached: bool = True
    is_phishing_signal: bool = False


# Security / Phishing warning patterns in Title
_PHISHING_TITLE_PATTERNS = [
    re.compile(r"\b(suspected\s+phishing|phishing\s+warning|deceptive\s+site|phishing\s+attack|malicious\s+site|dangerous\s+site|reported\s+phishing)\b", re.IGNORECASE),
    re.compile(r"\b(security\s+warning|warning:\s+suspected|threat\s+detected|site\s+blocked\s+by\s+security)\b", re.IGNORECASE),
]

# Challenge / Bot verification patterns in Title
_CHALLENGE_TITLE_PATTERNS = [
    re.compile(r"^just\s+a\s+moment\.{2,3}$", re.IGNORECASE),
    re.compile(r"\b(attention\s+required!\s*\|\s*cloudflare|security\s+check|verify\s+you\s+are\s+human|ddos\s+protection|ddos-guard|sucuri\s+website\s+firewall|imperva\s+challenge)\b", re.IGNORECASE),
]

# Phishing / Malicious Warning Body Patterns
_PHISHING_BODY_PATTERNS = [
    (re.compile(r"this\s+(?:website|site|page)\s+has\s+been\s+reported\s+(?:for|as)(?:\s+potential)?\s+phishing", re.IGNORECASE), "Website explicitly reported for potential phishing"),
    (re.compile(r"suspected\s+phishing(?:\s+site|\s+page|\s+detected)?", re.IGNORECASE), "Suspected phishing warning on interstitial page"),
    (re.compile(r"warning:\s+potential\s+phishing", re.IGNORECASE), "Explicit phishing warning on interstitial page"),
    (re.compile(r"deceptive\s+site\s+ahead", re.IGNORECASE), "Deceptive site ahead browser/security warning"),
    (re.compile(r"the\s+site\s+ahead\s+contains\s+(?:harmful\s+programs|malware)", re.IGNORECASE), "Malware/harmful site security warning"),
    (re.compile(r"phishing\s+attack\s+ahead", re.IGNORECASE), "Phishing attack ahead security warning"),
    (re.compile(r"potential\s+security\s+risk\s+ahead", re.IGNORECASE), "Potential security risk interstitial warning"),
    (re.compile(r"reported\s+as\s+unsafe(?:\s+website|\s+page)?", re.IGNORECASE), "Unsafe website report indicator"),
    (re.compile(r"this\s+(?:website|page)\s+is\s+blocked\s+due\s+to\s+(?:malware|phishing|security)", re.IGNORECASE), "Access blocked by security filter"),
]

# Bot / Verification Challenge Body Patterns
_CHALLENGE_BODY_PATTERNS = [
    (re.compile(r"\bverify\s+you\s+are\s+(?:a\s+)?human\b", re.IGNORECASE), "Human verification challenge"),
    (re.compile(r"\bconfirm\s+you\s+are\s+(?:a\s+)?human\b", re.IGNORECASE), "Human verification challenge"),
    (re.compile(r"\bchecking\s+your\s+browser\s+before\s+accessing\b", re.IGNORECASE), "Cloudflare/Anti-DDoS browser verification"),
    (re.compile(r"\bchecking\s+if\s+the\s+site\s+connection\s+is\s+secure\b", re.IGNORECASE), "Cloudflare Turnstile connection security check"),
    (re.compile(r"\bplease\s+complete\s+the\s+security\s+check\s+to\s+proceed\b", re.IGNORECASE), "Security verification challenge"),
    (re.compile(r"\battention\s+required!\s*\|\s*cloudflare\b", re.IGNORECASE), "Cloudflare security barrier"),
]

# Known Security / Challenge Domains
_INTERSTITIAL_DOMAINS = [
    "challenges.cloudflare.com",
    "safebrowsing.google.com",
    "blockpage",
    "security-interstitial",
]


def _extract_domain(url: str) -> str:
    """Extract lowercase hostname from a URL."""
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        return host.lower().strip()
    except Exception:
        return ""


def _domains_match(requested_host: str, final_host: str) -> bool:
    """Check if final host belongs to requested domain or common subdomain."""
    if not requested_host or not final_host:
        return True
    if requested_host == final_host:
        return True

    # Strip leading www.
    clean_req = requested_host[4:] if requested_host.startswith("www.") else requested_host
    clean_final = final_host[4:] if final_host.startswith("www.") else final_host

    if clean_req == clean_final:
        return True

    # Subdomain match
    if final_host.endswith("." + clean_req) or requested_host.endswith("." + clean_final):
        return True

    return False


def detect_interstitial(
    requested_url: str,
    final_url: Optional[str] = None,
    page_title: Optional[str] = None,
    html_content: Optional[str] = None,
    structure_metrics: Optional[Dict[str, int]] = None,
) -> InterstitialDetectionResult:
    """Detect whether navigation landed on a security interstitial or challenge page.

    Args:
        requested_url: The original URL requested by user.
        final_url: The actual browser URL after navigation/redirects.
        page_title: The HTML page title.
        html_content: The rendered HTML content of the page.
        structure_metrics: Optional dictionary of DOM structural metrics.

    Returns:
        InterstitialDetectionResult detailing findings.
    """
    req_url = requested_url or ""
    fin_url = final_url or req_url
    title = (page_title or "").strip()
    html = html_content or ""
    metrics = structure_metrics or {}

    req_host = _extract_domain(req_url)
    fin_host = _extract_domain(fin_url)

    # Initialize result
    result = InterstitialDetectionResult(
        is_interstitial=False,
        interstitial_type="NONE",
        reason="",
        indicators=[],
        page_title=title,
        requested_url=req_url,
        final_url=fin_url,
        target_domain_reached=True,
        is_phishing_signal=False,
    )

    # -------------------------------------------------------------
    # 1. External Security Interstitial Host Checks
    # -------------------------------------------------------------
    for sec_domain in _INTERSTITIAL_DOMAINS:
        if sec_domain in fin_host:
            result.is_interstitial = True
            result.interstitial_type = "SECURITY_BLOCKED"
            result.reason = f"Redirected to external security interstitial host ({fin_host})"
            result.indicators.append(f"External security domain: {fin_host}")
            result.target_domain_reached = False
            break

    # -------------------------------------------------------------
    # 2. Page Title Checks
    # -------------------------------------------------------------
    if title and not result.is_interstitial:
        # Check phishing warning titles
        for pattern in _PHISHING_TITLE_PATTERNS:
            if pattern.search(title):
                result.is_interstitial = True
                result.interstitial_type = "PHISHING_WARNING"
                result.is_phishing_signal = True
                result.reason = f"Security warning page title: '{title}'"
                result.indicators.append(f"Phishing/Security warning page title: '{title}'")
                result.target_domain_reached = False
                break

        # Check challenge titles (e.g. "Just a moment...", "Attention Required! | Cloudflare")
        if not result.is_interstitial:
            for pattern in _CHALLENGE_TITLE_PATTERNS:
                if pattern.search(title):
                    result.is_interstitial = True
                    result.interstitial_type = "BOT_CHALLENGE"
                    result.reason = f"Anti-bot/challenge page title: '{title}'"
                    result.indicators.append(f"Challenge page title: '{title}'")
                    result.target_domain_reached = False
                    break

    # -------------------------------------------------------------
    # 3. HTML Content & DOM Pattern Checks
    # -------------------------------------------------------------
    if html and not result.is_interstitial:
        # Strip script, style, noscript tags and comments to inspect only actual rendered visible content
        clean_text = re.sub(r"<(script|style|noscript)[^>]*>.*?</\1>", " ", html, flags=re.DOTALL | re.IGNORECASE)
        clean_text = re.sub(r"<!--.*?-->", " ", clean_text, flags=re.DOTALL)
        visible_text = re.sub(r"<[^>]+>", " ", clean_text)
        visible_text = " ".join(visible_text.split())

        # Check explicit phishing / security warning patterns
        phishing_matched = []
        for pattern, desc in _PHISHING_BODY_PATTERNS:
            if pattern.search(visible_text):
                phishing_matched.append(desc)

        if phishing_matched:
            result.is_interstitial = True
            result.interstitial_type = "PHISHING_WARNING"
            result.is_phishing_signal = True
            result.reason = f"Security warning detected in page content ({phishing_matched[0]})"
            result.indicators.extend(phishing_matched)
            result.target_domain_reached = False

        # Check challenge / bot verification patterns if not already flagged as phishing warning
        if not result.is_interstitial:
            challenge_matched = []
            for pattern, desc in _CHALLENGE_BODY_PATTERNS:
                if pattern.search(visible_text):
                    challenge_matched.append(desc)

            # Cloudflare Challenge DOM Containers
            cf_challenge_stage = ('id="challenge-stage"' in html or 'class="cf-browser-verification"' in html or 'id="challenge-form"' in html)

            total_elements = metrics.get("element_count", metrics.get("total_elements", 0)) if metrics else 0
            is_barrier = (total_elements < 40) or (len(visible_text) < 400)

            # A real bot challenge barrier blocks navigation before target content loads
            if (challenge_matched and is_barrier) or (cf_challenge_stage and is_barrier):
                result.is_interstitial = True
                result.interstitial_type = "BOT_CHALLENGE"
                reason_desc = challenge_matched[0] if challenge_matched else "Active Cloudflare browser verification challenge container"
                result.reason = f"Anti-bot/verification challenge detected ({reason_desc})"
                if challenge_matched:
                    result.indicators.extend(challenge_matched)
                if cf_challenge_stage:
                    result.indicators.append("Active Cloudflare Challenge DOM container detected")
                result.target_domain_reached = False

    # -------------------------------------------------------------
    # 4. Domain & Target Reached Assessment
    # -------------------------------------------------------------
    if req_host and fin_host and not _domains_match(req_host, fin_host):
        # Target domain changed completely
        if result.is_interstitial:
            result.target_domain_reached = False
            result.indicators.append(f"Domain mismatch: requested '{req_host}', landed on '{fin_host}'")
        else:
            # Check if landed on known security / parked / error page
            if any(term in fin_host for term in ["blocked", "suspended", "warning", "cloudflare", "secureserver"]):
                result.is_interstitial = True
                result.interstitial_type = "SECURITY_BLOCKED"
                result.reason = f"Redirected to external security/warning domain: {fin_host}"
                result.indicators.append(f"Redirected from '{req_host}' to security domain '{fin_host}'")
                result.target_domain_reached = False

    # Deduplicate indicators
    result.indicators = list(dict.fromkeys(result.indicators))

    return result
