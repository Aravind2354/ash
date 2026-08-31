"""
Domain Identity and Lexical URL Risk Analysis Module.

This module extracts structural, lexical, and cryptographic identity attributes
from domain names and URLs, including public suffix extraction, registrable domains,
subdomain depth, numeric sequences, punycode, and suspicious lexical indicators.
"""

import re
import math
import ipaddress
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field


# Comprehensive list of multi-part public suffixes / ccTLD second-level domains
MULTI_PART_TLDS: Set[str] = {
    # UK
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk", "mod.uk", "police.uk",
    # Poland
    "com.pl", "org.pl", "net.pl", "info.pl", "biz.pl", "edu.pl", "gov.pl", "mil.pl", "waw.pl", "warszawa.pl",
    "krakow.pl", "poznan.pl", "wroc.pl", "wroclaw.pl", "gda.pl", "gdansk.pl", "szczecin.pl", "lodz.pl", "lublin.pl",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "csiro.au", "asn.au", "id.au",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br", "art.br", "srv.br",
    # Japan
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp", "gr.jp", "lg.jp",
    # Germany & EU
    "co.de", "com.de", "eu.com", "de.com", "gb.net", "uk.com", "us.com",
    # Canada & New Zealand & South Africa
    "co.nz", "net.nz", "org.nz", "govt.nz", "co.za", "org.za", "net.za", "ac.za", "gov.za",
    # India & Asia
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in", "ac.in", "edu.in",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg", "com.my", "net.my", "org.my", "gov.my",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk", "com.tw", "net.tw", "org.tw", "gov.tw",
    # Generic ccTLDs
    "com.mx", "org.mx", "gob.mx", "edu.mx", "com.ar", "org.ar", "gov.ar", "com.tr", "org.tr", "gov.tr",
    "com.ru", "net.ru", "org.ru", "pp.ru", "com.ua", "net.ua", "org.ua", "gov.ua",
}

# Suspicious lexical keywords commonly found in phishing URLs/subdomains
SUSPICIOUS_KEYWORDS: Set[str] = {
    "login", "signin", "sign-in", "sign_in", "log-in", "log_in",
    "verify", "verification", "verif", "validate", "validation",
    "secure", "security", "protect", "protection", "safe",
    "account", "myaccount", "acct", "profile", "user",
    "update", "upgrade", "renew", "renewal", "reactivate",
    "authenticate", "authentication", "auth", "2fa", "mfa", "otp",
    "password", "passcode", "credential", "reset", "recover", "recovery",
    "billing", "invoice", "payment", "pay", "checkout", "wallet",
    "support", "helpdesk", "service", "customer", "contact",
    "confirmation", "confirm", "notice", "alert", "notification",
    "suspended", "suspension", "locked", "unlock", "restricted", "limit",
    "banking", "onlinebanking", "ebanking", "netbanking",
    "webscr", "ebayisapi", "portal", "client", "access",
}

# Suspicious TLDs commonly abused for disposable phishing campaigns
SUSPICIOUS_TLDS: Set[str] = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "cam", "sbs",
    "icu", "cyou", "monster", "work", "loan", "click", "fit", "rest",
    "surf", "racing", "date", "faith", "download", "stream", "bid",
}


@dataclass
class DomainIdentity:
    """Detailed domain identity and structural breakdown."""
    raw_url: str
    normalized_url: str
    hostname: str
    registrable_domain: str
    domain_name: str
    subdomain: str
    subdomain_count: int
    public_suffix: str
    port: Optional[int] = None
    is_ip_address: bool = False
    punycode_detected: bool = False
    numeric_ratio: float = 0.0
    longest_numeric_sequence: int = 0
    hyphen_count: int = 0
    entropy: float = 0.0
    matched_suspicious_words: List[str] = field(default_factory=list)
    suspicious_hostname: bool = False
    domain_identity_score: float = 1.0
    risk_factors: List[str] = field(default_factory=list)


class DomainAnalyzer:
    """Analyzes domain names and URLs for phishing and impersonation indicators."""

    @staticmethod
    def extract_registrable_domain(hostname: str) -> Tuple[str, str, str, str]:
        """
        Extract (subdomain, domain_name, registrable_domain, public_suffix) from hostname.
        
        Examples:
            'allegro.oferta7678678564.pl' -> ('allegro', 'oferta7678678564', 'oferta7678678564.pl', 'pl')
            'www.google.co.uk' -> ('www', 'google', 'google.co.uk', 'co.uk')
            'sub.example.com' -> ('sub', 'example', 'example.com', 'com')
            'google.com' -> ('', 'google', 'google.com', 'com')
            '192.168.1.1' -> ('', '192.168.1.1', '192.168.1.1', '')
        """
        clean_host = hostname.strip().lower().rstrip(".")
        if not clean_host:
            return "", "", "", ""

        # Check if host is IP address
        try:
            ipaddress.ip_address(clean_host)
            return "", clean_host, clean_host, ""
        except ValueError:
            pass

        parts = clean_host.split(".")
        if len(parts) == 1:
            return "", parts[0], parts[0], ""

        # Check for multi-part TLD match
        suffix = ""
        suffix_parts_len = 0
        for num_parts in [3, 2]:
            if len(parts) > num_parts:
                candidate_suffix = ".".join(parts[-num_parts:])
                if candidate_suffix in MULTI_PART_TLDS:
                    suffix = candidate_suffix
                    suffix_parts_len = num_parts
                    break

        if not suffix:
            suffix = parts[-1]
            suffix_parts_len = 1

        # The domain label is the part immediately before the suffix
        if len(parts) > suffix_parts_len:
            domain_name = parts[-(suffix_parts_len + 1)]
            registrable_domain = f"{domain_name}.{suffix}"
            subdomain_parts = parts[: -(suffix_parts_len + 1)]
            subdomain = ".".join(subdomain_parts)
        else:
            domain_name = parts[0]
            registrable_domain = clean_host
            subdomain = ""

        return subdomain, domain_name, registrable_domain, suffix

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob)

    @classmethod
    def analyze_domain(cls, url: str) -> DomainIdentity:
        """
        Perform in-depth domain identity and lexical risk analysis.

        Args:
            url: The URL to analyze.

        Returns:
            DomainIdentity containing extracted fields, scores, and risk factors.
        """
        raw_url = url.strip()
        parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
        
        hostname = (parsed.hostname or "").lower().strip()
        port = parsed.port

        # Check IP address
        is_ip = False
        try:
            if hostname:
                ipaddress.ip_address(hostname)
                is_ip = True
        except ValueError:
            is_ip = False

        # Extract domain breakdown
        subdomain, domain_name, registrable_domain, public_suffix = cls.extract_registrable_domain(hostname)
        subdomain_parts = [p for p in subdomain.split(".") if p]
        subdomain_count = len(subdomain_parts)

        # Punycode check
        punycode = "xn--" in hostname

        # Numeric sequences
        digits_count = sum(c.isdigit() for c in hostname)
        numeric_ratio = (digits_count / len(hostname)) if hostname else 0.0
        num_seqs = re.findall(r"\d+", hostname)
        longest_num_seq = max((len(s) for s in num_seqs), default=0)

        # Hyphen count
        hyphen_count = hostname.count("-")

        # Entropy of domain name
        entropy = cls.calculate_entropy(domain_name)

        # Check for suspicious keywords in subdomain, domain name, and URL path
        matched_words: List[str] = []
        path_text = parsed.path or ""
        tokens = re.split(r"[\.\-_/]", f"{subdomain}.{domain_name}.{path_text}")
        for token in tokens:
            token_clean = token.lower()
            if token_clean in SUSPICIOUS_KEYWORDS and token_clean not in matched_words:
                matched_words.append(token_clean)

        # Risk scoring
        risk_score = 1.0
        risk_factors: List[str] = []
        is_suspicious = False

        # 1. IP address in URL
        if is_ip:
            risk_score -= 0.40
            risk_factors.append("URL uses raw IP address instead of hostname")
            is_suspicious = True

        # 2. Punycode / Internationalized domain homograph
        if punycode:
            risk_score -= 0.35
            risk_factors.append("Punycode (xn--) encoding detected in hostname")
            is_suspicious = True

        # 3. Numeric-heavy domain (e.g. oferta7678678564)
        if longest_num_seq >= 6:
            risk_score -= 0.45
            risk_factors.append(f"Excessive numeric sequence in domain ({longest_num_seq} digits)")
            is_suspicious = True
        elif longest_num_seq >= 4 and numeric_ratio > 0.30:
            risk_score -= 0.30
            risk_factors.append(f"High numeric character ratio ({numeric_ratio:.0%}) in hostname")
            is_suspicious = True

        # 4. Deep subdomains (>2 levels)
        if subdomain_count >= 3:
            risk_score -= 0.25
            risk_factors.append(f"Excessive subdomain depth ({subdomain_count} levels)")
            is_suspicious = True

        # 5. Excessive hyphens
        if hyphen_count >= 3:
            risk_score -= 0.25
            risk_factors.append(f"Multiple hyphens ({hyphen_count}) in hostname")
            is_suspicious = True

        # 6. Suspicious TLD check
        tld_root = public_suffix.split(".")[-1].lower() if public_suffix else ""
        if tld_root in SUSPICIOUS_TLDS:
            risk_score -= 0.20
            risk_factors.append(f"Potentially abused top-level domain (.{tld_root})")
            is_suspicious = True

        # 7. Unusual non-standard port
        if port and port not in {80, 443, 8080, 8443}:
            risk_score -= 0.25
            risk_factors.append(f"Unusual web server port ({port})")
            is_suspicious = True

        # 8. High entropy (random character generation / DGA)
        if len(domain_name) >= 10 and entropy >= 3.8:
            risk_score -= 0.20
            risk_factors.append(f"High Shannon entropy in domain name ({entropy:.2f})")
            is_suspicious = True

        # 9. Suspicious security/login keywords in subdomain or path
        if matched_words:
            risk_score -= 0.20 * min(len(matched_words), 3)
            risk_factors.append(f"Suspicious authentication keywords in domain: {', '.join(matched_words)}")
            is_suspicious = True

        domain_score = max(0.0, min(1.0, risk_score))

        return DomainIdentity(
            raw_url=raw_url,
            normalized_url=parsed.geturl(),
            hostname=hostname,
            registrable_domain=registrable_domain,
            domain_name=domain_name,
            subdomain=subdomain,
            subdomain_count=subdomain_count,
            public_suffix=public_suffix,
            port=port,
            is_ip_address=is_ip,
            punycode_detected=punycode,
            numeric_ratio=numeric_ratio,
            longest_numeric_sequence=longest_num_seq,
            hyphen_count=hyphen_count,
            entropy=entropy,
            matched_suspicious_words=matched_words,
            suspicious_hostname=is_suspicious,
            domain_identity_score=round(domain_score, 4),
            risk_factors=risk_factors,
        )
