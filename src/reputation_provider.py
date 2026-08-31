"""
Domain and URL Threat Intelligence Reputation Provider Module.

Provides pluggable threat reputation checking supporting Google Safe Browsing
and VirusTotal APIs. Returns clean 'unavailable' status when no API keys are configured.
"""

import os
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import httpx


class ReputationProvider(ABC):
    """Abstract base class for domain reputation providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""
        pass

    @abstractmethod
    async def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL against threat intelligence database."""
        pass


class GoogleSafeBrowsingProvider(ReputationProvider):
    """Google Safe Browsing Lookup API v4 provider."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("SAFE_BROWSING_API_KEY")

    @property
    def name(self) -> str:
        return "Google Safe Browsing"

    async def check_url(self, url: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"status": "unavailable", "provider": self.name, "threat_detected": False}

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {"clientId": "fakewebsite-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.post(endpoint, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    matches = data.get("matches", [])
                    if matches:
                        threat_types = [m.get("threatType") for m in matches]
                        return {
                            "status": "available",
                            "provider": self.name,
                            "threat_detected": True,
                            "threat_types": threat_types,
                        }
                    return {"status": "available", "provider": self.name, "threat_detected": False}
                return {"status": "error", "provider": self.name, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "error", "provider": self.name, "error": str(e)}


class VirusTotalProvider(ReputationProvider):
    """VirusTotal API v3 URL analysis provider."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY")

    @property
    def name(self) -> str:
        return "VirusTotal"

    async def check_url(self, url: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"status": "unavailable", "provider": self.name, "threat_detected": False}

        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": self.api_key}

            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    is_threat = (malicious + suspicious) >= 2
                    return {
                        "status": "available",
                        "provider": self.name,
                        "threat_detected": is_threat,
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                    }
                return {"status": "error", "provider": self.name, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "error", "provider": self.name, "error": str(e)}


class ReputationService:
    """Aggregates and queries configured reputation providers."""

    def __init__(self):
        self.providers: list[ReputationProvider] = [
            GoogleSafeBrowsingProvider(),
            VirusTotalProvider(),
        ]

    async def check_reputation(self, url: str) -> Dict[str, Any]:
        """
        Check threat intelligence reputation for a URL.
        
        Returns:
            Dictionary with reputation status, provider details, and threat flag.
        """
        active_results = []
        for provider in self.providers:
            res = await provider.check_url(url)
            if res.get("status") == "available":
                active_results.append(res)
                if res.get("threat_detected"):
                    return {
                        "status": "threat_detected",
                        "threat_detected": True,
                        "provider": provider.name,
                        "details": res,
                    }

        if active_results:
            return {
                "status": "clean",
                "threat_detected": False,
                "provider": active_results[0].get("provider", "available"),
                "details": active_results,
            }

        return {
            "status": "unavailable",
            "threat_detected": False,
            "provider": "none",
            "details": "No external threat intelligence API key configured",
        }
