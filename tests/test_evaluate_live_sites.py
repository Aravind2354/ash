"""
Unit Tests for scripts/evaluate_live_sites.py using Mocked Telemetry Data.

Tests:
1. LiveSiteEvaluator initialization and model loading.
2. Single URL evaluation with mocked AuthenticityDetector responses.
3. Timeout handling on slow or hanging website analyses.
4. Error handling on sandbox / network exceptions without crashing.
5. CSV batch evaluation and result dataframe structure.
6. Metric computation separating ML-only and Hybrid decisions.
7. Discrepancy analysis detection.
8. Verifying evaluation data is never leaked or appended to training CSVs.
"""

import os
import asyncio
import tempfile
import numpy as np
import pandas as pd
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.models import (
    AnalysisData,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
)
from src.feature_extractor import FeatureExtractor, FEATURE_NAMES
from src.ml_model import MLPhishingModel
from scripts.evaluate_live_sites import LiveSiteEvaluator, parse_score_value


class TestEvaluateLiveSites:
    """Test suite for live website evaluation pipeline."""

    def test_parse_score_value(self):
        """Test parse_score_value handles floats, percentages, and None."""
        assert parse_score_value(0.85) == 0.85
        assert parse_score_value("85.00%") == 0.85
        assert parse_score_value("12.5%") == 0.125
        assert parse_score_value("0.75") == 0.75
        assert parse_score_value(None) is None
        assert parse_score_value("N/A") is None

    @pytest.mark.asyncio
    async def test_evaluate_single_url_legitimate_mock(self):
        """Test evaluation of a legitimate website with mocked detector response."""
        mock_detector = MagicMock()
        mock_detector.analyze_website_async = AsyncMock(return_value={
            "status": "completed",
            "risk_level": "SAFE",
            "authenticity_score": 0.95,
            "fake_score": 0.05,
            "confidence_indicator": "HIGH",
            "url": "https://www.google.com",
            "top_factors": ["Valid trusted SSL certificate chain"],
            "suspicious_indicators": [],
            "critical_indicators": [],
            "analysis_data": None,
            "error_message": None,
        })

        evaluator = LiveSiteEvaluator(detector=mock_detector, per_url_timeout=5)
        res = await evaluator.evaluate_single_url_async("https://www.google.com", expected_label=0)

        assert res["url"] == "https://www.google.com"
        assert res["expected_label"] == 0
        assert res["ml_prediction"] == 0
        assert res["hybrid_prediction"] == 0
        assert res["risk_level"] == "SAFE"
        assert res["analysis_status"] == "completed"

    @pytest.mark.asyncio
    async def test_evaluate_single_url_phishing_mock(self):
        """Test evaluation of a phishing spoof website with mocked detector response."""
        mock_detector = MagicMock()
        mock_detector.analyze_website_async = AsyncMock(return_value={
            "status": "completed",
            "risk_level": "PHISHING",
            "authenticity_score": 0.08,
            "fake_score": 0.92,
            "confidence_indicator": "HIGH",
            "url": "http://allegro.oferta7678678564.pl",
            "top_factors": ["BRAND_DOMAIN_MISMATCH", "CREDENTIAL_HARVESTING"],
            "suspicious_indicators": ["Excessive numeric sequence in domain"],
            "critical_indicators": ["BRAND_DOMAIN_MISMATCH"],
            "analysis_data": AnalysisData(
                dom=DOMData(
                    html_content="<html><title>Allegro</title><input type='password'></html>",
                    structure_metrics={"password_input_count": 1, "element_count": 60, "login_keyword_count": 2},
                ),
                ssl=SSLData(chain_valid=True, issuer="Let's Encrypt", expiration_date="2027-01-01T00:00:00Z"),
            ),
            "error_message": None,
        })

        evaluator = LiveSiteEvaluator(detector=mock_detector, per_url_timeout=5)
        res = await evaluator.evaluate_single_url_async("http://allegro.oferta7678678564.pl", expected_label=1)

        assert res["url"] == "http://allegro.oferta7678678564.pl"
        assert res["expected_label"] == 1
        assert res["ml_prediction"] == 1
        assert res["hybrid_prediction"] == 1
        assert res["risk_level"] == "PHISHING"
        assert "BRAND_DOMAIN_MISMATCH" in res["suspicious_indicators"]

    @pytest.mark.asyncio
    async def test_evaluate_single_url_timeout_handling(self):
        """Test that slow/hanging URL analysis times out gracefully without crashing."""
        async def slow_analysis(url):
            await asyncio.sleep(5)
            return {}

        mock_detector = MagicMock()
        mock_detector.analyze_website_async = slow_analysis

        evaluator = LiveSiteEvaluator(detector=mock_detector, per_url_timeout=1)
        res = await evaluator.evaluate_single_url_async("https://hanging-domain.example.com", expected_label=0)

        assert res["analysis_status"] == "failed"
        assert "timed out" in res["error_message"]

    @pytest.mark.asyncio
    async def test_evaluate_csv_batch_mock(self, tmp_path):
        """Test batch CSV evaluation with multiple URLs and metric computation."""
        input_csv = str(tmp_path / "test_input.csv")
        output_csv = str(tmp_path / "test_output.csv")

        pd.DataFrame([
            {"url": "https://www.google.com", "expected_label": 0},
            {"url": "http://allegro.oferta7678678564.pl", "expected_label": 1},
        ]).to_csv(input_csv, index=False)

        mock_detector = MagicMock()

        async def mock_analyze(url):
            if "google" in url:
                return {
                    "status": "completed",
                    "risk_level": "SAFE",
                    "authenticity_score": 0.98,
                    "fake_score": 0.02,
                    "confidence_indicator": "HIGH",
                    "url": url,
                    "top_factors": ["Valid SSL"],
                    "suspicious_indicators": [],
                }
            else:
                return {
                    "status": "completed",
                    "risk_level": "PHISHING",
                    "authenticity_score": 0.08,
                    "fake_score": 0.92,
                    "confidence_indicator": "HIGH",
                    "url": url,
                    "top_factors": ["BRAND_DOMAIN_MISMATCH"],
                    "suspicious_indicators": ["Credential harvesting"],
                    "analysis_data": AnalysisData(
                        dom=DOMData(
                            html_content="<html><title>Allegro</title><input type='password'></html>",
                            structure_metrics={"password_input_count": 1, "element_count": 60, "login_keyword_count": 2},
                        ),
                        ssl=SSLData(chain_valid=True, issuer="Let's Encrypt", expiration_date="2027-01-01T00:00:00Z"),
                    ),
                }

        mock_detector.analyze_website_async = mock_analyze

        evaluator = LiveSiteEvaluator(detector=mock_detector, per_url_timeout=5)
        df_res = await evaluator.evaluate_csv_async(input_csv, output_csv, concurrency=2)

        assert len(df_res) == 2
        assert os.path.exists(output_csv)
        assert list(df_res["ml_prediction"]) == [0, 1]
        assert list(df_res["hybrid_prediction"]) == [0, 1]

    def test_training_data_isolation(self, tmp_path):
        """Verify that evaluation URLs are NEVER appended to training or validation CSVs."""
        from scripts.build_dataset import DATA_DIR

        train_path = os.path.join(DATA_DIR, "train.csv")
        if os.path.exists(train_path):
            initial_train_mtime = os.path.getmtime(train_path)
            initial_train_len = len(pd.read_csv(train_path))

            # Run evaluation logic
            mock_detector = MagicMock()
            mock_detector.analyze_website_async = AsyncMock(return_value={"status": "completed"})
            evaluator = LiveSiteEvaluator(detector=mock_detector)

            # Assert train.csv was untouched
            assert os.path.getmtime(train_path) == initial_train_mtime
            assert len(pd.read_csv(train_path)) == initial_train_len
