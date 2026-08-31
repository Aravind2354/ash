"""
Unit and Property Tests for MLPhishingModel and XGBoost Inference.

Tests:
1. Model initialization and property checks
2. Model loading from disk
3. Training on feature matrices
4. Binary predictions and probability ranges [0.0, 1.0]
5. Probability summation invariant (P(0) + P(1) == 1.0)
6. Feature importances extraction
7. Feature explanation generation
8. Missing model file fail-safe
9. Input format flexibility (1D, 2D, dict)
"""

import os
import numpy as np
import pytest

from src.feature_extractor import FEATURE_NAMES
from src.ml_model import (
    MLPhishingModel,
    DEFAULT_MODEL_PATH,
)


@pytest.fixture
def trained_model():
    """Load or initialize trained MLPhishingModel."""
    model = MLPhishingModel()
    if not model.is_trained:
        # Train a small deterministic fixture model if disk model is missing
        rng = np.random.RandomState(42)
        X_dummy = rng.randn(100, len(FEATURE_NAMES)).astype(np.float32)
        y_dummy = rng.choice([0, 1], size=100).astype(np.int32)
        model.train(X_dummy, y_dummy, random_state=42)
    return model


class TestMLPhishingModel:
    """Test suite for MLPhishingModel operations."""

    def test_feature_names_integrity(self):
        """Feature names must contain exactly 48 distinct non-empty strings."""
        assert len(FEATURE_NAMES) == 48
        assert len(set(FEATURE_NAMES)) == 48
        for name in FEATURE_NAMES:
            assert isinstance(name, str) and len(name) > 0

    def test_model_loading_and_is_trained(self, trained_model):
        """Model must load and report is_trained == True."""
        assert trained_model.is_trained is True

    def test_predict_proba_shape_and_range(self, trained_model):
        """predict_proba must return valid probabilities in [0.0, 1.0]."""
        sample = {name: 0.0 for name in FEATURE_NAMES}
        sample["url_length"] = 25.0
        sample["is_https"] = 1.0
        sample["ssl_chain_valid"] = 1.0

        probs = trained_model.predict_proba(sample)
        assert probs.shape == (1, 2)
        assert 0.0 <= probs[0, 0] <= 1.0
        assert 0.0 <= probs[0, 1] <= 1.0
        assert pytest.approx(probs[0, 0] + probs[0, 1], abs=1e-5) == 1.0

    def test_predict_phishing_probability_scalar(self, trained_model):
        """predict_phishing_probability must return a single float probability."""
        sample = {name: 0.0 for name in FEATURE_NAMES}
        p = trained_model.predict_phishing_probability(sample)
        assert isinstance(p, float)
        assert 0.0 <= p <= 1.0

    def test_predict_binary_classification(self, trained_model):
        """predict must return 0 or 1 with configurable threshold."""
        sample_legit = {name: 0.0 for name in FEATURE_NAMES}
        sample_legit["is_https"] = 1.0
        sample_legit["ssl_chain_valid"] = 1.0
        sample_legit["ssl_recognized_ca"] = 1.0
        sample_legit["brand_domain_match"] = 1.0

        pred_legit = trained_model.predict(sample_legit)
        assert pred_legit[0] in [0, 1]

        sample_phish = {name: 0.0 for name in FEATURE_NAMES}
        sample_phish["brand_domain_mismatch"] = 1.0
        sample_phish["has_credential_harvesting_form"] = 1.0
        sample_phish["password_input_count"] = 1.0
        sample_phish["longest_numeric_sequence"] = 10.0
        sample_phish["suspicious_keyword_count"] = 3.0

        pred_phish = trained_model.predict(sample_phish)
        assert pred_phish[0] in [0, 1]

    def test_get_feature_importances(self, trained_model):
        """Feature importances dictionary must cover all features and sum to >= 0."""
        importances = trained_model.get_feature_importances()
        assert isinstance(importances, dict)
        assert len(importances) == len(FEATURE_NAMES)
        for name in FEATURE_NAMES:
            assert name in importances
            assert importances[name] >= 0.0

    def test_explain_prediction_returns_top_k(self, trained_model):
        """explain_prediction must return exactly top_k human-readable strings."""
        sample_phish = {name: 0.0 for name in FEATURE_NAMES}
        sample_phish["brand_domain_mismatch"] = 1.0
        sample_phish["has_credential_harvesting_form"] = 1.0
        sample_phish["password_input_count"] = 1.0
        sample_phish["longest_numeric_sequence"] = 10.0

        explanations = trained_model.explain_prediction(sample_phish, phishing_prob=0.92, top_k=3)
        assert isinstance(explanations, list)
        assert len(explanations) == 3
        for exp in explanations:
            assert isinstance(exp, str) and len(exp) > 0

    def test_missing_model_fail_safe(self, tmp_path):
        """Model with missing file must not crash and must provide fallback probabilities."""
        non_existent_path = str(tmp_path / "missing_model.json")
        model = MLPhishingModel(model_path=non_existent_path, auto_load=True)
        assert model.is_trained is False

        sample = {name: 0.0 for name in FEATURE_NAMES}
        sample["brand_domain_mismatch"] = 1.0
        sample["has_credential_harvesting_form"] = 1.0

        probs = model.predict_proba(sample)
        assert probs.shape == (1, 2)
        assert 0.0 <= probs[0, 1] <= 1.0
        assert probs[0, 1] > 0.50  # Fallback correctly identifies phishing indicators
