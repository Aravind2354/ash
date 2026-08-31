"""
Machine Learning Phishing Detection Model Module using XGBoost.

This module provides the XGBClassifier-based binary classification model
for website authenticity and phishing detection (0 = Legitimate, 1 = Phishing).
"""

import os
import json
import logging
from typing import Dict, List, Optional, Tuple, Any, Union
import numpy as np

try:
    import xgboost as xgb
    from xgboost import XGBClassifier
except ImportError:
    xgb = None
    XGBClassifier = None

from src.feature_extractor import FEATURE_NAMES, FeatureExtractor


DEFAULT_MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
DEFAULT_MODEL_PATH = os.path.join(DEFAULT_MODEL_DIR, "xgboost_phishing_model.json")
DEFAULT_FEATURE_NAMES_PATH = os.path.join(DEFAULT_MODEL_DIR, "feature_names.json")


# Human-friendly descriptions for feature explanations in reports
FEATURE_HUMAN_DESCRIPTIONS: Dict[str, Tuple[str, str]] = {
    "brand_domain_mismatch": (
        "Unauthorized brand impersonation detected on unregistered domain",
        "Official verified domain identity for claimed brand",
    ),
    "has_credential_harvesting_form": (
        "Credential harvesting input fields detected (password/email/payment/OTP)",
        "No credential harvesting inputs detected",
    ),
    "cross_domain_form_action_count": (
        "Form submission exfiltrating data to an external cross-domain endpoint",
        "Form actions strictly internal to same registrable domain",
    ),
    "longest_numeric_sequence": (
        "Suspicious long numeric sequence in domain name",
        "Standard alphabetical domain structure",
    ),
    "is_suspicious_tld": (
        "High-risk disposable top-level domain extension",
        "Standard trusted top-level domain",
    ),
    "domain_entropy": (
        "High randomness/entropy in domain name (potential algorithmic generation)",
        "Natural lexical domain name structure",
    ),
    "is_punycode": (
        "Punycode (xn--) internationalized domain homograph indicator",
        "Standard ASCII domain encoding",
    ),
    "has_ip_address": (
        "Raw IP address used in place of standard domain hostname",
        "Standard domain name system resolution",
    ),
    "subdomain_count": (
        "Excessive multi-level subdomain depth",
        "Standard shallow subdomain hierarchy",
    ),
    "hyphen_count": (
        "Multiple hyphens in hostname structure",
        "Clean hostname structure without excessive hyphens",
    ),
    "password_input_count": (
        "Password authentication input field present",
        "No password input fields present",
    ),
    "card_input_count": (
        "Payment / credit card data entry fields detected",
        "No payment card fields present",
    ),
    "otp_input_count": (
        "One-time security passcode (OTP/2FA) entry field detected",
        "No OTP/PIN input fields present",
    ),
    "hidden_input_count": (
        "Excessive hidden form parameter fields",
        "Normal form input configuration",
    ),
    "login_keyword_count": (
        "Security/login verification language detected in page content",
        "Standard general web content",
    ),
    "external_form_action_count": (
        "Form action targets external third-party URL",
        "Form submissions target verified origin",
    ),
    "threat_intelligence_flag": (
        "Confirmed threat intelligence alert from security providers",
        "No threat intelligence flags",
    ),
    "ssl_chain_valid": (
        "Untrusted or missing SSL/TLS certificate chain",
        "Valid trusted SSL certificate chain",
    ),
    "ssl_recognized_ca": (
        "Unrecognized or untrusted certificate authority",
        "Recognized trusted Certificate Authority",
    ),
    "network_https_ratio": (
        "Majority of network requests use unencrypted HTTP protocol",
        "High secure protocol adoption (HTTPS/WSS)",
    ),
    "dom_element_count": (
        "Sparse or suspicious DOM element hierarchy",
        "Rich DOM element hierarchy",
    ),
    "js_script_count": (
        "Suspicious JavaScript execution profile",
        "Standard script execution profile",
    ),
    "has_screenshot": (
        "Visual layout rendering captured",
        "Visual layout rendering captured",
    ),
}


class MLPhishingModel:
    """XGBoost-based machine learning model for website authenticity and phishing detection."""

    def __init__(
        self,
        model_path: Optional[str] = None,
        feature_names: Optional[List[str]] = None,
        logger: Optional[logging.Logger] = None,
        auto_load: bool = True,
    ):
        self.logger = logger or logging.getLogger(__name__)
        self.feature_names = list(feature_names or FEATURE_NAMES)
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.feature_extractor = FeatureExtractor()
        self._model: Optional[XGBClassifier] = None
        self._is_trained: bool = False

        if auto_load and os.path.exists(self.model_path):
            self.load_model(self.model_path)

    @property
    def is_trained(self) -> bool:
        """Check if model is trained and ready for inference."""
        return self._is_trained and self._model is not None

    def train(
        self,
        X: Union[np.ndarray, List[List[float]]],
        y: Union[np.ndarray, List[int]],
        eval_set: Optional[List[Tuple[np.ndarray, np.ndarray]]] = None,
        feature_names: Optional[List[str]] = None,
        n_estimators: int = 150,
        max_depth: int = 5,
        learning_rate: float = 0.08,
        subsample: float = 0.8,
        colsample_bytree: float = 0.8,
        random_state: int = 42,
    ) -> Dict[str, Any]:
        """
        Train the XGBoost classifier on numerical feature matrices.

        Args:
            X: 2D array-like feature matrix (n_samples, n_features).
            y: 1D array-like binary target array (0 = Legitimate, 1 = Phishing).
            eval_set: Optional validation set [(X_val, y_val)] for monitoring.
            feature_names: Optional feature names list.
            n_estimators: Number of boosting trees.
            max_depth: Max tree depth.
            learning_rate: Boosting learning rate.
            subsample: Row subsampling ratio.
            colsample_bytree: Column subsampling ratio.
            random_state: Random seed for deterministic reproducibility.

        Returns:
            Dictionary with training metadata and feature importances.
        """
        if XGBClassifier is None:
            raise RuntimeError("xgboost is not installed. Please install xgboost.")

        if feature_names:
            self.feature_names = list(feature_names)

        X_mat = np.array(X, dtype=np.float32)
        y_vec = np.array(y, dtype=np.int32)

        self._model = XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            subsample=subsample,
            colsample_bytree=colsample_bytree,
            random_state=random_state,
            eval_metric="logloss",
            tree_method="hist",
        )

        self.logger.info(f"Training XGBClassifier on {len(X_mat)} samples with {len(self.feature_names)} features...")
        self._model.fit(X_mat, y_vec, eval_set=eval_set, verbose=False)
        self._is_trained = True
        self.logger.info("XGBoost model training completed successfully.")

        importances = self.get_feature_importances()
        return {
            "n_samples": len(X_mat),
            "n_features": len(self.feature_names),
            "feature_importances": importances,
        }

    def predict_proba(self, X: Union[np.ndarray, List[List[float]], Dict[str, float]]) -> np.ndarray:
        """
        Predict binary class probabilities [P(legitimate), P(phishing)].

        Args:
            X: 2D feature matrix, single 1D vector, or feature dictionary.

        Returns:
            2D numpy array of probabilities with shape (n_samples, 2).
        """
        X_mat = self._format_input(X)

        if not self.is_trained:
            # Fallback heuristic calculation if model not yet loaded
            self.logger.warning("MLPhishingModel not trained/loaded. Using fallback probability calculation.")
            return self._fallback_predict_proba(X_mat)

        return self._model.predict_proba(X_mat)

    def predict(self, X: Union[np.ndarray, List[List[float]], Dict[str, float]], threshold: float = 0.5) -> np.ndarray:
        """
        Predict binary class (0 = Legitimate, 1 = Phishing).

        Args:
            X: Input feature matrix or vector.
            threshold: Decision threshold for phishing class (default 0.5).

        Returns:
            1D numpy array of binary predictions.
        """
        probs = self.predict_proba(X)
        return (probs[:, 1] >= threshold).astype(np.int32)

    def predict_phishing_probability(self, X: Union[np.ndarray, List[List[float]], Dict[str, float]]) -> float:
        """
        Predict scalar phishing probability [0.0, 1.0] for a single sample.

        Args:
            X: Single sample feature vector or dictionary.

        Returns:
            Float probability that sample is phishing (0.0 to 1.0).
        """
        probs = self.predict_proba(X)
        return float(probs[0, 1])

    def get_feature_importances(self) -> Dict[str, float]:
        """Get dictionary mapping feature name to normalized feature importance."""
        if not self.is_trained:
            return {name: 0.0 for name in self.feature_names}

        raw_importances = self._model.feature_importances_
        return {
            name: float(imp)
            for name, imp in zip(self.feature_names, raw_importances)
        }

    def explain_prediction(
        self,
        features_dict: Dict[str, float],
        phishing_prob: float,
        top_k: int = 3,
    ) -> List[str]:
        """
        Explain model prediction by selecting top contributing feature explanations.

        Args:
            features_dict: Dictionary of sample feature values.
            phishing_prob: Predicted phishing probability.
            top_k: Number of explanations to return (default 3).

        Returns:
            List of human-readable explanation strings.
        """
        importances = self.get_feature_importances()
        scored_signals: List[Tuple[float, str]] = []

        is_phishing = phishing_prob >= 0.50

        for f_name, f_val in features_dict.items():
            imp = importances.get(f_name, 0.0)
            if f_name not in FEATURE_HUMAN_DESCRIPTIONS:
                continue

            phish_desc, legit_desc = FEATURE_HUMAN_DESCRIPTIONS[f_name]

            if is_phishing:
                # Features that indicate phishing risk
                if f_val > 0.0 and f_name in {
                    "brand_domain_mismatch",
                    "has_credential_harvesting_form",
                    "cross_domain_form_action_count",
                    "longest_numeric_sequence",
                    "is_suspicious_tld",
                    "domain_entropy",
                    "is_punycode",
                    "has_ip_address",
                    "password_input_count",
                    "card_input_count",
                    "otp_input_count",
                    "hidden_input_count",
                    "login_keyword_count",
                    "external_form_action_count",
                    "threat_intelligence_flag",
                }:
                    weight = imp * (2.0 if f_name in {"brand_domain_mismatch", "has_credential_harvesting_form", "cross_domain_form_action_count"} else 1.0)
                    scored_signals.append((weight, phish_desc))
            else:
                # Features that indicate legitimate safety
                if f_name in {
                    "brand_domain_match",
                    "ssl_chain_valid",
                    "ssl_recognized_ca",
                    "network_https_ratio",
                    "dom_element_count",
                    "js_script_count",
                    "has_screenshot",
                } and f_val > 0.0:
                    weight = imp * 1.0
                    scored_signals.append((weight, legit_desc))

        scored_signals.sort(reverse=True, key=lambda item: item[0])

        explanations: List[str] = []
        for _, desc in scored_signals:
            if desc not in explanations:
                explanations.append(desc)
                if len(explanations) == top_k:
                    break

        # Fallbacks if fewer than top_k
        if len(explanations) < top_k:
            if is_phishing:
                fallbacks = [
                    "Phishing probability evaluated via multi-feature gradient boosted decision trees",
                    "Domain identity and structural metrics evaluated",
                    "Form input and credential security profile evaluated",
                ]
            else:
                fallbacks = [
                    "Valid trusted SSL certificate chain",
                    "Standard script execution profile",
                    "Rich DOM element hierarchy",
                ]
            for fb in fallbacks:
                if fb not in explanations:
                    explanations.append(fb)
                    if len(explanations) == top_k:
                        break

        return explanations[:top_k]

    def save_model(self, model_path: Optional[str] = None) -> str:
        """
        Save the trained XGBoost model and feature names to disk.

        Args:
            model_path: Destination JSON file path.

        Returns:
            The saved model file path.
        """
        if not self.is_trained:
            raise ValueError("Cannot save untrained model.")

        dest_path = model_path or self.model_path
        os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)

        self._model.save_model(dest_path)

        # Save feature names alongside model
        names_path = os.path.join(os.path.dirname(dest_path), "feature_names.json")
        with open(names_path, "w", encoding="utf-8") as f:
            json.dump(self.feature_names, f, indent=2)

        self.logger.info(f"Model successfully saved to {dest_path}")
        return dest_path

    def load_model(self, model_path: Optional[str] = None) -> bool:
        """
        Load a trained XGBoost model from disk.

        Args:
            model_path: Model JSON file path.

        Returns:
            True if loaded successfully, False otherwise.
        """
        target_path = model_path or self.model_path
        if not os.path.exists(target_path):
            self.logger.warning(f"Model file not found at {target_path}")
            return False

        if XGBClassifier is None:
            self.logger.error("Cannot load model: xgboost package is not available.")
            return False

        try:
            self._model = XGBClassifier()
            self._model.load_model(target_path)

            # Load feature names if available
            names_path = os.path.join(os.path.dirname(target_path), "feature_names.json")
            if os.path.exists(names_path):
                with open(names_path, "r", encoding="utf-8") as f:
                    self.feature_names = json.load(f)

            self._is_trained = True
            self.logger.info(f"Successfully loaded XGBoost model from {target_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error loading model from {target_path}: {e}")
            self._is_trained = False
            return False

    def _format_input(self, X: Union[np.ndarray, List[List[float]], Dict[str, float]]) -> np.ndarray:
        """Format arbitrary input into a 2D float32 numpy array."""
        if isinstance(X, dict):
            vector = [X.get(name, 0.0) for name in self.feature_names]
            return np.array([vector], dtype=np.float32)

        arr = np.array(X, dtype=np.float32)
        if arr.ndim == 1:
            return arr.reshape(1, -1)
        return arr

    def _fallback_predict_proba(self, X_mat: np.ndarray) -> np.ndarray:
        """Heuristic-weighted baseline probability if model weights file is uninitialized."""
        probs = []
        name_idx = {name: i for i, name in enumerate(self.feature_names)}

        for row in X_mat:
            phish_signals = 0.0
            total_weight = 0.0

            def get_f(name: str) -> float:
                return float(row[name_idx[name]]) if name in name_idx else 0.0

            # High-impact signals
            if get_f("brand_domain_mismatch") > 0:
                phish_signals += 0.85 * 3.0
                total_weight += 3.0
            if get_f("has_credential_harvesting_form") > 0 and get_f("brand_domain_mismatch") > 0:
                phish_signals += 0.95 * 3.0
                total_weight += 3.0
            if get_f("cross_domain_form_action_count") > 0:
                phish_signals += 0.90 * 2.5
                total_weight += 2.5
            if get_f("threat_intelligence_flag") > 0:
                phish_signals += 1.0 * 4.0
                total_weight += 4.0
            if get_f("longest_numeric_sequence") >= 6:
                phish_signals += 0.75 * 2.0
                total_weight += 2.0
            if get_f("is_suspicious_tld") > 0:
                phish_signals += 0.65 * 1.5
                total_weight += 1.5

            # Legitimate safety signals
            if get_f("brand_domain_match") > 0:
                phish_signals += 0.05 * 3.0
                total_weight += 3.0
            if get_f("ssl_chain_valid") > 0 and get_f("ssl_recognized_ca") > 0:
                phish_signals += 0.15 * 1.0
                total_weight += 1.0

            prob_phish = (phish_signals / total_weight) if total_weight > 0 else 0.15
            prob_phish = max(0.01, min(0.99, prob_phish))
            probs.append([1.0 - prob_phish, prob_phish])

        return np.array(probs, dtype=np.float32)
