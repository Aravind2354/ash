"""
Live Website Evaluation Script for Fake Website & Phishing Classifier.

Evaluates live or recorded URLs from a CSV file (default: data/live_evaluation_urls.csv)
using the trained XGBoost model and AuthenticityDetector without modifying or retraining the model.

Outputs results to: data/live_evaluation_results.csv

Calculates and reports:
- Number of samples per class (Class 0: Legitimate, Class 1: Phishing)
- Standalone XGBoost ML metrics (Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR, Confusion Matrix)
- Hybrid Decision Engine metrics (Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR, Confusion Matrix)
- Discrepancy analysis (ML says Legitimate vs Hybrid says Suspicious/Phishing)
- Robust per-URL timeout and bounded concurrency to prevent hangs
"""

import os
import sys
import json
import asyncio
import argparse
from typing import Dict, List, Tuple, Any, Optional
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.models import (
    AnalysisData,
    NetworkData,
    DOMData,
    JavaScriptData,
    VisualData,
    SSLData,
)
from src.feature_extractor import FeatureExtractor, FEATURE_NAMES
from src.ml_model import MLPhishingModel, DEFAULT_MODEL_PATH
from src.authenticity_detector import AuthenticityDetector
from scripts.build_dataset import DATA_DIR


DEFAULT_INPUT_CSV = os.path.join(DATA_DIR, "live_evaluation_urls.csv")
DEFAULT_OUTPUT_CSV = os.path.join(DATA_DIR, "live_evaluation_results.csv")


def parse_score_value(val: Any) -> Optional[float]:
    """Parse score value to float between 0.0 and 1.0 or None."""
    if val is None or val == "" or val == "N/A":
        return None
    if isinstance(val, (int, float)):
        return float(val) if val <= 1.0 else float(val) / 100.0
    if isinstance(val, str):
        cleaned = val.replace("%", "").strip()
        try:
            num = float(cleaned)
            return num if num <= 1.0 else num / 100.0
        except ValueError:
            return None
    return None


class LiveSiteEvaluator:
    """Evaluates website authenticity on real or mock URLs using ML and Hybrid pipeline."""

    def __init__(
        self,
        detector: Optional[AuthenticityDetector] = None,
        model: Optional[MLPhishingModel] = None,
        feature_extractor: Optional[FeatureExtractor] = None,
        per_url_timeout: int = 30,
    ):
        self.detector = detector or AuthenticityDetector()
        self.feature_extractor = feature_extractor or FeatureExtractor()
        self.model = model or MLPhishingModel(auto_load=True)
        self.per_url_timeout = per_url_timeout

        if not self.model.is_trained:
            print(f"Warning: ML model not loaded from {DEFAULT_MODEL_PATH}. Loading now...")
            self.model.load_model(DEFAULT_MODEL_PATH)

    async def evaluate_single_url_async(
        self,
        url: str,
        expected_label: int,
    ) -> Dict[str, Any]:
        """
        Analyze a single URL with strict timeout and fallback handling.
        Returns a dictionary of all recorded metrics.
        """
        clean_url = url.strip()
        print(f"\nAnalyzing: {clean_url} (Expected: {'PHISHING' if expected_label == 1 else 'LEGITIMATE'})...")

        # 1. Execute live analysis via AuthenticityDetector with strict per-url timeout
        try:
            report = await asyncio.wait_for(
                self.detector.analyze_website_async(clean_url),
                timeout=float(self.per_url_timeout),
            )
        except asyncio.TimeoutError:
            print(f"  [Timeout] Analysis exceeded per-url timeout limit of {self.per_url_timeout}s.")
            report = {
                "status": "failed",
                "risk_level": "FAILED",
                "authenticity_score": None,
                "fake_score": None,
                "confidence_indicator": "LOW",
                "url": clean_url,
                "analysis_data": None,
                "top_factors": [],
                "suspicious_indicators": [],
                "critical_indicators": [],
                "error_message": f"Analysis timed out after {self.per_url_timeout}s limit",
            }
        except Exception as exc:
            print(f"  [Error] Analysis exception: {exc}")
            report = {
                "status": "failed",
                "risk_level": "FAILED",
                "authenticity_score": None,
                "fake_score": None,
                "confidence_indicator": "LOW",
                "url": clean_url,
                "analysis_data": None,
                "top_factors": [],
                "suspicious_indicators": [],
                "critical_indicators": [],
                "error_message": str(exc),
            }

        # 2. Extract analysis_data if available, or reconstruct AnalysisData
        analysis_data = None
        raw_data = report.get("analysis_data")
        if isinstance(raw_data, AnalysisData):
            analysis_data = raw_data
        elif isinstance(raw_data, dict):
            # Parse dict into AnalysisData
            try:
                net_dict = raw_data.get("network") or {}
                dom_dict = raw_data.get("dom") or {}
                js_dict = raw_data.get("javascript") or {}
                vis_dict = raw_data.get("visual") or {}
                ssl_dict = raw_data.get("ssl") or {}

                analysis_data = AnalysisData(
                    network=NetworkData(**net_dict) if net_dict and not net_dict.get("failed") else None,
                    dom=DOMData(**dom_dict) if dom_dict and not dom_dict.get("failed") else None,
                    javascript=JavaScriptData(**js_dict) if js_dict and not js_dict.get("failed") else None,
                    visual=VisualData(**vis_dict) if vis_dict and not vis_dict.get("failed") else None,
                    ssl=SSLData(**ssl_dict) if ssl_dict and not ssl_dict.get("failed") else None,
                )
            except Exception:
                analysis_data = None

        # 3. Extract 48-feature dictionary
        features_dict = self.feature_extractor.extract_features_dict(
            data=analysis_data,
            url=clean_url,
        )

        # 4. Standalone XGBoost ML Prediction
        ml_phish_prob = float(self.model.predict_phishing_probability(features_dict))
        ml_prediction = 1 if ml_phish_prob >= 0.50 else 0

        # 5. Hybrid Final Decision & Scores
        raw_auth = parse_score_value(report.get("authenticity_score"))
        raw_fake = parse_score_value(report.get("fake_score"))
        risk_level = (report.get("risk_level") or "UNKNOWN").upper()
        confidence = (report.get("confidence_indicator") or "LOW").upper()
        status = report.get("status") or "unknown"
        error_msg = report.get("error_message") or ""

        # Calculate hybrid prediction (1 = Phishing/Suspicious, 0 = Legitimate)
        if risk_level in ["PHISHING", "HIGH_RISK", "SUSPICIOUS"]:
            hybrid_prediction = 1
        elif raw_fake is not None and raw_fake >= 0.50:
            hybrid_prediction = 1
        elif risk_level == "SAFE":
            hybrid_prediction = 0
        else:
            # For failed/inconclusive, fall back to ML prediction
            hybrid_prediction = ml_prediction

        suspicious_list = report.get("suspicious_indicators") or []
        critical_list = report.get("critical_indicators") or []
        combined_indicators = list(dict.fromkeys(critical_list + suspicious_list))

        result_row = {
            "url": clean_url,
            "expected_label": expected_label,
            "ml_phishing_probability": round(ml_phish_prob, 4),
            "ml_prediction": ml_prediction,
            "final_fake_score": round(raw_fake, 4) if raw_fake is not None else round(ml_phish_prob, 4),
            "authenticity_score": round(raw_auth, 4) if raw_auth is not None else round(1.0 - ml_phish_prob, 4),
            "confidence": confidence,
            "risk_level": risk_level,
            "hybrid_prediction": hybrid_prediction,
            "suspicious_indicators": " | ".join(combined_indicators) if combined_indicators else "None",
            "analysis_status": status,
            "error_message": error_msg if error_msg else "None",
        }

        print(f"  -> ML Prob: {ml_phish_prob:.4f} (Pred: {ml_prediction}) | Hybrid Fake: {result_row['final_fake_score']:.4f} (Pred: {hybrid_prediction}) | Risk: {risk_level} | Conf: {confidence}")
        return result_row

    async def evaluate_csv_async(
        self,
        input_csv_path: str,
        output_csv_path: Optional[str] = None,
        max_sites: Optional[int] = None,
        concurrency: int = 1,
    ) -> pd.DataFrame:
        """
        Evaluate all URLs from CSV file with bounded concurrency.
        """
        if not os.path.exists(input_csv_path):
            raise FileNotFoundError(f"Input CSV file not found at: {input_csv_path}")

        print("=" * 70)
        print("          LIVE WEBSITE CLASSIFICATION EVALUATION BENCHMARK")
        print("=" * 70)
        print(f"Input URLs File:  {input_csv_path}")
        out_csv = output_csv_path or DEFAULT_OUTPUT_CSV
        print(f"Output CSV File:  {out_csv}")

        df_in = pd.read_csv(input_csv_path)

        if "url" not in [c.lower() for c in df_in.columns]:
            raise ValueError(f"Input CSV missing required 'url' column. Columns: {list(df_in.columns)}")

        url_col = [c for c in df_in.columns if c.lower() == "url"][0]

        # Identify label column
        label_col = None
        for c in df_in.columns:
            if c.lower() in ["expected_label", "label", "is_phishing", "class", "target", "phishing"]:
                label_col = c
                break

        if label_col is None:
            print("Warning: No expected label column found. Defaulting all expected labels to 0 (unlabeled evaluation).")
            df_in["expected_label"] = 0
            label_col = "expected_label"

        # Apply max_sites limit if specified
        if max_sites is not None and max_sites > 0:
            df_in = df_in.head(max_sites)
            print(f"Limited evaluation to top {max_sites} URLs.")

        total_urls = len(df_in)
        print(f"Total URLs to evaluate: {total_urls} (Concurrency limit: {concurrency})")

        results: List[Dict[str, Any]] = []

        # Semaphore for bounded concurrency
        sem = asyncio.Semaphore(max(1, concurrency))

        async def worker(url_val: str, lbl_val: int):
            async with sem:
                return await self.evaluate_single_url_async(str(url_val), int(lbl_val))

        tasks = [
            worker(row[url_col], row[label_col])
            for _, row in df_in.iterrows()
        ]

        results = await asyncio.gather(*tasks)

        df_results = pd.DataFrame(results)

        # Save to output CSV
        os.makedirs(os.path.dirname(os.path.abspath(out_csv)), exist_ok=True)
        df_results.to_csv(out_csv, index=False)
        print(f"\nSaved evaluation results to: {out_csv}")

        # Compute and display performance metrics
        self.compute_and_print_metrics(df_results)

        return df_results

    def compute_and_print_metrics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Compute evaluation metrics separately for XGBoost-only and Hybrid decision.
        """
        y_true = df["expected_label"].values.astype(np.int32)
        y_ml_pred = df["ml_prediction"].values.astype(np.int32)
        y_ml_prob = df["ml_phishing_probability"].values.astype(np.float32)
        y_hyb_pred = df["hybrid_prediction"].values.astype(np.int32)
        y_hyb_prob = df["final_fake_score"].values.astype(np.float32)

        n_total = len(df)
        n_legit = int(np.sum(y_true == 0))
        n_phish = int(np.sum(y_true == 1))

        print("\n" + "=" * 70)
        print("               EVALUATION BENCHMARK METRICS SUMMARY")
        print("=" * 70)
        print(f"Total Samples Evaluated: {n_total}")
        print(f"  - Class 0 (Legitimate): {n_legit:>4} ({n_legit / n_total:.2%})")
        print(f"  - Class 1 (Phishing):   {n_phish:>4} ({n_phish / n_total:.2%})")

        # 1. XGBoost-Only Performance
        acc_ml = accuracy_score(y_true, y_ml_pred)
        prec_ml = precision_score(y_true, y_ml_pred, zero_division=0)
        rec_ml = recall_score(y_true, y_ml_pred, zero_division=0)
        f1_ml = f1_score(y_true, y_ml_pred, zero_division=0)
        roc_ml = roc_auc_score(y_true, y_ml_prob) if len(np.unique(y_true)) > 1 else 1.0
        cm_ml = confusion_matrix(y_true, y_ml_pred)

        tn_m, fp_m, fn_m, tp_m = cm_ml.ravel() if cm_ml.shape == (2, 2) else (0, 0, 0, 0)
        fpr_m = (fp_m / (fp_m + tn_m)) if (fp_m + tn_m) > 0 else 0.0
        fnr_m = (fn_m / (fn_m + tp_m)) if (fn_m + tp_m) > 0 else 0.0

        print("\n1. XGBoost-Only Model Performance:")
        print(f"   Accuracy:                 {acc_ml:.4f} ({acc_ml * 100:.2f}%)")
        print(f"   Precision:                {prec_ml:.4f} ({prec_ml * 100:.2f}%)")
        print(f"   Recall:                   {rec_ml:.4f} ({rec_ml * 100:.2f}%)")
        print(f"   F1-Score:                 {f1_ml:.4f}")
        print(f"   ROC-AUC Score:            {roc_ml:.4f}")
        print(f"   False Positive Rate (FPR): {fpr_m:.2%} ({fp_m} samples)")
        print(f"   False Negative Rate (FNR): {fnr_m:.2%} ({fn_m} samples)")
        print(f"   Confusion Matrix:         [TN={tn_m:<3} FP={fp_m:<3}] | [FN={fn_m:<3} TP={tp_m:<3}]")

        # 2. Hybrid Decision Engine Performance
        acc_hyb = accuracy_score(y_true, y_hyb_pred)
        prec_hyb = precision_score(y_true, y_hyb_pred, zero_division=0)
        rec_hyb = recall_score(y_true, y_hyb_pred, zero_division=0)
        f1_hyb = f1_score(y_true, y_hyb_pred, zero_division=0)
        roc_hyb = roc_auc_score(y_true, y_hyb_prob) if len(np.unique(y_true)) > 1 else 1.0
        cm_hyb = confusion_matrix(y_true, y_hyb_pred)

        tn_h, fp_h, fn_h, tp_h = cm_hyb.ravel() if cm_hyb.shape == (2, 2) else (0, 0, 0, 0)
        fpr_h = (fp_h / (fp_h + tn_h)) if (fp_h + tn_h) > 0 else 0.0
        fnr_h = (fn_h / (fn_h + tp_h)) if (fn_h + tp_h) > 0 else 0.0

        print("\n2. Hybrid Final Decision Performance (ML + Security Risk Gates):")
        print(f"   Accuracy:                 {acc_hyb:.4f} ({acc_hyb * 100:.2f}%)")
        print(f"   Precision:                {prec_hyb:.4f} ({prec_hyb * 100:.2f}%)")
        print(f"   Recall:                   {rec_hyb:.4f} ({rec_hyb * 100:.2f}%)")
        print(f"   F1-Score:                 {f1_hyb:.4f}")
        print(f"   ROC-AUC Score:            {roc_hyb:.4f}")
        print(f"   False Positive Rate (FPR): {fpr_h:.2%} ({fp_h} samples)")
        print(f"   False Negative Rate (FNR): {fnr_h:.2%} ({fn_h} samples)")
        print(f"   Confusion Matrix:         [TN={tn_h:<3} FP={fp_h:<3}] | [FN={fn_h:<3} TP={tp_h:<3}]")

        # 3. Discrepancy Analysis
        discrepancies = df[df["ml_prediction"] != df["hybrid_prediction"]]
        print(f"\n3. Discrepancy Analysis between ML and Hybrid Engine: {len(discrepancies)} cases")
        if len(discrepancies) > 0:
            for _, r in discrepancies.iterrows():
                print(f"   - {r['url']}: ML={r['ml_prediction']} (P={r['ml_phishing_probability']:.4f}) vs Hybrid={r['hybrid_prediction']} (Risk={r['risk_level']})")
        else:
            print("   None (ML predictions and Hybrid security verdicts are 100% aligned).")

        print("=" * 70)

        return {
            "ml_metrics": {"accuracy": acc_ml, "precision": prec_ml, "recall": rec_ml, "f1": f1_ml, "roc_auc": roc_ml, "fpr": fpr_m, "fnr": fnr_m},
            "hybrid_metrics": {"accuracy": acc_hyb, "precision": prec_hyb, "recall": rec_hyb, "f1": f1_hyb, "roc_auc": roc_hyb, "fpr": fpr_h, "fnr": fnr_h},
            "discrepancies_count": len(discrepancies),
        }


def main():
    parser = argparse.ArgumentParser(description="Evaluate website authenticity on URLs from CSV.")
    parser.add_argument("--input", "-i", type=str, default=DEFAULT_INPUT_CSV, help="Path to input CSV (default data/live_evaluation_urls.csv).")
    parser.add_argument("--output", "-o", type=str, default=DEFAULT_OUTPUT_CSV, help="Path to output CSV (default data/live_evaluation_results.csv).")
    parser.add_argument("--max-sites", "-n", type=int, default=None, help="Maximum number of URLs to evaluate.")
    parser.add_argument("--timeout", "-t", type=int, default=30, help="Per-URL analysis timeout in seconds (default 30).")
    parser.add_argument("--concurrency", "-c", type=int, default=1, help="Maximum concurrent URL analyses (default 1).")

    args = parser.parse_args()

    evaluator = LiveSiteEvaluator(per_url_timeout=args.timeout)
    asyncio.run(
        evaluator.evaluate_csv_async(
            input_csv_path=args.input,
            output_csv_path=args.output,
            max_sites=args.max_sites,
            concurrency=args.concurrency,
        )
    )


if __name__ == "__main__":
    main()
