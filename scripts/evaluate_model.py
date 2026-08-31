"""
Model Evaluation and Benchmark Script for Website Classifier.

Evaluates the trained XGBoost model and hybrid analysis engine against benchmark datasets.

Calculates and reports:
- Number of samples for each class (Class 0: Legitimate, Class 1: Phishing)
- Accuracy, Precision, Recall, F1-Score, ROC-AUC
- Confusion Matrix (TN, FP, FN, TP)
- False Positive Count & False Positive Rate (FPR)
- False Negative Count & False Negative Rate (FNR)
- Clear conceptual separation between:
  1. ML Probability
  2. Final Risk Score
  3. Confidence Level
"""

import os
import sys
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

from src.feature_extractor import FeatureExtractor, FEATURE_NAMES
from src.ml_model import MLPhishingModel, DEFAULT_MODEL_PATH
from scripts.build_dataset import DATA_DIR


def evaluate_dataset_file(
    eval_csv_path: str,
    model_path: Optional[str] = None,
    threshold: float = 0.50,
) -> Dict[str, Any]:
    """
    Evaluate the XGBoost model on a specified evaluation CSV dataset.

    Args:
        eval_csv_path: Path to evaluation CSV containing 48 features + is_phishing label.
        model_path: Path to model JSON (default models/xgboost_phishing_model.json).
        threshold: Decision threshold for phishing classification (default 0.50).

    Returns:
        Dictionary of comprehensive evaluation metrics.
    """
    if not os.path.exists(eval_csv_path):
        raise FileNotFoundError(f"Evaluation dataset not found at: {eval_csv_path}")

    print("=" * 65)
    print("                MODEL EVALUATION BENCHMARK")
    print("=" * 65)
    print(f"Evaluation Dataset File: {eval_csv_path}")

    df = pd.read_csv(eval_csv_path)

    # 1. Validate required columns
    missing_cols = [c for c in FEATURE_NAMES if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Evaluation dataset missing required feature columns: {missing_cols}")
    if "is_phishing" not in df.columns:
        raise ValueError("Evaluation dataset missing target column 'is_phishing'")

    # 2. Count samples for each class
    counts = df["is_phishing"].value_counts().to_dict()
    n_class_0 = counts.get(0, 0)
    n_class_1 = counts.get(1, 0)
    total_samples = len(df)

    print(f"\n1. Class Distribution:")
    print(f"   - Total Evaluation Samples: {total_samples}")
    print(f"   - Class 0 (Legitimate):     {n_class_0:>5} ({n_class_0 / total_samples:.2%})")
    print(f"   - Class 1 (Phishing):       {n_class_1:>5} ({n_class_1 / total_samples:.2%})")

    # 3. Load Model
    target_model_path = model_path or DEFAULT_MODEL_PATH
    model = MLPhishingModel(model_path=target_model_path)
    if not model.is_trained:
        raise RuntimeError(f"Failed to load trained model from {target_model_path}")

    # 4. Extract Feature Matrix and Target
    X = df[FEATURE_NAMES].values.astype(np.float32)
    y_true = df["is_phishing"].values.astype(np.int32)

    # 5. Model Inference (Strict Standard Threshold 0.50)
    probs = model.predict_proba(X)
    y_prob = probs[:, 1]
    y_pred = (y_prob >= threshold).astype(np.int32)

    # 6. Calculate Metrics
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_true, y_prob)
    cm = confusion_matrix(y_true, y_pred)

    tn, fp, fn, tp = cm.ravel()
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = (fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    print("\n2. Quantitative Performance Metrics:")
    print(f"   - Decision Threshold:       {threshold:.2f}")
    print(f"   - Accuracy:                 {acc:.4f} ({acc * 100:.2f}%)")
    print(f"   - Precision:                {prec:.4f} ({prec * 100:.2f}%)")
    print(f"   - Recall:                   {rec:.4f} ({rec * 100:.2f}%)")
    print(f"   - F1-Score:                 {f1:.4f}")
    print(f"   - ROC-AUC Score:            {roc_auc:.4f}")
    print(f"   - False Positive Count:     {fp} (FPR: {fpr:.2%})")
    print(f"   - False Negative Count:     {fn} (FNR: {fnr:.2%})")

    print("\n3. Confusion Matrix:")
    print(f"   [TN={tn:<5} FP={fp:<5}] (Actual Legitimate)")
    print(f"   [FN={fn:<5} TP={tp:<5}] (Actual Phishing)")
    print("\n4. Conceptual Value Separation in Evaluation:")
    print("   +--------------------+--------------------------------------------------------+")
    print("   | Metric Concept     | Definition & Scope in Production Pipeline              |")
    print("   +--------------------+--------------------------------------------------------+")
    print("   | ML Probability     | Statistical model output P(Phishing) from XGBoost      |")
    print("   | Final Risk Score   | Authenticity (1-p) & Fake score gated by security rule |")
    print("   | Confidence Level   | Data completeness based on collected category ratio    |")
    print("   +--------------------+--------------------------------------------------------+")
    print("=" * 65)

    return {
        "n_samples": total_samples,
        "n_class_0": int(n_class_0),
        "n_class_1": int(n_class_1),
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "roc_auc": float(roc_auc),
        "confusion_matrix": cm.tolist(),
        "fp_count": int(fp),
        "fn_count": int(fn),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "threshold": float(threshold),
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate website classifier on benchmark dataset.")
    parser.add_argument(
        "--dataset", "-d",
        type=str,
        default=os.path.join(DATA_DIR, "eval_benchmark.csv"),
        help="Path to evaluation CSV dataset (default data/eval_benchmark.csv)."
    )
    parser.add_argument(
        "--model", "-m",
        type=str,
        default=DEFAULT_MODEL_PATH,
        help="Path to trained XGBoost model JSON."
    )
    parser.add_argument(
        "--threshold", "-t",
        type=float,
        default=0.50,
        help="Decision threshold for classification (default 0.50)."
    )

    args = parser.parse_args()

    # If eval_benchmark.csv does not exist yet, prepare it from data/dataset.csv
    if not os.path.exists(args.dataset):
        from scripts.prepare_external_dataset import DatasetPreparer
        preparer = DatasetPreparer()
        input_src = os.path.join(DATA_DIR, "dataset.csv")
        if os.path.exists(input_src):
            print(f"Creating evaluation benchmark from {input_src}...")
            preparer.process_and_save(input_src)

    evaluate_dataset_file(
        eval_csv_path=args.dataset,
        model_path=args.model,
        threshold=args.threshold,
    )


if __name__ == "__main__":
    main()
