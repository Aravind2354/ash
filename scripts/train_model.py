"""
XGBoost Model Training Script for Website Authenticity & Phishing Detection.

Loads the dataset, validates features, performs stratified train/test split,
trains the XGBClassifier model, evaluates metrics (Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix),
and saves the trained model to models/xgboost_phishing_model.json.
"""

import os
import sys
import json
from typing import Tuple, Dict, List, Optional, Any
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.feature_extractor import FEATURE_NAMES
from src.ml_model import MLPhishingModel, DEFAULT_MODEL_PATH
from scripts.build_dataset import build_and_save_datasets, DATA_DIR


def train_and_evaluate(
    train_path: Optional[str] = None,
    val_path: Optional[str] = None,
    model_output_path: Optional[str] = None,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Train and evaluate the XGBoost phishing detection model on partitioned datasets.

    Args:
        train_path: Path to train.csv (defaults to data/train.csv).
        val_path: Path to val.csv (defaults to data/val.csv).
        model_output_path: Path to save trained model JSON.
        random_state: Random seed for deterministic reproducibility.

    Returns:
        Dictionary of evaluation metrics and training artifacts.
    """
    t_path = train_path or os.path.join(DATA_DIR, "train.csv")
    v_path = val_path or os.path.join(DATA_DIR, "val.csv")
    out_path = model_output_path or DEFAULT_MODEL_PATH

    if not os.path.exists(t_path) or not os.path.exists(v_path):
        print("Partitioned datasets not found. Running prepare_external_dataset...")
        from scripts.prepare_external_dataset import DatasetPreparer
        preparer = DatasetPreparer()
        input_src = os.path.join(DATA_DIR, "dataset.csv")
        if not os.path.exists(input_src):
            build_and_save_datasets(n_each=3000, seed=random_state)
        preparer.process_and_save(input_src, random_state=random_state)

    print(f"Loading training data from {t_path}...")
    df_train = pd.read_csv(t_path)
    print(f"Loading validation data from {v_path}...")
    df_val = pd.read_csv(v_path)

    # 1. Validate required columns
    for name, df in [("Training", df_train), ("Validation", df_val)]:
        missing_cols = [col for col in FEATURE_NAMES if col not in df.columns]
        if missing_cols:
            raise ValueError(f"{name} dataset is missing required feature columns: {missing_cols}")
        if "is_phishing" not in df.columns:
            raise ValueError(f"{name} dataset is missing target column 'is_phishing'")

    # 2. Check and handle missing/NaN values
    for df in [df_train, df_val]:
        if df[FEATURE_NAMES].isnull().any().any():
            df[FEATURE_NAMES] = df[FEATURE_NAMES].fillna(df[FEATURE_NAMES].median().fillna(0.0))

    # 3. Separate features and target
    X_train = df_train[FEATURE_NAMES].values.astype(np.float32)
    y_train = df_train["is_phishing"].values.astype(np.int32)

    X_test = df_val[FEATURE_NAMES].values.astype(np.float32)
    y_test = df_val["is_phishing"].values.astype(np.int32)

    print(f"Train samples: {len(X_train)} ({int(np.sum(y_train))} phishing, {len(y_train) - int(np.sum(y_train))} legitimate)")
    print(f"Val samples:   {len(X_test)} ({int(np.sum(y_test))} phishing, {len(y_test) - int(np.sum(y_test))} legitimate)")

    # 4. Initialize and train MLPhishingModel
    model = MLPhishingModel(
        model_path=out_path,
        feature_names=FEATURE_NAMES,
        auto_load=False,
    )

    print("\nTraining XGBClassifier...")
    train_metadata = model.train(
        X=X_train,
        y=y_train,
        eval_set=[(X_test, y_test)],
        feature_names=FEATURE_NAMES,
        n_estimators=150,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=random_state,
    )

    # 6. Evaluate on held-out test set
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 55)
    print("       HELD-OUT TEST SET EVALUATION METRICS       ")
    print("=" * 55)
    print(f"Accuracy:         {acc:.4f} ({acc * 100:.2f}%)")
    print(f"Precision:        {prec:.4f} ({prec * 100:.2f}%)")
    print(f"Recall:           {rec:.4f} ({rec * 100:.2f}%)")
    print(f"F1-Score:         {f1:.4f}")
    print(f"ROC-AUC:          {roc_auc:.4f}")
    print("\nConfusion Matrix:")
    print(f"  [TN={cm[0, 0]:<5} FP={cm[0, 1]:<5}] (Actual Legitimate)")
    print(f"  [FN={cm[1, 0]:<5} TP={cm[1, 1]:<5}] (Actual Phishing)")
    print("=" * 55)

    # 7. Print top feature importances
    importances = model.get_feature_importances()
    sorted_imp = sorted(importances.items(), key=lambda item: item[1], reverse=True)
    print("\nTop 10 Feature Importances:")
    for rank, (name, val) in enumerate(sorted_imp[:10], start=1):
        print(f"  {rank:>2}. {name:<35} {val:.4f}")

    # 8. Save trained model
    saved_path = model.save_model(out_path)
    print(f"\nTrained model successfully saved to: {saved_path}")

    metrics = {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1_score": float(f1),
        "roc_auc": float(roc_auc),
        "confusion_matrix": cm.tolist(),
        "n_train": len(X_train),
        "n_test": len(X_test),
        "top_features": sorted_imp[:10],
        "model_path": saved_path,
    }

    metrics_path = os.path.join(os.path.dirname(saved_path), "training_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    return metrics


if __name__ == "__main__":
    train_and_evaluate()
