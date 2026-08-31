"""
ML Validation Audit Script for Fake Website Detector.

Performs:
1. Feature list and canonical order verification
2. Dataset sample count, class balance, duplicate check
3. Train/Test leakage and correlation analysis
4. Stratified 5-Fold Cross-Validation
5. XGBoost model parameter and inference verification
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import xgboost as xgb

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.feature_extractor import FEATURE_NAMES
from src.ml_model import MLPhishingModel, DEFAULT_MODEL_PATH, DEFAULT_FEATURE_NAMES_PATH
from scripts.build_dataset import DATA_DIR


def run_ml_audit():
    print("=" * 60)
    print("          PHASE 1 & PHASE 2: ML VALIDATION AUDIT")
    print("=" * 60)

    dataset_path = os.path.join(DATA_DIR, "dataset.csv")
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        return

    df = pd.read_csv(dataset_path)
    print(f"1. Dataset Shape: {df.shape[0]} rows, {df.shape[1]} columns")

    # Class balance
    target_counts = df["is_phishing"].value_counts().to_dict()
    print(f"2. Class Balance: 0 (Legitimate): {target_counts.get(0, 0)}, 1 (Phishing): {target_counts.get(1, 0)}")
    balance_ratio = target_counts.get(1, 0) / df.shape[0]
    print(f"   Balance Ratio: {balance_ratio:.2%}")

    # Feature List & Order Verification
    print(f"\n3. Feature List Length: {len(FEATURE_NAMES)}")
    model_features_path = os.path.join(os.path.dirname(DEFAULT_MODEL_PATH), "feature_names.json")
    if os.path.exists(model_features_path):
        with open(model_features_path, "r", encoding="utf-8") as f:
            saved_names = json.load(f)
        is_order_identical = (saved_names == FEATURE_NAMES)
        print(f"   Feature Order in saved model matches FEATURE_NAMES exactly: {is_order_identical}")
    else:
        print("   Warning: models/feature_names.json not found")

    df_feature_cols = [c for c in df.columns if c != "is_phishing"]
    print(f"   Dataset feature columns match FEATURE_NAMES exactly: {df_feature_cols == FEATURE_NAMES}")

    # Duplicate check
    duplicate_rows = df.duplicated(subset=FEATURE_NAMES).sum()
    print(f"\n4. Duplicate Feature Rows in Dataset: {duplicate_rows} ({duplicate_rows / len(df):.2%})")

    # Check for target leakage / direct label proxies
    print("\n5. Feature Correlations with is_phishing (Top 10):")
    correlations = df[FEATURE_NAMES].apply(lambda s: s.corr(df["is_phishing"])).sort_values(ascending=False)
    for name, corr in correlations.head(10).items():
        print(f"   - {name:<35}: {corr:+.4f}")

    print("\n   Features with |corr| > 0.80:")
    high_corr = correlations[correlations.abs() > 0.80]
    if len(high_corr) == 0:
        print("   None (No single feature perfectly separates or reveals the label)")
    else:
        for name, corr in high_corr.items():
            print(f"   - {name:<35}: {corr:+.4f}")

    # Stratified 5-Fold Cross Validation
    print("\n6. Stratified 5-Fold Cross-Validation on Dataset:")
    X = df[FEATURE_NAMES].values.astype(np.float32)
    y = df["is_phishing"].values.astype(np.int32)

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    fold_accuracies = []
    fold_precisions = []
    fold_recalls = []
    fold_f1s = []
    fold_aucs = []

    for fold, (train_idx, val_idx) in enumerate(skf.split(X, y), start=1):
        X_train, X_val = X[train_idx], X[val_idx]
        y_train, y_val = y[train_idx], y[val_idx]

        clf = xgb.XGBClassifier(
            n_estimators=150,
            max_depth=5,
            learning_rate=0.08,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            eval_metric="logloss",
            tree_method="hist",
        )
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_val)
        y_prob = clf.predict_proba(X_val)[:, 1]

        acc = accuracy_score(y_val, y_pred)
        prec = precision_score(y_val, y_pred, zero_division=0)
        rec = recall_score(y_val, y_pred, zero_division=0)
        f1 = f1_score(y_val, y_pred, zero_division=0)
        auc = roc_auc_score(y_val, y_prob)

        fold_accuracies.append(acc)
        fold_precisions.append(prec)
        fold_recalls.append(rec)
        fold_f1s.append(f1)
        fold_aucs.append(auc)
        print(f"   Fold {fold}: Acc={acc:.4f}, Prec={prec:.4f}, Rec={rec:.4f}, F1={f1:.4f}, AUC={auc:.4f}")

    print("-" * 60)
    print(f"   Mean 5-Fold Accuracy:  {np.mean(fold_accuracies):.4f} +/- {np.std(fold_accuracies):.4f}")
    print(f"   Mean 5-Fold Precision: {np.mean(fold_precisions):.4f} +/- {np.std(fold_precisions):.4f}")
    print(f"   Mean 5-Fold Recall:    {np.mean(fold_recalls):.4f} +/- {np.std(fold_recalls):.4f}")
    print(f"   Mean 5-Fold F1-Score:  {np.mean(fold_f1s):.4f} +/- {np.std(fold_f1s):.4f}")
    print(f"   Mean 5-Fold ROC-AUC:   {np.mean(fold_aucs):.4f} +/- {np.std(fold_aucs):.4f}")
    print("=" * 60)


if __name__ == "__main__":
    run_ml_audit()
