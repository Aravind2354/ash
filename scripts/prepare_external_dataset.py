"""
Reusable External Dataset Preparation Pipeline for Website Classifier.

Supports:
1. Importing external CSV datasets (both pre-extracted numerical features and raw URLs).
2. Standardizing label column to `is_phishing` (0 = Legitimate, 1 = Phishing).
3. Validating 48-feature schema and exact canonical column order.
4. Removing exact and near-duplicate rows.
5. Missing-value validation and deterministic imputation.
6. Class balance analysis and reporting.
7. Strict 3-way stratified partition (Train 70% / Validation 15% / Final Evaluation 15%)
   to guarantee zero contamination between training and evaluation.
"""

import os
import sys
import argparse
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.feature_extractor import FeatureExtractor, FEATURE_NAMES
from scripts.build_dataset import DATA_DIR


# Common label column synonyms in public cybersecurity datasets
LABEL_COLUMN_SYNONYMS = [
    "is_phishing", "label", "class", "target", "phishing",
    "status", "result", "verdict", "type", "category"
]

# Standard label mapping for string values
LABEL_VALUE_MAPPINGS = {
    "0": 0, "1": 1, 0: 0, 1: 1,
    "legitimate": 0, "legit": 0, "benign": 0, "safe": 0, "good": 0, "normal": 0,
    "phishing": 1, "phish": 1, "malicious": 1, "bad": 1, "suspicious": 1, "fake": 1,
    True: 1, False: 0, "true": 1, "false": 0,
}


class DatasetPreparer:
    """Validates, cleans, standardizes, and partitions external website datasets."""

    def __init__(self, data_dir: Optional[str] = None):
        self.data_dir = data_dir or DATA_DIR
        self.feature_extractor = FeatureExtractor()
        os.makedirs(self.data_dir, exist_ok=True)

    def load_and_standardize_csv(self, file_path: str) -> pd.DataFrame:
        """
        Load a CSV file, identify label column, extract missing features if needed,
        and validate against the 48-feature canonical schema.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Input dataset file not found: {file_path}")

        print(f"Loading external dataset from: {file_path}")
        df_raw = pd.read_csv(file_path)
        print(f"Raw shape: {df_raw.shape[0]} rows, {df_raw.shape[1]} columns")

        # 1. Identify Target Label Column
        target_col = None
        for col in df_raw.columns:
            if col.strip().lower() in LABEL_COLUMN_SYNONYMS:
                target_col = col
                break

        if target_col is None:
            raise ValueError(
                f"Could not identify target label column in CSV. "
                f"Expected one of: {LABEL_COLUMN_SYNONYMS}. Found columns: {list(df_raw.columns)}"
            )

        # Standardize target values to integer 0 or 1
        y_series = df_raw[target_col].map(
            lambda v: LABEL_VALUE_MAPPINGS.get(str(v).strip().lower() if not isinstance(v, (int, bool)) else v, None)
        )

        if y_series.isnull().any():
            invalid_count = y_series.isnull().sum()
            print(f"Warning: Dropping {invalid_count} rows with unrecognized label values in column '{target_col}'.")
            valid_mask = y_series.notnull()
            df_raw = df_raw[valid_mask].copy()
            y_series = y_series[valid_mask].astype(int)
        else:
            y_series = y_series.astype(int)

        # 2. Check if feature columns are already present or need extraction from 'url'
        missing_features = [col for col in FEATURE_NAMES if col not in df_raw.columns]

        if not missing_features:
            # Pre-extracted dataset
            print("Detected pre-extracted 48-feature dataset.")
            df_features = df_raw[FEATURE_NAMES].copy()
        elif "url" in [c.lower() for c in df_raw.columns]:
            # Raw URLs provided: extract features using FeatureExtractor
            url_col = [c for c in df_raw.columns if c.lower() == "url"][0]
            print(f"Missing {len(missing_features)} features. Extracting features from URL column '{url_col}'...")
            extracted_rows = []
            for url_val in df_raw[url_col]:
                f_dict = self.feature_extractor.extract_features_dict(url=str(url_val))
                extracted_rows.append(f_dict)
            df_features = pd.DataFrame(extracted_rows)[FEATURE_NAMES]
        else:
            raise ValueError(
                f"Dataset is missing required feature columns: {missing_features} and does not contain a 'url' column for extraction."
            )

        # Ensure all feature columns are numeric float32
        for col in FEATURE_NAMES:
            df_features[col] = pd.to_numeric(df_features[col], errors="coerce").astype(np.float32)

        # Attach standardized label
        df_features["is_phishing"] = y_series.values

        return df_features

    def clean_and_validate(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove duplicates and handle missing/infinite values."""
        initial_len = len(df)

        # 1. Remove duplicate feature rows
        df_clean = df.drop_duplicates(subset=FEATURE_NAMES).copy()
        dup_count = initial_len - len(df_clean)
        if dup_count > 0:
            print(f"Removed {dup_count} duplicate rows ({dup_count / initial_len:.2%}). Clean rows: {len(df_clean)}")
        else:
            print("No duplicate rows found.")

        # 2. Check and handle missing/infinite values
        has_nulls = df_clean[FEATURE_NAMES].isnull().any().any()
        has_infs = np.isinf(df_clean[FEATURE_NAMES].values).any()

        if has_nulls or has_infs:
            print("Handling missing/infinite feature values with deterministic column medians...")
            df_clean[FEATURE_NAMES] = df_clean[FEATURE_NAMES].replace([np.inf, -np.inf], np.nan)
            medians = df_clean[FEATURE_NAMES].median().fillna(0.0)
            df_clean[FEATURE_NAMES] = df_clean[FEATURE_NAMES].fillna(medians)

        # 3. Class balance report
        counts = df_clean["is_phishing"].value_counts().to_dict()
        c0 = counts.get(0, 0)
        c1 = counts.get(1, 0)
        total = len(df_clean)
        print(f"\nClass Balance:")
        print(f"  Class 0 (Legitimate): {c0:>6} ({c0 / total:.2%})")
        print(f"  Class 1 (Phishing):   {c1:>6} ({c1 / total:.2%})")

        return df_clean

    def partition_dataset(
        self,
        df: pd.DataFrame,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        eval_ratio: float = 0.15,
        random_state: int = 42,
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Split dataset into strictly separate Train, Validation, and Final Evaluation sets.

        Returns:
            (df_train, df_val, df_eval)
        """
        assert np.isclose(train_ratio + val_ratio + eval_ratio, 1.0), "Split ratios must sum to 1.0"

        y = df["is_phishing"].values

        # Step 1: Split into (Train + Val) and Final Evaluation set
        df_train_val, df_eval = train_test_split(
            df,
            test_size=eval_ratio,
            stratify=y,
            random_state=random_state,
        )

        # Step 2: Split (Train + Val) into Train and Validation set
        val_relative_ratio = val_ratio / (train_ratio + val_ratio)
        y_train_val = df_train_val["is_phishing"].values

        df_train, df_val = train_test_split(
            df_train_val,
            test_size=val_relative_ratio,
            stratify=y_train_val,
            random_state=random_state,
        )

        print("\nDataset 3-Way Partition:")
        print(f"  1. Training Set:         {len(df_train):>6} samples ({len(df_train)/len(df):.1%}) [Legit: {(df_train['is_phishing'] == 0).sum()}, Phish: {(df_train['is_phishing'] == 1).sum()}]")
        print(f"  2. Validation Set:       {len(df_val):>6} samples ({len(df_val)/len(df):.1%}) [Legit: {(df_val['is_phishing'] == 0).sum()}, Phish: {(df_val['is_phishing'] == 1).sum()}]")
        print(f"  3. Final Evaluation Set: {len(df_eval):>6} samples ({len(df_eval)/len(df):.1%}) [Legit: {(df_eval['is_phishing'] == 0).sum()}, Phish: {(df_eval['is_phishing'] == 1).sum()}]")

        return df_train, df_val, df_eval

    def process_and_save(
        self,
        input_csv_path: str,
        output_dir: Optional[str] = None,
        random_state: int = 42,
    ) -> Dict[str, str]:
        """Complete workflow to load, validate, clean, split, and save datasets."""
        out_dir = output_dir or self.data_dir
        os.makedirs(out_dir, exist_ok=True)

        df_standard = self.load_and_standardize_csv(input_csv_path)
        df_clean = self.clean_and_validate(df_standard)

        df_train, df_val, df_eval = self.partition_dataset(df_clean, random_state=random_state)

        # Save partitioned files
        train_path = os.path.join(out_dir, "train.csv")
        val_path = os.path.join(out_dir, "val.csv")
        eval_path = os.path.join(out_dir, "eval_benchmark.csv")
        full_path = os.path.join(out_dir, "dataset.csv")

        df_train.to_csv(train_path, index=False)
        df_val.to_csv(val_path, index=False)
        df_eval.to_csv(eval_path, index=False)
        df_clean.to_csv(full_path, index=False)

        print(f"\nSaved partitioned datasets to:")
        print(f"  - Training:         {train_path}")
        print(f"  - Validation:       {val_path}")
        print(f"  - Final Evaluation: {eval_path}")

        return {
            "train_path": train_path,
            "val_path": val_path,
            "eval_path": eval_path,
            "dataset_path": full_path,
        }


def main():
    parser = argparse.ArgumentParser(description="Prepare and partition external dataset for website classifier.")
    parser.add_argument("--input", "-i", type=str, default=os.path.join(DATA_DIR, "dataset.csv"), help="Path to input CSV dataset.")
    parser.add_argument("--output-dir", "-o", type=str, default=DATA_DIR, help="Destination directory for partitioned datasets.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility.")

    args = parser.parse_args()

    preparer = DatasetPreparer(data_dir=args.output_dir)
    preparer.process_and_save(input_csv_path=args.input, random_state=args.seed)


if __name__ == "__main__":
    main()
