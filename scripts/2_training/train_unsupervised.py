"""
scripts/train_unsupervised.py
-----------------------------------------------------------------------------
IoTGuard Pipeline — Offline Unsupervised / One-Class Model Training

Position in pipeline
    Raw / converted IoT CSVs
        →  create_train_test_split.py  (clean + dedup + leakage‑safe)
        →  data/iotguard_training_clean.csv
        →  [THIS FILE]  (unsupervised / one-class training + threshold tuning)
        →  models/unsup_isoforest.joblib + models/unsup_meta.json
        →  decision_loop.py (optional alternative scoring backend)

High‑level responsibilities
    - Load a merged CSV of IoT flows (ideally with a `label` column).
    - Normalize column names and select the numeric features defined in
      `configs/model.yaml:features` so training and streaming stay aligned.
    - Train a one-class / anomaly detection model (IsolationForest) primarily
      on **benign** traffic (semi-supervised).
    - Compute an anomaly score for each sample (higher = more anomalous).
    - If labels are available, optionally tune a decision threshold on these
      scores to maximize F1 for attacks vs benign.
      Otherwise fall back to a high quantile of benign scores.
    - Save:
          models/unsup_isoforest.joblib  — the trained IsolationForest model,
          models/unsup_meta.json         — feature order, tuned threshold, and CSV path.

This script is run offline during experimentation; at runtime the decision loop
can load the saved model + meta as an alternative to the supervised model.
-----------------------------------------------------------------------------
"""

import os
import json
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import yaml
from joblib import dump
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    average_precision_score,
)

import sys
# Add scripts directory and subdirectories to path for imports
_scripts_dir = Path(__file__).parent.parent
sys.path.insert(0, str(_scripts_dir))
from path_setup import configure_paths
configure_paths()

from utils_common import make_binary_labels


# ---------- Config / global defaults ----------
CFG_PATH = Path("configs/model.yaml")


def _load_yaml_cfg() -> dict:
    """Load configs/model.yaml if present; otherwise return {}."""
    try:
        if CFG_PATH.exists():
            return yaml.safe_load(CFG_PATH.read_text(encoding="utf-8")) or {}
    except Exception:
        pass
    return {}


_CFG = _load_yaml_cfg()
_FEATURES_CFG = list(_CFG.get("features") or [])
_UNSUP_CFG = dict(_CFG.get("unsupervised") or {})


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize column names (strip + replace spaces) to be robust to CSV quirks."""
    df = df.copy()
    df.columns = [c.strip().replace(" ", "_") for c in df.columns]
    return df


def _pick_features(df: pd.DataFrame) -> list[str]:
    """
    Choose feature columns for training.

    Prefer the explicit `features:` schema from configs/model.yaml so that
    unsupervised training stays aligned with both supervised training and
    the online decision loop.
    """
    if _FEATURES_CFG:
        missing = [c for c in _FEATURES_CFG if c not in df.columns]
        if missing:
            raise ValueError(
                f"Training CSV is missing expected feature columns from configs/model.yaml: {missing}"
            )
        return [c for c in _FEATURES_CFG if c in df.columns]

    # Fallback: all numeric columns except 'label'
    feat_cols = [c for c in df.columns if c != "label"]
    feat_cols = [c for c in feat_cols if pd.api.types.is_numeric_dtype(df[c])]
    return feat_cols


def _pick_threshold_from_scores(
    scores: np.ndarray,
    y_true: np.ndarray | None = None,
    fallback_quantile: float = 0.99,
) -> tuple[float, float | None]:
    """
    Determine a decision threshold for anomaly scores.

    - scores: array of anomaly scores where **higher = more anomalous**.
    - y_true: optional binary labels (0 = benign, 1 = attack).
    - If y_true is provided and has at least one positive and one negative,
      choose threshold that maximizes F1 on the PR curve and return (thr, pr_auc).
    - Otherwise, fall back to the specified quantile of the scores and
      return (thr, None).
    """
    scores = np.asarray(scores, dtype=float)

    if y_true is not None:
        y_true = np.asarray(y_true, dtype=int)
        pos = int(y_true.sum())
        neg = int((y_true == 0).sum())
        if pos > 0 and neg > 0:
            pr_auc = float(average_precision_score(y_true, scores))
            prec, rec, thr = precision_recall_curve(y_true, scores)
            # precision_recall_curve returns len(thr) = len(prec) - 1
            f1 = (2 * prec[:-1] * rec[:-1]) / (prec[:-1] + rec[:-1] + 1e-12)
            best_idx = int(np.nanargmax(f1))
            best_thr = float(thr[best_idx])
            return best_thr, pr_auc

    # Fallback: high-quantile threshold (e.g., 99% of benign should be below)
    q = float(np.quantile(scores, fallback_quantile))
    return q, None


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Train an unsupervised / one-class anomaly detector (IsolationForest)."
    )
    ap.add_argument(
        "--csv",
        required=True,
        help="Path to merged CSV (features + optional 'label').",
    )
    ap.add_argument(
        "--model-out",
        default="models/unsup_isoforest.joblib",
        help="Path to save unsupervised model.",
    )
    ap.add_argument(
        "--meta-out",
        default="models/unsup_meta.json",
        help="Path to save meta JSON (features, threshold, etc.).",
    )
    ap.add_argument(
        "--train-on",
        choices=["benign_only", "all"],
        default=str(_UNSUP_CFG.get("train_on", "benign_only")),
        help="Whether to fit the model only on benign rows (recommended) or on all data.",
    )
    ap.add_argument(
        "--contamination",
        type=float,
        default=float(_UNSUP_CFG.get("contamination", 0.05)),
        help="Expected proportion of anomalies in the training data (IsolationForest).",
    )
    ap.add_argument(
        "--n-estimators",
        type=int,
        default=int(_UNSUP_CFG.get("n_estimators", 200)),
        help="Number of base estimators (trees) for IsolationForest.",
    )
    ap.add_argument(
        "--max-samples",
        type=float,
        default=float(_UNSUP_CFG.get("max_samples", 1.0)),
        help="Max samples per tree (float in (0,1] as fraction, or int).",
    )
    ap.add_argument(
        "--random-state",
        type=int,
        default=int(_UNSUP_CFG.get("random_state", 42)),
        help="Random seed.",
    )
    ap.add_argument(
        "--fallback-quantile",
        type=float,
        default=float(_UNSUP_CFG.get("fallback_quantile", 0.99)),
        help="Quantile for threshold when labels are not available (0-1).",
    )
    args = ap.parse_args()

    # ---------- Load ----------
    df = pd.read_csv(args.csv)
    df = _normalize_columns(df)

    # ---------- Robust Input Validation ----------
    # Check for empty dataset
    if len(df) == 0:
        raise ValueError("Empty training dataset. CSV has no data rows.")
    
    # Check for minimum sample count
    MIN_SAMPLES = 50
    if len(df) < MIN_SAMPLES:
        print(f"[WARNING] Very small dataset ({len(df)} samples). Consider gathering more data.")
    
    # Check for missing values and handle them
    missing_counts = df.isnull().sum()
    if missing_counts.any():
        missing_cols = missing_counts[missing_counts > 0]
        print(f"[WARNING] Columns with missing values:\n{missing_cols}")
        df = df.dropna()
        print(f"   -> After dropping NaN rows: {len(df)} samples remaining")
    
    # Check for infinite values
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    inf_mask = np.isinf(df[numeric_cols]).any()
    if inf_mask.any():
        inf_cols = inf_mask[inf_mask].index.tolist()
        print(f"[WARNING] Columns with infinite values: {inf_cols}")
        df = df.replace([np.inf, -np.inf], np.nan).dropna()
        print(f"   -> After handling inf values: {len(df)} samples remaining")

    # ---------- Feature selection ----------
    feat_cols = _pick_features(df)
    X_all = df[feat_cols].to_numpy(dtype=np.float32)

    # ---------- Labels (optional, for evaluation / threshold tuning) ----------
    y_bin = None
    if "label" in df.columns:
        y_bin = make_binary_labels(df, label_col="label").to_numpy(dtype=int)

    # ---------- Choose training subset ----------
    if args.train_on == "benign_only" and y_bin is not None:
        mask_benign = (y_bin == 0)
        if not mask_benign.any():
            print(
                "[!] No benign samples found; falling back to training on all rows."
            )
            X_train = X_all
        else:
            X_train = X_all[mask_benign]
            print(
                f"[*] Training on benign-only subset: {int(mask_benign.sum())} / {len(y_bin)} rows."
            )
    else:
        X_train = X_all
        print("[*] Training on all rows (unsupervised).")

    # Additional robustness check: ensure we have enough samples
    if len(X_train) < 20:
        print("[WARNING] Very few training samples. IsolationForest may not perform well.")

    print(
        f"   Samples (train): {len(X_train)} | Features: {len(feat_cols)} | CSV rows (all): {len(X_all)}"
    )

    # ---------- Model ----------
    iso = IsolationForest(
        n_estimators=args.n_estimators,
        max_samples=args.max_samples,
        contamination=args.contamination,
        random_state=args.random_state,
        n_jobs=-1,
    )

    print("[*] Fitting IsolationForest...")
    iso.fit(X_train)

    # ---------- Scores & threshold ----------
    # IsolationForest.score_samples: higher score = less abnormal.
    # We invert so that higher score = more anomalous, similar to P(attack).
    raw_scores = iso.score_samples(X_all)
    anomaly_scores = -raw_scores

    best_thr, pr_auc = _pick_threshold_from_scores(
        anomaly_scores,
        y_true=y_bin,
        fallback_quantile=args.fallback_quantile,
    )

    print(f"[*] Chosen anomaly threshold: {best_thr:.4f}")
    if pr_auc is not None and y_bin is not None:
        print(f"PR-AUC (unsup scores vs labels): {pr_auc:.4f}")
        yhat = (anomaly_scores >= best_thr).astype(int)
        cm = confusion_matrix(y_bin, yhat)
        cr = classification_report(y_bin, yhat, digits=4)
        print("Confusion @thr:\n", cm)
        print("\nReport @thr:\n", cr)

    # ---------- Save ----------
    os.makedirs(os.path.dirname(args.model_out), exist_ok=True)
    dump(iso, args.model_out)

    meta = {
        "algorithm": "IsolationForest",
        "features": feat_cols,
        "threshold": float(best_thr),
        "contamination": float(args.contamination),
        "train_on": args.train_on,
        "csv_path": args.csv,
        "score_higher_is_anomalous": True,
        "fallback_quantile": float(args.fallback_quantile),
    }
    with open(args.meta_out, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"Saved unsupervised model -> {args.model_out}")
    print(f"Saved meta              -> {args.meta_out}")


if __name__ == "__main__":
    main()




