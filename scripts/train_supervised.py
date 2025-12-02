"""
scripts/train_supervised.py
-----------------------------------------------------------------------------
IoTGuard Pipeline — Offline Supervised Model Training

Position in pipeline
    Raw / converted IoT CSVs
        →  create_train_test_split.py  (clean + dedup + leakage‑safe)
        →  data/iotguard_training_clean.csv
        →  [THIS FILE]  (supervised training + threshold tuning)
        →  models/lightgbm.joblib + models/model_meta.json
        →  decision_loop.py / test_holdout.py

High‑level responsibilities
    - Load a merged, cleaned CSV of IoT flows (with a `label` column).
    - Normalize column names and select the final numeric features used by the model.
      By default this is the `features:` list in configs/model.yaml so training and
      streaming stay perfectly aligned.
    - Convert labels to **binary**:
          benign → 0
          anything else → 1.
    - Split into train/validation sets with stratification.
    - Train a LightGBM binary classifier with early stopping, logging binary_logloss.
    - Compute:
          ROC‑AUC on the validation split,
          PR‑AUC using average_precision_score (never negative),
          a best operating threshold that maximizes F1 on the PR curve
          (with a safety cap so the threshold doesn’t go to 1.0).
    - Save:
          models/lightgbm.joblib       — the trained classifier,
          models/model_meta.json       — the exact feature order, tuned threshold, and CSV path.

This script is run offline during experimentation; at runtime the decision loop only loads the saved model + meta.
-----------------------------------------------------------------------------
"""

import os, json, argparse
from pathlib import Path
from datetime import datetime, timezone
import numpy as np
import pandas as pd
import yaml

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    average_precision_score,
    roc_auc_score,
)

from joblib import dump
import lightgbm as lgb
from lightgbm import LGBMClassifier


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
_LGBM_CFG = dict(_CFG.get("lgbm") or {})
_FEATURES_CFG = list(_CFG.get("features") or [])

def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    # LightGBM warns about spaces; normalize once and keep the same order.
    df = df.copy()
    df.columns = [c.strip().replace(" ", "_") for c in df.columns]
    return df


def _to_binary_labels(series: pd.Series) -> np.ndarray:
    """
    Map multi-class 'label' to binary:
       benign -> 0
       anything else -> 1
    Accepts strings or already-binary.
    """
    if series.dtype == np.number or np.issubdtype(series.dtype, np.number):
        # Already numeric (assume 0/1)
        return series.astype(int).to_numpy()

    s = series.astype(str)
    return (s.str.lower() != "benign").astype(int).to_numpy()


def pick_best_threshold(y_true: np.ndarray, y_prob: np.ndarray):
    """
    Choose threshold maximizing F1 on PR curve, and return PR-AUC.
    Uses robust average_precision_score for PR-AUC (non-negative).
    """
    pr_auc = float(average_precision_score(y_true, y_prob))

    prec, rec, thr = precision_recall_curve(y_true, y_prob)
    # precision_recall_curve returns len(thr) = len(prec) - 1
    f1 = (2 * prec[:-1] * rec[:-1]) / (prec[:-1] + rec[:-1] + 1e-12)
    best_idx = int(np.nanargmax(f1))
    best_thr = float(thr[best_idx])
    # Cap threshold at 0.95 for practical use (avoid overconfidence at 1.0)
    if best_thr >= 0.99:
        # If threshold is too high, use 0.95 for better real-world performance
        best_thr = 0.95
    return best_thr, pr_auc


def main():
    ap = argparse.ArgumentParser(description="Train LightGBM IDS (binary).")
    ap.add_argument("--csv", required=True, help="Path to merged CSV (features + 'label').")
    ap.add_argument("--test-size", type=float, default=0.2, help="Validation split fraction.")
    ap.add_argument("--random-state", type=int, default=42, help="Random seed.")
    ap.add_argument("--model-out", default=None, help="Path to save model (defaults to config based on type).")
    ap.add_argument("--meta-out", default=None, help="Path to save meta JSON (defaults to config based on type).")
    ap.add_argument("--model-type", default="iot", choices=["iot", "it"], help="Model type to train (iot or it).")
    # Hyperparameter defaults are taken from configs/model.yaml:lgbm when available
    ap.add_argument(
        "--learning-rate",
        type=float,
        default=float(_LGBM_CFG.get("learning_rate", 0.05)),
    )
    ap.add_argument(
        "--n-estimators",
        type=int,
        default=int(_LGBM_CFG.get("n_estimators", 2000)),
    )
    ap.add_argument(
        "--num-leaves",
        type=int,
        default=int(_LGBM_CFG.get("num_leaves", 63)),
    )
    ap.add_argument("--max-depth", type=int, default=-1)
    ap.add_argument("--min-data-in-leaf", type=int, default=50)
    ap.add_argument(
        "--subsample",
        type=float,
        default=float(_LGBM_CFG.get("subsample", 0.8)),
    )
    ap.add_argument(
        "--colsample-bytree",
        type=float,
        default=float(_LGBM_CFG.get("colsample_bytree", 0.8)),
    )
    ap.add_argument("--early-stopping-rounds", type=int, default=200)
    ap.add_argument("--eval-every", type=int, default=200, help="Log eval every N rounds.")
    args = ap.parse_args()

    # Resolve paths based on model type if not provided
    if not args.model_out or not args.meta_out:
        models_cfg = _CFG.get("models", {})
        type_cfg = models_cfg.get(args.model_type, {})
        
        if not args.model_out:
            args.model_out = type_cfg.get("path", "models/lightgbm.joblib")
            
        if not args.meta_out:
            args.meta_out = type_cfg.get("meta", "models/model_meta.json")

    print(f"[*] Training '{args.model_type}' model -> {args.model_out}")

    # ---------- Load ----------
    df = pd.read_csv(args.csv)
    df = _normalize_columns(df)

    if "label" not in df.columns:
        raise ValueError("CSV must contain a 'label' column.")

    # ---------- Feature selection ----------
    # Prefer the explicit schema from configs/model.yaml so it matches inference.
    if _FEATURES_CFG:
        missing = [c for c in _FEATURES_CFG if c not in df.columns]
        if missing:
            raise ValueError(
                f"Training CSV is missing expected feature columns from configs/model.yaml: {missing}"
            )
        feat_cols = [c for c in _FEATURES_CFG if c in df.columns]
    else:
        # Fallback: all numeric except label, dropping deprecated fields.
        feat_cols = [c for c in df.columns if c != "label"]
        drop_cols = ["uniq_src", "uniq_dst"]
        feat_cols = [c for c in feat_cols if c not in drop_cols]
        feat_cols = [c for c in feat_cols if pd.api.types.is_numeric_dtype(df[c])]

    X = df[feat_cols].to_numpy(dtype=np.float32)
    y = _to_binary_labels(df["label"])

    n_pos = int(y.sum())
    n_all = len(y)
    print("[*] Loading training data...")
    print(f"   rows: {n_all} columns: {df.shape[1]}")
    print(f"   Samples: {n_all} | Features: {len(feat_cols)} | Positives: {n_pos} ({100.0*n_pos/n_all:.2f}%)")

    # ---------- Split ----------
    Xtr, Xva, ytr, yva = train_test_split(
        X, y, test_size=args.test_size, random_state=args.random_state, stratify=y
    )

    # ---------- Model ----------
    clf = LGBMClassifier(
        objective="binary",
        learning_rate=args.learning_rate,
        n_estimators=args.n_estimators,
        num_leaves=args.num_leaves,
        max_depth=args.max_depth,
        min_child_samples=args.min_data_in_leaf,
        subsample=args.subsample,
        colsample_bytree=args.colsample_bytree,
        class_weight="balanced",  # handle imbalance robustly
        n_jobs=-1,
        verbose=-1,
    )

    # Early stopping that works across LightGBM versions:
    callbacks = [
        lgb.early_stopping(stopping_rounds=args.early_stopping_rounds, verbose=False),
        lgb.log_evaluation(period=args.eval_every),
    ]

    print("[*] Training model...")
    clf.fit(
        Xtr, ytr,
        eval_set=[(Xva, yva)],
        eval_metric="binary_logloss",
        callbacks=callbacks
    )

    # ---------- Validation ----------
    pva = clf.predict_proba(Xva)[:, 1]
    roc = roc_auc_score(yva, pva)
    print(f"ROC-AUC (val): {roc:.4f}")

    best_thr, pr_auc = pick_best_threshold(yva, pva)
    print(f"\nPR-AUC (val): {pr_auc:.4f} | best_thr: {best_thr:.3f}")

    yhat = (pva >= best_thr).astype(int)

    cm = confusion_matrix(yva, yhat)
    cr = classification_report(yva, yhat, digits=4)
    print("Confusion @best_thr:\n", cm)
    print("\nReport @best_thr:\n", cr)

    # ---------- Save ----------
    os.makedirs(os.path.dirname(args.model_out), exist_ok=True)
    dump(clf, args.model_out)

    # Load existing meta to preserve version if it exists, else start at 1.0.0
    existing_version = "1.0.0"
    try:
        if Path(args.meta_out).exists():
            old_meta = json.loads(Path(args.meta_out).read_text(encoding="utf-8"))
            if "model_version" in old_meta:
                # Bump patch version
                parts = old_meta["model_version"].split(".")
                parts[-1] = str(int(parts[-1]) + 1)
                existing_version = ".".join(parts)
    except Exception:
        pass

    meta = {
        "threshold": best_thr,
        "features": feat_cols,  # preserve exact training order
        "label_positive": 1,
        "label_negative": 0,
        "csv_path": args.csv,
        "model_version": existing_version,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "model_type": "LightGBM",
        "roc_auc": round(roc, 4),
        "pr_auc": round(pr_auc, 4),
        "train_samples": len(ytr),
        "val_samples": len(yva),
        "description": "IoTGuard binary classifier for IoT intrusion detection"
    }
    with open(args.meta_out, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"Saved model   -> {args.model_out}")
    print(f"Saved meta    -> {args.meta_out}")


if __name__ == "__main__":
    main()
