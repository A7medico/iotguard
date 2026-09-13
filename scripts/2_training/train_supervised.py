"""
scripts/2_training/train_supervised.py
-----------------------------------------------------------------------------
IoTGuard Pipeline — State-of-the-Art Supervised Model Training

Key Features:
    - Stratified 5-Fold Cross-Validation for unbiased performance estimation
    - Regularized LightGBM (L1/L2 penalties, shallow depth) to prevent overfitting
    - Platt Probability Calibration (CalibratedClassifierCV) for continuous,
      realistic risk probabilities
    - Out-Of-Fold (OOF) PR-AUC threshold tuning
    - Comprehensive performance reporting (ROC-AUC, PR-AUC, Brier Score, F1)
-----------------------------------------------------------------------------
"""

import os
import json
import argparse
import sys
from pathlib import Path
from datetime import datetime, timezone
import numpy as np
import pandas as pd
import yaml

from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    average_precision_score,
    roc_auc_score,
    brier_score_loss,
    log_loss,
)
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from joblib import dump
import lightgbm as lgb
from lightgbm import LGBMClassifier

# Centralized Path Setup
_scripts_dir = Path(__file__).parent.parent
sys.path.insert(0, str(_scripts_dir))
from path_setup import configure_paths
configure_paths()

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
    df = df.copy()
    df.columns = [c.strip().replace(" ", "_") for c in df.columns]
    return df

def _to_binary_labels(series: pd.Series) -> np.ndarray:
    if series.dtype == np.number or np.issubdtype(series.dtype, np.number):
        return series.astype(int).to_numpy()
    s = series.astype(str)
    return (s.str.lower() != "benign").astype(int).to_numpy()

def pick_best_threshold(y_true: np.ndarray, y_prob: np.ndarray):
    """
    Choose threshold maximizing F1 on PR curve, and return PR-AUC.
    Caps at 0.90 for practical, balanced real-world operations.
    """
    pr_auc = float(average_precision_score(y_true, y_prob))
    prec, rec, thr = precision_recall_curve(y_true, y_prob)
    f1 = (2 * prec[:-1] * rec[:-1]) / (prec[:-1] + rec[:-1] + 1e-12)
    best_idx = int(np.nanargmax(f1))
    best_thr = float(thr[best_idx])
    
    # Cap threshold between 0.65 and 0.90 for balanced real-world performance
    best_thr = max(0.65, min(0.90, best_thr))
    return best_thr, pr_auc

def main():
    ap = argparse.ArgumentParser(description="Train LightGBM IDS with 5-Fold CV & Probability Calibration.")
    ap.add_argument("--csv", required=True, help="Path to merged CSV (features + 'label').")
    ap.add_argument("--random-state", type=int, default=42, help="Random seed.")
    ap.add_argument("--model-out", default=None, help="Path to save model.")
    ap.add_argument("--meta-out", default=None, help="Path to save meta JSON.")
    ap.add_argument("--model-type", default="iot", choices=["iot", "it"], help="Model type (iot or it).")
    
    # Regularization & Architecture defaults (SOTA Tabular Settings)
    ap.add_argument("--learning-rate", type=float, default=0.05)
    ap.add_argument("--n-estimators", type=int, default=200)
    ap.add_argument("--num-leaves", type=int, default=16, help="Constrained leaves to prevent overfitting.")
    ap.add_argument("--max-depth", type=int, default=5, help="Shallow tree depth for generalization.")
    ap.add_argument("--min-child-samples", type=int, default=80, help="Min samples per leaf.")
    ap.add_argument("--subsample", type=float, default=0.80)
    ap.add_argument("--colsample-bytree", type=float, default=0.80)
    ap.add_argument("--reg-alpha", type=float, default=2.0, help="L1 regularization penalty.")
    ap.add_argument("--reg-lambda", type=float, default=5.0, help="L2 regularization penalty.")
    ap.add_argument("--calibrate", action="store_true", default=True, help="Apply Platt probability calibration.")
    args = ap.parse_args()

    # Resolve paths based on model type
    if not args.model_out or not args.meta_out:
        models_cfg = _CFG.get("models", {})
        type_cfg = models_cfg.get(args.model_type, {})
        if not args.model_out:
            args.model_out = type_cfg.get("path", f"models/lightgbm{'_it' if args.model_type == 'it' else ''}.joblib")
        if not args.meta_out:
            args.meta_out = type_cfg.get("meta", f"models/model_meta{'_it' if args.model_type == 'it' else ''}.json")

    print("=" * 75)
    print(f"  [+] IoTGuard Model Training Pipeline [{args.model_type.upper()} Mode]")
    print(f"     Target Model: {args.model_out}")
    print(f"     Target Meta:  {args.meta_out}")
    print("=" * 75)

    # 1. Load & Preprocess Data
    df = pd.read_csv(args.csv)
    df = _normalize_columns(df)
    
    if "label" not in df.columns:
        raise ValueError("Training CSV must contain a 'label' column.")

    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    
    feat_cols = _FEATURES_CFG if _FEATURES_CFG else [c for c in df.columns if c != "label"]
    X = df[feat_cols].to_numpy(dtype=np.float32)
    y = _to_binary_labels(df["label"])

    n_samples = len(y)
    n_pos = int(y.sum())
    n_neg = n_samples - n_pos
    print(f"\n[*] Dataset: {n_samples:,} samples | {len(feat_cols)} features")
    print(f"    - Benign (0): {n_neg:,} ({n_neg/n_samples*100:.1f}%)")
    print(f"    - Attack (1): {n_pos:,} ({n_pos/n_samples*100:.1f}%)")

    # 2. Stratified 5-Fold Cross Validation
    n_splits = 5
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=args.random_state)
    
    oof_predictions = np.zeros(n_samples, dtype=np.float32)
    fold_aucs = []
    fold_praucs = []
    fold_briers = []

    print(f"\n[*] Running Stratified {n_splits}-Fold Cross-Validation...")
    print("-" * 75)

    base_lgbm = LGBMClassifier(
        objective="binary",
        learning_rate=args.learning_rate,
        n_estimators=args.n_estimators,
        num_leaves=args.num_leaves,
        max_depth=args.max_depth,
        min_child_samples=args.min_child_samples,
        subsample=args.subsample,
        colsample_bytree=args.colsample_bytree,
        reg_alpha=args.reg_alpha,
        reg_lambda=args.reg_lambda,
        class_weight="balanced",
        n_jobs=-1,
        verbose=-1,
        random_state=args.random_state,
    )

    for fold, (train_idx, val_idx) in enumerate(skf.split(X, y), 1):
        X_tr, y_tr = X[train_idx], y[train_idx]
        X_va, y_va = X[val_idx], y[val_idx]
        
        # Train fold model
        fold_model = LGBMClassifier(**base_lgbm.get_params())
        fold_model.fit(X_tr, y_tr)
        
        # Predict validation probabilities
        val_probs = fold_model.predict_proba(X_va)[:, 1]
        oof_predictions[val_idx] = val_probs
        
        # Compute fold metrics
        roc = roc_auc_score(y_va, val_probs)
        prauc = average_precision_score(y_va, val_probs)
        brier = brier_score_loss(y_va, val_probs)
        
        fold_aucs.append(roc)
        fold_praucs.append(prauc)
        fold_briers.append(brier)
        
        print(f"  Fold {fold}/{n_splits}: ROC-AUC = {roc:.4f} | PR-AUC = {prauc:.4f} | Brier = {brier:.4f}")

    # 3. Overall Cross-Validation Performance
    mean_roc = float(np.mean(fold_aucs))
    mean_prauc = float(np.mean(fold_praucs))
    mean_brier = float(np.mean(fold_briers))
    best_thr, _ = pick_best_threshold(y, oof_predictions)
    
    print("-" * 75)
    print(f"  [+] 5-Fold OOF Mean ROC-AUC:  {mean_roc:.4f} (+/- {np.std(fold_aucs):.4f})")
    print(f"  [+] 5-Fold OOF Mean PR-AUC:   {mean_prauc:.4f} (+/- {np.std(fold_praucs):.4f})")
    print(f"  [+] 5-Fold Mean Brier Score:  {mean_brier:.4f} (Lower = Better Probability Calibration)")
    print(f"  [+] Tuned Decision Threshold: {best_thr:.3f}")

    # Evaluate classification report on Out-Of-Fold predictions
    oof_binary = (oof_predictions >= best_thr).astype(int)
    cm = confusion_matrix(y, oof_binary)
    cr = classification_report(y, oof_binary, target_names=["Benign", "Attack"], digits=4)
    
    print("\n[+] Out-Of-Fold Confusion Matrix:")
    print(f"    [[TN: {cm[0,0]:<6}  FP: {cm[0,1]:<6}]")
    print(f"     [FN: {cm[1,0]:<6}  TP: {cm[1,1]:<6}]]")
    print(f"\n[+] Out-Of-Fold Classification Report (at threshold {best_thr:.3f}):\n{cr}")

    # 4. Train Final Model on Full Dataset with Probability Calibration
    print("[*] Training final calibrated production model on 100% of dataset...")
    final_lgbm = LGBMClassifier(**base_lgbm.get_params())
    
    if args.calibrate:
        # 5-fold cross-validated probability calibration
        final_model = CalibratedClassifierCV(
            estimator=final_lgbm,
            method="sigmoid",
            cv=5
        )
        final_model.fit(X, y)
    else:
        final_model = final_lgbm
        final_model.fit(X, y)

    # 5. Save Model & Comprehensive Metadata
    out_model_path = Path(args.model_out)
    out_meta_path = Path(args.meta_out)
    
    out_model_path.parent.mkdir(parents=True, exist_ok=True)
    out_meta_path.parent.mkdir(parents=True, exist_ok=True)
    
    dump(final_model, out_model_path)
    print(f"\n[OK] Saved Calibrated Model -> {out_model_path}")

    meta = {
        "threshold": float(best_thr),
        "features": feat_cols,
        "label_positive": 1,
        "label_negative": 0,
        "csv_path": str(args.csv),
        "model_version": "2.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "model_type": "LightGBM + Platt Calibration (5-Fold CV)",
        "roc_auc": round(mean_roc, 4),
        "pr_auc": round(mean_prauc, 4),
        "brier_score": round(mean_brier, 4),
        "train_samples": n_samples,
        "n_splits": n_splits,
        "regularization": {
            "max_depth": args.max_depth,
            "num_leaves": args.num_leaves,
            "reg_alpha": args.reg_alpha,
            "reg_lambda": args.reg_lambda,
            "min_child_samples": args.min_child_samples
        },
        "description": f"IoTGuard calibrated {args.model_type.upper()} classifier for intrusion detection"
    }

    out_meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[OK] Saved Model Metadata   -> {out_meta_path}")
    print("=" * 75)

if __name__ == "__main__":
    main()
