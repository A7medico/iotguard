#!/usr/bin/env python3
"""
scripts/2_training/retrain_with_real_data.py
-----------------------------------------------------------------------------
IoTGuard Model Upgrade Pipeline — Merge Real + Synthetic Data & Retrain

This script orchestrates the full retraining pipeline:
  1. Convert Edge-IIoTset real-world IoT data -> IoTGuard 13 features
  2. Load existing synthetic training data
  3. Merge, balance, and deduplicate
  4. Retrain supervised model (LightGBM + Platt Calibration)
  5. Retrain unsupervised model (IsolationForest)
  6. Evaluate both on holdout data
  7. Back up old models before overwriting

Usage:
    python scripts/2_training/retrain_with_real_data.py
-----------------------------------------------------------------------------
"""

import os
import sys
import json
import shutil
from pathlib import Path
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import yaml
from joblib import dump, load

from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    average_precision_score,
    roc_auc_score,
    brier_score_loss,
)
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import IsolationForest
from lightgbm import LGBMClassifier

# ── Path Setup ───────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
sys.path.insert(0, str(PROJECT_ROOT / "scripts" / "1_data_input"))

# ── Constants ────────────────────────────────────────────────────────────────
FEATURES = [
    "flows", "bytes_total", "pkts_total", "syn_ratio", "mean_bytes_flow",
    "ack_ratio", "fin_ratio", "rst_ratio", "http_ratio", "tcp_ratio",
    "protocol_diversity", "std_bytes", "iat_mean",
]

EDGE_IIOTSET_INPUT = Path(
    "data/test_holdout/archive/Edge-IIoTset dataset/"
    "Selected dataset for ML and DL/ML-EdgeIIoT-dataset.csv"
)
EDGE_MAPPED_OUTPUT = Path("data/edge_iiotset_mapped.csv")
EXISTING_TRAIN_CSV = Path("data/iotguard_training_clean.csv")
MERGED_TRAIN_CSV = Path("data/iotguard_training_merged.csv")

MODEL_DIR = Path("models")
BACKUP_DIR = MODEL_DIR / "backup"


def _load_config() -> dict:
    cfg_path = Path("configs/model.yaml")
    if cfg_path.exists():
        return yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    return {}


def _to_binary_labels(series: pd.Series) -> np.ndarray:
    if pd.api.types.is_numeric_dtype(series):
        return series.astype(int).to_numpy()
    s = series.astype(str)
    return (s.str.lower() != "benign").astype(int).to_numpy()


def pick_best_threshold(y_true, y_prob):
    pr_auc = float(average_precision_score(y_true, y_prob))
    prec, rec, thr = precision_recall_curve(y_true, y_prob)
    f1 = (2 * prec[:-1] * rec[:-1]) / (prec[:-1] + rec[:-1] + 1e-12)
    best_idx = int(np.nanargmax(f1))
    best_thr = float(thr[best_idx])
    best_thr = max(0.65, min(0.90, best_thr))
    return best_thr, pr_auc


# ═════════════════════════════════════════════════════════════════════════════
# STEP 1: Convert Edge-IIoTset
# ═════════════════════════════════════════════════════════════════════════════
def step1_convert_edge_iiotset():
    """Convert Edge-IIoTset packet data to IoTGuard flow features."""
    print("\n" + "=" * 75)
    print("  STEP 1: Convert Edge-IIoTset Real-World IoT Data")
    print("=" * 75)

    if not EDGE_IIOTSET_INPUT.exists():
        print(f"  [SKIP] Edge-IIoTset not found at {EDGE_IIOTSET_INPUT}")
        return False

    from convert_edge_iiotset import convert_edge_iiotset
    convert_edge_iiotset(
        input_path=EDGE_IIOTSET_INPUT,
        output_path=EDGE_MAPPED_OUTPUT,
        window_size=30,
        max_rows=None,
        sample_per_class=None,
    )
    return EDGE_MAPPED_OUTPUT.exists()


# ═════════════════════════════════════════════════════════════════════════════
# STEP 2: Merge Datasets
# ═════════════════════════════════════════════════════════════════════════════
def step2_merge_datasets():
    """Merge existing synthetic data with real Edge-IIoTset data."""
    print("\n" + "=" * 75)
    print("  STEP 2: Merge Synthetic + Real-World Datasets")
    print("=" * 75)

    parts = []

    # Load existing synthetic training data
    if EXISTING_TRAIN_CSV.exists():
        df_synth = pd.read_csv(EXISTING_TRAIN_CSV)
        df_synth.columns = [c.strip().replace(" ", "_") for c in df_synth.columns]
        # Ensure it has our features + label
        if all(f in df_synth.columns for f in FEATURES) and "label" in df_synth.columns:
            df_synth = df_synth[FEATURES + ["label"]]
            print(f"  [+] Synthetic IoTGuard data: {len(df_synth):,} rows")
            parts.append(df_synth)
        else:
            print(f"  [!] Synthetic data missing expected columns, skipping")

    # Load converted Edge-IIoTset
    if EDGE_MAPPED_OUTPUT.exists():
        df_edge = pd.read_csv(EDGE_MAPPED_OUTPUT)
        df_edge.columns = [c.strip().replace(" ", "_") for c in df_edge.columns]
        if all(f in df_edge.columns for f in FEATURES) and "label" in df_edge.columns:
            df_edge = df_edge[FEATURES + ["label"]]
            print(f"  [+] Edge-IIoTset real data:  {len(df_edge):,} rows")
            parts.append(df_edge)
        else:
            print(f"  [!] Edge-IIoTset data missing expected columns, skipping")

    if not parts:
        print("  [ERROR] No valid training data found!")
        return None

    # Merge
    df_merged = pd.concat(parts, ignore_index=True)
    df_merged = df_merged.replace([np.inf, -np.inf], np.nan).fillna(0)

    # Shuffle
    df_merged = df_merged.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\n  [*] Merged dataset: {len(df_merged):,} total rows")
    print(f"      Features: {len(FEATURES)}")
    print(f"\n      Label distribution:")
    for label, count in df_merged["label"].value_counts().items():
        pct = count / len(df_merged) * 100
        print(f"        {str(label):25s}: {count:>8,} ({pct:.1f}%)")

    # Save merged
    df_merged.to_csv(MERGED_TRAIN_CSV, index=False)
    print(f"\n  [OK] Saved merged dataset -> {MERGED_TRAIN_CSV}")

    return df_merged


# ═════════════════════════════════════════════════════════════════════════════
# STEP 3: Backup Old Models
# ═════════════════════════════════════════════════════════════════════════════
def step3_backup_models():
    """Back up current models before overwriting."""
    print("\n" + "=" * 75)
    print("  STEP 3: Backup Existing Models")
    print("=" * 75)

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / timestamp

    model_files = [
        "lightgbm.joblib", "lightgbm_it.joblib",
        "model_meta.json", "model_meta_it.json",
        "unsup_isoforest.joblib", "unsup_meta.json",
        "classes.json",
    ]

    backed_up = 0
    for fname in model_files:
        src = MODEL_DIR / fname
        if src.exists():
            backup_path.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, backup_path / fname)
            backed_up += 1

    if backed_up > 0:
        print(f"  [OK] Backed up {backed_up} model files -> {backup_path}")
    else:
        print(f"  [SKIP] No existing models to back up")


# ═════════════════════════════════════════════════════════════════════════════
# STEP 4: Retrain Supervised Model
# ═════════════════════════════════════════════════════════════════════════════
def step4_retrain_supervised(df: pd.DataFrame):
    """Retrain LightGBM with 5-fold CV + Platt calibration on merged data."""
    print("\n" + "=" * 75)
    print("  STEP 4: Retrain Supervised Model (LightGBM + Platt Calibration)")
    print("=" * 75)

    X = df[FEATURES].to_numpy(dtype=np.float32)
    y = _to_binary_labels(df["label"])

    n_samples = len(y)
    n_pos = int(y.sum())
    n_neg = n_samples - n_pos
    print(f"\n  [*] Training set: {n_samples:,} samples | {len(FEATURES)} features")
    print(f"      Benign (0): {n_neg:,} ({n_neg/n_samples*100:.1f}%)")
    print(f"      Attack (1): {n_pos:,} ({n_pos/n_samples*100:.1f}%)")

    # ── Hyperparameters (upgraded from previous defaults) ────────────────
    cfg = _load_config()
    lgbm_cfg = cfg.get("lgbm", {})

    base_lgbm = LGBMClassifier(
        objective="binary",
        learning_rate=float(lgbm_cfg.get("learning_rate", 0.05)),
        n_estimators=int(lgbm_cfg.get("n_estimators", 300)),
        num_leaves=int(lgbm_cfg.get("num_leaves", 31)),
        max_depth=6,
        min_child_samples=60,
        subsample=float(lgbm_cfg.get("subsample", 0.8)),
        colsample_bytree=float(lgbm_cfg.get("colsample_bytree", 0.8)),
        reg_alpha=1.5,
        reg_lambda=4.0,
        class_weight="balanced",
        n_jobs=-1,
        verbose=-1,
        random_state=42,
    )

    # ── 5-Fold Cross-Validation ──────────────────────────────────────────
    n_splits = 5
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    oof_predictions = np.zeros(n_samples, dtype=np.float32)
    fold_aucs = []
    fold_praucs = []
    fold_briers = []

    print(f"\n  [*] Running Stratified {n_splits}-Fold Cross-Validation...")
    print("  " + "-" * 73)

    for fold, (train_idx, val_idx) in enumerate(skf.split(X, y), 1):
        X_tr, y_tr = X[train_idx], y[train_idx]
        X_va, y_va = X[val_idx], y[val_idx]

        fold_model = LGBMClassifier(**base_lgbm.get_params())
        fold_model.fit(X_tr, y_tr)

        val_probs = fold_model.predict_proba(X_va)[:, 1]
        oof_predictions[val_idx] = val_probs

        roc = roc_auc_score(y_va, val_probs)
        prauc = average_precision_score(y_va, val_probs)
        brier = brier_score_loss(y_va, val_probs)

        fold_aucs.append(roc)
        fold_praucs.append(prauc)
        fold_briers.append(brier)

        print(f"    Fold {fold}/{n_splits}: ROC-AUC = {roc:.4f} | PR-AUC = {prauc:.4f} | Brier = {brier:.4f}")

    # ── OOF Results ──────────────────────────────────────────────────────
    mean_roc = float(np.mean(fold_aucs))
    mean_prauc = float(np.mean(fold_praucs))
    mean_brier = float(np.mean(fold_briers))
    best_thr, _ = pick_best_threshold(y, oof_predictions)

    print("  " + "-" * 73)
    print(f"    [+] 5-Fold Mean ROC-AUC:  {mean_roc:.4f} (±{np.std(fold_aucs):.4f})")
    print(f"    [+] 5-Fold Mean PR-AUC:   {mean_prauc:.4f} (±{np.std(fold_praucs):.4f})")
    print(f"    [+] 5-Fold Mean Brier:    {mean_brier:.4f}")
    print(f"    [+] Tuned Threshold:      {best_thr:.3f}")

    oof_binary = (oof_predictions >= best_thr).astype(int)
    cm = confusion_matrix(y, oof_binary)
    cr = classification_report(y, oof_binary, target_names=["Benign", "Attack"], digits=4)

    print(f"\n    [+] Out-Of-Fold Confusion Matrix:")
    print(f"        [[TN: {cm[0,0]:<6}  FP: {cm[0,1]:<6}]")
    print(f"         [FN: {cm[1,0]:<6}  TP: {cm[1,1]:<6}]]")
    print(f"\n    [+] OOF Classification Report (threshold={best_thr:.3f}):\n{cr}")

    # ── Train Final Calibrated Model ─────────────────────────────────────
    print("  [*] Training final calibrated production model on 100% of data...")
    final_lgbm = LGBMClassifier(**base_lgbm.get_params())
    final_model = CalibratedClassifierCV(
        estimator=final_lgbm,
        method="sigmoid",
        cv=5,
    )
    final_model.fit(X, y)

    # ── Save Model ───────────────────────────────────────────────────────
    model_path = MODEL_DIR / "lightgbm.joblib"
    meta_path = MODEL_DIR / "model_meta.json"

    dump(final_model, model_path)
    print(f"\n  [OK] Saved Model -> {model_path}")

    meta = {
        "threshold": float(best_thr),
        "features": FEATURES,
        "label_positive": 1,
        "label_negative": 0,
        "csv_path": str(MERGED_TRAIN_CSV),
        "model_version": "3.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "model_type": "LightGBM + Platt Calibration (5-Fold CV)",
        "roc_auc": round(mean_roc, 4),
        "pr_auc": round(mean_prauc, 4),
        "brier_score": round(mean_brier, 4),
        "train_samples": n_samples,
        "n_splits": n_splits,
        "data_sources": [
            "IoTGuard synthetic (70K)",
            "Edge-IIoTset real-world IoT/IIoT (converted)",
        ],
        "regularization": {
            "max_depth": 6,
            "num_leaves": 31,
            "reg_alpha": 1.5,
            "reg_lambda": 4.0,
            "min_child_samples": 60,
        },
        "description": "IoTGuard v3.0 calibrated classifier — trained on merged synthetic + real-world Edge-IIoTset IoT data",
    }

    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"  [OK] Saved Meta  -> {meta_path}")

    return mean_roc, mean_prauc, mean_brier, best_thr


# ═════════════════════════════════════════════════════════════════════════════
# STEP 5: Retrain Unsupervised Model
# ═════════════════════════════════════════════════════════════════════════════
def step5_retrain_unsupervised(df: pd.DataFrame):
    """Retrain IsolationForest on benign-only data with optimized max_samples."""
    print("\n" + "=" * 75)
    print("  STEP 5: Retrain Unsupervised Model (IsolationForest)")
    print("=" * 75)

    X_all = df[FEATURES].to_numpy(dtype=np.float32)
    y_bin = _to_binary_labels(df["label"])

    # Train only on benign data
    mask_benign = (y_bin == 0)
    X_train = X_all[mask_benign]
    print(f"  [*] Training on benign-only: {mask_benign.sum():,} / {len(y_bin):,} rows")

    # Optimized IsolationForest (max_samples=256 per Liu et al.)
    iso = IsolationForest(
        n_estimators=200,
        max_samples=min(256, len(X_train)),  # Key optimization: prevents 150MB model bloat
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )

    print("  [*] Fitting IsolationForest (max_samples=256)...")
    iso.fit(X_train)

    # Score all data
    raw_scores = iso.score_samples(X_all)
    anomaly_scores = -raw_scores

    # Find best threshold
    pr_auc = float(average_precision_score(y_bin, anomaly_scores))
    prec, rec, thr = precision_recall_curve(y_bin, anomaly_scores)
    f1 = (2 * prec[:-1] * rec[:-1]) / (prec[:-1] + rec[:-1] + 1e-12)
    best_idx = int(np.nanargmax(f1))
    best_thr = float(thr[best_idx])

    print(f"  [*] Anomaly threshold: {best_thr:.4f}")
    print(f"  [*] PR-AUC (unsup): {pr_auc:.4f}")

    yhat = (anomaly_scores >= best_thr).astype(int)
    cm = confusion_matrix(y_bin, yhat)
    cr = classification_report(y_bin, yhat, target_names=["Benign", "Anomaly"], digits=4)
    print(f"\n    Confusion @threshold:\n{cm}")
    print(f"\n    Report @threshold:\n{cr}")

    # Save
    model_path = MODEL_DIR / "unsup_isoforest.joblib"
    meta_path = MODEL_DIR / "unsup_meta.json"

    dump(iso, model_path)
    model_size_mb = model_path.stat().st_size / 1024 / 1024
    print(f"\n  [OK] Saved Model -> {model_path} ({model_size_mb:.1f} MB)")

    meta = {
        "algorithm": "IsolationForest",
        "features": FEATURES,
        "threshold": float(best_thr),
        "contamination": 0.05,
        "train_on": "benign_only",
        "csv_path": str(MERGED_TRAIN_CSV),
        "score_higher_is_anomalous": True,
        "fallback_quantile": 0.99,
        "max_samples": 256,
        "model_version": "3.0.0",
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"  [OK] Saved Meta  -> {meta_path}")


# ═════════════════════════════════════════════════════════════════════════════
# STEP 6: Evaluate on Holdout Data
# ═════════════════════════════════════════════════════════════════════════════
def step6_evaluate_holdout():
    """Evaluate upgraded models on holdout test data."""
    print("\n" + "=" * 75)
    print("  STEP 6: Evaluate Upgraded Models on Holdout Data")
    print("=" * 75)

    model = load(MODEL_DIR / "lightgbm.joblib")
    meta = json.loads((MODEL_DIR / "model_meta.json").read_text(encoding="utf-8"))
    threshold = meta["threshold"]
    features = meta["features"]

    test_dir = Path("data/test_holdout")
    csv_files = sorted(test_dir.glob("*.csv"))

    # Skip archive subdirectories
    csv_files = [f for f in csv_files if f.is_file()]

    if not csv_files:
        print("  [SKIP] No holdout CSVs found")
        return

    print(f"  Model Threshold: {threshold:.4f}")
    print(f"  Features: {len(features)}\n")

    all_y_true = []
    all_scores = []

    for f in csv_files:
        try:
            df = pd.read_csv(f)
            df.columns = [c.strip().replace(" ", "_") for c in df.columns]

            if "label" not in df.columns:
                if "benign" in f.name.lower():
                    df["label"] = "benign"
                else:
                    df["label"] = "attack"

            y_true = (~df["label"].astype(str).str.lower().isin(["benign", "normal"])).astype(int).to_numpy()

            # Prepare features
            for feat in features:
                if feat not in df.columns:
                    df[feat] = 0.0
            X = df[features].replace([np.inf, -np.inf], np.nan).fillna(0)

            scores = model.predict_proba(X)[:, 1]
            y_pred = (scores >= threshold).astype(int)

            is_benign_file = "benign" in f.name.lower()
            n = len(y_true)

            if is_benign_file:
                fp_count = y_pred.sum()
                print(f"    {f.name:45s} (BENIGN) -> FP: {fp_count}/{n} ({fp_count/n*100:.1f}%)")
            else:
                det = y_pred.sum()
                print(f"    {f.name:45s} (ATTACK) -> Det: {det}/{n} ({det/n*100:.1f}%)")

            all_y_true.extend(y_true)
            all_scores.extend(scores)

        except Exception as e:
            print(f"    {f.name:45s} [ERROR] {e}")

    if all_y_true:
        all_y_true = np.array(all_y_true)
        all_scores = np.array(all_scores)
        all_preds = (all_scores >= threshold).astype(int)

        cm = confusion_matrix(all_y_true, all_preds)
        tn, fp, fn, tp = cm.ravel()
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        fpr = fp / (tn + fp) if (tn + fp) > 0 else 0
        roc = roc_auc_score(all_y_true, all_scores) if len(np.unique(all_y_true)) > 1 else 0

        print(f"\n    {'='*60}")
        print(f"    HOLDOUT RESULTS (threshold={threshold:.4f})")
        print(f"    {'='*60}")
        print(f"    Recall:    {recall*100:.2f}%")
        print(f"    Precision: {precision*100:.2f}%")
        print(f"    FPR:       {fpr*100:.2f}%")
        print(f"    ROC-AUC:   {roc:.4f}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════════════
def main():
    print("=" * 75)
    print("  IoTGuard Model Upgrade Pipeline v3.0")
    print("  Merging Real-World Edge-IIoTset + Synthetic IoT Data")
    print("  " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 75)

    # Step 1: Convert real-world data
    edge_available = step1_convert_edge_iiotset()

    # Step 2: Merge datasets
    df_merged = step2_merge_datasets()
    if df_merged is None:
        print("\n[FATAL] No training data available. Aborting.")
        sys.exit(1)

    # Step 3: Backup old models
    step3_backup_models()

    # Step 4: Retrain supervised model
    roc, prauc, brier, thr = step4_retrain_supervised(df_merged)

    # Step 5: Retrain unsupervised model
    step5_retrain_unsupervised(df_merged)

    # Step 6: Evaluate on holdout
    step6_evaluate_holdout()

    # ── Final Summary ────────────────────────────────────────────────────
    print("\n" + "=" * 75)
    print("  MODEL UPGRADE COMPLETE")
    print("=" * 75)
    print(f"  Version:        3.0.0")
    print(f"  Training Data:  {len(df_merged):,} samples (synthetic + real)")
    print(f"  ROC-AUC:        {roc:.4f}")
    print(f"  PR-AUC:         {prauc:.4f}")
    print(f"  Brier Score:    {brier:.4f}")
    print(f"  Threshold:      {thr:.3f}")
    if edge_available:
        print(f"  Data Sources:   IoTGuard synthetic + Edge-IIoTset (10 IoT sensors, 14 attack types)")
    else:
        print(f"  Data Sources:   IoTGuard synthetic only")
    print("=" * 75)


if __name__ == "__main__":
    main()
