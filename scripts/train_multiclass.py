"""
scripts/train_multiclass.py
-----------------------------------------------------------------------------
IoTGuard Pipeline — Offline Multiclass Model Training

Train a LightGBM multiclass classifier that predicts ATTACK TYPE (and benign)
instead of just binary attack/benign. The decision loop already understands
multiclass models when models/classes.json is present.

This script:
  - uses the same feature set defined in configs/model.yaml,
  - expects a 'label' column with string classes (e.g., 'benign', 'ddos_syn', ...),
  - trains a LightGBM model with objective='multiclass',
  - saves:
        models/lightgbm.joblib   – the multiclass model,
        models/model_meta.json   – feature list + CSV path,
        models/classes.json      – class names + benign_index.

Usage:
    python scripts/train_multiclass.py --csv data/iotguard_training_clean.csv
-----------------------------------------------------------------------------
"""

import os, json, argparse
from pathlib import Path
import numpy as np
import pandas as pd
import yaml

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

from joblib import dump
from lightgbm import LGBMClassifier


CFG_PATH = Path("configs/model.yaml")


def _load_yaml_cfg() -> dict:
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


def main():
    ap = argparse.ArgumentParser(description="Train LightGBM IDS (multiclass attack type).")
    ap.add_argument("--csv", required=True, help="Path to merged CSV (features + 'label').")
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--random-state", type=int, default=42)
    ap.add_argument("--model-out", default="models/lightgbm.joblib")
    ap.add_argument("--meta-out", default="models/model_meta.json")
    ap.add_argument("--classes-out", default="models/classes.json")
    # hyperparams from config when present
    ap.add_argument("--learning-rate", type=float, default=float(_LGBM_CFG.get("learning_rate", 0.05)))
    ap.add_argument("--n-estimators", type=int, default=int(_LGBM_CFG.get("n_estimators", 500)))
    ap.add_argument("--num-leaves", type=int, default=int(_LGBM_CFG.get("num_leaves", 64)))
    ap.add_argument("--max-depth", type=int, default=-1)
    ap.add_argument("--min-data-in-leaf", type=int, default=50)
    ap.add_argument("--subsample", type=float, default=float(_LGBM_CFG.get("subsample", 0.8)))
    ap.add_argument("--colsample-bytree", type=float, default=float(_LGBM_CFG.get("colsample_bytree", 0.8)))
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    df = _normalize_columns(df)

    if "label" not in df.columns:
        raise ValueError("CSV must contain a 'label' column.")

    # feature selection aligned with configs/model.yaml
    if _FEATURES_CFG:
        missing = [c for c in _FEATURES_CFG if c not in df.columns]
        if missing:
            raise ValueError(f"Training CSV missing expected feature columns: {missing}")
        feat_cols = [c for c in _FEATURES_CFG if c in df.columns]
    else:
        feat_cols = [c for c in df.columns if c != "label" and pd.api.types.is_numeric_dtype(df[c])]

    X = df[feat_cols].to_numpy(dtype=np.float32)

    # map labels to integers, ensure benign is a known class
    labels = df["label"].astype(str).str.strip().str.lower()
    classes = sorted(labels.unique())
    if "benign" not in classes:
        classes.insert(0, "benign")
    class_to_idx = {c: i for i, c in enumerate(classes)}
    y = labels.map(lambda s: class_to_idx.get(s, class_to_idx["benign"])).to_numpy(dtype=int)

    print("[*] Multiclass training data:")
    print(f"   rows: {len(df)} | features: {len(feat_cols)} | classes: {classes}")

    Xtr, Xva, ytr, yva = train_test_split(
        X, y, test_size=args.test_size, random_state=args.random_state, stratify=y
    )

    clf = LGBMClassifier(
        objective="multiclass",
        num_class=len(classes),
        learning_rate=args.learning_rate,
        n_estimators=args.n_estimators,
        num_leaves=args.num_leaves,
        max_depth=args.max_depth,
        min_child_samples=args.min_data_in_leaf,
        subsample=args.subsample,
        colsample_bytree=args.colsample_bytree,
        n_jobs=-1,
        verbose=-1,
    )

    print("[*] Training multiclass model...")
    clf.fit(Xtr, ytr, eval_set=[(Xva, yva)], eval_metric="multi_logloss")

    y_pred = clf.predict(Xva)
    cm = confusion_matrix(yva, y_pred)
    cr = classification_report(yva, y_pred, target_names=classes, digits=4)
    print("Confusion (multiclass):\n", cm)
    print("\nReport (multiclass):\n", cr)

    os.makedirs(os.path.dirname(args.model_out), exist_ok=True)
    dump(clf, args.model_out)

    meta = {
        "features": feat_cols,
        "csv_path": args.csv,
        "mode": "multiclass",
    }
    Path(args.meta_out).write_text(json.dumps(meta, indent=2), encoding="utf-8")

    classes_meta = {
        "classes": classes,
        "benign_index": class_to_idx["benign"],
    }
    Path(args.classes_out).write_text(json.dumps(classes_meta, indent=2), encoding="utf-8")

    print(f"Saved multiclass model   -> {args.model_out}")
    print(f"Saved model meta         -> {args.meta_out}")
    print(f"Saved classes metadata   -> {args.classes_out}")


if __name__ == "__main__":
    main()





