"""
scripts/check_feature_drift.py
-----------------------------------------------------------------------------
Quick feature sanity / drift check:

Compares simple stats (mean/std/range) between:
  - training features from data/iotguard_training_clean.csv, and
  - recent live features from data/features.csv.

This helps you see if live traffic has drifted away from what the model saw
at training time.
-----------------------------------------------------------------------------
"""

from pathlib import Path
import json

import numpy as np
import pandas as pd


def summarize(df: pd.DataFrame, cols):
    stats = {}
    for c in cols:
        if c not in df.columns:
            continue
        s = pd.to_numeric(df[c], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
        if s.empty:
            continue
        stats[c] = {
            "mean": float(s.mean()),
            "std": float(s.std()),
            "min": float(s.min()),
            "max": float(s.max()),
        }
    return stats


def main():
    train_path = Path("data/iotguard_training_clean.csv")
    live_path = Path("data/features.csv")
    meta_path = Path("models/model_meta.json")

    if not train_path.exists() or not live_path.exists() or not meta_path.exists():
        raise SystemExit("Missing training CSV, features.csv, or model_meta.json.")

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    feats = meta.get("features") or []
    if not feats:
        raise SystemExit("model_meta.json missing 'features' list.")

    print(f"[*] Using {len(feats)} features: {feats}")

    df_train = pd.read_csv(train_path)
    df_live = pd.read_csv(live_path)

    # Recent subset of live data
    if len(df_live) > 5000:
        df_live = df_live.iloc[-5000:]

    train_stats = summarize(df_train, feats)
    live_stats = summarize(df_live, feats)

    print("\nFeature drift summary (train vs recent live):")
    print(f"{'feature':<24} {'train_mean':>12} {'live_mean':>12} {'Δmean%':>10}")
    print("-" * 64)
    for c in feats:
        t = train_stats.get(c)
        l = live_stats.get(c)
        if not t or not l:
            continue
        tm, lm = t["mean"], l["mean"]
        delta = 0.0 if tm == 0 else (lm - tm) / abs(tm) * 100.0
        print(f"{c:<24} {tm:12.3f} {lm:12.3f} {delta:10.2f}")


if __name__ == "__main__":
    main()





