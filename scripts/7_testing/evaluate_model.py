#!/usr/bin/env python3
"""
Quick model evaluation using synthetic test data that mimics
the 13-feature schema used by IoTGuard.

Generates benign and various attack patterns, then evaluates
the trained LightGBM model's detection performance.
"""
import numpy as np
import pandas as pd
import joblib
import json
from pathlib import Path
from sklearn.metrics import (
    confusion_matrix, classification_report,
    roc_auc_score, average_precision_score, roc_curve
)

MODEL_PATH = Path("models/lightgbm.joblib")
META_PATH  = Path("models/model_meta.json")

# Load model and metadata
print("=" * 70)
print("IoTGuard Model Evaluation")
print("=" * 70)

model = joblib.load(MODEL_PATH)
with open(META_PATH, "r", encoding="utf-8") as f:
    meta = json.load(f)

features = meta["features"]
threshold = meta.get("threshold", 0.75)

print(f"\nModel:      {meta.get('model_type', 'LightGBM')} v{meta.get('model_version', '?')}")
print(f"Trained on: {meta.get('train_samples', '?'):,} samples")
print(f"Threshold:  {threshold}")
print(f"Features:   {len(features)}")
print(f"Train ROC-AUC: {meta.get('roc_auc', '?')}")
print(f"Train PR-AUC:  {meta.get('pr_auc', '?')}")

# -------------------------------------------------------------------
# Generate synthetic test data with realistic IoT traffic patterns
# -------------------------------------------------------------------
rng = np.random.default_rng(42)
N_BENIGN = 2000
N_ATTACK = 2000

def gen_benign(n, rng):
    """Normal IoT device traffic: low flow counts, small packets, moderate ratios."""
    return pd.DataFrame({
        "flows":              rng.integers(3, 25, n),
        "bytes_total":        rng.integers(500, 15000, n),
        "pkts_total":         rng.integers(10, 120, n),
        "syn_ratio":          rng.uniform(0.02, 0.30, n).round(3),
        "mean_bytes_flow":    rng.uniform(30, 600, n).round(1),
        "ack_ratio":          rng.uniform(0.25, 0.70, n).round(3),
        "fin_ratio":          rng.uniform(0.05, 0.30, n).round(3),
        "rst_ratio":          rng.uniform(0.0, 0.05, n).round(3),
        "http_ratio":         rng.uniform(0.0, 0.40, n).round(3),
        "tcp_ratio":          rng.uniform(0.7, 1.0, n).round(3),
        "protocol_diversity": rng.integers(1, 4, n),
        "std_bytes":          rng.uniform(5, 150, n).round(2),
        "iat_mean":           rng.uniform(0.01, 0.80, n).round(4),
    })

def gen_syn_flood(n, rng):
    """SYN flood: very high SYN ratio, many flows, high packets."""
    return pd.DataFrame({
        "flows":              rng.integers(30, 80, n),
        "bytes_total":        rng.integers(50000, 2000000, n),
        "pkts_total":         rng.integers(500, 80000, n),
        "syn_ratio":          rng.uniform(0.70, 0.99, n).round(3),
        "mean_bytes_flow":    rng.uniform(500, 5000, n).round(1),
        "ack_ratio":          rng.uniform(0.0, 0.05, n).round(3),
        "fin_ratio":          rng.uniform(0.0, 0.02, n).round(3),
        "rst_ratio":          rng.uniform(0.0, 0.05, n).round(3),
        "http_ratio":         rng.uniform(0.0, 0.05, n).round(3),
        "tcp_ratio":          rng.uniform(0.95, 1.0, n).round(3),
        "protocol_diversity": rng.integers(1, 2, n),
        "std_bytes":          rng.uniform(0, 30, n).round(2),
        "iat_mean":           rng.uniform(0.0001, 0.005, n).round(6),
    })

def gen_volumetric_ddos(n, rng):
    """Volumetric DDoS (Mirai/UDP): massive bytes, low protocol diversity."""
    return pd.DataFrame({
        "flows":              rng.integers(20, 70, n),
        "bytes_total":        rng.integers(1000000, 10000000, n),
        "pkts_total":         rng.integers(5000, 100000, n),
        "syn_ratio":          rng.uniform(0.1, 0.5, n).round(3),
        "mean_bytes_flow":    rng.uniform(2000, 50000, n).round(1),
        "ack_ratio":          rng.uniform(0.0, 0.1, n).round(3),
        "fin_ratio":          rng.uniform(0.0, 0.05, n).round(3),
        "rst_ratio":          rng.uniform(0.0, 0.1, n).round(3),
        "http_ratio":         rng.uniform(0.0, 0.05, n).round(3),
        "tcp_ratio":          rng.uniform(0.3, 0.7, n).round(3),
        "protocol_diversity": rng.integers(1, 3, n),
        "std_bytes":          rng.uniform(0, 50, n).round(2),
        "iat_mean":           rng.uniform(0.00001, 0.002, n).round(6),
    })

def gen_port_scan(n, rng):
    """Port scan: high RST ratio, many small flows."""
    return pd.DataFrame({
        "flows":              rng.integers(30, 100, n),
        "bytes_total":        rng.integers(1000, 10000, n),
        "pkts_total":         rng.integers(50, 200, n),
        "syn_ratio":          rng.uniform(0.3, 0.6, n).round(3),
        "mean_bytes_flow":    rng.uniform(10, 100, n).round(1),
        "ack_ratio":          rng.uniform(0.0, 0.1, n).round(3),
        "fin_ratio":          rng.uniform(0.0, 0.05, n).round(3),
        "rst_ratio":          rng.uniform(0.50, 0.90, n).round(3),
        "http_ratio":         rng.uniform(0.0, 0.05, n).round(3),
        "tcp_ratio":          rng.uniform(0.9, 1.0, n).round(3),
        "protocol_diversity": rng.integers(1, 3, n),
        "std_bytes":          rng.uniform(0, 20, n).round(2),
        "iat_mean":           rng.uniform(0.0001, 0.01, n).round(6),
    })

def gen_web_attack(n, rng):
    """Web attack (SQLi/XSS): high HTTP ratio."""
    return pd.DataFrame({
        "flows":              rng.integers(5, 30, n),
        "bytes_total":        rng.integers(5000, 100000, n),
        "pkts_total":         rng.integers(20, 500, n),
        "syn_ratio":          rng.uniform(0.05, 0.2, n).round(3),
        "mean_bytes_flow":    rng.uniform(200, 5000, n).round(1),
        "ack_ratio":          rng.uniform(0.2, 0.5, n).round(3),
        "fin_ratio":          rng.uniform(0.05, 0.2, n).round(3),
        "rst_ratio":          rng.uniform(0.0, 0.1, n).round(3),
        "http_ratio":         rng.uniform(0.55, 0.95, n).round(3),
        "tcp_ratio":          rng.uniform(0.8, 1.0, n).round(3),
        "protocol_diversity": rng.integers(2, 6, n),
        "std_bytes":          rng.uniform(50, 3000, n).round(2),
        "iat_mean":           rng.uniform(0.01, 0.3, n).round(4),
    })

# Build test set
n_per_attack = N_ATTACK // 4
benign_df  = gen_benign(N_BENIGN, rng)
syn_df     = gen_syn_flood(n_per_attack, rng)
vol_df     = gen_volumetric_ddos(n_per_attack, rng)
scan_df    = gen_port_scan(n_per_attack, rng)
web_df     = gen_web_attack(n_per_attack, rng)

benign_df["label"] = 0
benign_df["attack_type"] = "Benign"
syn_df["label"] = 1
syn_df["attack_type"] = "SYN Flood"
vol_df["label"] = 1
vol_df["attack_type"] = "Volumetric DDoS"
scan_df["label"] = 1
scan_df["attack_type"] = "Port Scan"
web_df["label"] = 1
web_df["attack_type"] = "Web Attack"

test_df = pd.concat([benign_df, syn_df, vol_df, scan_df, web_df], ignore_index=True)
# Shuffle
test_df = test_df.sample(frac=1, random_state=42).reset_index(drop=True)

y_true = test_df["label"].values
attack_types = test_df["attack_type"].values
X = test_df[features]

print(f"\n--- Test Dataset ---")
print(f"Total:   {len(test_df):,}")
print(f"Benign:  {(y_true == 0).sum():,}")
print(f"Attack:  {(y_true == 1).sum():,}")
for at in ["SYN Flood", "Volumetric DDoS", "Port Scan", "Web Attack"]:
    print(f"  - {at}: {(attack_types == at).sum()}")

# -------------------------------------------------------------------
# Score with model
# -------------------------------------------------------------------
scores = model.predict_proba(X)[:, 1]
y_pred = (scores >= threshold).astype(int)

# -------------------------------------------------------------------
# Overall Metrics
# -------------------------------------------------------------------
print(f"\n{'=' * 70}")
print(f"OVERALL RESULTS (threshold={threshold})")
print(f"{'=' * 70}")

cm = confusion_matrix(y_true, y_pred)
tn, fp, fn, tp = cm.ravel()

recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
precision = tp / (tp + fp) if (tp + fp) > 0 else 0
fpr       = fp / (tn + fp) if (tn + fp) > 0 else 0
accuracy  = (tp + tn) / len(y_true)
f1        = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

print(f"\nConfusion Matrix:")
print(f"                Predicted")
print(f"              Benign  Attack")
print(f"  Actual Benign  {tn:5d}   {fp:5d}")
print(f"  Actual Attack  {fn:5d}   {tp:5d}")

print(f"\n  Accuracy:           {accuracy*100:.2f}%")
print(f"  Recall (Detection): {recall*100:.2f}%")
print(f"  Precision:          {precision*100:.2f}%")
print(f"  F1-Score:           {f1:.4f}")
print(f"  False Positive Rate:{fpr*100:.2f}%")

roc_auc = roc_auc_score(y_true, scores)
pr_auc  = average_precision_score(y_true, scores)
print(f"  ROC-AUC:            {roc_auc:.4f}")
print(f"  PR-AUC:             {pr_auc:.4f}")

# -------------------------------------------------------------------
# Per-Attack-Type Breakdown
# -------------------------------------------------------------------
print(f"\n{'=' * 70}")
print("PER-ATTACK-TYPE DETECTION RATES")
print(f"{'=' * 70}")
print(f"{'Attack Type':<20} | {'Samples':>7} | {'Detected':>8} | {'Rate':>8} | {'Avg Score':>9}")
print("-" * 70)

for at in ["Benign", "SYN Flood", "Volumetric DDoS", "Port Scan", "Web Attack"]:
    mask = attack_types == at
    n = mask.sum()
    if at == "Benign":
        fp_count = y_pred[mask].sum()
        avg = scores[mask].mean()
        print(f"{at:<20} | {n:>7} | {fp_count:>5} FP | {fp_count/n*100:>6.2f}% | {avg:>9.4f}")
    else:
        det = y_pred[mask].sum()
        avg = scores[mask].mean()
        print(f"{at:<20} | {n:>7} | {det:>8} | {det/n*100:>6.2f}% | {avg:>9.4f}")

# -------------------------------------------------------------------
# Threshold Sensitivity
# -------------------------------------------------------------------
print(f"\n{'=' * 70}")
print("THRESHOLD SENSITIVITY ANALYSIS")
print(f"{'=' * 70}")
print(f"{'Threshold':<10} | {'Recall':>8} | {'Precision':>10} | {'FPR':>8} | {'F1':>8}")
print("-" * 56)

for thr in [0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95, 0.99]:
    preds_t = (scores >= thr).astype(int)
    cm_t = confusion_matrix(y_true, preds_t)
    tn_t, fp_t, fn_t, tp_t = cm_t.ravel()
    rec = tp_t / (tp_t + fn_t) if (tp_t + fn_t) > 0 else 0
    prec = tp_t / (tp_t + fp_t) if (tp_t + fp_t) > 0 else 0
    fpr_t = fp_t / (tn_t + fp_t) if (tn_t + fp_t) > 0 else 0
    f1_t = 2*(prec*rec)/(prec+rec) if (prec+rec) > 0 else 0
    marker = " <-- current" if abs(thr - threshold) < 0.001 else ""
    print(f"{thr:<10.2f} | {rec*100:>6.2f}% | {prec*100:>8.2f}% | {fpr_t*100:>6.2f}% | {f1_t:>6.4f}{marker}")

# -------------------------------------------------------------------
# Score Distribution
# -------------------------------------------------------------------
print(f"\n{'=' * 70}")
print("SCORE DISTRIBUTION")
print(f"{'=' * 70}")

ben_scores = scores[y_true == 0]
atk_scores = scores[y_true == 1]

print(f"\n  Benign scores:  mean={ben_scores.mean():.4f}  std={ben_scores.std():.4f}  "
      f"min={ben_scores.min():.4f}  max={ben_scores.max():.4f}")
print(f"  Attack scores:  mean={atk_scores.mean():.4f}  std={atk_scores.std():.4f}  "
      f"min={atk_scores.min():.4f}  max={atk_scores.max():.4f}")

# Score histogram (text-based)
print(f"\n  Score ranges (Benign / Attack):")
for lo in np.arange(0, 1.0, 0.1):
    hi = lo + 0.1
    b = ((ben_scores >= lo) & (ben_scores < hi)).sum()
    a = ((atk_scores >= lo) & (atk_scores < hi)).sum()
    b_bar = "█" * min(b // 20, 40)
    a_bar = "█" * min(a // 20, 40)
    print(f"  [{lo:.1f}-{hi:.1f}) Benign: {b:>5} {b_bar}")
    print(f"           Attack: {a:>5} {a_bar}")

print(f"\n{'=' * 70}")
print("EVALUATION COMPLETE")
print(f"{'=' * 70}")
