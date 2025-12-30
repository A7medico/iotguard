#!/usr/bin/env python3
"""
Test model on UNSEEN HOLDOUT data from data/test_holdout/.
"""
import pandas as pd
import numpy as np
import joblib
import json
from pathlib import Path
import argparse
from sklearn.metrics import confusion_matrix, roc_auc_score, average_precision_score

MODEL_PATH = Path("models/lightgbm.joblib")
META_PATH = Path("models/model_meta.json")
TEST_DIR = Path("data/test_holdout")

def load_model():
    model = joblib.load(MODEL_PATH)
    with open(META_PATH, "r", encoding="utf-8") as f:
        meta = json.load(f)
    return model, meta

def prepare_features(df, meta):
    required = meta["features"]
    df.columns = [c.strip().replace(" ", "_") for c in df.columns]
    
    # Fill missing
    for f in required:
        if f not in df.columns:
            df[f] = 0.0
            
    X = df[required].copy()
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    return X

def main():
    if not TEST_DIR.exists():
        print(f"[ERROR] Test directory {TEST_DIR} not found!")
        return

    files = sorted(list(TEST_DIR.glob("*.csv")))

    # Option A: IoTGuard-only evaluation
    # ----------------------------------
    # Skip CICIDS2017 WorkingHours datasets and other non-IoT enterprise files
    # so that holdout evaluation reflects the intended IoT domain.
    exclude_patterns = [
        "monday-workinghours", "tuesday-workinghours", "wednesday-workinghours",
        "thursday-morning-webattacks", "thursday-afternoon-infiltration",
        "friday-morning_13f", "friday-afternoon-ddos_13f",
        "friday-afternoon-portscan_13f",
    ]
    orig_count = len(files)
    files = [
        f for f in files
        if not any(pat in f.name.lower() for pat in exclude_patterns)
    ]

    if orig_count != len(files):
        skipped = orig_count - len(files)
        print(f"[INFO] Skipped {skipped} non-IoT holdout file(s) (CICIDS2017 WorkingHours, etc.).")
    if not files:
        print(f"[ERROR] No CSV files found in {TEST_DIR} after filtering")
        return

    print("=" * 60)
    print("TESTING ON HOLDOUT DATA (Files Never Seen During Training)")
    print("=" * 60)

    model, meta = load_model()
    threshold = meta.get("threshold", 0.95)
    print(f"Model Threshold: {threshold:.4f}")
    print(f"Features: {len(meta['features'])}")
    
    all_y_true = []
    all_y_pred = []
    all_scores = []
    
    results = []

    for f in files:
        try:
            df = pd.read_csv(f)
            if "label" not in df.columns:
                # Infer label
                if "benign" in f.name.lower():
                    label = "benign"
                else:
                    label = "attack"
                df["label"] = label
                
            # Binary label
            y_true = (~df["label"].astype(str).str.lower().isin(["benign", "normal"])).astype(int).to_numpy()
            
            X = prepare_features(df, meta)
            
            if hasattr(model, "predict_proba"):
                scores = model.predict_proba(X)[:, 1]
            else:
                scores = model.predict(X)
                
            preds = (scores >= threshold).astype(int)
            
            # Store results
            all_y_true.extend(y_true)
            all_y_pred.extend(preds)
            all_scores.extend(scores)
            
            # File stats
            acc = np.mean(y_true == preds)
            attack_rate = preds.mean()
            
            # Determine file type
            is_attack_file = y_true.mean() > 0.5
            status = "ATTACK" if is_attack_file else "BENIGN"
            
            # Detection check
            if is_attack_file:
                 detected = preds.sum()
                 total = len(preds)
                 rate = detected / total
                 print(f"  [FILE] {f.name[:40]:<40} ({status}) -> Detected: {detected}/{total} ({rate*100:.1f}%)")
            else:
                 fp = preds.sum()
                 total = len(preds)
                 rate = fp / total
                 print(f"  [FILE] {f.name[:40]:<40} ({status}) -> False Pos: {fp}/{total} ({rate*100:.1f}%)")
                 
        except Exception as e:
            print(f"  [ERROR] Failed to process {f.name}: {e}")

    # Aggregated Metrics
    print("\n" + "=" * 60)
    print("GLOBAL METRICS ON HOLDOUT SET")
    print("=" * 60)
    
    y_true = np.array(all_y_true)
    y_pred = np.array(all_y_pred)
    all_scores = np.array(all_scores)

    # Current Threshold Report
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    print(f"\nConfusion Matrix (Threshold={threshold:.4f}):")
    print(f"      Pred:0  Pred:1")
    print(f"Act:0 {tn:6d}  {fp:6d}")
    print(f"Act:1 {fn:6d}  {tp:6d}")
    
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    fpr = fp / (tn + fp) if (tn + fp) > 0 else 0
    
    print(f"\nRecall (Detection Rate): {recall*100:.2f}%")
    print(f"Precision:               {precision*100:.2f}%")
    print(f"False Positive Rate:     {fpr*100:.2f}%")
    
    try:
        auc = roc_auc_score(y_true, all_scores)
        print(f"ROC-AUC:                 {auc:.4f}")
    except:
        pass

    # --- Threshold Sensitivity Analysis ---
    print("\n" + "-" * 60)
    print("THRESHOLD SENSITIVITY ANALYSIS")
    print("-" * 60)
    print(f"{'Threshold':<10} | {'Recall':<10} | {'Precision':<10} | {'FPR':<10} | {'F1-Score':<10}")
    print("-" * 60)

    for thr in [0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 0.98, 0.99]:
        preds_t = (all_scores >= thr).astype(int)
        cm_t = confusion_matrix(y_true, preds_t)
        tn_t, fp_t, fn_t, tp_t = cm_t.ravel()
        
        rec_t = tp_t / (tp_t + fn_t) if (tp_t + fn_t) > 0 else 0
        prec_t = tp_t / (tp_t + fp_t) if (tp_t + fp_t) > 0 else 0
        fpr_t = fp_t / (tn_t + fp_t) if (tn_t + fp_t) > 0 else 0
        f1_t = 2 * (prec_t * rec_t) / (prec_t + rec_t) if (prec_t + rec_t) > 0 else 0
        
        # Highlight best candidate (e.g. FPR < 1% and High Recall)
        marker = ""
        if fpr_t < 0.01 and rec_t > 0.90:
            marker = "  <-- RECOMMENDED"
        elif fpr_t < 0.05 and rec_t > 0.95:
             marker = "  (Good Balance)"

        print(f"{thr:<10.2f} | {rec_t*100:6.2f}%    | {prec_t*100:6.2f}%    | {fpr_t*100:6.2f}%    | {f1_t:.4f}{marker}")

    print("-" * 60)


if __name__ == "__main__":
    main()


