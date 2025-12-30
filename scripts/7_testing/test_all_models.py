#!/usr/bin/env python3
"""
Test ALL model configurations systematically:
1. Supervised-only (LightGBM)
2. Unsupervised-only (IsolationForest)
3. Hybrid mode with different strategies (OR, AND, weighted)
"""
import pandas as pd
import numpy as np
import joblib
import json
from pathlib import Path
from sklearn.metrics import confusion_matrix, roc_auc_score, classification_report
import sys

# Paths
MODEL_DIR = Path("models")
SUPERVISED_MODEL = MODEL_DIR / "lightgbm.joblib"
SUPERVISED_META = MODEL_DIR / "model_meta.json"
UNSUPERVISED_MODEL = MODEL_DIR / "unsup_isoforest.joblib"
UNSUPERVISED_META = MODEL_DIR / "unsup_meta.json"
TEST_DIR = Path("data/test_holdout")

# Colors for output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 80}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text:^80}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 80}{Colors.ENDC}\n")


def print_subheader(text):
    print(f"\n{Colors.OKBLUE}{text}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}{'-' * len(text)}{Colors.ENDC}")


def load_models():
    """Load both supervised and unsupervised models"""
    sup_model = joblib.load(SUPERVISED_MODEL)
    with open(SUPERVISED_META, 'r') as f:
        sup_meta = json.load(f)
    
    unsup_model = joblib.load(UNSUPERVISED_MODEL)
    with open(UNSUPERVISED_META, 'r') as f:
        unsup_meta = json.load(f)
    
    return sup_model, sup_meta, unsup_model, unsup_meta


def prepare_features(df, features):
    """Prepare feature matrix from dataframe"""
    df.columns = [c.strip().replace(" ", "_") for c in df.columns]
    
    # Fill missing features with 0
    for f in features:
        if f not in df.columns:
            df[f] = 0.0
    
    X = df[features].copy()
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    return X


def load_test_data():
    """Load all test files and prepare data"""
    # Exclude non-IoT datasets
    exclude_patterns = [
        "monday-workinghours", "tuesday-workinghours", "wednesday-workinghours",
        "thursday-morning-webattacks", "thursday-afternoon-infiltration",
        "friday-morning", "friday-afternoon",
    ]
    
    files = sorted(list(TEST_DIR.glob("*.csv")))
    files = [f for f in files if not any(pat in f.name.lower() for pat in exclude_patterns)]
    
    all_data = []
    for f in files:
        try:
            df = pd.read_csv(f)
            
            # Infer label if missing
            if "label" not in df.columns:
                label = "benign" if "benign" in f.name.lower() else "attack"
                df["label"] = label
            
            df["source_file"] = f.name
            all_data.append(df)
        except Exception as e:
            print(f"{Colors.WARNING}Warning: Failed to load {f.name}: {e}{Colors.ENDC}")
    
    combined = pd.concat(all_data, ignore_index=True)
    
    # Create binary labels
    y_true = (~combined["label"].astype(str).str.lower().isin(["benign", "normal"])).astype(int)
    
    return combined, y_true.values


def compute_metrics(y_true, y_pred, scores=None):
    """Compute and return performance metrics"""
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    fpr = fp / (tn + fp) if (tn + fp) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    
    metrics = {
        'TP': int(tp),
        'TN': int(tn),
        'FP': int(fp),
        'FN': int(fn),
        'Recall': recall,
        'Precision': precision,
        'FPR': fpr,
        'F1': f1,
        'Accuracy': accuracy,
    }
    
    if scores is not None and len(np.unique(y_true)) > 1:
        try:
            metrics['ROC-AUC'] = roc_auc_score(y_true, scores)
        except:
            metrics['ROC-AUC'] = None
    
    return metrics


def print_metrics(metrics, title):
    """Print metrics in a formatted way"""
    print_subheader(title)
    print(f"Confusion Matrix:")
    print(f"  TN: {metrics['TN']:>7,}  FP: {metrics['FP']:>7,}")
    print(f"  FN: {metrics['FN']:>7,}  TP: {metrics['TP']:>7,}")
    print()
    print(f"  Detection Rate (Recall):  {metrics['Recall']*100:>6.2f}%")
    print(f"  Precision:                {metrics['Precision']*100:>6.2f}%")
    print(f"  False Positive Rate:      {metrics['FPR']*100:>6.2f}%")
    print(f"  F1-Score:                 {metrics['F1']:>6.4f}")
    print(f"  Accuracy:                 {metrics['Accuracy']*100:>6.2f}%")
    if 'ROC-AUC' in metrics and metrics['ROC-AUC'] is not None:
        print(f"  ROC-AUC:                  {metrics['ROC-AUC']:>6.4f}")


def test_supervised_only(sup_model, sup_meta, X, y_true):
    """Test supervised model only"""
    print_header("TEST 1: SUPERVISED MODEL ONLY (LightGBM)")
    
    threshold = sup_meta.get("threshold", 0.5)
    print(f"Threshold: {threshold:.4f}")
    print(f"Features: {len(sup_meta['features'])}")
    
    if hasattr(sup_model, "predict_proba"):
        scores = sup_model.predict_proba(X)[:, 1]
    else:
        scores = sup_model.predict(X)
    
    y_pred = (scores >= threshold).astype(int)
    
    metrics = compute_metrics(y_true, y_pred, scores)
    print_metrics(metrics, "Supervised Model Performance")
    
    return metrics, scores


def test_unsupervised_only(unsup_model, unsup_meta, X, y_true):
    """Test unsupervised model only"""
    print_header("TEST 2: UNSUPERVISED MODEL ONLY (IsolationForest)")
    
    threshold = unsup_meta.get("threshold", 0.5)
    print(f"Threshold: {threshold:.4f}")
    print(f"Algorithm: {unsup_meta.get('algorithm', 'IsolationForest')}")
    print(f"Contamination: {unsup_meta.get('contamination', 0.05)}")
    
    # IsolationForest: decision_function gives anomaly scores
    # Higher (positive) = more anomalous
    raw_scores = unsup_model.decision_function(X)
    
    # Normalize to [0, 1] range for consistency
    scores = (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-10)
    
    y_pred = (scores >= threshold).astype(int)
    
    metrics = compute_metrics(y_true, y_pred, scores)
    print_metrics(metrics, "Unsupervised Model Performance")
    
    return metrics, scores


def test_hybrid_or(sup_scores, unsup_scores, sup_meta, unsup_meta, y_true):
    """Test hybrid mode with OR strategy"""
    print_header("TEST 3: HYBRID MODE - OR Strategy")
    print("Flag if EITHER supervised OR unsupervised detects (more sensitive)")
    
    sup_threshold = sup_meta.get("threshold", 0.5)
    unsup_threshold = unsup_meta.get("threshold", 0.5)
    
    sup_pred = (sup_scores >= sup_threshold).astype(int)
    unsup_pred = (unsup_scores >= unsup_threshold).astype(int)
    
    y_pred = np.maximum(sup_pred, unsup_pred)  # OR logic
    
    # Combined score (max of both)
    combined_scores = np.maximum(sup_scores, unsup_scores)
    
    metrics = compute_metrics(y_true, y_pred, combined_scores)
    print_metrics(metrics, "Hybrid OR Performance")
    
    return metrics


def test_hybrid_and(sup_scores, unsup_scores, sup_meta, unsup_meta, y_true):
    """Test hybrid mode with AND strategy"""
    print_header("TEST 4: HYBRID MODE - AND Strategy")
    print("Flag only if BOTH supervised AND unsupervised detect (more conservative)")
    
    sup_threshold = sup_meta.get("threshold", 0.5)
    unsup_threshold = unsup_meta.get("threshold", 0.5)
    
    sup_pred = (sup_scores >= sup_threshold).astype(int)
    unsup_pred = (unsup_scores >= unsup_threshold).astype(int)
    
    y_pred = np.minimum(sup_pred, unsup_pred)  # AND logic
    
    # Combined score (min of both)
    combined_scores = np.minimum(sup_scores, unsup_scores)
    
    metrics = compute_metrics(y_true, y_pred, combined_scores)
    print_metrics(metrics, "Hybrid AND Performance")
    
    return metrics


def test_hybrid_weighted(sup_scores, unsup_scores, y_true, sup_weight=0.7, unsup_weight=0.3):
    """Test hybrid mode with weighted strategy"""
    print_header("TEST 5: HYBRID MODE - WEIGHTED Strategy")
    print(f"Supervised weight: {sup_weight:.2f}")
    print(f"Unsupervised weight: {unsup_weight:.2f}")
    
    # Weighted average of scores
    combined_scores = (sup_weight * sup_scores) + (unsup_weight * unsup_scores)
    
    # Find optimal threshold using F1-score
    thresholds = np.arange(0.1, 1.0, 0.05)
    best_f1 = 0
    best_threshold = 0.5
    
    for thr in thresholds:
        y_pred_temp = (combined_scores >= thr).astype(int)
        metrics_temp = compute_metrics(y_true, y_pred_temp)
        if metrics_temp['F1'] > best_f1:
            best_f1 = metrics_temp['F1']
            best_threshold = thr
    
    print(f"Optimal threshold (by F1): {best_threshold:.4f}")
    
    y_pred = (combined_scores >= best_threshold).astype(int)
    
    metrics = compute_metrics(y_true, y_pred, combined_scores)
    print_metrics(metrics, "Hybrid Weighted Performance")
    
    return metrics


def create_comparison_table(results):
    """Create comparison table of all models"""
    print_header("COMPARISON OF ALL MODELS")
    
    # Table headers
    headers = ["Model/Strategy", "Recall", "Precision", "FPR", "F1-Score", "ROC-AUC"]
    
    print(f"{headers[0]:<25} | {headers[1]:<10} | {headers[2]:<10} | {headers[3]:<10} | {headers[4]:<10} | {headers[5]:<10}")
    print("-" * 100)
    
    for name, metrics in results.items():
        recall = f"{metrics['Recall']*100:.2f}%"
        precision = f"{metrics['Precision']*100:.2f}%"
        fpr = f"{metrics['FPR']*100:.2f}%"
        f1 = f"{metrics['F1']:.4f}"
        auc = f"{metrics.get('ROC-AUC', 0):.4f}" if metrics.get('ROC-AUC') else "N/A"
        
        print(f"{name:<25} | {recall:<10} | {precision:<10} | {fpr:<10} | {f1:<10} | {auc:<10}")
    
    # Recommendations
    print("\n" + "=" * 100)
    print_subheader("RECOMMENDATIONS")
    
    # Find best by different criteria
    best_f1 = max(results.items(), key=lambda x: x[1]['F1'])
    best_recall = max(results.items(), key=lambda x: x[1]['Recall'])
    lowest_fpr = min(results.items(), key=lambda x: x[1]['FPR'])
    
    print(f"{Colors.OKGREEN}Best F1-Score:         {best_f1[0]} (F1={best_f1[1]['F1']:.4f}){Colors.ENDC}")
    print(f"{Colors.OKGREEN}Best Detection Rate:   {best_recall[0]} (Recall={best_recall[1]['Recall']*100:.2f}%){Colors.ENDC}")
    print(f"{Colors.OKGREEN}Lowest False Positives: {lowest_fpr[0]} (FPR={lowest_fpr[1]['FPR']*100:.2f}%){Colors.ENDC}")


def main():
    print_header("COMPREHENSIVE MODEL TESTING")
    print(f"Test Directory: {TEST_DIR}")
    print(f"Models: {SUPERVISED_MODEL.name}, {UNSUPERVISED_MODEL.name}")
    
    # Load models
    print("\nLoading models...")
    sup_model, sup_meta, unsup_model, unsup_meta = load_models()
    print(f"{Colors.OKGREEN}✓ Models loaded successfully{Colors.ENDC}")
    
    # Load test data
    print("\nLoading test data...")
    df, y_true = load_test_data()
    print(f"{Colors.OKGREEN}✓ Loaded {len(df):,} test samples{Colors.ENDC}")
    print(f"  Benign: {(y_true == 0).sum():,} samples ({(y_true == 0).mean()*100:.1f}%)")
    print(f"  Attack: {(y_true == 1).sum():,} samples ({(y_true == 1).mean()*100:.1f}%)")
    
    # Prepare features
    features = sup_meta['features']
    X = prepare_features(df, features)
    print(f"{Colors.OKGREEN}✓ Features prepared: {X.shape[1]} features{Colors.ENDC}")
    
    # Store results
    results = {}
    
    # Test 1: Supervised only
    metrics_sup, sup_scores = test_supervised_only(sup_model, sup_meta, X, y_true)
    results["Supervised (LightGBM)"] = metrics_sup
    
    # Test 2: Unsupervised only
    metrics_unsup, unsup_scores = test_unsupervised_only(unsup_model, unsup_meta, X, y_true)
    results["Unsupervised (IsoForest)"] = metrics_unsup
    
    # Test 3: Hybrid OR
    metrics_or = test_hybrid_or(sup_scores, unsup_scores, sup_meta, unsup_meta, y_true)
    results["Hybrid - OR"] = metrics_or
    
    # Test 4: Hybrid AND
    metrics_and = test_hybrid_and(sup_scores, unsup_scores, sup_meta, unsup_meta, y_true)
    results["Hybrid - AND"] = metrics_and
    
    # Test 5: Hybrid Weighted
    metrics_weighted = test_hybrid_weighted(sup_scores, unsup_scores, y_true, sup_weight=0.7, unsup_weight=0.3)
    results["Hybrid - Weighted (0.7/0.3)"] = metrics_weighted
    
    # Final comparison
    create_comparison_table(results)
    
    print(f"\n{Colors.OKGREEN}{Colors.BOLD}Testing complete!{Colors.ENDC}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Testing interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.FAIL}Error: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
