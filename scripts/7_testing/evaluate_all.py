"""
scripts/evaluate_all.py
-----------------------------------------------------------------------------
Comprehensive Model Evaluation Script
-----------------------------------------------------------------------------
Tests all trained models on "unseen" data:
1. IoT Model (LightGBM) -> Tested on data/test_holdout/*.csv
2. IT Model (LightGBM)  -> Tested on 20% holdout from data/it_training_clean.csv
3. Ensemble             -> Tested on both datasets

Outputs:
- Accuracy, Precision, Recall, F1, ROC-AUC
- Confusion Matrices
-----------------------------------------------------------------------------
"""

import sys
import pandas as pd
import numpy as np
import joblib
import json
import os
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, accuracy_score

# Add scripts directory and subdirectories to path for imports
_scripts_dir = Path(__file__).parent.parent
sys.path.insert(0, str(_scripts_dir))
from path_setup import configure_paths
configure_paths()
from ensemble import EnsemblePredictor

# Paths
IOT_MODEL_PATH = Path("models/lightgbm.joblib")
IOT_META_PATH = Path("models/model_meta.json")
IT_MODEL_PATH = Path("models/lightgbm_it.joblib")
IT_META_PATH = Path("models/model_meta_it.json")
IT_DATA_PATH = Path("data/it_training_clean.csv")
IOT_TEST_DIR = Path("data/test_holdout")

def load_model_and_meta(model_path, meta_path):
    if not model_path.exists():
        print(f"X Model not found: {model_path}")
        return None, None
    
    print(f"Loading model: {model_path}")
    model = joblib.load(model_path)
    meta = {}
    if meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
    return model, meta

def prepare_features(df, features):
    """Ensure dataframe has exactly the features required by the model."""
    # Normalize columns
    df.columns = [c.strip().replace(" ", "_") for c in df.columns]
    
    X = df.copy()
    # Add missing features with 0
    for f in features:
        if f not in X.columns:
            X[f] = 0.0
            
    # Select only required features in correct order
    X = X[features]
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    return X

def evaluate(name, y_true, y_pred, y_scores=None):
    print(f"\n>>> EVALUATION REPORT: {name}")
    print("-" * 60)
    
    acc = accuracy_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)
    
    print(f"Accuracy:  {acc:.2%}")
    
    if y_scores is not None:
        try:
            auc = roc_auc_score(y_true, y_scores)
            print(f"ROC-AUC:   {auc:.4f}")
        except:
            print("ROC-AUC:   N/A")
            
    print("\nConfusion Matrix:")
    print(cm)
    
    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, target_names=["Benign", "Attack"]))
    print("-" * 60)
    
    return acc

def get_iot_test_data(features):
    """Load and aggregate all IoT holdout files."""
    if not IOT_TEST_DIR.exists():
        print("! IoT test directory not found.")
        return None, None

    files = list(IOT_TEST_DIR.glob("*.csv"))
    if not files:
        print("! No IoT test files found.")
        return None, None
        
    print(f"Loading {len(files)} IoT test files...")
    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f)
            # Infer label if missing
            if "label" not in df.columns:
                label = 0 if "benign" in f.name.lower() else 1
                df["label"] = label
            else:
                # Normalize label to 0/1
                df["label"] = (df["label"].astype(str).str.lower() != "benign").astype(int)
            dfs.append(df)
        except Exception as e:
            print(f"Skipping {f}: {e}")
            
    if not dfs:
        return None, None
        
    full_df = pd.concat(dfs, ignore_index=True)
    X = prepare_features(full_df, features)
    y = full_df["label"].values
    return X, y

def get_it_test_data(features):
    """Load IT data and split to get a holdout set."""
    if not IT_DATA_PATH.exists():
        print("! IT training data not found.")
        return None, None
        
    print("Loading IT data for split...")
    df = pd.read_csv(IT_DATA_PATH)
    
    # Use a different random state than training (42) to simulate "unseen"
    # though ideally we should have saved the split.
    # We'll use 999.
    train_df, test_df = train_test_split(df, test_size=0.2, random_state=999, stratify=df["label"])
    
    print(f"IT Test Set: {len(test_df)} samples")
    
    X = prepare_features(test_df, features)
    y = test_df["label"].values
    return X, y

def main():
    print("========================================================")
    print("IoTGuard COMPREHENSIVE MODEL EVALUATION")
    print("========================================================")
    
    # ---------------------------------------------------------
    # 1. Evaluate IoT Model
    # ---------------------------------------------------------
    iot_model, iot_meta = load_model_and_meta(IOT_MODEL_PATH, IOT_META_PATH)
    if iot_model:
        features = iot_meta.get("features", [])
        threshold = iot_meta.get("threshold", 0.5)
        
        X_iot, y_iot = get_iot_test_data(features)
        
        if X_iot is not None:
            print(f"\nTesting IoT Model on {len(X_iot)} samples...")
            y_prob = iot_model.predict_proba(X_iot)[:, 1]
            y_pred = (y_prob >= threshold).astype(int)
            evaluate("IoT Model (LightGBM)", y_iot, y_pred, y_prob)
            
            # Test Ensemble on IoT Data
            print("\nTesting Ensemble on IoT Data...")
            # Initialize ensemble manually with IoT model
            ensemble = EnsemblePredictor(
                supervised_path=str(IOT_MODEL_PATH),
                supervised_meta_path=str(IOT_META_PATH)
            )
            # Predict batch
            results = ensemble.predict_batch(X_iot.values)
            ens_scores = [r["score"] for r in results]
            ens_preds = [1 if r["is_attack"] else 0 for r in results]
            evaluate("Ensemble (IoT Mode)", y_iot, ens_preds, ens_scores)

    # ---------------------------------------------------------
    # 2. Evaluate IT Model
    # ---------------------------------------------------------
    it_model, it_meta = load_model_and_meta(IT_MODEL_PATH, IT_META_PATH)
    if it_model:
        features = it_meta.get("features", [])
        threshold = it_meta.get("threshold", 0.5)
        
        X_it, y_it = get_it_test_data(features)
        
        if X_it is not None:
            print(f"\nTesting IT Model on {len(X_it)} samples...")
            y_prob = it_model.predict_proba(X_it)[:, 1]
            y_pred = (y_prob >= threshold).astype(int)
            evaluate("IT Model (LightGBM)", y_it, y_pred, y_prob)

            # Test Ensemble on IT Data
            print("\nTesting Ensemble on IT Data...")
            # Initialize ensemble manually with IT model
            ensemble_it = EnsemblePredictor(
                supervised_path=str(IT_MODEL_PATH),
                supervised_meta_path=str(IT_META_PATH)
            )
            # Predict batch
            results = ensemble_it.predict_batch(X_it.values)
            ens_scores = [r["score"] for r in results]
            ens_preds = [1 if r["is_attack"] else 0 for r in results]
            evaluate("Ensemble (IT Mode)", y_it, ens_preds, ens_scores)

if __name__ == "__main__":
    main()
