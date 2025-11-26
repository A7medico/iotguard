#!/usr/bin/env python3
"""
Analyze feature importance of the trained LightGBM model.
"""
import joblib
import json
import pandas as pd
import numpy as np
from pathlib import Path
# import matplotlib.pyplot as plt

def analyze_model_importance():
    """Load model and show feature importance."""
    
    model_path = Path("models/lightgbm.joblib")
    meta_path = Path("models/model_meta.json")
    
    if not model_path.exists() or not meta_path.exists():
        print("[ERROR] Model or metadata not found.")
        return

    print("=" * 60)
    print("Feature Importance Analysis")
    print("=" * 60)

    # Load model
    print(f"\n[*] Loading model from {model_path}...")
    model = joblib.load(model_path)
    
    with open(meta_path, "r") as f:
        meta = json.load(f)
    
    features = meta.get("features", [])
    print(f"[*] Model uses {len(features)} features.")

    # Get feature importance
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        
        # Create DataFrame
        df_imp = pd.DataFrame({
            "feature": features,
            "importance": importances
        })
        
        # Normalize importance
        df_imp["importance_normalized"] = df_imp["importance"] / df_imp["importance"].sum()
        
        # Sort
        df_imp = df_imp.sort_values("importance", ascending=False).reset_index(drop=True)
        
        print("\n[FEATURE IMPORTANCE RANKING]")
        print(f"{'Rank':<5} {'Feature':<20} {'Importance':<12} {'Percentage':<10}")
        print("-" * 50)
        
        for i, row in df_imp.iterrows():
            print(f"{i+1:<5} {row['feature']:<20} {row['importance']:<12.4f} {row['importance_normalized']*100:6.2f}%")
            
        # Check for dominance
        top_1_pct = df_imp.iloc[0]["importance_normalized"]
        if top_1_pct > 0.5:
            print(f"\n[WARNING] Heavy reliance on top feature: {df_imp.iloc[0]['feature']} ({top_1_pct*100:.1f}%)")
            print("The model might be vulnerable if this feature is manipulated.")
        else:
            print(f"\n[OK] Feature importance is distributed. Top feature: {df_imp.iloc[0]['feature']} ({top_1_pct*100:.1f}%)")

    else:
        print("[ERROR] Model does not support feature_importances_ attribute.")

if __name__ == "__main__":
    analyze_model_importance()
