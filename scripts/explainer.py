"""
scripts/explainer.py
-----------------------------------------------------------------------------
IoTGuard Component — Real‑Time Model Explainability (SHAP)

Position in pipeline
    lightgbm.joblib + model_meta.json
        →  decision_loop.py
        →  [THIS FILE]  (SHAP explanations)
        →  alerts.jsonl / dashboard ("Reason (XAI)" column)

High‑level responsibilities
    - Wrap SHAP's TreeExplainer for the trained LightGBM model so that, for any
      single feature row, we can compute **per‑feature contributions** to the
      attack score.
    - Extract the **top positive contributions** (features that push the score
      toward "attack") and format them as a short, human‑readable string like:
          "syn_ratio (+0.45), bytes_total (+0.21)".
    - Be fast enough for real‑time usage inside the streaming decision loop.
-----------------------------------------------------------------------------
"""

import shap
import pandas as pd
import numpy as np
import warnings

# Suppress SHAP/numba warnings for cleaner output
warnings.filterwarnings("ignore")

class RealTimeExplainer:
    def __init__(self, model, feature_names, background_data=None):
        """
        Initialize the explainer with the trained LightGBM model.
        
        Args:
            model: The trained model object (LGBMClassifier or similar).
            feature_names: List of feature names (strings).
            background_data: Optional DataFrame for background distribution (not strictly needed for TreeExplainer).
        """
        self.model = model
        self.feature_names = feature_names
        
        # TreeExplainer is fast and optimized for trees (LightGBM/XGBoost/RF)
        # providing 'marginal' contributions (approximate but fast) or 'true' SHAP values.
        # For real-time, we want speed.
        try:
            self.explainer = shap.TreeExplainer(model)
        except Exception as e:
            print(f"[Explainer] Failed to init TreeExplainer: {e}")
            self.explainer = None

    def explain_row(self, row_df: pd.DataFrame, top_n=3):
        """
        Explain a single row prediction.
        
        Args:
            row_df: A DataFrame with a single row (matching feature_names).
            top_n: Number of top contributing features to return.
            
        Returns:
            A string summarizing the top reasons, e.g., 
            "syn_ratio (+0.45), bytes_total (+0.21)"
        """
        if not self.explainer:
            return "Explainer not initialized"
            
        try:
            # Calculate SHAP values for this row
            # shap_values returns an array of shape (1, n_features)
            # or (1, n_features, n_classes) depending on model type
            shap_values = self.explainer.shap_values(row_df)
            
            # Handle binary classification output (might be list of arrays)
            if isinstance(shap_values, list):
                # Class 1 (Attack) is usually index 1
                vals = shap_values[1][0]
            elif len(shap_values.shape) == 3:
                 vals = shap_values[0, :, 1] # (samples, features, class)
            else:
                vals = shap_values[0]

            # vals is now a 1D array of contributions for Class 1 (Attack)
            
            # Pair features with their SHAP impact
            contributions = []
            for name, val in zip(self.feature_names, vals):
                contributions.append((name, val))
            
            # Sort by absolute impact (or just positive impact if we only care why it IS an attack)
            # We care why score is HIGH, so we look for positive values.
            pos_contributions = [c for c in contributions if c[1] > 0]
            pos_contributions.sort(key=lambda x: x[1], reverse=True)
            
            top = pos_contributions[:top_n]
            
            if not top:
                return "global bias" # No specific feature pushed it up, likely base value
            
            reasons = []
            for name, val in top:
                # Format: "feature (+0.12)"
                # We can also show the actual feature value if we wanted, but keep it simple first.
                val_str = f"+{val:.2f}"
                reasons.append(f"{name} ({val_str})")
                
            return ", ".join(reasons)

        except Exception as e:
            return f"Explainer error: {str(e)}"

