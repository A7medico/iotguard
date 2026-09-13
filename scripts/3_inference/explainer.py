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
import hashlib
from collections import OrderedDict

# Suppress SHAP/numba warnings for cleaner output
warnings.filterwarnings("ignore")


class LRUCache:
    """Simple LRU cache for SHAP explanations."""
    
    def __init__(self, maxsize=100):
        self.cache = OrderedDict()
        self.maxsize = maxsize
        self.hits = 0
        self.misses = 0
    
    def _make_key(self, row_values: tuple) -> str:
        """Create a hash key from row values."""
        # Round floats to reduce cache fragmentation
        rounded = tuple(round(v, 4) if isinstance(v, float) else v for v in row_values)
        return hashlib.md5(str(rounded).encode()).hexdigest()
    
    def get(self, row_values: tuple):
        """Get cached value or None."""
        key = self._make_key(row_values)
        if key in self.cache:
            self.hits += 1
            # Move to end (most recently used)
            self.cache.move_to_end(key)
            return self.cache[key]
        self.misses += 1
        return None
    
    def set(self, row_values: tuple, value: str):
        """Cache a value."""
        key = self._make_key(row_values)
        if key in self.cache:
            self.cache.move_to_end(key)
        else:
            if len(self.cache) >= self.maxsize:
                # Remove oldest
                self.cache.popitem(last=False)
            self.cache[key] = value
    
    def stats(self) -> dict:
        """Return cache statistics."""
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {
            "hits": self.hits,
            "misses": self.misses,
            "size": len(self.cache),
            "maxsize": self.maxsize,
            "hit_rate_pct": round(hit_rate, 1)
        }


class RealTimeExplainer:
    """
    Real-time SHAP explainer with caching for performance.
    
    Features:
        - LRU cache to avoid recomputing explanations for similar inputs
        - Graceful fallback if SHAP initialization fails
        - Thread-safe (SHAP TreeExplainer is thread-safe for reads)
    """
    
    def __init__(self, model, feature_names, background_data=None, cache_size=100):
        """
        Initialize the explainer with the trained LightGBM model.
        
        Args:
            model: The trained model object (LGBMClassifier or similar).
            feature_names: List of feature names (strings).
            background_data: Optional DataFrame for background distribution.
            cache_size: Maximum number of explanations to cache.
        """
        self.model = model
        self.feature_names = list(feature_names)
        self._cache = LRUCache(maxsize=cache_size)
        
        # TreeExplainer is fast and optimized for trees (LightGBM/XGBoost/RF)
        try:
            tree_model = model
            if hasattr(model, "calibrated_classifiers_") and len(model.calibrated_classifiers_) > 0:
                first_clf = model.calibrated_classifiers_[0]
                tree_model = getattr(first_clf, "estimator", getattr(first_clf, "base_estimator", model))
            elif hasattr(model, "estimator"):
                tree_model = model.estimator
                
            self.explainer = shap.TreeExplainer(tree_model)
            self._initialized = True
        except Exception as e:
            print(f"[Explainer] Failed to init TreeExplainer: {e}")
            self.explainer = None
            self._initialized = False

    def explain_row(self, row_df: pd.DataFrame, top_n=3, use_cache=True):
        """
        Explain a single row prediction with optional caching.
        
        Args:
            row_df: A DataFrame with a single row (matching feature_names).
            top_n: Number of top contributing features to return.
            use_cache: Whether to use the LRU cache (default True).
            
        Returns:
            A string summarizing the top reasons, e.g., 
            "syn_ratio (+0.45), bytes_total (+0.21)"
        """
        if not self.explainer:
            return "Explainer not initialized"
        
        try:
            # Create cache key from row values
            row_values = tuple(row_df.iloc[0].values)
            
            # Check cache first
            if use_cache:
                cached = self._cache.get(row_values)
                if cached is not None:
                    return cached
            
            # Calculate SHAP values for this row
            # shap_values returns an array of shape (1, n_features)
            # or (1, n_features, n_classes) depending on model type
            shap_values = self.explainer.shap_values(row_df)
            
            # Handle binary classification output (might be list of arrays)
            if isinstance(shap_values, list):
                # Class 1 (Attack) is usually index 1
                vals = shap_values[1][0]
            elif len(shap_values.shape) == 3:
                vals = shap_values[0, :, 1]  # (samples, features, class)
            else:
                vals = shap_values[0]

            # vals is now a 1D array of contributions for Class 1 (Attack)
            
            # Pair features with their SHAP impact
            contributions = []
            for name, val in zip(self.feature_names, vals):
                contributions.append((name, float(val)))
            
            # Sort by absolute impact (or just positive impact if we only care why it IS an attack)
            # We care why score is HIGH, so we look for positive values.
            pos_contributions = [c for c in contributions if c[1] > 0]
            pos_contributions.sort(key=lambda x: x[1], reverse=True)
            
            top = pos_contributions[:top_n]
            
            if not top:
                result = "global bias"  # No specific feature pushed it up, likely base value
            else:
                reasons = []
                for name, val in top:
                    # Format: "feature (+0.12)"
                    val_str = f"+{val:.2f}"
                    reasons.append(f"{name} ({val_str})")
                result = ", ".join(reasons)
            
            # Cache the result
            if use_cache:
                self._cache.set(row_values, result)
            
            return result

        except Exception as e:
            return f"Explainer error: {str(e)}"
    
    def cache_stats(self) -> dict:
        """Return cache statistics for monitoring."""
        return self._cache.stats()
    
    @property
    def is_initialized(self) -> bool:
        """Check if explainer was initialized successfully."""
        return self._initialized

