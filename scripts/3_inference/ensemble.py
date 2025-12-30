"""
scripts/ensemble.py
=============================================================================
IoTGuard — Ensemble Model Predictions
=============================================================================

PIPELINE POSITION:
    This module combines predictions from multiple models:
    
    ┌─────────────────┐
    │   LightGBM      │──┐
    │  (supervised)   │  │     ┌─────────────────┐     ┌─────────────────┐
    └─────────────────┘  ├──>  │   ensemble.py   │ --> │ Final Decision  │
    ┌─────────────────┐  │     │  (this file)    │     │ (attack/benign) │
    │ IsolationForest │──┘     └─────────────────┘     └─────────────────┘
    │  (unsupervised) │
    └─────────────────┘

WHY ENSEMBLE:
    Different models have different strengths:
    
    SUPERVISED (LightGBM):
        + Excellent at detecting known attack patterns
        + High precision when trained on labeled data
        - May miss novel/zero-day attacks
        - Requires labeled training data
    
    UNSUPERVISED (IsolationForest):
        + Can detect novel anomalies
        + Doesn't need attack labels
        + Catches unusual patterns
        - Higher false positive rate
        - Less accurate on known attacks
    
    ENSEMBLE COMBINES BOTH:
        - Better coverage (catches more attacks)
        - More robust to novel threats
        - Calibrated confidence scores

COMBINATION STRATEGIES:
    weighted: score = w1*supervised + w2*unsupervised (default)
    or:       alert if EITHER model detects
    and:      alert only if BOTH models detect
    max:      use the higher of the two scores

CONFIGURATION (in configs/model.yaml):
    ensemble:
      strategy: weighted
      supervised_weight: 0.7
      unsupervised_weight: 0.3
      calibrate: true

USAGE EXAMPLES:
    # Basic usage
    from ensemble import get_ensemble
    ensemble = get_ensemble()
    result = ensemble.predict(features)
    print(f"Score: {result['score']}, Attack: {result['is_attack']}")
    
    # With explanation
    result = ensemble.predict(features)
    print(ensemble.explain_prediction(result))
    
    # API usage (in api_dashboard.py)
    @app.post("/api/v1/predict")
    def predict():
        ensemble = get_ensemble()
        return ensemble.predict(request.json["features"])
=============================================================================
"""

import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import numpy as np

# ============================================================================
# OPTIONAL DEPENDENCIES
# These are needed for loading models, but the module can still be imported
# if they're missing (just won't work)
# ============================================================================
try:
    from joblib import load
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

logger = logging.getLogger("iotguard.ensemble")


# ============================================================================
# CONFIGURATION
# Load ensemble settings from model.yaml
# ============================================================================

def _load_config() -> dict:
    """
    Load ensemble configuration from model.yaml.
    
    CONFIGURATION OPTIONS:
        strategy: how to combine model scores
        supervised_weight: weight for LightGBM (0-1)
        unsupervised_weight: weight for IsolationForest (0-1)
        calibrate: whether to apply probability calibration
    
    Returns:
        Configuration dict, or {} if not found
    """
    cfg_path = Path("configs/model.yaml")
    if cfg_path.exists() and YAML_AVAILABLE:
        try:
            cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            return cfg.get("ensemble", {})
        except Exception:
            pass
    return {}


class EnsemblePredictor:
    """
    Ensemble predictor combining supervised and unsupervised models.
    
    ARCHITECTURE:
        EnsemblePredictor
        ├── supervised_model (LightGBM)       - Loaded from models/lightgbm.joblib
        ├── unsupervised_model (IsoForest)    - Loaded from models/unsup_isoforest.joblib
        │
        ├── predict(X)                        - Main prediction method
        │   ├── _get_supervised_score()       - Get LightGBM probability
        │   ├── _get_unsupervised_score()     - Get IsoForest anomaly score
        │   ├── _combine_scores()             - Apply ensemble strategy
        │   └── _calibrate_score()            - Probability calibration
        │
        └── explain_prediction()              - Human-readable explanation
    
    THREAD SAFETY:
        This class is thread-safe after initialization.
        Multiple threads can call predict() simultaneously.
    """
    
    def __init__(
        self,
        supervised_path: Optional[str] = None,
        unsupervised_path: str = "models/unsup_isoforest.joblib",
        supervised_meta_path: Optional[str] = None,
        unsupervised_meta_path: str = "models/unsup_meta.json"
    ):
        """
        Initialize the ensemble predictor by loading models.
        
        INITIALIZATION STEPS:
            1. Load configuration from model.yaml
            2. Resolve model paths based on IOTGUARD_ENV (iot/it)
            3. Load supervised model (LightGBM)
            4. Load unsupervised model (IsolationForest)
        
        Args:
            supervised_path: Path to LightGBM joblib file (overrides env config)
            unsupervised_path: Path to IsolationForest joblib file
            supervised_meta_path: Path to supervised model metadata
            unsupervised_meta_path: Path to unsupervised model metadata
        """
        import os
        
        # Initialize model references
        self.supervised_model = None
        self.unsupervised_model = None
        self.supervised_threshold = 0.5
        self.unsupervised_threshold = 0.5
        self.features = []
        
        # ---------------------------------------------------------------
        # Load configuration from model.yaml
        # ---------------------------------------------------------------
        cfg = _load_config()  # This gets 'ensemble' section
        
        # We also need the 'models' section for path resolution
        full_cfg = {}
        cfg_path = Path("configs/model.yaml")
        if cfg_path.exists() and YAML_AVAILABLE:
            try:
                full_cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            except Exception:
                pass
        
        # Resolve paths if not explicitly provided
        if not supervised_path:
            env_mode = os.getenv("IOTGUARD_ENV", "iot").lower()
            models_cfg = full_cfg.get("models", {})
            env_cfg = models_cfg.get(env_mode, {})
            
            supervised_path = env_cfg.get("path", "models/lightgbm.joblib")
            if not supervised_meta_path:
                supervised_meta_path = env_cfg.get("meta", "models/model_meta.json")
            
            logger.info(f"🌍 Ensemble using environment: {env_mode.upper()}")
        
        # Fallback defaults if still None
        supervised_path = supervised_path or "models/lightgbm.joblib"
        supervised_meta_path = supervised_meta_path or "models/model_meta.json"
        
        # Ensemble strategy: how to combine model scores
        # Options: "weighted", "or", "and", "max"
        self.strategy = cfg.get("strategy", "weighted")
        
        # Weights for weighted strategy (should sum to 1.0)
        self.sup_weight = cfg.get("supervised_weight", 0.7)
        self.unsup_weight = cfg.get("unsupervised_weight", 0.3)
        
        # Whether to apply probability calibration
        self.calibrate = cfg.get("calibrate", True)
        
        # ---------------------------------------------------------------
        # Load both models
        # ---------------------------------------------------------------
        self._load_models(
            supervised_path, unsupervised_path,
            supervised_meta_path, unsupervised_meta_path
        )
    
    def _load_models(
        self,
        sup_path: str,
        unsup_path: str,
        sup_meta_path: str,
        unsup_meta_path: str
    ) -> None:
        """
        Load both models and their metadata from disk.
        
        MODEL FILES:
            models/lightgbm.joblib        - Trained LightGBM classifier
            models/model_meta.json        - Features, threshold for LightGBM
            models/unsup_isoforest.joblib - Trained IsolationForest
            models/unsup_meta.json        - Threshold for IsolationForest
        
        ERROR HANDLING:
            If a model fails to load, we log the error but continue.
            The ensemble can work with just one model (degraded mode).
        """
        if not JOBLIB_AVAILABLE:
            logger.error("joblib not installed, cannot load models")
            return
        
        # ---------------------------------------------------------------
        # Load supervised model (LightGBM)
        # ---------------------------------------------------------------
        try:
            if Path(sup_path).exists():
                self.supervised_model = load(sup_path)
                
                # Load metadata (threshold, feature order)
                if Path(sup_meta_path).exists():
                    meta = json.loads(Path(sup_meta_path).read_text(encoding="utf-8"))
                    self.supervised_threshold = meta.get("threshold", 0.5)
                    self.features = meta.get("features", [])
                
                logger.info(
                    f"✅ Loaded supervised model "
                    f"(threshold={self.supervised_threshold:.3f})"
                )
        except Exception as e:
            logger.error(f"Failed to load supervised model: {e}")
        
        # ---------------------------------------------------------------
        # Load unsupervised model (IsolationForest)
        # ---------------------------------------------------------------
        try:
            if Path(unsup_path).exists():
                self.unsupervised_model = load(unsup_path)
                
                # Load metadata (threshold)
                if Path(unsup_meta_path).exists():
                    meta = json.loads(Path(unsup_meta_path).read_text(encoding="utf-8"))
                    self.unsupervised_threshold = meta.get("threshold", 0.5)
                
                logger.info(
                    f"✅ Loaded unsupervised model "
                    f"(threshold={self.unsupervised_threshold:.3f})"
                )
        except Exception as e:
            logger.error(f"Failed to load unsupervised model: {e}")
    
    def _get_supervised_score(self, X: np.ndarray) -> np.ndarray:
        """
        Get probability scores from the supervised model.
        
        HOW LIGHTGBM SCORES WORK:
            LightGBM's predict_proba() returns [P(benign), P(attack)]
            We take the second column: P(attack)
            Score range: 0.0 (definitely benign) to 1.0 (definitely attack)
        
        Args:
            X: Feature array of shape (n_samples, n_features)
            
        Returns:
            Array of attack probabilities
        """
        if self.supervised_model is None:
            # No model loaded, return neutral score
            return np.full(len(X), 0.5)
        
        try:
            proba = self.supervised_model.predict_proba(X)
            return proba[:, 1]  # Column 1 = P(attack)
        except Exception as e:
            logger.error(f"Supervised prediction failed: {e}")
            return np.full(len(X), 0.5)
    
    def _get_unsupervised_score(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores from the unsupervised model.
        
        HOW ISOLATION FOREST SCORES WORK:
            IsolationForest.score_samples() returns negative scores:
                - More negative = more anomalous
                - Around 0 = normal
                - Positive = very normal
            
            We convert to 0-1 range where:
                - 0.0 = definitely normal
                - 1.0 = definitely anomalous
        
        CONVERSION FORMULA:
            We use a sigmoid transformation:
            output = 1 / (1 + exp(raw_score * 2))
            
            This maps:
                raw = -1.0 -> output ≈ 0.88 (very anomalous)
                raw =  0.0 -> output = 0.50 (uncertain)
                raw =  1.0 -> output ≈ 0.12 (very normal)
        
        Args:
            X: Feature array
            
        Returns:
            Array of anomaly scores (0-1, higher = more anomalous)
        """
        if self.unsupervised_model is None:
            return np.full(len(X), 0.5)
        
        try:
            # Get raw scores (more negative = more anomalous)
            raw_scores = self.unsupervised_model.score_samples(X)
            
            # Convert to 0-1 range using sigmoid
            # Multiply by 2 to make the transformation steeper
            scores = 1 / (1 + np.exp(raw_scores * 2))
            return scores
        except Exception as e:
            logger.error(f"Unsupervised prediction failed: {e}")
            return np.full(len(X), 0.5)
    
    def _calibrate_score(self, score: float) -> float:
        """
        Apply Platt scaling-like calibration to convert score to probability.
        
        WHY CALIBRATE:
            Raw model scores may not be well-calibrated probabilities.
            A score of 0.7 might not mean 70% chance of being an attack.
            Calibration adjusts scores to be more accurate probabilities.
        
        HOW IT WORKS:
            We apply a sigmoid transformation with learned parameters:
            calibrated = 1 / (1 + exp(-(a * score + b)))
            
            Parameters a and b would ideally be learned from validation data.
            Here we use reasonable defaults that stretch the score distribution.
        
        Args:
            score: Raw combined score (0-1)
            
        Returns:
            Calibrated probability (0-1)
        """
        if not self.calibrate:
            return score
        
        # Sigmoid calibration parameters
        # a > 1 makes the curve steeper (more confident)
        # b shifts the midpoint
        # NOTE: Using milder calibration (a=1.2, b=0) to avoid over-confident predictions
        a, b = 1.2, 0.0
        calibrated = 1 / (1 + np.exp(-(a * (score - 0.5) * 4)))
        return float(np.clip(calibrated, 0, 1))
    
    def _compute_confidence(
        self,
        sup_score: float,
        unsup_score: float,
        combined_score: float
    ) -> float:
        """
        Compute confidence in the prediction.
        
        CONFIDENCE IS HIGHER WHEN:
            1. Both models agree (both high or both low)
            2. Combined score is far from 0.5 (clear decision)
        
        FORMULA:
            confidence = 0.4 * agreement + 0.6 * extremity
            
            agreement: 1.0 if models agree, 0.5 if they disagree
            extremity: how far the combined score is from 0.5
        
        Args:
            sup_score: Supervised model score
            unsup_score: Unsupervised model score
            combined_score: Final combined score
            
        Returns:
            Confidence value (0-1)
        """
        # Do both models agree on the classification?
        sup_pred = sup_score > self.supervised_threshold
        unsup_pred = unsup_score > self.unsupervised_threshold
        agreement = 1.0 if sup_pred == unsup_pred else 0.5
        
        # How extreme is the combined score? (0.5 = neutral, 0 or 1 = extreme)
        extremity = abs(combined_score - 0.5) * 2
        
        # Weighted combination
        confidence = (agreement * 0.4 + extremity * 0.6)
        return float(np.clip(confidence, 0, 1))
    
    def predict_single(self, X: np.ndarray) -> Dict[str, Any]:
        """
        Make ensemble prediction for a single sample.
        
        PREDICTION FLOW:
            1. Get score from supervised model
            2. Get score from unsupervised model
            3. Combine scores using strategy (weighted/or/and/max)
            4. Apply calibration
            5. Compare to threshold
            6. Compute confidence
        
        Args:
            X: Feature array of shape (1, n_features)
            
        Returns:
            Dictionary containing:
                score: Final combined score (0-1)
                is_attack: Boolean classification
                threshold: Threshold used
                confidence: Confidence in prediction (0-1)
                supervised_score: Score from LightGBM
                unsupervised_score: Score from IsolationForest
                strategy: Ensemble strategy used
                
        EXAMPLE:
            result = ensemble.predict_single(features)
            
            if result["is_attack"]:
                print(f"Attack detected! Score: {result['score']:.2%}")
                print(f"Confidence: {result['confidence']:.2%}")
        """
        X = np.atleast_2d(X)
        
        # ---------------------------------------------------------------
        # Get scores from both models
        # ---------------------------------------------------------------
        sup_score = float(self._get_supervised_score(X)[0])
        unsup_score = float(self._get_unsupervised_score(X)[0])
        
        # ---------------------------------------------------------------
        # Combine scores using selected strategy
        # ---------------------------------------------------------------
        if self.strategy == "weighted":
            # Weighted average: default strategy
            combined = (
                self.sup_weight * sup_score + 
                self.unsup_weight * unsup_score
            )
        elif self.strategy == "or":
            # Alert if EITHER model is suspicious
            # (More sensitive, might have more false positives)
            combined = max(sup_score, unsup_score)
        elif self.strategy == "and":
            # Alert only if BOTH models agree
            # (More conservative, might miss some attacks)
            combined = min(sup_score, unsup_score)
        elif self.strategy == "max":
            # Take the maximum (same as "or" for binary)
            combined = max(sup_score, unsup_score)
        else:
            # Fallback: simple average
            combined = (sup_score + unsup_score) / 2
        
        # ---------------------------------------------------------------
        # Apply probability calibration
        # ---------------------------------------------------------------
        calibrated = self._calibrate_score(combined)
        
        # ---------------------------------------------------------------
        # Compute weighted threshold (also calibrated for consistency)
        # ---------------------------------------------------------------
        raw_threshold = (
            self.sup_weight * self.supervised_threshold +
            self.unsup_weight * self.unsupervised_threshold
        )
        # Apply same calibration to threshold so scales match
        threshold = self._calibrate_score(raw_threshold) if self.calibrate else raw_threshold
        
        # ---------------------------------------------------------------
        # Build result
        # ---------------------------------------------------------------
        return {
            "score": round(calibrated, 4),
            "is_attack": calibrated >= threshold,
            "threshold": round(threshold, 4),
            "confidence": round(
                self._compute_confidence(sup_score, unsup_score, calibrated), 
                4
            ),
            "supervised_score": round(sup_score, 4),
            "unsupervised_score": round(unsup_score, 4),
            "strategy": self.strategy
        }
    
    def predict(self, X: np.ndarray) -> Dict[str, Any]:
        """
        Make ensemble prediction.
        
        Alias for predict_single(). For batch predictions, use predict_batch().
        
        Args:
            X: Feature array
            
        Returns:
            Prediction dictionary
        """
        return self.predict_single(X)
    
    def predict_batch(self, X: np.ndarray) -> list:
        """
        Make predictions for multiple samples efficiently.
        
        Args:
            X: Feature array of shape (n_samples, n_features)
            
        Returns:
            List of prediction dictionaries
        """
        X = np.atleast_2d(X)
        
        # 1. Get scores for the whole batch at once (Vectorized)
        sup_scores = self._get_supervised_score(X)
        unsup_scores = self._get_unsupervised_score(X)
        
        results = []
        
        # 2. Process each result
        for i in range(len(X)):
            sup_score = float(sup_scores[i])
            unsup_score = float(unsup_scores[i])
            
            # Combine
            if self.strategy == "weighted":
                combined = (self.sup_weight * sup_score + self.unsup_weight * unsup_score)
            elif self.strategy == "or":
                combined = max(sup_score, unsup_score)
            elif self.strategy == "and":
                combined = min(sup_score, unsup_score)
            elif self.strategy == "max":
                combined = max(sup_score, unsup_score)
            else:
                combined = (sup_score + unsup_score) / 2
            
            # Calibrate
            calibrated = self._calibrate_score(combined)
            
            # Threshold (also calibrated for consistency)
            raw_threshold = (
                self.sup_weight * self.supervised_threshold +
                self.unsup_weight * self.unsupervised_threshold
            )
            threshold = self._calibrate_score(raw_threshold) if self.calibrate else raw_threshold
            
            # Confidence
            confidence = self._compute_confidence(sup_score, unsup_score, calibrated)
            
            results.append({
                "score": round(calibrated, 4),
                "is_attack": calibrated >= threshold,
                "threshold": round(threshold, 4),
                "confidence": round(confidence, 4),
                "supervised_score": round(sup_score, 4),
                "unsupervised_score": round(unsup_score, 4),
                "strategy": self.strategy
            })
            
        return results
    
    def explain_prediction(self, result: Dict[str, Any]) -> str:
        """
        Generate human-readable explanation of a prediction.
        
        USE CASE:
            For debugging or display in dashboard UI.
        
        Args:
            result: Prediction dictionary from predict()
            
        Returns:
            Multi-line explanation string
            
        EXAMPLE OUTPUT:
            🚨 THREAT DETECTED (score: 85.00%)
               Strategy: weighted
               Supervised model: 92.00%
               Unsupervised model: 71.00%
               Confidence: 88.00%
               ⚠️ Both models strongly agree on threat
        """
        lines = []
        
        if result["is_attack"]:
            lines.append(f"🚨 THREAT DETECTED (score: {result['score']:.2%})")
        else:
            lines.append(f"✅ Normal traffic (score: {result['score']:.2%})")
        
        lines.append(f"   Strategy: {result['strategy']}")
        lines.append(f"   Supervised model: {result['supervised_score']:.2%}")
        lines.append(f"   Unsupervised model: {result['unsupervised_score']:.2%}")
        lines.append(f"   Confidence: {result['confidence']:.2%}")
        
        # Add interpretation
        if result["supervised_score"] > 0.7 and result["unsupervised_score"] > 0.7:
            lines.append("   ⚠️ Both models strongly agree on threat")
        elif result["supervised_score"] > 0.7:
            lines.append("   📊 Supervised model shows high confidence")
        elif result["unsupervised_score"] > 0.7:
            lines.append("   📈 Unsupervised model detects anomaly")
        
        return "\n".join(lines)


# ============================================================================
# SINGLETON PATTERN
# Single global instance for convenient import
# ============================================================================
_ensemble: Optional[EnsemblePredictor] = None


def get_ensemble() -> EnsemblePredictor:
    """
    Get or create the global ensemble predictor.
    
    USAGE:
        from ensemble import get_ensemble
        ensemble = get_ensemble()
        result = ensemble.predict(features)
    
    WHY SINGLETON:
        - Models only loaded once (expensive operation)
        - Consistent configuration across application
        - Memory efficient (models not duplicated)
    
    Returns:
        The global EnsemblePredictor instance
    """
    global _ensemble
    if _ensemble is None:
        _ensemble = EnsemblePredictor()
    return _ensemble


# ============================================================================
# STANDALONE TESTING
# ============================================================================
if __name__ == "__main__":
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )
    
    print("=" * 60)
    print("IoTGuard Ensemble Predictor Test")
    print("=" * 60)
    
    # Create ensemble
    ensemble = EnsemblePredictor()
    
    print(f"\nConfiguration:")
    print(f"  Strategy: {ensemble.strategy}")
    print(f"  Supervised weight: {ensemble.sup_weight}")
    print(f"  Unsupervised weight: {ensemble.unsup_weight}")
    print(f"  Supervised model loaded: {ensemble.supervised_model is not None}")
    print(f"  Unsupervised model loaded: {ensemble.unsupervised_model is not None}")
    
    # Test with sample features (13 features as per model.yaml)
    print("\nTest prediction with sample features:")
    test_features = np.array([[
        100,    # flows
        50000,  # bytes_total
        100,    # pkts_total
        0.2,    # syn_ratio
        500,    # mean_bytes_flow
        0.5,    # ack_ratio
        0.1,    # fin_ratio
        0.0,    # rst_ratio
        0.3,    # http_ratio
        0.8,    # tcp_ratio
        5,      # protocol_diversity
        1000,   # std_bytes
        0.5     # iat_mean
    ]])
    
    result = ensemble.predict(test_features)
    print(ensemble.explain_prediction(result))
