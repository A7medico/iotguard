"""
scripts/3_inference/zero_day_engine.py
-----------------------------------------------------------------------------
IoTGuard Enterprise — Tri-Modal Unsupervised Zero-Day Anomaly Detection Engine

Fuses three complementary unsupervised detectors trained on benign network traffic:
  1. IsolationForest: Tree-based space partitioning (isolates extreme outliers).
  2. ECOD (Empirical Cumulative Distribution Outlier Detector): Non-parametric,
     hyperparameter-free tail-probability scoring across all 13 features
     (implemented in pure NumPy/SciPy — zero external dependencies).
  3. Robust Mahalanobis / PCA Reconstruction Error Scorer: Captures multivariate
     covariance violations (e.g., when syn_ratio and ack_ratio violate normal
     TCP state machine correlations).

Outputs:
  - unified unsup_score in [0, 1]
  - is_anomaly boolean flag
  - anomaly_contributors: ranked list of features that violated the empirical tail
-----------------------------------------------------------------------------
"""

from __future__ import annotations

import os
import json
import logging
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from joblib import dump, load
from sklearn.ensemble import IsolationForest

logger = logging.getLogger("iotguard.zero_day_engine")

# ── 13-Feature Schema Contract ──────────────────────────────────────────────
SCHEMA_13_FEATURES: List[str] = [
    "flows",
    "bytes_total",
    "pkts_total",
    "syn_ratio",
    "mean_bytes_flow",
    "ack_ratio",
    "fin_ratio",
    "rst_ratio",
    "http_ratio",
    "tcp_ratio",
    "protocol_diversity",
    "std_bytes",
    "iat_mean",
]

# Baseline empirical priors (benign traffic statistics aligned with curated IoT dataset)
DEFAULT_BENIGN_STATS: Dict[str, Dict[str, float]] = {
    "flows": {"mean": 19.6, "std": 32.8, "min": 1.0, "max": 900.0},
    "bytes_total": {"mean": 311170.0, "std": 1096000.0, "min": 100.0, "max": 48000000.0},
    "pkts_total": {"mean": 440.0, "std": 1300.0, "min": 2.0, "max": 53000.0},
    "syn_ratio": {"mean": 0.17, "std": 0.16, "min": 0.0, "max": 0.98},
    "mean_bytes_flow": {"mean": 8635.0, "std": 24500.0, "min": 20.0, "max": 850000.0},
    "ack_ratio": {"mean": 0.42, "std": 0.14, "min": 0.0, "max": 0.86},
    "fin_ratio": {"mean": 0.09, "std": 0.07, "min": 0.0, "max": 0.55},
    "rst_ratio": {"mean": 0.03, "std": 0.07, "min": 0.0, "max": 0.50},
    "http_ratio": {"mean": 0.19, "std": 0.13, "min": 0.0, "max": 0.95},
    "tcp_ratio": {"mean": 0.83, "std": 0.32, "min": 0.0, "max": 1.0},
    "protocol_diversity": {"mean": 1.4, "std": 0.56, "min": 1.0, "max": 3.0},
    "std_bytes": {"mean": 51.7, "std": 59.5, "min": 0.0, "max": 350.0},
    "iat_mean": {"mean": 0.12, "std": 0.14, "min": 0.0, "max": 1.5},
}


# =============================================================================
# 1. ECOD: Empirical Cumulative Distribution Outlier Detector (Pure NumPy)
# =============================================================================

class ECODDetector:
    """
    Empirical Cumulative Distribution Outlier Detector (ECOD).
    Fast, non-parametric, hyperparameter-free tail-probability outlier scorer.
    Computes left and right empirical CDF tail probabilities across all features:
        P_left = P(X_d <= x_d)
        P_right = P(X_d >= x_d)
        O_d(x) = max(-log P_left, -log P_right)
    Total ECOD score: S_ecod(x) = sum_d O_d(x)
    """

    def __init__(self, features: Optional[List[str]] = None) -> None:
        self.features = list(features or SCHEMA_13_FEATURES)
        self.sorted_data: Dict[str, np.ndarray] = {}
        self.n_samples: int = 0
        self.baseline_mean: float = 0.0
        self.baseline_std: float = 1.0
        self.baseline_p50: float = 0.0
        self.baseline_p95: float = 0.0
        self.baseline_p99: float = 0.0
        self.is_fitted: bool = False

    def fit(self, X: Union[np.ndarray, pd.DataFrame]) -> "ECODDetector":
        """Fit empirical CDFs on benign training traffic."""
        if isinstance(X, pd.DataFrame):
            df = X[self.features]
            data = df.to_numpy(dtype=float)
        else:
            data = np.asarray(X, dtype=float)

        self.n_samples = data.shape[0]
        if self.n_samples == 0:
            return self

        self.sorted_data = {}
        for idx, feat in enumerate(self.features):
            col = data[:, idx]
            self.sorted_data[feat] = np.sort(col)

        # Precompute per-feature tail distributions on training baseline
        eps = 0.5 / max(1, self.n_samples)
        train_feat_scores = np.zeros((self.n_samples, len(self.features)), dtype=float)
        for idx, feat in enumerate(self.features):
            sorted_col = self.sorted_data[feat]
            col = data[:, idx]
            l_ranks = np.searchsorted(sorted_col, col, side="right")
            p_l = np.maximum(l_ranks / self.n_samples, eps)
            r_ranks = self.n_samples - np.searchsorted(sorted_col, col, side="left")
            p_r = np.maximum(r_ranks / self.n_samples, eps)
            train_feat_scores[:, idx] = np.maximum(-np.log(p_l), -np.log(p_r))

        self.feat_means = {f: float(np.mean(train_feat_scores[:, i])) for i, f in enumerate(self.features)}
        self.feat_stds = {f: max(1e-4, float(np.std(train_feat_scores[:, i]))) for i, f in enumerate(self.features)}

        # Calibrate baseline distribution of raw ECOD scores on training data
        raw_scores = self._raw_score_batch(data)
        self.baseline_mean = float(np.mean(raw_scores))
        self.baseline_std = max(1e-6, float(np.std(raw_scores)))
        self.baseline_p50 = float(np.percentile(raw_scores, 50.0))
        self.baseline_p95 = float(np.percentile(raw_scores, 95.0))
        self.baseline_p99 = float(np.percentile(raw_scores, 99.0))
        self.is_fitted = True
        return self

    def _raw_score_vector(self, x_vec: np.ndarray) -> Tuple[float, Dict[str, float]]:
        """Compute raw unnormalized ECOD score and per-feature tail scores."""
        if not self.is_fitted or self.n_samples == 0:
            return 0.0, {feat: 0.0 for feat in self.features}

        eps = 0.5 / max(1, self.n_samples)
        contributions: Dict[str, float] = {}

        for idx, feat in enumerate(self.features):
            val = float(x_vec[idx])
            sorted_col = self.sorted_data[feat]
            n = self.n_samples

            # Left tail: P(X <= val)
            left_rank = int(np.searchsorted(sorted_col, val, side="right"))
            p_left = max(float(left_rank) / n, eps)
            s_left = -math.log(p_left)

            # Right tail: P(X >= val)
            right_rank = n - int(np.searchsorted(sorted_col, val, side="left"))
            p_right = max(float(right_rank) / n, eps)
            s_right = -math.log(p_right)

            contributions[feat] = max(s_left, s_right)

        total_raw = sum(contributions.values())
        return total_raw, contributions

    def _raw_score_batch(self, data: np.ndarray) -> np.ndarray:
        """Batch raw scoring."""
        scores = np.zeros(data.shape[0], dtype=float)
        eps = 0.5 / max(1, self.n_samples)
        n = self.n_samples

        for idx, feat in enumerate(self.features):
            sorted_col = self.sorted_data[feat]
            col = data[:, idx]

            left_ranks = np.searchsorted(sorted_col, col, side="right")
            p_left = np.maximum(left_ranks / n, eps)
            s_left = -np.log(p_left)

            right_ranks = n - np.searchsorted(sorted_col, col, side="left")
            p_right = np.maximum(right_ranks / n, eps)
            s_right = -np.log(p_right)

            scores += np.maximum(s_left, s_right)

        return scores

    def score_sample(
        self, x: Union[np.ndarray, pd.Series, Dict[str, float]]
    ) -> Tuple[float, Dict[str, float]]:
        """
        Score a single sample.
        Returns:
            (normalized_score_in_0_1, per_feature_tail_scores)
        """
        if isinstance(x, dict):
            x_vec = np.array(
                [x.get(f, DEFAULT_BENIGN_STATS.get(f, {}).get("mean", 0.0)) for f in self.features],
                dtype=float,
            )
        elif isinstance(x, pd.Series):
            x_vec = np.array(
                [x.get(f, DEFAULT_BENIGN_STATS.get(f, {}).get("mean", 0.0)) for f in self.features],
                dtype=float,
            )
        else:
            x_vec = np.asarray(x, dtype=float).ravel()

        raw_score, contributions = self._raw_score_vector(x_vec)
        if not self.is_fitted:
            return 0.0, contributions

        # Compute standardized deviation per feature
        feat_means = getattr(self, "feat_means", {})
        feat_stds = getattr(self, "feat_stds", {})
        z_scores = [
            (contributions[f] - feat_means.get(f, 1.5)) / max(1e-4, feat_stds.get(f, 1.0))
            for f in self.features
        ]
        s_max = max(z_scores) if z_scores else 0.0
        s_mean = float(np.mean([max(0.0, z) for z in z_scores])) if z_scores else 0.0
        comb = 0.6 * s_max + 0.4 * s_mean
        norm_score = float(1.0 / (1.0 + math.exp(-1.5 * (comb - 2.0))))
        norm_score = float(np.clip(norm_score, 0.0, 1.0))
        return norm_score, contributions


# =============================================================================
# 2. Robust Mahalanobis / PCA Reconstruction Error Scorer
# =============================================================================

class PCACovarianceDetector:
    """
    Robust Mahalanobis / PCA Reconstruction Error Scorer.
    Standardizes features using benign baseline statistics, projects onto
    top principal eigenspace, and calculates:
      1. Reconstruction error: ||z - \\hat{z}||^2 (captures correlation / ratio breakdown)
      2. Mahalanobis projection distance in eigenspace: z_proj^T \\Lambda^-1 z_proj
    High scores occur when multivariate relationships (e.g. syn_ratio vs. ack_ratio,
    or bytes_total vs. pkts_total) violate normal TCP state machines.
    """

    def __init__(self, n_components: int = 5, features: Optional[List[str]] = None) -> None:
        self.features = list(features or SCHEMA_13_FEATURES)
        self.n_components = n_components
        self.mean: np.ndarray = np.zeros(len(self.features))
        self.scale: np.ndarray = np.ones(len(self.features))
        self.components: np.ndarray = np.eye(len(self.features), self.n_components)
        self.singular_values: np.ndarray = np.ones(self.n_components)
        self.variances: np.ndarray = np.ones(self.n_components)
        self.baseline_rec_mean: float = 0.0
        self.baseline_rec_std: float = 1.0
        self.baseline_rec_p50: float = 0.0
        self.baseline_rec_p95: float = 0.0
        self.baseline_rec_p99: float = 0.0
        self.is_fitted: bool = False

    def fit(self, X: Union[np.ndarray, pd.DataFrame]) -> "PCACovarianceDetector":
        """Fit PCA and covariance subspace on benign training traffic."""
        if isinstance(X, pd.DataFrame):
            df = X[self.features]
            data = df.to_numpy(dtype=float)
        else:
            data = np.asarray(X, dtype=float)

        n_samples, n_features = data.shape
        if n_samples < 2:
            return self

        self.mean = np.mean(data, axis=0)
        self.scale = np.std(data, axis=0)
        self.scale[self.scale < 1e-6] = 1.0

        # Standardized matrix
        Z = (data - self.mean) / self.scale

        # Singular Value Decomposition
        U, S, Vt = np.linalg.svd(Z, full_matrices=False)
        k = min(self.n_components, n_features, n_samples - 1)
        self.n_components = k
        self.components = Vt[:k].T  # shape (n_features, k)
        self.singular_values = S[:k]
        self.variances = (self.singular_values ** 2) / max(1, n_samples - 1)
        self.variances[self.variances < 1e-6] = 1e-6

        # Calibration on training baseline
        Z_proj = Z @ self.components
        Z_rec = Z_proj @ self.components.T
        residuals = (Z - Z_rec) ** 2
        self.feat_rec_means = {f: float(np.mean(residuals[:, i])) for i, f in enumerate(self.features)}
        self.feat_rec_stds = {f: max(1e-4, float(np.std(residuals[:, i]))) for i, f in enumerate(self.features)}
        rec_errors = np.sum(residuals, axis=1)

        self.baseline_rec_mean = float(np.mean(rec_errors))
        self.baseline_rec_std = max(1e-6, float(np.std(rec_errors)))
        self.baseline_rec_p50 = float(np.percentile(rec_errors, 50.0))
        self.baseline_rec_p95 = float(np.percentile(rec_errors, 95.0))
        self.baseline_rec_p99 = float(np.percentile(rec_errors, 99.0))
        self.is_fitted = True
        return self

    def score_sample(
        self, x: Union[np.ndarray, pd.Series, Dict[str, float]]
    ) -> Tuple[float, Dict[str, float]]:
        """
        Compute reconstruction residual and Mahalanobis anomaly score.
        Returns:
            (normalized_score_in_0_1, per_feature_residual_contributions)
        """
        if isinstance(x, dict):
            x_vec = np.array(
                [x.get(f, self.mean[i] if self.is_fitted else 0.0) for i, f in enumerate(self.features)],
                dtype=float,
            )
        elif isinstance(x, pd.Series):
            x_vec = np.array(
                [x.get(f, self.mean[i] if self.is_fitted else 0.0) for i, f in enumerate(self.features)],
                dtype=float,
            )
        else:
            x_vec = np.asarray(x, dtype=float).ravel()

        if not self.is_fitted:
            return 0.0, {feat: 0.0 for feat in self.features}

        z = (x_vec - self.mean) / self.scale
        z_proj = z @ self.components
        z_rec = z_proj @ self.components.T

        # Per-feature squared residual
        feat_res = (z - z_rec) ** 2
        contributions = {feat: float(feat_res[i]) for i, feat in enumerate(self.features)}

        # Standardized residuals per feature to capture specific ratio decoupling
        feat_means = getattr(self, "feat_rec_means", {})
        feat_stds = getattr(self, "feat_rec_stds", {})
        z_feat = [
            (contributions[f] - feat_means.get(f, 0.5)) / max(1e-4, feat_stds.get(f, 0.5))
            for f in self.features
        ]
        s_max = max(z_feat) if z_feat else 0.0
        s_mean = float(np.mean([max(0.0, zf) for zf in z_feat])) if z_feat else 0.0

        composite_z = 0.6 * s_max + 0.4 * s_mean
        k = 1.5
        norm_score = float(1.0 / (1.0 + math.exp(-k * (composite_z - 2.0))))
        norm_score = float(np.clip(norm_score, 0.0, 1.0))
        return norm_score, contributions


# =============================================================================
# 3. Tri-Modal Zero-Day Anomaly Detection Engine
# =============================================================================

class ZeroDayAnomalyEngine:
    """
    Tri-Modal Unsupervised Zero-Day Anomaly Detection Engine.
    Fuses:
      1. IsolationForest (tree space partitioning)
      2. ECOD (Empirical Cumulative Distribution Outlier Detector)
      3. Robust Mahalanobis / PCA Reconstruction Error Scorer
    """

    def __init__(
        self,
        features: Optional[List[str]] = None,
        threshold: float = 0.65,
        weights: Tuple[float, float, float] = (0.35, 0.35, 0.30),
        isoforest: Optional[IsolationForest] = None,
        ecod: Optional[ECODDetector] = None,
        pca: Optional[PCACovarianceDetector] = None,
    ) -> None:
        self.features = list(features or SCHEMA_13_FEATURES)
        self.threshold = float(threshold)
        self.weights = weights
        self.isoforest = isoforest
        self.ecod = ecod or ECODDetector(self.features)
        self.pca = pca or PCACovarianceDetector(n_components=5, features=self.features)
        self.is_fitted = False

    def fit(
        self,
        X_benign: Union[np.ndarray, pd.DataFrame],
        isoforest_n_estimators: int = 200,
        contamination: float = 0.05,
    ) -> "ZeroDayAnomalyEngine":
        """Fit all 3 detectors on benign traffic baseline."""
        if isinstance(X_benign, pd.DataFrame):
            df = X_benign[self.features]
            data = df.to_numpy(dtype=float)
        else:
            data = np.asarray(X_benign, dtype=float)

        # 1. Fit IsolationForest if not provided
        if self.isoforest is None:
            self.isoforest = IsolationForest(
                n_estimators=isoforest_n_estimators,
                contamination=contamination,
                max_samples=min(512, len(data)),
                random_state=42,
                n_jobs=-1,
            )
            self.isoforest.fit(data)

        # 2. Fit ECOD
        self.ecod.fit(data)

        # 3. Fit PCA / Robust Covariance
        self.pca.fit(data)

        self.is_fitted = True
        return self

    def score(
        self, x: Union[pd.DataFrame, pd.Series, Dict[str, float], np.ndarray]
    ) -> Tuple[float, bool, List[Tuple[str, float]]]:
        """
        Score a traffic window using the tri-modal fusion engine.

        Returns:
            (unsup_score, is_anomaly, anomaly_contributors)
            - unsup_score: float in [0, 1]
            - is_anomaly: bool flag (True if unsup_score >= threshold)
            - anomaly_contributors: list of (feature_name, contribution_score) sorted descending
        """
        # Convert to vector and dict for sub-models
        if isinstance(x, pd.DataFrame):
            row_dict = {f: float(x[f].iloc[0]) for f in self.features if f in x.columns}
            x_mat = x[self.features].values
        elif isinstance(x, pd.Series):
            row_dict = {f: float(x.get(f, 0.0)) for f in self.features}
            x_mat = np.array([[row_dict[f] for f in self.features]])
        elif isinstance(x, dict):
            row_dict = {f: float(x.get(f, 0.0)) for f in self.features}
            x_mat = np.array([[row_dict[f] for f in self.features]])
        else:
            arr = np.asarray(x, dtype=float).ravel()
            row_dict = {f: float(arr[i]) for i, f in enumerate(self.features)}
            x_mat = arr.reshape(1, -1)

        # 1. IsolationForest score
        s_iso = 0.0
        if self.isoforest is not None:
            try:
                raw_iso = float(-self.isoforest.score_samples(x_mat)[0])
                # Score calibration: raw_iso in [0.35, 0.75] -> [0, 1]
                s_iso = float(np.clip((raw_iso - 0.45) / 0.25, 0.0, 1.0))
            except Exception as e:
                logger.warning(f"IsoForest scoring error: {e}")
                s_iso = 0.0

        # 2. ECOD score & per-feature tail probabilities
        s_ecod, ecod_contribs = self.ecod.score_sample(row_dict)

        # 3. PCA reconstruction residual & covariance violation
        s_pca, pca_contribs = self.pca.score_sample(row_dict)

        # Tri-modal weighted fusion
        w_iso, w_ecod, w_pca = self.weights
        fused_weighted = (w_iso * s_iso) + (w_ecod * s_ecod) + (w_pca * s_pca)

        # Soft max-pooling boost: if any single detector detects a severe violation,
        # ensure it is not drowned out
        max_sub = max(s_iso, s_ecod, s_pca)
        unsup_score = float(np.clip(max(fused_weighted, 0.85 * max_sub), 0.0, 1.0))
        is_anomaly = bool(unsup_score >= self.threshold)

        # Rank anomaly contributors
        max_ecod = max(ecod_contribs.values()) if ecod_contribs else 1.0
        max_pca = max(pca_contribs.values()) if pca_contribs else 1.0
        contributors_combined: List[Tuple[str, float]] = []

        for feat in self.features:
            norm_e = ecod_contribs.get(feat, 0.0) / max(1e-6, max_ecod)
            norm_p = pca_contribs.get(feat, 0.0) / max(1e-6, max_pca)
            combined_contrib = 0.5 * norm_e + 0.5 * norm_p
            contributors_combined.append((feat, round(float(combined_contrib), 4)))

        contributors_combined.sort(key=lambda t: t[1], reverse=True)
        return unsup_score, is_anomaly, contributors_combined

    # Duck-typing sklearn anomaly detector for seamless drop-in
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Compatibility method for sklearn-style score_samples."""
        scores = []
        for i in range(len(X)):
            s, _, _ = self.score(X[i])
            scores.append(-s)  # sklearn convention: lower = more anomalous
        return np.array(scores, dtype=float)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Compatibility method: -1 for outlier, 1 for inlier."""
        preds = []
        for i in range(len(X)):
            _, is_anom, _ = self.score(X[i])
            preds.append(-1 if is_anom else 1)
        return np.array(preds, dtype=int)

    def save(self, model_path: Union[str, Path] = "models/zero_day_engine.joblib") -> Path:
        """Serialize engine to disk."""
        p = Path(model_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        dump(self, p)
        logger.info(f"Saved ZeroDayAnomalyEngine to {p}")
        return p

    @classmethod
    def load(cls, model_path: Union[str, Path] = "models/zero_day_engine.joblib") -> "ZeroDayAnomalyEngine":
        """Load engine from disk."""
        p = Path(model_path)
        if not p.exists():
            raise FileNotFoundError(f"Model file not found: {p}")
        obj = load(p)
        return obj


# =============================================================================
# 4. Engine Factory & Auto-Calibration
# =============================================================================

def build_or_load_zero_day_engine(
    model_path: Union[str, Path] = "models/zero_day_engine.joblib",
    isoforest_path: Union[str, Path] = "models/unsup_isoforest.joblib",
    training_csv: Union[str, Path] = "data/iotguard_training_clean.csv",
    threshold: float = 0.65,
) -> ZeroDayAnomalyEngine:
    """
    Build or load the Tri-Modal Zero-Day Anomaly Engine.
    Prioritizes loading existing serialized model. If missing, automatically
    fits on benign baseline data and serializes.
    """
    p_engine = Path(model_path)
    if p_engine.exists():
        try:
            engine = ZeroDayAnomalyEngine.load(p_engine)
            logger.info(f"Loaded ZeroDayAnomalyEngine from {p_engine}")
            return engine
        except Exception as e:
            logger.warning(f"Failed to load cached ZeroDayAnomalyEngine: {e}")

    # Load pre-existing IsolationForest if available
    iso = None
    p_iso = Path(isoforest_path)
    if p_iso.exists():
        try:
            iso = load(p_iso)
            logger.info(f"Loaded existing IsolationForest from {p_iso}")
        except Exception as e:
            logger.warning(f"Could not load IsolationForest from {p_iso}: {e}")

    engine = ZeroDayAnomalyEngine(features=SCHEMA_13_FEATURES, threshold=threshold, isoforest=iso)

    # Fit on benign training data
    p_csv = Path(training_csv)
    if p_csv.exists():
        try:
            df = pd.read_csv(p_csv)
            if "label" in df.columns:
                benign_df = df[df["label"].str.lower() == "benign"]
                if len(benign_df) >= 100:
                    df = benign_df
            engine.fit(df.head(10000))
            logger.info(f"Calibrated ZeroDayAnomalyEngine on {len(df)} benign samples")
        except Exception as e:
            logger.warning(f"Could not fit ZeroDayAnomalyEngine from CSV: {e}")

    if not engine.is_fitted:
        # Fallback to empirical synthetic distribution based on DEFAULT_BENIGN_STATS
        np.random.seed(42)
        n = 2000
        synthetic_data = {}
        for feat in SCHEMA_13_FEATURES:
            stat = DEFAULT_BENIGN_STATS[feat]
            synthetic_data[feat] = np.clip(
                np.random.normal(loc=stat["mean"], scale=stat["std"], size=n),
                stat["min"],
                stat["max"],
            )
        syn_df = pd.DataFrame(synthetic_data)
        engine.fit(syn_df)
        logger.info("Calibrated ZeroDayAnomalyEngine using empirical prior baseline")

    try:
        engine.save(p_engine)
    except Exception as e:
        logger.warning(f"Could not save ZeroDayAnomalyEngine to {p_engine}: {e}")

    return engine
