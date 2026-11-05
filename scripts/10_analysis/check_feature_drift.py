"""
scripts/10_analysis/check_feature_drift.py
=============================================================================
IoTGuard Phase 6 — Online Feature Drift Detection & Distribution Monitoring
=============================================================================

Capabilities:
  1. Statistical Drift Metrics:
     - Population Stability Index (PSI): Measures population divergence across
       binned quantile distributions.
       * PSI < 0.10  : Stable / No drift
       * 0.10 <= PSI < 0.25 : Moderate drift
       * PSI >= 0.25 : Significant drift (action required)
     - Kolmogorov-Smirnov (KS) 2-Sample Test: Non-parametric test for equality
       of continuous one-dimensional distributions.
  2. Fleet Continual Learning Trigger:
     Evaluates incoming sliding windows against baseline training distributions
     (`data/iotguard_training_clean.csv`) across the 13-feature schema. When
     distribution drift is detected, triggers or recommends a federated model sync.
  3. Importable Module & Standalone CLI:
     Provides `FeatureDriftDetector` class for runtime inference/API calls and
     a formatted terminal table when executed directly.
=============================================================================
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd

logger = logging.getLogger("iotguard.drift")

try:
    from scipy.stats import ks_2samp
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False

SCHEMA_13_FEATURES = [
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


# ============================================================================
# 1. Statistical Drift Functions (PSI & KS)
# ============================================================================

def calculate_psi(
    baseline: Union[np.ndarray, pd.Series, List[float]],
    target: Union[np.ndarray, pd.Series, List[float]],
    num_buckets: int = 10,
    epsilon: float = 1e-4,
) -> float:
    """
    Calculate the Population Stability Index (PSI) between two numeric samples.

    Formula:
        PSI = sum((T_i - B_i) * ln((T_i + eps) / (B_i + eps)))

    Args:
        baseline: Reference / training data array.
        target: Live / production data array.
        num_buckets: Number of quantile buckets to evaluate.
        epsilon: Smoothing factor to avoid division by zero or log(0).

    Returns:
        PSI score as a positive float rounded to 4 decimals.
    """
    b = np.asarray(baseline, dtype=float)
    t = np.asarray(target, dtype=float)

    # Filter NaNs and Infs
    b = b[np.isfinite(b)]
    t = t[np.isfinite(t)]

    if len(b) < 2 or len(t) < 2:
        return 0.0

    # If both baseline and target are constant and equal
    if np.all(b == b[0]) and np.all(t == b[0]):
        return 0.0

    # Determine quantile bin edges from baseline
    try:
        quantiles = np.linspace(0, 100, num_buckets + 1)
        bins = np.percentile(b, quantiles)
        bins = np.unique(bins)
        if len(bins) < 2:
            # Fallback to uniform bins if quantiles collapse
            bins = np.linspace(min(b.min(), t.min()), max(b.max(), t.max()), num_buckets + 1)
            bins = np.unique(bins)
    except Exception:
        bins = np.linspace(min(b.min(), t.min()), max(b.max(), t.max()), num_buckets + 1)
        bins = np.unique(bins)

    if len(bins) < 2:
        return 0.0

    # Ensure bins cover full range of both distributions
    bins[0] = min(bins[0], b.min(), t.min()) - 1e-6
    bins[-1] = max(bins[-1], b.max(), t.max()) + 1e-6

    # Calculate bucket counts
    b_counts, _ = np.histogram(b, bins=bins)
    t_counts, _ = np.histogram(t, bins=bins)

    # Compute proportions
    b_prop = (b_counts / max(len(b), 1)) + epsilon
    t_prop = (t_counts / max(len(t), 1)) + epsilon

    # Re-normalize to sum to 1.0
    b_prop = b_prop / np.sum(b_prop)
    t_prop = t_prop / np.sum(t_prop)

    # Compute PSI
    psi_value = np.sum((t_prop - b_prop) * np.log(t_prop / b_prop))
    return float(round(max(0.0, psi_value), 4))


def calculate_ks(
    baseline: Union[np.ndarray, pd.Series, List[float]],
    target: Union[np.ndarray, pd.Series, List[float]],
) -> Tuple[float, float]:
    """
    Compute Kolmogorov-Smirnov 2-sample statistic and p-value.
    Returns:
        (ks_statistic: float, p_value: float)
    """
    b = np.asarray(baseline, dtype=float)
    t = np.asarray(target, dtype=float)

    b = b[np.isfinite(b)]
    t = t[np.isfinite(t)]

    if len(b) < 2 or len(t) < 2:
        return (0.0, 1.0)

    if SCIPY_AVAILABLE:
        try:
            res = ks_2samp(b, t)
            return (float(round(res.statistic, 4)), float(round(res.pvalue, 6)))
        except Exception:
            pass

    # Pure numpy fallback for two-sample KS test
    data1 = np.sort(b)
    data2 = np.sort(t)
    n1 = len(data1)
    n2 = len(data2)

    data_all = np.concatenate([data1, data2])
    cdf1 = np.searchsorted(data1, data_all, side="right") / n1
    cdf2 = np.searchsorted(data2, data_all, side="right") / n2

    d_stat = float(np.max(np.abs(cdf1 - cdf2)))
    # Asymptotic p-value approximation
    en = np.sqrt(n1 * n2 / (n1 + n2))
    p_approx = np.exp(-2 * (en * d_stat) ** 2) if en * d_stat > 0 else 1.0

    return (float(round(d_stat, 4)), float(round(min(1.0, max(0.0, p_approx)), 6)))


def evaluate_feature_drift(
    baseline: Union[np.ndarray, pd.Series, List[float]],
    target: Union[np.ndarray, pd.Series, List[float]],
    feature_name: str,
) -> Dict[str, Any]:
    """
    Perform a complete distribution drift evaluation for a single feature.
    """
    b = np.asarray(baseline, dtype=float)
    t = np.asarray(target, dtype=float)
    b = b[np.isfinite(b)]
    t = t[np.isfinite(t)]

    psi = calculate_psi(b, t)
    ks_stat, p_val = calculate_ks(b, t)

    b_mean = float(np.mean(b)) if len(b) > 0 else 0.0
    t_mean = float(np.mean(t)) if len(t) > 0 else 0.0
    delta_pct = 0.0 if b_mean == 0 else ((t_mean - b_mean) / abs(b_mean)) * 100.0

    # Severity classification based on industry-standard PSI thresholds
    if psi >= 0.25:
        severity = "high"
    elif psi >= 0.10:
        severity = "moderate"
    else:
        severity = "low"

    # Flag drift if PSI is high or KS shows statistically significant high divergence
    drift_detected = (severity == "high") or (ks_stat >= 0.25 and p_val < 0.01)

    return {
        "feature": feature_name,
        "psi": psi,
        "ks_stat": ks_stat,
        "p_value": p_val,
        "severity": severity,
        "drift_detected": drift_detected,
        "baseline_mean": round(b_mean, 4),
        "target_mean": round(t_mean, 4),
        "mean_delta_pct": round(delta_pct, 2),
    }


# ============================================================================
# 2. FeatureDriftDetector Class
# ============================================================================

class FeatureDriftDetector:
    """
    Fleet-wide continuous distribution drift analyzer.

    Monitors incoming production flow windows against the baseline model
    training distribution across all 13 schema features.
    """

    def __init__(
        self,
        baseline_df: Optional[pd.DataFrame] = None,
        baseline_path: Union[str, Path] = "data/iotguard_training_clean.csv",
        features: Optional[List[str]] = None,
    ):
        self.features = features or SCHEMA_13_FEATURES
        self.baseline_path = Path(baseline_path)
        self.baseline_df = baseline_df

        if self.baseline_df is None and self.baseline_path.exists():
            try:
                df = pd.read_csv(self.baseline_path)
                # Keep only valid numeric feature columns
                cols = [c for c in self.features if c in df.columns]
                self.baseline_df = df[cols].apply(pd.to_numeric, errors="coerce")
            except Exception as e:
                logger.warning(f"Could not load baseline CSV at {self.baseline_path}: {e}")

    def check_drift(
        self,
        live_data: Union[pd.DataFrame, str, Path] = "data/features.csv",
        sample_size: int = 2000,
    ) -> Dict[str, Any]:
        """
        Evaluate live sliding window features against the baseline distribution.

        Args:
            live_data: DataFrame, CSV path, or Path to live features buffer.
            sample_size: Max recent rows to sample from live data.

        Returns:
            Dict containing overall drift metrics, feature-level breakdown,
            and action recommendation.
        """
        if self.baseline_df is None or self.baseline_df.empty:
            return {
                "ok": False,
                "error": "Baseline dataset not available for drift comparison",
                "drift_detected": False,
                "recommendation": "BASELINE_UNAVAILABLE",
            }

        # Load live target data
        df_live: Optional[pd.DataFrame] = None
        if isinstance(live_data, pd.DataFrame):
            df_live = live_data.copy()
        else:
            live_path = Path(live_data)
            if live_path.exists():
                try:
                    df_live = pd.read_csv(live_path)
                except Exception as e:
                    return {
                        "ok": False,
                        "error": f"Failed reading live data at {live_path}: {e}",
                        "drift_detected": False,
                        "recommendation": "LIVE_DATA_UNAVAILABLE",
                    }

        if df_live is None or df_live.empty:
            return {
                "ok": False,
                "error": "No live features available to evaluate",
                "drift_detected": False,
                "recommendation": "INSUFFICIENT_LIVE_DATA",
            }

        # Keep recent slice if large
        if len(df_live) > sample_size:
            df_live = df_live.iloc[-sample_size:]

        results: List[Dict[str, Any]] = []
        psi_scores: List[float] = []
        high_drift_features: List[str] = []
        moderate_drift_features: List[str] = []

        for feat in self.features:
            if feat not in self.baseline_df.columns or feat not in df_live.columns:
                continue

            b_vals = self.baseline_df[feat].dropna().values
            t_vals = pd.to_numeric(df_live[feat], errors="coerce").dropna().values

            if len(b_vals) < 2 or len(t_vals) < 2:
                continue

            feat_res = evaluate_feature_drift(b_vals, t_vals, feat)
            results.append(feat_res)
            psi_scores.append(feat_res["psi"])

            if feat_res["severity"] == "high":
                high_drift_features.append(feat)
            elif feat_res["severity"] == "moderate":
                moderate_drift_features.append(feat)

        mean_psi = float(round(np.mean(psi_scores), 4)) if psi_scores else 0.0
        max_psi = float(round(np.max(psi_scores), 4)) if psi_scores else 0.0

        drift_detected = (len(high_drift_features) > 0) or (mean_psi >= 0.15)

        # Formulate actionable recommendation for continual learning
        if len(high_drift_features) >= 2 or mean_psi >= 0.25:
            recommendation = "TRIGGER_FEDERATED_SYNC"
        elif drift_detected:
            recommendation = "MONITOR_DRIFT_ACTIVE"
        else:
            recommendation = "FLEET_STABLE"

        return {
            "ok": True,
            "drift_detected": drift_detected,
            "recommendation": recommendation,
            "mean_psi": mean_psi,
            "max_psi": max_psi,
            "features_evaluated": len(results),
            "high_drift_features": high_drift_features,
            "moderate_drift_features": moderate_drift_features,
            "feature_details": results,
            "sample_size": len(df_live),
        }


# ============================================================================
# 3. CLI Entry Point
# ============================================================================

def main():
    """Terminal utility to inspect drift between training and live features."""
    detector = FeatureDriftDetector()
    report = detector.check_drift("data/features.csv")

    if not report.get("ok"):
        print(f"[!] Drift check failed: {report.get('error')}")
        return

    print("=" * 72)
    print("IoTGuard Online Feature Drift Report (Training vs. Live)")
    print(f"Status: {report['recommendation']} | Mean PSI: {report['mean_psi']:.4f} | Max PSI: {report['max_psi']:.4f}")
    print("=" * 72)
    print(f"{'Feature':<22} {'Train Mean':>12} {'Live Mean':>12} {'PSI':>8} {'KS Stat':>9} {'Severity':>10}")
    print("-" * 72)

    for item in report.get("feature_details", []):
        sev_icon = "🔴" if item["severity"] == "high" else ("🟡" if item["severity"] == "moderate" else "🟢")
        print(
            f"{item['feature']:<22} "
            f"{item['baseline_mean']:12.2f} "
            f"{item['target_mean']:12.2f} "
            f"{item['psi']:8.4f} "
            f"{item['ks_stat']:9.4f} "
            f"{sev_icon} {item['severity']:>8}"
        )
    print("=" * 72)


if __name__ == "__main__":
    main()
