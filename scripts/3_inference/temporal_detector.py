"""
scripts/3_inference/temporal_detector.py
-----------------------------------------------------------------------------
IoTGuard Component — Stateful Temporal Sequence & Drift Detector (Phase 2)

Detects stealthy, multi-stage, and low-and-slow campaigns spanning multiple
consecutive time windows (e.g., slow port scans, creeping half-open SYN floods,
sustained HTTP credential stuffing, or connection-frequency accumulation).

Standard LightGBM and IsolationForest models evaluate each 10-second window
independently. Attackers who intentionally keep single-window metrics below
the 0.90 detection threshold can be captured here by tracking temporal drift,
trend slopes, and multi-window feature consistency.

Key Capabilities:
  1. Rolling Deque Buffer:
     Maintains rolling windows (K=6 to 12 windows, 1-2 minutes) per source IP
     and globally across the 13 canonical features.
  2. Fast Statistical Temporal Drift / Trend Detector:
     Computes least-squares linear slopes, monotonic step ratios, baseline
     relative escalations, and endpoint elevations for:
       - rst_ratio   (stealth port scanning / rejected probes)
       - syn_ratio   (half-open reconnaissance / slow SYN flood)
       - flows       (connection count accumulation)
       - http_ratio  (creeping L7 brute-force / API scraping)
  3. Rolling Window Feature Aggregator & Sequence Model Hook:
     Extracts rolling statistical summaries (mean, std, delta, slopes) and
     supports optional TCN/GRU/MLP sequence model callables.
  4. Decision Boost Calculation:
     Generates a normalized temporal anomaly score and risk boost [0.0, 1.0]
     to elevate borderline single-window events over the policy threshold.
-----------------------------------------------------------------------------
"""

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd


# ── Canonical 13 Features ───────────────────────────────────────────────────
CANONICAL_FEATURES = [
    "flows", "bytes_total", "pkts_total", "syn_ratio", "mean_bytes_flow",
    "ack_ratio", "fin_ratio", "rst_ratio",
    "http_ratio", "tcp_ratio", "protocol_diversity",
    "std_bytes", "iat_mean",
]

DEFAULT_TRACKED_DRIFT_FEATURES = [
    "rst_ratio",
    "syn_ratio",
    "flows",
    "http_ratio",
]


@dataclass
class TemporalResult:
    """Structured result from a temporal sequence evaluation."""
    temporal_score: float = 0.0          # Combined temporal risk score in [0.0, 1.0]
    is_temporal_anomaly: bool = False    # True if temporal_score >= drift_threshold
    drift_score: float = 0.0             # Statistical drift score in [0.0, 1.0]
    sequence_score: Optional[float] = None  # Score from sequence model hook (if used)
    boost: float = 0.0                   # Decision score boost (temporal_score * boost_weight)
    drifting_features: List[str] = field(default_factory=list)
    trend_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    window_count: int = 0
    entity_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "temporal_score": round(self.temporal_score, 4),
            "is_temporal_anomaly": self.is_temporal_anomaly,
            "drift_score": round(self.drift_score, 4),
            "sequence_score": round(self.sequence_score, 4) if self.sequence_score is not None else None,
            "boost": round(self.boost, 4),
            "drifting_features": self.drifting_features,
            "trend_details": self.trend_details,
            "window_count": self.window_count,
            "entity_id": self.entity_id,
        }


# ── Statistical Drift Calculation ───────────────────────────────────────────

def compute_linear_slope(values: List[float]) -> float:
    """
    Compute ordinary least-squares slope across uniform time steps t = 0..N-1.
    Slope m = sum((t - t_bar) * (y - y_bar)) / sum((t - t_bar)^2).
    """
    n = len(values)
    if n < 2:
        return 0.0

    t = np.arange(n, dtype=float)
    t_bar = (n - 1) / 2.0
    denom = (n * (n * n - 1.0)) / 12.0
    if denom <= 0:
        return 0.0

    y = np.array(values, dtype=float)
    y_bar = float(np.mean(y))
    num = float(np.sum((t - t_bar) * (y - y_bar)))
    return num / denom


def compute_monotonic_ratio(values: List[float], tolerance: float = 1e-4) -> float:
    """
    Fraction of consecutive time-steps that are non-decreasing.
    A sustained creeping attack will have high monotonic ratio (e.g. >= 0.75).
    """
    n = len(values)
    if n < 2:
        return 0.0
    increases = sum(1 for i in range(1, n) if values[i] >= values[i - 1] - tolerance)
    return float(increases / (n - 1))


def score_feature_drift(
    feature_name: str,
    values: List[float],
) -> Tuple[float, Dict[str, Any]]:
    """
    Evaluate statistical drift for a single tracked feature over N windows.

    Returns:
        (score in [0.0, 1.0], details_dict)
    """
    n = len(values)
    if n < 3:
        return 0.0, {"error": "insufficient_windows"}

    y = [float(v) for v in values]
    curr = y[-1]
    baseline = y[0]
    y_min = min(y)
    y_max = max(y)
    delta = curr - baseline
    slope = compute_linear_slope(y)
    mono_ratio = compute_monotonic_ratio(y)

    score = 0.0

    if feature_name in ("rst_ratio", "syn_ratio", "http_ratio"):
        # Normalized ratio features [0.0, 1.0]
        # Creeping probe indicators:
        # 1. Slope: slope >= 0.04/window is significant
        slope_comp = min(1.0, max(0.0, slope / 0.05))
        # 2. Delta: total rise >= 0.20 over window
        delta_comp = min(1.0, max(0.0, delta / 0.20))
        # 3. Monotonicity: >= 0.60
        mono_comp = max(0.0, (mono_ratio - 0.5) * 2.0)
        # 4. Absolute current elevation:
        elev_thresh = 0.08 if feature_name == "rst_ratio" else 0.15
        elev_comp = min(1.0, max(0.0, (curr - elev_thresh) / 0.25))

        if delta > 0.04 and curr >= elev_thresh:
            raw_score = (
                0.35 * slope_comp +
                0.35 * delta_comp +
                0.15 * mono_comp +
                0.15 * elev_comp
            )
            score = float(np.clip(raw_score, 0.0, 1.0))
        else:
            score = 0.0

    elif feature_name == "flows":
        # Volumetric count feature (typically 5 to 50 for quiet IoT nodes)
        # Creeping scan or connection build-up
        rel_increase = (curr - baseline) / max(1.0, baseline)
        slope_norm = min(1.0, max(0.0, slope / 6.0))
        rel_comp = min(1.0, max(0.0, rel_increase / 2.0))
        mono_comp = max(0.0, (mono_ratio - 0.5) * 2.0)

        if curr >= 25 and delta >= 10 and curr > baseline * 1.3:
            raw_score = (
                0.40 * slope_norm +
                0.40 * rel_comp +
                0.20 * mono_comp
            )
            score = float(np.clip(raw_score, 0.0, 1.0))
        else:
            score = 0.0

    else:
        # Generic numerical feature fallback
        if y_max > y_min:
            norm_delta = delta / max(1.0, abs(baseline))
            score = float(np.clip(max(0.0, norm_delta) * mono_ratio, 0.0, 1.0))

    details = {
        "current": round(curr, 4),
        "baseline": round(baseline, 4),
        "min": round(y_min, 4),
        "max": round(y_max, 4),
        "delta": round(delta, 4),
        "slope": round(slope, 5),
        "monotonic_ratio": round(mono_ratio, 3),
        "score": round(score, 4),
    }
    return score, details


# ── Rolling Window Feature Aggregator ────────────────────────────────────────

class RollingWindowAggregator:
    """
    Computes statistical sequence aggregations over sliding windows of the
    13 canonical features. Useful for extracting temporal context vectors or
    feeding downstream sequence models.
    """

    def __init__(self, features: Optional[List[str]] = None):
        self.features = features or list(CANONICAL_FEATURES)

    def aggregate(self, window_matrix: np.ndarray) -> Dict[str, Any]:
        """
        Args:
            window_matrix: 2D array of shape (N, num_features).

        Returns:
            Dictionary containing temporal summary statistics.
        """
        if window_matrix.ndim != 2 or window_matrix.shape[0] == 0:
            return {}

        n_samples, n_feats = window_matrix.shape
        means = np.mean(window_matrix, axis=0)
        stds = np.std(window_matrix, axis=0)
        mins = np.min(window_matrix, axis=0)
        maxs = np.max(window_matrix, axis=0)
        deltas = window_matrix[-1] - window_matrix[0]

        # Calculate slopes for each feature
        slopes = np.zeros(n_feats)
        for j in range(n_feats):
            slopes[j] = compute_linear_slope(window_matrix[:, j].tolist())

        result: Dict[str, Any] = {
            "window_count": n_samples,
            "means": dict(zip(self.features, means)),
            "stds": dict(zip(self.features, stds)),
            "deltas": dict(zip(self.features, deltas)),
            "slopes": dict(zip(self.features, slopes)),
        }
        return result

    def compute_anomaly_index(self, window_matrix: np.ndarray) -> float:
        """
        Heuristic multivariate sequence volatility / escalation index in [0.0, 1.0].
        """
        if window_matrix.shape[0] < 3:
            return 0.0

        # Focus on ratios and flow variances
        idx_rst = self.features.index("rst_ratio") if "rst_ratio" in self.features else -1
        idx_syn = self.features.index("syn_ratio") if "syn_ratio" in self.features else -1
        idx_flow = self.features.index("flows") if "flows" in self.features else -1

        sub_scores = []
        if idx_rst >= 0:
            s_rst, _ = score_feature_drift("rst_ratio", window_matrix[:, idx_rst].tolist())
            sub_scores.append(s_rst)
        if idx_syn >= 0:
            s_syn, _ = score_feature_drift("syn_ratio", window_matrix[:, idx_syn].tolist())
            sub_scores.append(s_syn)
        if idx_flow >= 0:
            s_fl, _ = score_feature_drift("flows", window_matrix[:, idx_flow].tolist())
            sub_scores.append(s_fl)

        return float(max(sub_scores)) if sub_scores else 0.0


# ── Temporal Detector Engine ─────────────────────────────────────────────────

class TemporalDetector:
    """
    Stateful rolling-window detector for multi-stage & low-and-slow attacks.

    Maintains rolling deques of consecutive traffic windows, tracks creeping
    drift across key reconnaissance features, supports custom sequence models,
    and calculates risk score boosts.
    """

    def __init__(
        self,
        window_size: int = 8,
        min_windows: int = 4,
        drift_threshold: float = 0.50,
        boost_weight: float = 0.25,
        tracked_features: Optional[List[str]] = None,
        sequence_model: Optional[Callable[[np.ndarray], float]] = None,
    ):
        """
        Args:
            window_size: Maximum rolling window count K (typically 6-12).
            min_windows: Minimum windows needed before drift detection activates.
            drift_threshold: Cutoff above which is_temporal_anomaly is True.
            boost_weight: Multiplier applied to temporal_score to compute decision boost.
            tracked_features: Features tracked for creeping drift.
            sequence_model: Optional sequence model hook (e.g. TCN/GRU or callable).
        """
        self.window_size = max(4, min(24, int(window_size)))
        self.min_windows = max(2, min(self.window_size, int(min_windows)))
        self.drift_threshold = float(drift_threshold)
        self.boost_weight = float(boost_weight)
        self.tracked_features = tracked_features or list(DEFAULT_TRACKED_DRIFT_FEATURES)
        self.sequence_model = sequence_model

        # Buffers
        self.global_buffer: deque = deque(maxlen=self.window_size)
        self.ip_buffers: Dict[str, deque] = {}
        self.aggregator = RollingWindowAggregator(CANONICAL_FEATURES)

    # ── Input Normalization ──────────────────────────────────────────────────

    def _normalize_input(
        self,
        features: Union[Dict[str, Any], pd.Series, pd.DataFrame, np.ndarray, List[float]],
    ) -> Dict[str, float]:
        """Convert any supported input into a clean {feature: float} dictionary."""
        out: Dict[str, float] = {}

        if isinstance(features, pd.DataFrame):
            if len(features) > 0:
                row = features.iloc[0]
                for c in CANONICAL_FEATURES:
                    out[c] = float(row.get(c, 0.0))
            return out

        if isinstance(features, pd.Series):
            for c in CANONICAL_FEATURES:
                out[c] = float(features.get(c, 0.0))
            return out

        if isinstance(features, dict):
            for c in CANONICAL_FEATURES:
                out[c] = float(features.get(c, 0.0))
            return out

        if isinstance(features, (list, tuple, np.ndarray)):
            arr = np.asarray(features).flatten()
            for i, c in enumerate(CANONICAL_FEATURES):
                out[c] = float(arr[i]) if i < len(arr) else 0.0
            return out

        return {c: 0.0 for c in CANONICAL_FEATURES}

    # ── Update & Scoring ─────────────────────────────────────────────────────

    def update(
        self,
        features: Union[Dict[str, Any], pd.Series, pd.DataFrame, np.ndarray, List[float]],
        ip: Optional[str] = None,
    ) -> TemporalResult:
        """
        Ingest a new feature window, update rolling buffers, and evaluate temporal drift.

        Args:
            features: 13-feature vector or dict for current time window.
            ip: Optional source IP to maintain per-IP temporal state.

        Returns:
            TemporalResult with drift metrics and boost.
        """
        row_dict = self._normalize_input(features)

        # Update global buffer
        self.global_buffer.append(row_dict)

        # Update per-IP buffer if IP provided
        target_buffer = self.global_buffer
        entity_id = "global"
        if ip:
            clean_ip = str(ip).strip()
            if clean_ip and clean_ip not in ("0.0.0.0", "127.0.0.1", "none", "unknown"):
                if clean_ip not in self.ip_buffers:
                    self.ip_buffers[clean_ip] = deque(maxlen=self.window_size)
                self.ip_buffers[clean_ip].append(row_dict)
                target_buffer = self.ip_buffers[clean_ip]
                entity_id = clean_ip

        n_windows = len(target_buffer)
        if n_windows < self.min_windows:
            return TemporalResult(
                temporal_score=0.0,
                is_temporal_anomaly=False,
                drift_score=0.0,
                sequence_score=None,
                boost=0.0,
                drifting_features=[],
                trend_details={},
                window_count=n_windows,
                entity_id=entity_id,
            )

        # 1. Evaluate Statistical Feature Drift
        drifting_feats: List[str] = []
        trend_details: Dict[str, Dict[str, Any]] = {}
        feature_scores: List[float] = []

        for feat in self.tracked_features:
            series = [float(w.get(feat, 0.0)) for w in target_buffer]
            score_f, details = score_feature_drift(feat, series)
            trend_details[feat] = details
            feature_scores.append(score_f)
            if score_f >= 0.45:
                drifting_feats.append(feat)

        # Base drift score is max feature drift
        max_feat_score = max(feature_scores) if feature_scores else 0.0

        # Multi-feature synergy boost (e.g. rst_ratio creeping + flows building up)
        if len(drifting_feats) > 1:
            multi_boost = 0.15 * (len(drifting_feats) - 1)
            drift_score = min(1.0, max_feat_score + multi_boost)
        else:
            drift_score = max_feat_score

        # 2. Sequence Model Hook (Optional)
        sequence_score: Optional[float] = None
        if self.sequence_model is not None:
            try:
                # Build (N, 13) matrix
                mat = np.array([
                    [w[c] for c in CANONICAL_FEATURES] for w in target_buffer
                ], dtype=float)

                if callable(self.sequence_model):
                    sequence_score = float(self.sequence_model(mat))
                elif hasattr(self.sequence_model, "predict"):
                    pred = self.sequence_model.predict(mat)
                    sequence_score = float(pred[0] if hasattr(pred, "__len__") else pred)
            except Exception:
                sequence_score = None

        # 3. Combine Drift & Sequence Scores
        if sequence_score is not None:
            temporal_score = max(drift_score, sequence_score)
        else:
            temporal_score = drift_score

        temporal_score = float(np.clip(temporal_score, 0.0, 1.0))
        is_anomaly = temporal_score >= self.drift_threshold
        boost = float(temporal_score * self.boost_weight)

        return TemporalResult(
            temporal_score=temporal_score,
            is_temporal_anomaly=is_anomaly,
            drift_score=drift_score,
            sequence_score=sequence_score,
            boost=boost,
            drifting_features=drifting_feats,
            trend_details=trend_details,
            window_count=n_windows,
            entity_id=entity_id,
        )

    def get_score(self, ip: Optional[str] = None) -> float:
        """Get latest temporal score for an IP or global buffer."""
        buf = self.ip_buffers.get(ip) if ip and ip in self.ip_buffers else self.global_buffer
        if len(buf) < self.min_windows:
            return 0.0
        # Evaluate last state
        res = self.update(buf[-1], ip=ip)
        return res.temporal_score

    def reset(self, ip: Optional[str] = None) -> None:
        """Clear temporal buffers."""
        if ip:
            if ip in self.ip_buffers:
                self.ip_buffers[ip].clear()
        else:
            self.global_buffer.clear()
            self.ip_buffers.clear()

    # ── Simulation & Test Utilities ──────────────────────────────────────────

    @classmethod
    def simulate_scan(
        cls,
        base_row: Optional[Dict[str, float]] = None,
        num_windows: int = 6,
        scan_type: str = "rst",
    ) -> List[Dict[str, float]]:
        """
        Generate a synthetic sequence of windows representing a low-and-slow campaign.

        scan_type:
          - "rst": slow port scan (creeping rst_ratio and flows)
          - "syn": stealth half-open SYN scan (creeping syn_ratio)
          - "http": creeping credential brute force (creeping http_ratio)
        """
        base = base_row.copy() if base_row else {
            "flows": 15.0, "bytes_total": 45000.0, "pkts_total": 120.0,
            "syn_ratio": 0.08, "mean_bytes_flow": 500.0, "ack_ratio": 0.85,
            "fin_ratio": 0.05, "rst_ratio": 0.01, "http_ratio": 0.10,
            "tcp_ratio": 0.90, "protocol_diversity": 2.0, "std_bytes": 100.0,
            "iat_mean": 0.05,
        }

        windows = []
        for i in range(num_windows):
            w = dict(base)
            step = i / max(1, num_windows - 1)

            if scan_type == "rst":
                # RST ratio creeps from 0.01 to 0.42, flows from 15 to 55
                w["rst_ratio"] = round(0.01 + 0.40 * step, 4)
                w["flows"] = round(15.0 + 40.0 * step, 1)
                w["pkts_total"] = round(120.0 + 80.0 * step, 1)
                w["ack_ratio"] = round(max(0.1, 0.85 - 0.40 * step), 4)

            elif scan_type == "syn":
                # SYN ratio creeps from 0.08 to 0.50
                w["syn_ratio"] = round(0.08 + 0.42 * step, 4)
                w["flows"] = round(15.0 + 35.0 * step, 1)
                w["ack_ratio"] = round(max(0.1, 0.85 - 0.35 * step), 4)

            elif scan_type == "http":
                # HTTP ratio creeps from 0.10 to 0.70
                w["http_ratio"] = round(0.10 + 0.60 * step, 4)
                w["flows"] = round(15.0 + 25.0 * step, 1)

            windows.append(w)

        return windows

