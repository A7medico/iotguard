"""
tests/test_temporal_detector.py
-----------------------------------------------------------------------------
Comprehensive tests for Temporal Sequence & Drift Detection (Phase 2 Upgrade).

Validates:
  1. Rolling window buffer capacity, min_windows, and per-IP isolation.
  2. Fast statistical drift math (least-squares linear slope, monotonic ratio).
  3. Creeping feature escalation scoring (rst_ratio, syn_ratio, flows, http_ratio).
  4. Rolling window feature aggregator and custom sequence model hooks.
  5. Multi-window low-and-slow attack detection (6-window stealth port scan, SYN flood, brute force).
  6. Hybrid decision boosting for borderline single-window events.
  7. Zero False Positive Rate (FPR) impact on data/test_holdout/unseen_benign_holdout.csv.
  8. EnsemblePredictor integration and temporal explanation formatting.
-----------------------------------------------------------------------------
"""

import json
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from temporal_detector import (
    TemporalDetector,
    TemporalResult,
    RollingWindowAggregator,
    compute_linear_slope,
    compute_monotonic_ratio,
    score_feature_drift,
    CANONICAL_FEATURES,
)
from scoring import compute_hybrid_decision, infer_attack_taxonomy
from ensemble import EnsemblePredictor
from policy import PolicyConfig


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def base_window() -> dict[str, float]:
    """Typical quiet benign window."""
    return {
        "flows": 14.0,
        "bytes_total": 42000.0,
        "pkts_total": 110.0,
        "syn_ratio": 0.08,
        "mean_bytes_flow": 480.0,
        "ack_ratio": 0.86,
        "fin_ratio": 0.04,
        "rst_ratio": 0.01,
        "http_ratio": 0.12,
        "tcp_ratio": 0.92,
        "protocol_diversity": 2.0,
        "std_bytes": 110.0,
        "iat_mean": 0.045,
    }


@pytest.fixture
def detector() -> TemporalDetector:
    """Standard detector instance with window_size=8 and min_windows=4."""
    return TemporalDetector(
        window_size=8,
        min_windows=4,
        drift_threshold=0.50,
        boost_weight=0.25,
    )


# ── 1. Buffer & Rolling Window Capacity ──────────────────────────────────────

class TestTemporalWindowBuffer:
    def test_buffer_capacity_bounded(self, detector, base_window):
        """Deque must not exceed window_size."""
        for _ in range(20):
            detector.update(base_window)
        assert len(detector.global_buffer) == detector.window_size

    def test_min_windows_guard(self, detector, base_window):
        """Detector returns neutral zero score until min_windows are accumulated."""
        for i in range(detector.min_windows - 1):
            res = detector.update(base_window)
            assert res.temporal_score == 0.0
            assert res.is_temporal_anomaly is False
            assert res.window_count == i + 1

    def test_per_ip_isolation(self, detector, base_window):
        """Traffic from distinct IPs must maintain separate temporal histories."""
        ip_a = "192.168.1.100"
        ip_b = "10.0.0.5"

        # Update IP A with 5 normal windows
        for _ in range(5):
            detector.update(base_window, ip=ip_a)

        # Update IP B with 2 normal windows
        for _ in range(2):
            detector.update(base_window, ip=ip_b)

        assert len(detector.ip_buffers[ip_a]) == 5
        assert len(detector.ip_buffers[ip_b]) == 2

    def test_reset_functionality(self, detector, base_window):
        """reset() should clear all buffers or specific IP buffers."""
        detector.update(base_window, ip="192.168.1.10")
        detector.update(base_window)
        assert len(detector.global_buffer) > 0

        # Reset specific IP
        detector.reset(ip="192.168.1.10")
        assert len(detector.ip_buffers["192.168.1.10"]) == 0
        assert len(detector.global_buffer) > 0

        # Full reset
        detector.reset()
        assert len(detector.global_buffer) == 0
        assert len(detector.ip_buffers) == 0


# ── 2. Fast Statistical Drift Math ──────────────────────────────────────────

class TestStatisticalDriftMath:
    def test_linear_slope_scenarios(self):
        # Flat sequence
        assert abs(compute_linear_slope([0.1, 0.1, 0.1, 0.1])) < 1e-6
        # Positive monotonic slope
        slope_pos = compute_linear_slope([0.0, 0.1, 0.2, 0.3])
        assert np.isclose(slope_pos, 0.1, atol=1e-3)
        # Negative slope
        slope_neg = compute_linear_slope([0.5, 0.4, 0.3, 0.2])
        assert slope_neg < 0

    def test_monotonic_ratio(self):
        # Strictly increasing
        assert compute_monotonic_ratio([1.0, 2.0, 3.0, 4.0]) == 1.0
        # Half increasing, half decreasing
        assert compute_monotonic_ratio([1.0, 2.0, 1.0, 2.0]) == 2.0 / 3.0
        # Strictly decreasing
        assert compute_monotonic_ratio([4.0, 3.0, 2.0, 1.0]) == 0.0

    def test_score_feature_drift_ratio(self):
        # Benign steady rst_ratio
        score_flat, details_flat = score_feature_drift("rst_ratio", [0.01, 0.012, 0.009, 0.011, 0.01])
        assert score_flat == 0.0

        # Escalating creeping rst_ratio (e.g. stealth scan)
        creeping_rst = [0.01, 0.08, 0.16, 0.24, 0.32, 0.40]
        score_drift, details_drift = score_feature_drift("rst_ratio", creeping_rst)
        assert score_drift >= 0.70
        assert details_drift["slope"] > 0.05
        assert details_drift["delta"] >= 0.30

    def test_score_feature_drift_flows(self):
        # Benign steady flows
        score_steady, _ = score_feature_drift("flows", [15.0, 14.0, 16.0, 15.0, 17.0])
        assert score_steady == 0.0

        # Creeping flows buildup (15 -> 55)
        score_creep, _ = score_feature_drift("flows", [15.0, 22.0, 30.0, 38.0, 46.0, 55.0])
        assert score_creep >= 0.60


# ── 3. Rolling Window Aggregator & Sequence Model Hook ───────────────────────

class TestRollingAggregatorAndHooks:
    def test_rolling_window_aggregator(self):
        aggregator = RollingWindowAggregator(CANONICAL_FEATURES)
        # Create (6, 13) matrix
        matrix = np.ones((6, 13)) * 10.0
        matrix[:, 0] = np.array([10.0, 20.0, 30.0, 40.0, 50.0, 60.0])  # flows creeping

        res = aggregator.aggregate(matrix)
        assert res["window_count"] == 6
        assert np.isclose(res["means"]["flows"], 35.0)
        assert np.isclose(res["deltas"]["flows"], 50.0)
        assert res["slopes"]["flows"] > 0

    def test_sequence_model_hook_integration(self, base_window):
        # Create a mock sequence model callable
        def mock_seq_model(mat: np.ndarray) -> float:
            assert mat.shape[1] == 13
            return 0.88

        det = TemporalDetector(
            window_size=6,
            min_windows=3,
            sequence_model=mock_seq_model,
        )

        for _ in range(4):
            res = det.update(base_window)

        assert res.sequence_score == 0.88
        assert res.temporal_score >= 0.88
        assert res.is_temporal_anomaly is True


# ── 4. Low-and-Slow Attack Simulation & Decision Boost ───────────────────────

class TestLowAndSlowSimulation:
    def test_6_window_slow_rst_scan_triggers_boost(self, detector):
        """
        Simulate a 6-window slow port scan where single-window scores sit
        below the 0.90 threshold, but temporal sequence escalation boosts
        the effective risk score over 0.90.
        """
        scan_windows = TemporalDetector.simulate_scan(scan_type="rst", num_windows=6)
        # Single-window supervised model outputs that stay under the 0.90 threshold
        sub_threshold_scores = [0.15, 0.30, 0.45, 0.60, 0.72, 0.82]

        results = []
        for i, (win, base_p) in enumerate(zip(scan_windows, sub_threshold_scores)):
            temp_res = detector.update(win)
            eff_p, is_attack, source = compute_hybrid_decision(
                sup_score=base_p,
                sup_threshold=0.90,
                unsup_score=0.0,
                unsup_is_anomaly=False,
                mode="supervised",
                combine="or",
                sup_weight=1.0,
                unsup_weight=0.0,
                temporal_score=temp_res.temporal_score,
                temporal_boost_weight=detector.boost_weight,
                temporal_is_anomaly=temp_res.is_temporal_anomaly,
            )
            results.append((eff_p, is_attack, source, temp_res))

        # First 3 windows: collecting baseline
        assert results[0][1] is False
        assert results[1][1] is False
        assert results[2][1] is False

        # Windows 5 & 6: Temporal drift triggered, effective score boosted past 0.90
        eff_p_final, is_attack_final, source_final, temp_res_final = results[5]
        assert is_attack_final is True
        assert source_final == "temporal"
        assert eff_p_final >= 0.90
        assert "rst_ratio" in temp_res_final.drifting_features
        assert "flows" in temp_res_final.drifting_features

        # Verify taxonomy maps directly to PortScan
        taxonomy, conf = infer_attack_taxonomy(
            pd.Series(scan_windows[-1]),
            pd.DataFrame([scan_windows[-1]]),
            source_final,
            drifting_features=temp_res_final.drifting_features,
        )
        assert taxonomy == "PortScan"
        assert conf >= 0.85

    def test_slow_syn_flood_rampup(self, detector):
        """Simulate slow SYN reconnaissance / flood ramp-up."""
        scan_windows = TemporalDetector.simulate_scan(scan_type="syn", num_windows=6)
        for w in scan_windows:
            res = detector.update(w)

        assert res.is_temporal_anomaly is True
        assert "syn_ratio" in res.drifting_features

        tax, _ = infer_attack_taxonomy(
            pd.Series(scan_windows[-1]),
            pd.DataFrame([scan_windows[-1]]),
            "temporal",
            drifting_features=res.drifting_features,
        )
        assert tax == "DDoS-SYN"

    def test_slow_http_brute_force_rampup(self, detector):
        """Simulate creeping HTTP credential brute forcing."""
        scan_windows = TemporalDetector.simulate_scan(scan_type="http", num_windows=6)
        for w in scan_windows:
            res = detector.update(w)

        assert res.is_temporal_anomaly is True
        assert "http_ratio" in res.drifting_features

        tax, _ = infer_attack_taxonomy(
            pd.Series(scan_windows[-1]),
            pd.DataFrame([scan_windows[-1]]),
            "temporal",
            drifting_features=res.drifting_features,
        )
        assert tax in ("BruteForce", "DDoS-HTTP")


# ── 5. Holdout Benign False Positive Rate Safety ─────────────────────────────

class TestHoldoutBenignFPRSafety:
    def test_no_fpr_increase_on_unseen_benign_holdout(self):
        """
        Verify that processing the 5,000-sample unseen benign holdout dataset
        through the stateful temporal detector produces ZERO false positives
        at the 0.90 decision threshold.
        """
        holdout_path = Path("data/test_holdout/unseen_benign_holdout.csv")
        if not holdout_path.exists():
            pytest.skip("data/test_holdout/unseen_benign_holdout.csv not found")

        df = pd.read_csv(holdout_path)
        meta_path = Path("models/model_meta.json")
        model_path = Path("models/lightgbm.joblib")

        from joblib import load
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        features = meta["features"]
        model = load(model_path)

        # Baseline single-window probabilities
        X_df = df[features]
        base_probas = model.predict_proba(X_df)[:, 1]

        # Verify baseline FPR is 0.0
        assert (base_probas >= 0.90).sum() == 0

        # Stream through temporal detector
        detector = TemporalDetector(window_size=8, min_windows=4, boost_weight=0.25)
        false_positives = 0

        for i, row in df.iterrows():
            base_p = float(base_probas[i])
            temp_res = detector.update(row[features])
            eff_p, is_attack, _ = compute_hybrid_decision(
                sup_score=base_p,
                sup_threshold=0.90,
                unsup_score=0.0,
                unsup_is_anomaly=False,
                mode="supervised",
                combine="or",
                sup_weight=1.0,
                unsup_weight=0.0,
                temporal_score=temp_res.temporal_score,
                temporal_boost_weight=0.25,
                temporal_is_anomaly=temp_res.is_temporal_anomaly,
            )
            if is_attack:
                false_positives += 1

        assert false_positives == 0, f"Expected 0 false positives, got {false_positives}"


# ── 6. EnsemblePredictor Integration ─────────────────────────────────────────

class TestEnsembleTemporalIntegration:
    def test_ensemble_predict_contains_temporal_keys(self, base_window):
        """EnsemblePredictor should include temporal metrics in its output dictionary."""
        ensemble = EnsemblePredictor()
        ensemble.temporal_detector.reset()

        result = ensemble.predict(base_window)
        assert "score" in result
        assert "raw_score" in result
        assert "temporal_score" in result
        assert "temporal_boost" in result
        assert "drifting_features" in result
        assert isinstance(result["drifting_features"], list)

    def test_ensemble_detects_simulated_scan(self):
        """EnsemblePredictor should detect multi-window scan and format explanation."""
        ensemble = EnsemblePredictor()
        ensemble.temporal_detector.reset()

        scan_windows = TemporalDetector.simulate_scan(scan_type="rst", num_windows=6)
        results = [ensemble.predict(w) for w in scan_windows]

        final_res = results[-1]
        assert final_res["temporal_score"] > 0.50
        assert final_res["temporal_boost"] > 0.10

        explanation = ensemble.explain_prediction(final_res)
        assert isinstance(explanation, str)
        assert "Temporal drift" in explanation or "Temporal sequence" in explanation

