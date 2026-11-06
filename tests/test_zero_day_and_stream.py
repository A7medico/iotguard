"""
tests/test_zero_day_and_stream.py
-----------------------------------------------------------------------------
IoTGuard Enterprise — Unit Tests for:
  1. ECOD Empirical Cumulative Distribution Outlier Detection
  2. Robust Mahalanobis / PCA Reconstruction Error & Covariance Violation Scorer
  3. Tri-Modal Zero-Day Anomaly Fusion Engine
  4. Multi-Class Shannon Entropy Unknown Threat Detection
  5. O(1) Byte-Offset CSV Stream Tailer & Flat CPU Guarantee
-----------------------------------------------------------------------------
"""

import os
import time
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from zero_day_engine import (
    ECODDetector,
    PCACovarianceDetector,
    ZeroDayAnomalyEngine,
    build_or_load_zero_day_engine,
    SCHEMA_13_FEATURES,
    DEFAULT_BENIGN_STATS,
)
from scoring import (
    compute_shannon_entropy,
    infer_attack_taxonomy,
    compute_unsupervised_score,
)
from stream_reader import FastCSVStreamReader


# =============================================================================
# 1. ECOD (Empirical Cumulative Distribution Outlier Detector) Tests
# =============================================================================

class TestECODDetector:
    def test_ecod_fit_and_tail_detection(self):
        np.random.seed(42)
        n = 500
        # Synthetic benign data around default means
        benign_data = np.zeros((n, len(SCHEMA_13_FEATURES)))
        for i, f in enumerate(SCHEMA_13_FEATURES):
            stat = DEFAULT_BENIGN_STATS[f]
            benign_data[:, i] = np.random.normal(stat["mean"], stat["std"], n)

        ecod = ECODDetector(SCHEMA_13_FEATURES)
        ecod.fit(benign_data)
        assert ecod.is_fitted
        assert ecod.n_samples == n

        # In-distribution benign sample
        benign_sample = {f: DEFAULT_BENIGN_STATS[f]["mean"] for f in SCHEMA_13_FEATURES}
        norm_score, contribs = ecod.score_sample(benign_sample)
        assert 0.0 <= norm_score <= 0.60, f"Expected low benign score, got {norm_score}"

        # Extreme right-tail outlier on syn_ratio
        anom_sample = dict(benign_sample)
        anom_sample["syn_ratio"] = DEFAULT_BENIGN_STATS["syn_ratio"]["mean"] + 10 * DEFAULT_BENIGN_STATS["syn_ratio"]["std"]
        norm_score_anom, contribs_anom = ecod.score_sample(anom_sample)
        assert norm_score_anom > 0.80, f"Expected high tail anomaly score, got {norm_score_anom}"

        # syn_ratio should have the highest tail score
        top_contrib = max(contribs_anom.items(), key=lambda t: t[1])[0]
        assert top_contrib == "syn_ratio", f"Expected syn_ratio as top contributor, got {top_contrib}"

    def test_ecod_left_tail_detection(self):
        # ack_ratio is normally ~0.78; a sudden drop to 0.0 is an extreme left-tail outlier
        np.random.seed(42)
        n = 300
        data = np.random.normal(loc=0.78, scale=0.08, size=(n, len(SCHEMA_13_FEATURES)))
        ecod = ECODDetector(SCHEMA_13_FEATURES)
        ecod.fit(data)

        left_tail_sample = {f: 0.78 for f in SCHEMA_13_FEATURES}
        ack_idx = SCHEMA_13_FEATURES.index("ack_ratio")
        left_tail_sample["ack_ratio"] = 0.01  # severe drop
        score, contribs = ecod.score_sample(left_tail_sample)
        assert score > 0.70
        assert contribs["ack_ratio"] == max(contribs.values())


# =============================================================================
# 2. Robust PCA & Covariance Violation Tests
# =============================================================================

class TestPCACovarianceDetector:
    def test_pca_covariance_breakdown_detection(self):
        np.random.seed(123)
        n = 500
        # Create dataset where feature 3 (syn_ratio) and feature 5 (ack_ratio) are negatively correlated:
        # normal TCP state machine: ack_ratio ~ 1.0 - syn_ratio
        X = np.random.uniform(0.1, 0.9, size=(n, len(SCHEMA_13_FEATURES)))
        syn_col = SCHEMA_13_FEATURES.index("syn_ratio")
        ack_col = SCHEMA_13_FEATURES.index("ack_ratio")
        X[:, syn_col] = np.random.uniform(0.05, 0.25, size=n)
        X[:, ack_col] = 1.0 - X[:, syn_col] + np.random.normal(0, 0.02, size=n)

        pca = PCACovarianceDetector(n_components=4, features=SCHEMA_13_FEATURES)
        pca.fit(X)
        assert pca.is_fitted

        # In-distribution correlated sample
        benign_sample = {f: float(np.mean(X[:, i])) for i, f in enumerate(SCHEMA_13_FEATURES)}
        benign_sample["syn_ratio"] = 0.10
        benign_sample["ack_ratio"] = 0.90
        b_score, b_contribs = pca.score_sample(benign_sample)
        assert b_score < 0.60

        # Covariance violation: both syn_ratio and ack_ratio decouple (e.g. syn=0.85, ack=0.0)
        violation_sample = dict(benign_sample)
        violation_sample["syn_ratio"] = 0.85
        violation_sample["ack_ratio"] = 0.02
        v_score, v_contribs = pca.score_sample(violation_sample)
        assert v_score > 0.65
        assert v_contribs["syn_ratio"] > b_contribs["syn_ratio"]


# =============================================================================
# 3. Tri-Modal Zero-Day Anomaly Engine Tests
# =============================================================================

class TestZeroDayAnomalyEngine:
    def test_tri_modal_fusion_scoring(self, tmp_path):
        engine = build_or_load_zero_day_engine(
            model_path=tmp_path / "zero_day_engine.joblib",
            threshold=0.65,
        )
        assert engine.is_fitted
        assert len(engine.features) == 13

        # Score normal benign row
        benign_row = {
            "flows": 15, "bytes_total": 7500, "pkts_total": 55, "syn_ratio": 0.12,
            "mean_bytes_flow": 450.0, "ack_ratio": 0.44, "fin_ratio": 0.08, "rst_ratio": 0.01,
            "http_ratio": 0.18, "tcp_ratio": 0.95, "protocol_diversity": 1.0, "std_bytes": 40.0,
            "iat_mean": 0.06,
        }
        score, is_anom, contribs = engine.score(benign_row)
        assert 0.0 <= score <= 0.60
        assert not is_anom
        assert len(contribs) == 13

        # Score extreme zero-day attack
        attack_row = {
            "flows": 600, "bytes_total": 80_000_000, "pkts_total": 200_000, "syn_ratio": 0.98,
            "mean_bytes_flow": 133333.0, "ack_ratio": 0.0, "fin_ratio": 0.0, "rst_ratio": 0.0,
            "http_ratio": 0.0, "tcp_ratio": 1.0, "protocol_diversity": 1, "std_bytes": 8000.0,
            "iat_mean": 0.00005,
        }
        score_atk, is_anom_atk, contribs_atk = engine.score(attack_row)
        assert score_atk >= 0.70
        assert is_anom_atk is True
        assert isinstance(contribs_atk[0], tuple)
        assert len(contribs_atk[0]) == 2
        # Highest ranked features should include pkts_total, flows, or bytes_total
        top_3_names = [name for name, _ in contribs_atk[:3]]
        assert any(k in top_3_names for k in ("pkts_total", "bytes_total", "flows", "syn_ratio", "mean_bytes_flow"))

    def test_duck_typing_sklearn_compatibility(self, tmp_path):
        engine = build_or_load_zero_day_engine(
            model_path=tmp_path / "zero_day_engine_duck.joblib"
        )
        sample_mat = np.random.uniform(0.1, 0.9, size=(5, 13))
        # score_samples
        scores = engine.score_samples(sample_mat)
        assert len(scores) == 5
        assert all(isinstance(s, (float, np.floating)) for s in scores)

        # predict
        preds = engine.predict(sample_mat)
        assert len(preds) == 5
        assert set(preds).issubset({-1, 1})

    def test_compute_unsupervised_score_with_contributors(self, tmp_path):
        engine = build_or_load_zero_day_engine(
            model_path=tmp_path / "zero_day_engine_scoring.joblib"
        )
        row = pd.Series({f: 0.1 for f in SCHEMA_13_FEATURES})
        x_df = pd.DataFrame([row])

        # 2-tuple return (backward compatible)
        score, is_anom = compute_unsupervised_score(x_df, engine, threshold=0.65, return_contributors=False)
        assert isinstance(score, float)
        assert isinstance(is_anom, bool)

        # 3-tuple return with contributors
        score3, is_anom3, contribs3 = compute_unsupervised_score(x_df, engine, threshold=0.65, return_contributors=True)
        assert isinstance(score3, float)
        assert isinstance(is_anom3, bool)
        assert isinstance(contribs3, list)
        assert len(contribs3) == 13


# =============================================================================
# 4. Multi-Class Shannon Entropy Unknown Threat Detection Tests
# =============================================================================

class TestShannonEntropyNoveltyDetection:
    def test_shannon_entropy_math(self):
        # 1. Peaked distribution (confident prediction)
        peaked = [0.01, 0.01, 0.96, 0.01, 0.01]
        h_peaked, h_peaked_norm = compute_shannon_entropy(peaked)
        assert h_peaked_norm < 0.35, f"Expected low entropy for peaked distribution, got {h_peaked_norm}"

        # 2. Uniform distribution (maximum uncertainty)
        uniform = [0.2, 0.2, 0.2, 0.2, 0.2]
        h_uni, h_uni_norm = compute_shannon_entropy(uniform)
        assert pytest.approx(h_uni_norm, rel=1e-3) == 1.0

        # 3. Degenerate distribution (100% on one class)
        degenerate = [1.0, 0.0, 0.0]
        h_deg, h_deg_norm = compute_shannon_entropy(degenerate)
        assert h_deg == 0.0
        assert h_deg_norm == 0.0

    def test_infer_attack_taxonomy_entropy_zero_day_trigger(self):
        class MockUncertainModel:
            def predict_proba(self, x):
                # Flat distribution across 5 attack classes
                return np.array([[0.20, 0.20, 0.20, 0.20, 0.20]])

        class MockConfidentModel:
            def predict_proba(self, x):
                # Peaked distribution on port_scan
                return np.array([[0.02, 0.92, 0.02, 0.02, 0.02]])

        classes = ["benign", "port_scan", "syn_flood", "mirai", "bruteforce"]
        row = pd.Series({"syn_ratio": 0.1, "rst_ratio": 0.05, "bytes_total": 1000})
        x_df = pd.DataFrame([row])

        # 1. High-entropy model triggers ZeroDay-Anomaly
        cat_unc, conf_unc = infer_attack_taxonomy(
            row=row,
            x_df=x_df,
            detection_source="supervised",
            multiclass_model=MockUncertainModel(),
            multiclass_classes=classes,
            entropy_threshold=0.70,
        )
        assert cat_unc == "ZeroDay-Anomaly"
        assert conf_unc >= 0.80

        # 2. Confident model predicts known taxonomy
        cat_conf, conf_conf = infer_attack_taxonomy(
            row=row,
            x_df=x_df,
            detection_source="supervised",
            multiclass_model=MockConfidentModel(),
            multiclass_classes=classes,
            entropy_threshold=0.70,
        )
        assert cat_conf == "PortScan"
        assert conf_conf == 0.92


# =============================================================================
# 5. O(1) Byte-Offset CSV Stream Tailer Tests
# =============================================================================

class TestO1StreamReaderIncrementalTailing:
    def test_o1_incremental_seek_and_flat_cpu(self, tmp_path):
        csv_file = tmp_path / "features_stream.csv"
        header = (
            "flows,bytes_total,pkts_total,syn_ratio,mean_bytes_flow,ack_ratio,"
            "fin_ratio,rst_ratio,http_ratio,tcp_ratio,protocol_diversity,std_bytes,iat_mean\n"
        )
        row_template = "{},5000,50,0.1,500.0,0.8,0.1,0.0,0.2,0.9,3,120.5,0.04\n"

        # 1. Write initial 1,000 rows
        with open(csv_file, "w", encoding="utf-8") as f:
            f.write(header)
            for i in range(1000):
                f.write(row_template.format(i))

        reader = FastCSVStreamReader(csv_file, expected_features=SCHEMA_13_FEATURES)

        # Initial read of full 1,000 rows
        t0 = time.perf_counter()
        df1, row_off1, byte_off1 = reader.read_new_rows(saved_row_offset=0, saved_byte_offset=0)
        t_initial = time.perf_counter() - t0
        assert len(df1) == 1000
        assert row_off1 == 1000
        assert byte_off1 > 0

        # 2. Append only 5 new rows
        with open(csv_file, "a", encoding="utf-8") as f:
            for i in range(1000, 1005):
                f.write(row_template.format(i))

        # Incremental O(1) seek read
        t1 = time.perf_counter()
        df2, row_off2, byte_off2 = reader.read_new_rows(
            saved_row_offset=row_off1, saved_byte_offset=byte_off1
        )
        t_incremental = time.perf_counter() - t1

        assert len(df2) == 5, f"Expected exactly 5 newly appended rows, got {len(df2)}"
        assert row_off2 == 1005
        assert byte_off2 > byte_off1
        assert df2["flows"].iloc[0] == 1000
        assert df2["flows"].iloc[-1] == 1004

        # Incremental read should be blindingly fast (O(1) seek, not scanning 1000 historical rows)
        assert t_incremental < 0.05, f"Incremental read took too long: {t_incremental:.4f}s"

    def test_stream_reader_file_truncation_recovery(self, tmp_path):
        csv_file = tmp_path / "features_rotated.csv"
        header = "flows,bytes_total,pkts_total,syn_ratio,mean_bytes_flow,ack_ratio,fin_ratio,rst_ratio,http_ratio,tcp_ratio,protocol_diversity,std_bytes,iat_mean\n"
        row = "10,5000,50,0.1,500.0,0.8,0.1,0.0,0.2,0.9,3,120.5,0.04\n"

        with open(csv_file, "w", encoding="utf-8") as f:
            f.write(header)
            f.write(row * 20)

        reader = FastCSVStreamReader(csv_file)
        df1, row_off1, byte_off1 = reader.read_new_rows(0, 0)
        assert len(df1) == 20

        # Truncate file (simulate log rotation)
        with open(csv_file, "w", encoding="utf-8") as f:
            f.write(header)
            f.write(row * 3)

        # Reader must detect truncation and safely reset
        df2, row_off2, byte_off2 = reader.read_new_rows(
            saved_row_offset=row_off1, saved_byte_offset=byte_off1
        )
        assert len(df2) == 3
        assert row_off2 == 3
