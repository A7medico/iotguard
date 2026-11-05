"""
tests/test_federated_drift.py
-----------------------------------------------------------------------------
Comprehensive Unit Tests for Edge Federated Learning (FedAvg), Differential
Privacy, and Online Feature Drift Monitoring (Phase 6 Verification)
-----------------------------------------------------------------------------
"""

import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import numpy as np
import pandas as pd
import pytest

# Ensure repository root and script directories are on sys.path
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "2_training"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "5_dashboard"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "10_analysis"))

import check_feature_drift
from check_feature_drift import (
    FeatureDriftDetector,
    calculate_ks,
    calculate_psi,
    evaluate_feature_drift,
    SCHEMA_13_FEATURES,
)
import federated_learning
from federated_learning import (
    EdgeClientNode,
    FederatedCoordinator,
    LocalModelUpdate,
    clip_and_perturb_deltas,
    federated_averaging,
    get_federated_coordinator,
)


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    """Create a test client for the dashboard Flask application."""
    test_storage = tmp_path / "test_fed_model.json"
    test_backup = tmp_path / "test_backups"

    test_coord = FederatedCoordinator(
        storage_path=test_storage,
        backup_dir=test_backup,
        clip_norm=1.0,
        noise_multiplier=0.01,
        enable_dp=True,
    )
    monkeypatch.setattr(federated_learning, "_GLOBAL_FEDERATED_COORDINATOR", test_coord)

    from api_dashboard import app
    app.config["TESTING"] = True
    app.config["DEBUG"] = False

    with app.test_client() as client:
        yield client


# ============================================================================
# 1. Feature Drift Math & PSI / KS Tests
# ============================================================================

class TestFeatureDriftMath:
    """Tests for PSI and Kolmogorov-Smirnov distribution divergence metrics."""

    def test_calculate_psi_identical_distributions(self):
        """Identical distributions should yield PSI close to 0.0."""
        np.random.seed(42)
        data = np.random.normal(10.0, 2.0, size=2000)
        psi = calculate_psi(data, data)
        assert psi < 0.01

    def test_calculate_psi_moderate_and_severe_shift(self):
        """Distribution shifts should scale PSI appropriately."""
        np.random.seed(42)
        baseline = np.random.normal(10.0, 2.0, size=2000)

        # Moderate shift (mean shifted by 0.5 std)
        moderate = np.random.normal(11.0, 2.0, size=2000)
        psi_mod = calculate_psi(baseline, moderate)
        assert psi_mod > 0.05

        # Severe shift (mean shifted by 3 std)
        severe = np.random.normal(18.0, 2.0, size=2000)
        psi_sev = calculate_psi(baseline, severe)
        assert psi_sev >= 0.25

    def test_calculate_psi_edge_cases(self):
        """Test PSI calculation with constant, empty, or degenerate arrays."""
        # Empty array
        assert calculate_psi([], []) == 0.0
        # Constant identical arrays
        c1 = np.ones(100) * 5.0
        c2 = np.ones(100) * 5.0
        assert calculate_psi(c1, c2) == 0.0

    def test_calculate_ks_identical_and_divergent(self):
        """Kolmogorov-Smirnov test should detect continuous distribution equality."""
        np.random.seed(42)
        b = np.random.uniform(0.0, 1.0, size=1000)
        t_same = np.random.uniform(0.0, 1.0, size=1000)
        t_diff = np.random.uniform(2.0, 5.0, size=1000)

        stat_same, p_same = calculate_ks(b, t_same)
        assert stat_same < 0.10
        assert p_same > 0.01

        stat_diff, p_diff = calculate_ks(b, t_diff)
        assert stat_diff > 0.90
        assert p_diff < 0.001

    def test_evaluate_feature_drift_schema(self):
        """evaluate_feature_drift returns standardized feature report schema."""
        b = np.linspace(1, 100, 100)
        t = np.linspace(50, 150, 100)
        res = evaluate_feature_drift(b, t, "syn_ratio")

        for key in ("feature", "psi", "ks_stat", "p_value", "severity", "drift_detected", "baseline_mean", "target_mean", "mean_delta_pct"):
            assert key in res
        assert res["feature"] == "syn_ratio"
        assert res["severity"] in ("low", "moderate", "high")


# ============================================================================
# 2. FeatureDriftDetector Class Tests
# ============================================================================

class TestFeatureDriftDetector:
    """Tests for continuous drift detection against 13-feature baseline."""

    def test_detector_with_stable_data(self):
        """Stable synthetic data produces FLEET_STABLE recommendation."""
        np.random.seed(42)
        n = 500
        df = pd.DataFrame({
            f: np.random.normal(50, 5, size=n) for f in SCHEMA_13_FEATURES
        })

        detector = FeatureDriftDetector(baseline_df=df)
        report = detector.check_drift(live_data=df.copy(), sample_size=500)

        assert report["ok"] is True
        assert report["drift_detected"] is False
        assert report["recommendation"] == "FLEET_STABLE"
        assert report["features_evaluated"] == 13

    def test_detector_with_drifted_features(self):
        """Severe feature shifts trigger TRIGGER_FEDERATED_SYNC."""
        np.random.seed(42)
        n = 500
        df_base = pd.DataFrame({
            f: np.random.normal(10, 2, size=n) for f in SCHEMA_13_FEATURES
        })

        df_live = df_base.copy()
        # Shift multiple key features massively
        df_live["syn_ratio"] = np.random.normal(50, 2, size=n)
        df_live["flows"] = np.random.normal(200, 20, size=n)
        df_live["bytes_total"] = np.random.normal(10000, 500, size=n)

        detector = FeatureDriftDetector(baseline_df=df_base)
        report = detector.check_drift(live_data=df_live, sample_size=500)

        assert report["ok"] is True
        assert report["drift_detected"] is True
        assert report["recommendation"] == "TRIGGER_FEDERATED_SYNC"
        assert len(report["high_drift_features"]) >= 2


# ============================================================================
# 3. Federated Learning & Privacy Preservation Tests
# ============================================================================

class TestFederatedPrivacyAndMath:
    """Tests verifying privacy guarantees and FedAvg mathematical correctness."""

    def test_edge_node_local_training_and_privacy_contract(self):
        """
        Verify edge nodes compute 13-feature weight updates while
        never exporting raw feature rows, packets, or PCAP data.
        """
        node = EdgeClientNode("gateway_test_home", device_count=10, device_type="iot")
        global_w = np.zeros(13, dtype=float)
        global_b = 0.0

        update = node.train_local_step(global_weights=global_w, global_bias=global_b, epochs=3)

        assert isinstance(update, LocalModelUpdate)
        assert update.node_id == "gateway_test_home"
        assert len(update.weights) == 13
        assert len(update.weight_deltas) == 13
        assert update.num_samples > 0

        # PRIVACY VERIFICATION: Confirm only scalars and parameter deltas exist
        payload = update.to_dict()
        assert "local_data" not in payload
        assert "raw_features" not in payload
        assert "packets" not in payload
        assert "flows" not in payload
        for key in ("weights", "bias", "weight_deltas", "bias_delta", "num_samples", "loss", "accuracy"):
            assert key in payload

    def test_differential_privacy_clipping_and_noise(self):
        """L2 norm of weight deltas must be clipped to clip_norm threshold."""
        raw_deltas = np.array([5.0] * 13, dtype=float)  # L2 norm = sqrt(13 * 25) = ~18.0
        clip_norm = 1.0

        # Test pure clipping without noise
        clipped_pure = clip_and_perturb_deltas(raw_deltas, clip_norm=clip_norm, noise_multiplier=0.0)
        norm_pure = float(np.linalg.norm(clipped_pure))
        assert pytest.approx(norm_pure, rel=1e-3) == 1.0

        # Test clipping with noise
        perturbed = clip_and_perturb_deltas(raw_deltas, clip_norm=clip_norm, noise_multiplier=0.1, random_seed=42)
        assert not np.array_equal(clipped_pure, perturbed)

    def test_fedavg_weighted_average_math(self):
        """FedAvg must compute exact sample-weighted parameter aggregation."""
        gw = np.zeros(13, dtype=float)
        gb = 0.0

        # Node 1: 100 samples, delta = +1.0
        u1 = LocalModelUpdate(
            node_id="node1",
            num_samples=100,
            weights=[1.0] * 13,
            bias=0.2,
            weight_deltas=[1.0] * 13,
            bias_delta=0.2,
            loss=0.5,
            accuracy=0.85,
            timestamp=time.time(),
        )

        # Node 2: 300 samples, delta = +3.0
        u2 = LocalModelUpdate(
            node_id="node2",
            num_samples=300,
            weights=[3.0] * 13,
            bias=0.6,
            weight_deltas=[3.0] * 13,
            bias_delta=0.6,
            loss=0.3,
            accuracy=0.92,
            timestamp=time.time(),
        )

        # Total samples = 400.
        # Expected weight delta = (100/400)*1.0 + (300/400)*3.0 = 0.25 + 2.25 = 2.50
        # Expected bias delta   = (100/400)*0.2 + (300/400)*0.6 = 0.05 + 0.45 = 0.50
        new_w, new_b, metrics = federated_averaging([u1, u2], gw, gb)

        assert np.allclose(new_w, 2.50)
        assert pytest.approx(new_b, rel=1e-4) == 0.50
        assert metrics["participating_nodes"] == 2
        assert metrics["total_samples_evaluated"] == 400


# ============================================================================
# 4. Federated Coordinator & Lifecycle Tests
# ============================================================================

class TestFederatedCoordinator:
    """Tests for the fleet coordinator, hash-verification, and backups."""

    def test_coordinator_lifecycle_and_backup(self, tmp_path):
        """Coordinator executes round, verifies hash, and saves backup archive."""
        storage = tmp_path / "global_model.json"
        backup_dir = tmp_path / "backups"

        coord = FederatedCoordinator(
            storage_path=storage,
            backup_dir=backup_dir,
            clip_norm=1.0,
            noise_multiplier=0.02,
            enable_dp=True,
        )

        assert coord.current_round == 0
        initial_hash = coord.global_model_hash
        assert len(initial_hash) > 0

        # Execute Round 1
        res = coord.execute_round(epochs=1, trigger_reason="unit_test")

        assert res["round"] == 1
        assert res["global_model_hash"] != initial_hash
        assert len(res["participating_nodes"]) >= 3
        assert storage.exists()

        # Verify backup was created in backup_dir
        backups = list(backup_dir.glob("federated_round_1_*.json"))
        assert len(backups) == 1

        # Check fleet status
        status = coord.get_fleet_status()
        assert status["ok"] is True
        assert status["round"] == 1
        assert status["total_nodes"] >= 4
        assert "privacy" in status
        assert "drift_status" in status


# ============================================================================
# 5. Dashboard API Integration Tests
# ============================================================================

class TestFederatedApiEndpoints:
    """Tests for /api/v1/federated/status and /api/v1/federated/round."""

    def test_api_federated_status(self, app_client):
        """GET /api/v1/federated/status returns complete fleet telemetry."""
        resp = app_client.get("/api/v1/federated/status")
        assert resp.status_code == 200

        data = resp.get_json()
        assert data["ok"] is True
        assert "round" in data
        assert "global_model_hash" in data
        assert "nodes" in data and isinstance(data["nodes"], list)
        assert "drift_status" in data
        assert "privacy" in data

    def test_api_federated_round_trigger(self, app_client):
        """POST /api/v1/federated/round advances training round and updates status."""
        # 1. Trigger round
        resp = app_client.post(
            "/api/v1/federated/round",
            json={"epochs": 2, "lr": 0.01, "reason": "api_test"},
        )
        assert resp.status_code == 200

        data = resp.get_json()
        assert data["ok"] is True
        assert "round_report" in data
        round_num = data["round_report"]["round"]
        assert round_num >= 1

        # 2. Check status reflects updated round
        status_resp = app_client.get("/api/v1/federated/status")
        status_data = status_resp.get_json()
        assert status_data["round"] == round_num

