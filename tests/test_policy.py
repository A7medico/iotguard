"""
tests/test_policy.py
-----------------------------------------------------------------------------
Unit tests for the policy engine (scripts/3_inference/policy.py)
-----------------------------------------------------------------------------
"""

import time
import pytest
from policy import (
    PolicyConfig,
    load_policy,
    evaluate_response,
    debug_no_block_reason,
    determine_response,
    IPBaselineTracker,
    update_ip_baseline,
    block_ip_wrapper,
)


class TestPolicyConfig:
    def test_default_values(self):
        policy = PolicyConfig()
        assert policy.threshold == 0.90
        assert policy.grace == 2
        assert policy.window == 5
        assert policy.cooldown_sec == 5.0
        assert policy.instant_block == 0.95
        assert policy.dry_run is True
        assert policy.use_adaptive is False
        assert policy.adaptive_sensitivity == 2.0
        assert policy.adaptive_history == 60
        assert policy.adaptive_min_threshold == 0.50
        assert policy.hybrid_mode == "hybrid"
        assert policy.unsup_enabled is True
        assert policy.unsup_threshold is None
        assert policy.combine_strategy == "or"
        assert policy.ip_anomaly_z == 3.0

    def test_compatibility_aliases(self):
        policy = PolicyConfig()
        # adaptive_window alias for adaptive_history
        assert policy.adaptive_window == 60
        policy.adaptive_window = 120
        assert policy.adaptive_history == 120

        # adaptive_min alias for adaptive_min_threshold
        assert policy.adaptive_min == 0.50
        policy.adaptive_min = 0.40
        assert policy.adaptive_min_threshold == 0.40

        # hybrid_combine alias for combine_strategy
        assert policy.hybrid_combine == "or"
        policy.hybrid_combine = "weighted"
        assert policy.combine_strategy == "weighted"


class TestLoadPolicy:
    def test_load_from_yaml(self, tmp_path):
        cfg_file = tmp_path / "model.yaml"
        cfg_file.write_text(
            """
decision:
  threshold: 0.85
  grace: 3
  window: 6
  cooldown_sec: 10.0
  instant_block: 0.92
  dry_run: false
  use_adaptive: true
  adaptive_sensitivity: 2.5
  adaptive_window: 45
  adaptive_min: 0.55
  ip_anomaly_z: 3.5

hybrid:
  mode: "supervised"
  combine_strategy: "and"
  supervised_weight: 0.8
  unsupervised_weight: 0.2
  unsup_only_label: "CUSTOM_ANOMALY"

unsupervised:
  enabled: false
""",
            encoding="utf-8",
        )

        policy, mtime = load_policy(str(cfg_file))
        assert mtime > 0
        assert policy.threshold == 0.85
        assert policy.grace == 3
        assert policy.window == 6
        assert policy.cooldown_sec == 10.0
        assert policy.instant_block == 0.92
        assert policy.dry_run is False
        assert policy.use_adaptive is True
        assert policy.adaptive_sensitivity == 2.5
        assert policy.adaptive_history == 45
        assert policy.adaptive_min_threshold == 0.55
        assert policy.hybrid_mode == "supervised"
        assert policy.combine_strategy == "and"
        assert policy.unsup_enabled is False
        assert policy.supervised_weight == 0.8
        assert policy.unsupervised_weight == 0.2
        assert policy.unsup_only_label == "CUSTOM_ANOMALY"
        assert policy.ip_anomaly_z == 3.5

    def test_load_missing_file_returns_defaults(self):
        policy, mtime = load_policy("non_existent_config.yaml")
        assert mtime == 0.0
        assert policy.threshold == 0.90
        assert policy.grace == 2


class TestEvaluateResponse:
    def test_benign_returns_none(self):
        policy = PolicyConfig()
        resp, should_block = evaluate_response(
            is_attack=False,
            score=0.1,
            hits=0,
            policy=policy,
            last_block_time=0.0,
        )
        assert resp == "NONE"
        assert should_block is False

    def test_soft_block_when_grace_reached(self):
        policy = PolicyConfig(grace=2, cooldown_sec=5.0)
        resp, should_block = evaluate_response(
            is_attack=True,
            score=0.91,
            hits=2,
            policy=policy,
            last_block_time=0.0,  # long ago
        )
        assert resp == "SOFT"
        assert should_block is True

    def test_hard_block_on_instant_threshold(self):
        policy = PolicyConfig(instant_block=0.95, grace=5)
        resp, should_block = evaluate_response(
            is_attack=True,
            score=0.96,
            hits=1,  # below grace
            policy=policy,
            last_block_time=0.0,
        )
        assert resp == "HARD"
        assert should_block is True

    def test_kill_block_on_critical_score(self):
        policy = PolicyConfig()
        resp, should_block = evaluate_response(
            is_attack=True,
            score=0.99,
            hits=0,
            policy=policy,
            last_block_time=0.0,
        )
        assert resp == "KILL"
        assert should_block is True

    def test_cooldown_prevents_block(self):
        policy = PolicyConfig(cooldown_sec=10.0, grace=2)
        now = time.time()
        resp, should_block = evaluate_response(
            is_attack=True,
            score=0.92,
            hits=2,
            policy=policy,
            last_block_time=now - 2.0,  # only 2s ago (< 10s cooldown)
        )
        assert resp == "NONE"
        assert should_block is False

    def test_debug_no_block_reason(self):
        policy = PolicyConfig(grace=2, instant_block=0.95, cooldown_sec=5.0)
        now = time.time()

        # Benign
        reason = debug_no_block_reason(False, "NONE", 0, 0.1, policy, 0.0)
        assert reason == "benign"

        # Cooldown
        reason = debug_no_block_reason(True, "NONE", 3, 0.96, policy, now - 1.0)
        assert "cooldown" in reason

        # Below criteria
        reason = debug_no_block_reason(True, "NONE", 1, 0.91, policy, 0.0)
        assert "below criteria" in reason

        # When blocked, debug reason is None
        reason = debug_no_block_reason(True, "SOFT", 2, 0.91, policy, 0.0)
        assert reason is None


class TestIPBaselineTracker:
    def test_insufficient_samples_returns_none(self):
        tracker = IPBaselineTracker(min_samples=5)
        res = tracker.update_and_check("192.168.1.50", 1000.0)
        assert res is None

    def test_normal_traffic_not_anomalous(self):
        tracker = IPBaselineTracker(min_samples=5)
        for _ in range(10):
            res = tracker.update_and_check("192.168.1.50", 1000.0)
        assert res is False

    def test_spike_triggers_anomaly(self):
        tracker = IPBaselineTracker(min_samples=5)
        # Establish stable baseline
        for _ in range(10):
            tracker.update_and_check("192.168.1.50", 100.0)
        # Massive spike
        res = tracker.update_and_check("192.168.1.50", 1_000_000.0, z_threshold=3.0)
        assert res is True

    def test_empty_ip_returns_none(self):
        tracker = IPBaselineTracker()
        assert tracker.update_and_check("", 500.0) is None


class TestBlockWrapper:
    def test_dry_run_returns_success(self):
        ok, how = block_ip_wrapper("10.0.0.5", dry_run=True, severity="hard")
        assert ok is True
        assert "dry-run-hard" in how

    def test_empty_ip_fails(self):
        ok, how = block_ip_wrapper("", dry_run=False)
        assert ok is False
        assert how == "no-ip"

