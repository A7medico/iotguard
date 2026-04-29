"""
tests/test_decision_loop_utils.py
-----------------------------------------------------------------------------
IoTGuard Tests — Decision Loop Utility Functions

Purpose
    Test the utility functions exported by decision_loop.py:
    - classify_attack_heuristic(): Rule-based attack classification
    - compute_adaptive_threshold(): Dynamic threshold calculation

These tests verify that the decision loop's helper functions behave correctly
in isolation, without needing the full ML pipeline to be running.

Test Categories
    - Attack Classification: Verify heuristic rules for different attack types
    - Adaptive Threshold: Verify threshold computation with various score histories

Running
    pytest tests/test_decision_loop_utils.py -v
-----------------------------------------------------------------------------
"""

import pandas as pd
import numpy as np

from decision_loop import classify_attack_heuristic, compute_adaptive_threshold


class TestClassifyAttackHeuristic:
    """Tests for the rule-based attack classification heuristic."""
    
    def test_web_attack_high_http_ratio(self):
        """
        Test that high HTTP ratio traffic is classified as a web attack.
        
        Web attacks (SQLi, XSS, brute force) typically have high HTTP traffic
        ratios and relatively low SYN/RST indicators.
        """
        row = pd.Series({
            "http_ratio": 0.8,     # High HTTP traffic (web attack indicator)
            "syn_ratio": 0.1,      # Low SYN ratio
            "rst_ratio": 0.0,      # No connection resets
            "bytes_total": 10_000,
            "pkts_total": 50,
            "mean_bytes_flow": 200.0,
            "flows": 5,
        })
        label = classify_attack_heuristic(row)
        assert "Web Attack" in label, f"Expected 'Web Attack' in label, got: {label}"

    def test_syn_flood_high_syn_ratio(self):
        """
        Test that high SYN ratio traffic is classified as SYN flood.
        
        SYN flood attacks are characterized by:
        - Very high SYN ratio (many new connections)
        - Often high volume (bytes/packets)
        - High number of flows
        """
        row = pd.Series({
            "http_ratio": 0.0,      # Not HTTP traffic
            "syn_ratio": 0.9,       # Very high SYN ratio (attack indicator)
            "rst_ratio": 0.0,
            "bytes_total": 1_000_000,  # High volume
            "pkts_total": 50_000,
            "mean_bytes_flow": 1000.0,
            "flows": 200,          # Many flows
        })
        label = classify_attack_heuristic(row)
        assert "SYN Flood" in label, f"Expected 'SYN Flood' in label, got: {label}"


class TestComputeAdaptiveThreshold:
    """Tests for the adaptive threshold computation."""
    
    def test_short_history_returns_base_threshold(self):
        """
        Test that with insufficient history, base threshold is returned.
        
        With fewer than 10 scores, there's not enough data for reliable
        statistical analysis, so we fall back to the base threshold.
        """
        scores = [0.1, 0.2, 0.3]  # Only 3 scores (< 10 minimum)
        
        thr = compute_adaptive_threshold(
            scores,
            base_threshold=0.7,
            sensitivity=2.0,
            min_threshold=0.5
        )
        
        assert thr == 0.7, f"Expected base threshold 0.7, got: {thr}"

    def test_adaptive_threshold_with_noisy_data(self):
        """
        Test that adaptive threshold is at least as high as base threshold.
        
        When scores have high variance (noisy data), the adaptive threshold
        should be computed using mean + sensitivity * std, but never
        lower than the base threshold to maintain security.
        """
        rng = np.random.default_rng(0)
        
        # Generate 100 noisy scores with mean ~0.4, std ~0.1
        scores = rng.normal(0.4, 0.1, size=100).clip(0.0, 1.0).tolist()
        
        thr = compute_adaptive_threshold(
            scores,
            base_threshold=0.5,
            sensitivity=2.0,
            min_threshold=0.3
        )
        
        # Dynamic threshold should be >= base_threshold
        assert thr >= 0.5, f"Threshold {thr} should be >= base threshold 0.5"

    def test_consistent_scores_near_base_threshold(self):
        """
        Test that very consistent low scores don't drop below min_threshold.
        
        Even with very consistent low scores, the threshold should respect
        the min_threshold floor for safety.
        """
        # Very consistent low scores
        scores = [0.1] * 50
        
        thr = compute_adaptive_threshold(
            scores,
            base_threshold=0.3,
            sensitivity=2.0,
            min_threshold=0.2
        )
        
        # Should not go below base (which is higher than min here)
        assert thr >= 0.3, f"Threshold {thr} should be >= base threshold 0.3"
