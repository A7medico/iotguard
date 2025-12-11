"""
tests/test_train_supervised_utils.py
-----------------------------------------------------------------------------
IoTGuard Tests — Supervised Training Utility Functions

Purpose
    Test the utility functions used during supervised model training:
    - _to_binary_labels(): Convert multi-class labels to binary
    - pick_best_threshold(): Select optimal decision threshold from PR curve

These tests verify that training utilities work correctly in isolation,
ensuring reliable model training and threshold selection.

Test Categories
    - Label Conversion: Verify correct binary mapping for various label formats
    - Threshold Selection: Verify optimal threshold computation from scores

Running
    pytest tests/test_train_supervised_utils.py -v
-----------------------------------------------------------------------------
"""

import numpy as np
import pandas as pd

from scripts.train_supervised import _to_binary_labels, pick_best_threshold


class TestToBinaryLabels:
    """Tests for the binary label conversion function."""
    
    def test_string_labels_various_cases(self):
        """
        Test that string labels are correctly converted to binary.
        
        Expected behavior:
        - "benign" and "Benign" (case-insensitive) → 0
        - All other labels → 1 (attack)
        
        This tests the robustness to:
        - Case variations (benign, BENIGN, Benign)
        - Different attack label names
        """
        s = pd.Series(["benign", "BENIGN", "attack", "ddos", "Benign"])
        y = _to_binary_labels(s)
        
        expected = [0, 0, 1, 1, 0]
        assert y.tolist() == expected, (
            f"Expected {expected}, got {y.tolist()}"
        )

    def test_numeric_labels_passthrough(self):
        """
        Test that already-numeric labels are passed through correctly.
        
        When labels are already encoded as integers (0, 1), they should
        be preserved without modification.
        """
        s = pd.Series([0, 1, 0, 1])
        y = _to_binary_labels(s)
        
        assert y.dtype == int, f"Expected int dtype, got {y.dtype}"
        assert y.tolist() == [0, 1, 0, 1], (
            f"Expected [0, 1, 0, 1], got {y.tolist()}"
        )

    def test_mixed_attack_labels(self):
        """
        Test that various attack type labels all map to 1.
        
        Common attack labels from different datasets should all be
        recognized as non-benign (attack class).
        """
        s = pd.Series([
            "benign",
            "DDoS",           # Generic DDoS
            "PortScan",       # Reconnaissance
            "BotNet",         # Botnet activity
            "normal",         # Alternative benign name (should NOT be benign here)
        ])
        y = _to_binary_labels(s)
        
        # Only exact "benign" matches should be 0
        # Note: "normal" is not in the default benign tokens
        assert y.tolist()[0] == 0, "benign should map to 0"
        assert y.tolist()[1:4] == [1, 1, 1], "Attack labels should map to 1"
        assert y.tolist()[4] == 1, "normal should map to 1 (not in benign tokens)"


class TestPickBestThreshold:
    """Tests for the optimal threshold selection function."""
    
    def test_separable_problem_reasonable_threshold(self):
        """
        Test that a well-separated problem yields a reasonable threshold.
        
        With clearly separable classes (low-score benign, high-score attack),
        the optimal threshold should fall in the middle gap, and PR-AUC
        should be high (good discrimination).
        """
        rng = np.random.default_rng(42)
        
        # Create a mildly separable problem:
        # - Class 0 (benign): scores around 0.2
        # - Class 1 (attack): scores around 0.8
        y_true = np.array([0] * 100 + [1] * 100)
        scores = np.concatenate([
            rng.normal(0.2, 0.05, size=100),  # Benign: low scores
            rng.normal(0.8, 0.05, size=100)   # Attack: high scores
        ])
        scores = np.clip(scores, 0.0, 1.0)

        thr, pr_auc = pick_best_threshold(y_true, scores)
        
        # Threshold should be between the two clusters
        assert 0.1 < thr < 0.95, (
            f"Threshold {thr} should be in reasonable range [0.1, 0.95]"
        )
        
        # PR-AUC should be high for well-separated classes
        assert pr_auc > 0.8, (
            f"PR-AUC {pr_auc} should be > 0.8 for separable problem"
        )

    def test_perfect_separation_high_pr_auc(self):
        """
        Test that perfect separation yields near-perfect PR-AUC.
        """
        y_true = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
        scores = np.array([0.1, 0.1, 0.2, 0.2, 0.3, 0.7, 0.8, 0.8, 0.9, 0.9])
        
        thr, pr_auc = pick_best_threshold(y_true, scores)
        
        # Perfect separation should yield very high PR-AUC
        assert pr_auc > 0.95, f"PR-AUC {pr_auc} should be near 1.0"
