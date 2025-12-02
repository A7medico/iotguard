import pandas as pd
import numpy as np

from scripts.decision_loop import classify_attack_heuristic, compute_adaptive_threshold


def test_classify_attack_heuristic_web_attack():
    row = pd.Series(
        {
            "http_ratio": 0.8,
            "syn_ratio": 0.1,
            "rst_ratio": 0.0,
            "bytes_total": 10_000,
            "pkts_total": 50,
            "mean_bytes_flow": 200.0,
            "flows": 5,
        }
    )
    label = classify_attack_heuristic(row)
    assert "Web Attack" in label


def test_classify_attack_heuristic_syn_flood():
    row = pd.Series(
        {
            "http_ratio": 0.0,
            "syn_ratio": 0.9,
            "rst_ratio": 0.0,
            "bytes_total": 1_000_000,
            "pkts_total": 50_000,
            "mean_bytes_flow": 1000.0,
            "flows": 200,
        }
    )
    label = classify_attack_heuristic(row)
    assert "SYN Flood" in label


def test_compute_adaptive_threshold_short_history_returns_base():
    scores = [0.1, 0.2, 0.3]
    thr = compute_adaptive_threshold(scores, base_threshold=0.7, sensitivity=2.0, min_threshold=0.5)
    assert thr == 0.7


def test_compute_adaptive_threshold_raises_when_noise_high():
    rng = np.random.default_rng(0)
    scores = rng.normal(0.4, 0.1, size=100).clip(0.0, 1.0).tolist()
    thr = compute_adaptive_threshold(scores, base_threshold=0.5, sensitivity=2.0, min_threshold=0.3)
    # with some variance, dynamic threshold should be >= base_threshold
    assert thr >= 0.5


