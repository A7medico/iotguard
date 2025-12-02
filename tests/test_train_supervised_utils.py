import numpy as np

from scripts.train_supervised import _to_binary_labels, pick_best_threshold


def test_to_binary_labels_string_labels():
    import pandas as pd

    s = pd.Series(["benign", "BENIGN", "attack", "ddos", "Benign"])
    y = _to_binary_labels(s)
    assert y.tolist() == [0, 0, 1, 1, 0]


def test_to_binary_labels_numeric_passthrough():
    import pandas as pd

    s = pd.Series([0, 1, 0, 1])
    y = _to_binary_labels(s)
    assert y.dtype == int
    assert y.tolist() == [0, 1, 0, 1]


def test_pick_best_threshold_reasonable_range():
    rng = np.random.default_rng(42)
    # create a mildly separable problem
    y_true = np.array([0] * 100 + [1] * 100)
    scores = np.concatenate(
        [rng.normal(0.2, 0.05, size=100), rng.normal(0.8, 0.05, size=100)]
    )
    scores = np.clip(scores, 0.0, 1.0)

    thr, pr_auc = pick_best_threshold(y_true, scores)
    # threshold should not be degenerate and PR-AUC should be highish
    assert 0.1 < thr < 0.95
    assert pr_auc > 0.8


