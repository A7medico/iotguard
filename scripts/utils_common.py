# scripts/utils_common.py
import json, pandas as pd

# Fallback benign tokens (case-insensitive); we treat ANY of these as benign
BENIGN_TOKENS = {
    "benign", "benigntraffic", "benign_final", "normal",
    "benign_sim", "ciciot_benign"
}

def make_binary_labels(df: pd.DataFrame, label_col: str = "label",
                       classes_path: str = "models/classes.json") -> pd.Series:
    """
    Map labels to binary: benign -> 0, non-benign -> 1.
    Robust to:
      - classes.json missing or different benign label
      - capitalization / small spelling variants like 'BenignTraffic'
    """
    benign_label = "benign"
    benign_idx = 0

    # Try to read classes.json (optional)
    try:
        meta = json.load(open(classes_path, "r"))
        classes = meta.get("classes", [])
        if classes:
            benign_idx = int(meta.get("benign_index", 0))
            if 0 <= benign_idx < len(classes):
                benign_label = classes[benign_idx]
    except Exception:
        pass  # fall back to defaults

    col = df[label_col]

    # If numeric-encoded labels: 0..K-1 → benign is benign_idx
    if col.dtype.kind in "iu":
        y = (col != benign_idx).astype(int)
        return y

    # String labels (most common)
    s = col.astype(str)

    # Primary rule: exact benign_label from classes.json
    benign_mask = s == benign_label

    # Fallback rule: case-insensitive membership in benign tokens
    benign_mask |= s.str.lower().isin(BENIGN_TOKENS)

    # Final binary label
    y = (~benign_mask).astype(int)

    # Optional: quick sanity print (uncomment when debugging)
    # print("DEBUG benign count:", int((y==0).sum()), "attack count:", int((y==1).sum()))
    return y
