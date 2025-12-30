"""
scripts/utils_common.py
-----------------------------------------------------------------------------
IoTGuard Component — Shared Utility Functions

Purpose
    Provide common utility functions used across multiple IoTGuard scripts,
    ensuring consistent behavior for:
    - Label processing (binary classification mapping)
    - Data normalization
    - Common transformations

Usage
    from utils_common import make_binary_labels
    y = make_binary_labels(df, label_col="label")

Functions
    - make_binary_labels: Convert multi-class labels to binary (benign vs attack)

Note
    This module is imported by:
    - train_supervised.py (during model training)
    - train_unsupervised.py (for anomaly detection training)
    - test_holdout.py (for evaluation)
-----------------------------------------------------------------------------
"""

import json
from pathlib import Path
from typing import Set

import pandas as pd


# ---------- Constants ----------
# Fallback benign tokens (case-insensitive).
# We treat ANY of these labels as "benign" (class 0) during binary conversion.
# This handles common variations across different datasets.
BENIGN_TOKENS: Set[str] = {
    "benign",           # Standard benign label
    "benigntraffic",    # CIC-IDS style
    "benign_final",     # Post-processed labels
    "normal",           # Alternative terminology
    "benign_sim",       # Simulated benign traffic
    "ciciot_benign"     # CIC-IoT dataset specific
}


def make_binary_labels(
    df: pd.DataFrame,
    label_col: str = "label",
    classes_path: str = "models/classes.json"
) -> pd.Series:
    """
    Map multi-class labels to binary: benign → 0, non-benign → 1.
    
    This function handles the common need to convert multi-class attack
    labels (e.g., "DDoS", "PortScan", "Botnet") into a binary classification
    problem where we only care about "is this an attack or not?"
    
    The function is robust to:
    - Different benign label names (via BENIGN_TOKENS fallback)
    - Case variations ("Benign", "BENIGN", "benign")
    - classes.json configuration (if present)
    - Already-numeric labels (passthrough)
    
    Args:
        df: DataFrame containing the label column.
        label_col: Name of the column containing labels (default: "label").
        classes_path: Path to classes.json with class metadata (optional).
        
    Returns:
        pd.Series of binary labels (0 = benign, 1 = attack).
        
    Examples:
        >>> df = pd.DataFrame({"label": ["benign", "DDoS", "PortScan", "Benign"]})
        >>> y = make_binary_labels(df)
        >>> y.tolist()
        [0, 1, 1, 0]
        
        >>> df = pd.DataFrame({"label": [0, 1, 2, 0]})  # Already numeric
        >>> y = make_binary_labels(df)
        >>> y.tolist()
        [0, 1, 1, 0]  # Assuming benign_index=0 in classes.json
        
    Processing Steps:
        1. Try to load benign label from classes.json (if exists)
        2. Check if labels are already numeric → use benign_index
        3. For string labels → match against benign_label or BENIGN_TOKENS
        4. Return binary series: 0 for benign, 1 for attack
    """
    # Default benign label and index
    benign_label = "benign"
    benign_idx = 0

    # ---------- Step 1: Try to Load classes.json ----------
    # This file is created during training and contains the class mapping.
    # If present, use it to determine which class index is "benign".
    try:
        classes_file = Path(classes_path)
        if classes_file.exists():
            meta = json.load(open(classes_path, "r"))
            classes = meta.get("classes", [])
            
            if classes:
                # Get benign index from metadata (default 0)
                benign_idx = int(meta.get("benign_index", 0))
                
                # Validate and get benign label
                if 0 <= benign_idx < len(classes):
                    benign_label = classes[benign_idx]
    except Exception:
        pass  # Fall back to defaults if classes.json is missing/invalid

    # Get the label column
    col = df[label_col]

    # ---------- Step 2: Handle Numeric Labels ----------
    # If labels are already encoded as integers (0, 1, 2, ...), we use
    # the benign_index directly. Labels matching benign_idx become 0,
    # all others become 1.
    if col.dtype.kind in "iu":  # 'i' = signed int, 'u' = unsigned int
        y = (col != benign_idx).astype(int)
        return y

    # ---------- Step 3: Handle String Labels ----------
    # Convert to string for consistent processing
    s = col.astype(str)

    # Primary rule: exact match against benign_label from classes.json
    benign_mask = s == benign_label

    # Fallback rule: case-insensitive membership in benign tokens
    # This handles variations like "BenignTraffic", "BENIGN", etc.
    benign_mask |= s.str.lower().isin(BENIGN_TOKENS)

    # ---------- Step 4: Create Binary Labels ----------
    # benign (True in mask) → 0, attack (False in mask) → 1
    y = (~benign_mask).astype(int)

    # Debug output (uncomment for troubleshooting)
    # print(f"DEBUG: benign_count={int((y==0).sum())}, attack_count={int((y==1).sum())}")
    
    return y
