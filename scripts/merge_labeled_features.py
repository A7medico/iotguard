import argparse
from pathlib import Path
import pandas as pd
# -----------------------------------------------------------------------------
# Utility — Merge numeric-labeled feature CSVs
#
# Purpose
#   - Concatenate several feature files and stamp a numeric label per file.
#   - This is the binary-label counterpart to merge_multiclass.py.
#
# Usage
#   python scripts/merge_labeled_features.py --out data/iotguard_training.csv \
#     --add data/benign.csv:0 --add data/attack.csv:1
# -----------------------------------------------------------------------------

FEATURE_COLUMNS = [
    "flows","bytes_total","pkts_total",
    "uniq_src","uniq_dst","syn_ratio","mean_bytes_flow",
]

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Merge multiple features.csv files and attach constant labels")
    p.add_argument("--out", required=True, help="Output CSV path (e.g., data/iotguard_training.csv)")
    p.add_argument(
        "--add",
        action="append",
        required=True,
        help="Pair of 'path:label' (label can be 0/1 or benign/attack). Repeat for multiple sources.",
    )
    return p.parse_args()

def coerce_label(val: str) -> int:
    val = str(val).strip().lower()
    if val in {"1","attack","malicious","malware"}: return 1
    if val in {"0","benign","normal"}: return 0
    # fallback: try int
    return 1 if int(val) != 0 else 0

def main():
    args = parse_args()
    frames = []
    for item in args.add:
        try:
            path_str, label_str = item.split(":", 1)
        except ValueError:
            raise SystemExit(f"--add expects 'path:label', got: {item}")
        path = Path(path_str)
        if not path.exists():
            raise SystemExit(f"Missing file: {path}")
        df = pd.read_csv(path)
        # keep only expected columns (drop unknowns), warn if missing
        missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
        if missing:
            raise SystemExit(f"{path} missing columns: {missing}")
        out = df[FEATURE_COLUMNS].copy()
        out["label"] = coerce_label(label_str)
        frames.append(out)

    if not frames:
        raise SystemExit("No inputs provided")

    merged = pd.concat(frames, ignore_index=True)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    merged.to_csv(args.out, index=False)
    print(f"Wrote {args.out} rows={len(merged)}")

if __name__ == "__main__":
    main()


