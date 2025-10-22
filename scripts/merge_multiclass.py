# scripts/merge_multiclass.py
# -----------------------------------------------------------------------------
# Utility — Merge multiple feature CSVs preserving string labels
#
# Purpose
#   - Concatenate several converted feature files (each already matching the
#     7-feature schema) into a single training CSV while keeping the string
#     class label column intact (e.g., benign, ddos_http, recon).
#
# Usage
#   python scripts/merge_multiclass.py --out data/iotguard_training.csv \
#     data/ciciot_benign.csv data/ciciot_ddos_http.csv ...
# -----------------------------------------------------------------------------
import argparse
from pathlib import Path
import pandas as pd


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Concatenate multiple feature CSVs preserving string labels")
    p.add_argument("--out", required=True, help="Output CSV path (e.g., data/iotguard_training.csv)")
    p.add_argument("inputs", nargs="+", help="Input CSV paths (must include a 'label' column)")
    return p.parse_args()


def main():
    args = parse_args()
    frames = []
    for p in args.inputs:
        path = Path(p)
        if not path.exists():
            raise SystemExit(f"Missing file: {path}")
        df = pd.read_csv(path)
        if "label" not in df.columns:
            raise SystemExit(f"{path} has no 'label' column; add one during conversion or beforehand")
        frames.append(df)

    if not frames:
        raise SystemExit("No inputs provided")

    merged = pd.concat(frames, ignore_index=True)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    merged.to_csv(args.out, index=False)
    print(f"Wrote {args.out} rows={len(merged)}")


if __name__ == "__main__":
    main()


