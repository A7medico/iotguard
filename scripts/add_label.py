import argparse
from pathlib import Path
import pandas as pd
# -----------------------------------------------------------------------------
# Utility — Ensure a CSV has a 'label' column (constant value)
#
# Purpose
#   - Add or overwrite a 'label' column with a constant string for all rows.
#     Useful when preparing class-specific files before a multiclass merge.
#
# Usage
#   python scripts/add_label.py --in data/ciciot_ddos_http.csv --label ddos_http
#   # optional different output path:
#   python scripts/add_label.py --in in.csv --label benign --out out.csv
# -----------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Ensure a CSV has a 'label' column with a constant value")
    p.add_argument("--in", dest="inp", required=True, help="Input CSV path")
    p.add_argument("--label", required=True, help="Constant label value to set if missing")
    p.add_argument("--out", dest="out", default=None, help="Optional output path (defaults to overwrite input)")
    return p.parse_args()


def main():
    args = parse_args()
    inp = Path(args.inp)
    out = Path(args.out) if args.out else inp
    if not inp.exists():
        raise SystemExit(f"Missing file: {inp}")
    df = pd.read_csv(inp)
    if "label" not in df.columns:
        df["label"] = args.label
    df.to_csv(out, index=False)
    print(f"Wrote {out} rows={len(df)} with label column")


if __name__ == "__main__":
    main()


