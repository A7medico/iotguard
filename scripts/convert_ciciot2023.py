import argparse
import re
from pathlib import Path
import pandas as pd

# Our model feature schema
# -----------------------------------------------------------------------------
# Why this converter exists
#   CICIoT2023 exports many per-window features with varied names and casing.
#   The decision loop uses a compact 7-feature schema. This script normalizes
#   a CICIoT2023 CSV into that schema and optionally carries over class labels.
#
# Typical usage
#   python scripts/convert_ciciot2023.py --in file.csv --out data/out.csv \
#     --label-field Label            # preserves string labels
#   python scripts/add_label.py --in data/out.csv --label ddos_http
# -----------------------------------------------------------------------------
FEATURES = [
    "flows",
    "bytes_total",
    "pkts_total",
    "uniq_src",
    "uniq_dst",
    "syn_ratio",
    "mean_bytes_flow",
]

def norm(name: str) -> str:
    """Normalize column names to be robust to spaces/case/punct (e.g. 'Tot Sum'->'totsum')."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())

def find_col(df: pd.DataFrame, candidates: list[str]) -> str | None:
    """Find first matching column by normalized name from candidates."""
    normed = {norm(c): c for c in df.columns}
    for cand in candidates:
        key = norm(cand)
        if key in normed:
            return normed[key]
    return None

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Convert CICIoT2023-style CSV to IoTGuard features.csv schema")
    ap.add_argument("--in", dest="inp", required=True, help="Input CICIoT2023 CSV path")
    ap.add_argument("--out", dest="out", required=True, help="Output CSV path (features.csv-like)")
    ap.add_argument("--label-field", default=None, help="Optional label/category field name to carry over")
    ap.add_argument("--binary", action="store_true", help="Map label to binary attack vs benign")
    return ap.parse_args()

def map_row(row, cols):
    number = float(row.get(cols["number"], 0) or 0)
    totsum = float(row.get(cols["totsum"], 0) or 0)
    # prefer proportion column if available, else compute from count
    syn_prop = None
    if cols.get("synflagnum"):
        try:
            syn_prop = float(row.get(cols["synflagnum"], 0) or 0)
        except Exception:
            syn_prop = None
    if syn_prop is None:
        try:
            syn_count = float(row.get(cols.get("syncount"), 0) or 0)
            syn_prop = (syn_count / number) if number > 0 else 0.0
        except Exception:
            syn_prop = 0.0

    flows = number if number > 0 else 0.0
    bytes_total = totsum
    pkts_total = number
    uniq_src = 1  # dataset window rows typically aggregate per segment; default to 1
    uniq_dst = 1
    syn_ratio = max(0.0, min(1.0, syn_prop))
    mean_bytes_flow = (bytes_total / flows) if flows > 0 else 0.0

    return {
        "flows": int(flows),
        "bytes_total": float(bytes_total),
        "pkts_total": float(pkts_total),
        "uniq_src": int(uniq_src),
        "uniq_dst": int(uniq_dst),
        "syn_ratio": float(round(syn_ratio, 6)),
        "mean_bytes_flow": float(round(mean_bytes_flow, 6)),
    }

def main():
    args = parse_args()
    inp = Path(args.inp)
    out = Path(args.out)
    if not inp.exists():
        raise SystemExit(f"Input not found: {inp}")

    df = pd.read_csv(inp)
    # Identify key columns by common names from CICIoT2023 feature list
    col_number = find_col(df, ["Number", "number", "pkt number", "pktnum"])  # total packets
    col_totsum = find_col(df, ["Tot Sum", "totsum", "total bytes", "total length"])  # sum of packet len
    col_synflagnum = find_col(df, ["syn flag number", "synflagnumber", "syn flag proportion"])  # proportion
    col_syncount = find_col(df, ["syn count", "syncount"])  # count

    if not col_number or not col_totsum:
        raise SystemExit("Missing required columns: Number and Tot Sum (or equivalents)")

    cols = {
        "number": col_number,
        "totsum": col_totsum,
        "synflagnum": col_synflagnum,
        "syncount": col_syncount,
    }

    out_rows = []
    for _, r in df.iterrows():
        out_rows.append(map_row(r, cols))

    out_df = pd.DataFrame(out_rows, columns=FEATURES)

    # Optional label carryover
    if args.label_field and args.label_field in df.columns:
        lab = df[args.label_field].astype(str).str.strip().str.lower()
        if args.binary:
            out_df["label"] = lab.apply(lambda x: 0 if x in {"benign", "normal"} else 1)
        else:
            out_df["label"] = lab

    out.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(out, index=False)
    print(f"Wrote {out} rows={len(out_df)}")

if __name__ == "__main__":
    main()


