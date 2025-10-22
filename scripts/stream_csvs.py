# scripts/stream_csvs.py
# -----------------------------------------------------------------------------
# IoTGuard Pipeline — Multi-CSV Streamer
#
# Purpose
#   - Streams rows from one or more feature CSVs into data/features.csv to
#     simulate different traffic regimes (e.g., benign, ddos_http) in sequence.
#
# Where it sits in the pipeline
#   [Converted Feature CSVs] → [THIS FILE] → data/features.csv → decision_loop.py
#
# Usage
#   python scripts/stream_csvs.py data/ciciot_benign.csv data/ciciot_ddos_http.csv \
#          --rate 10 --cycles 5 --rows-per-file 100
#
# Operational notes
#   - Ensures the features header exists in data/features.csv.
#   - Streams each input file in order per cycle; repeats for --cycles.
#   - Only writes the seven known feature columns; extra columns are ignored.
# -----------------------------------------------------------------------------
import argparse
import csv
import time
from pathlib import Path

FEATURE_COLUMNS = [
    "flows","bytes_total","pkts_total",
    "uniq_src","uniq_dst","syn_ratio","mean_bytes_flow",
]

OUT_PATH = Path("data/features.csv")


def ensure_header():
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not OUT_PATH.exists() or OUT_PATH.read_text(encoding="utf-8").strip() == "":
        OUT_PATH.write_text(
            ",".join(FEATURE_COLUMNS) + "\n", encoding="utf-8"
        )


def stream_file(input_path: Path, writer: csv.DictWriter, rows: int | None, delay_s: float):
    count = 0
    with input_path.open("r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            payload = {k: row.get(k, 0) for k in FEATURE_COLUMNS}
            writer.writerow(payload)
            count += 1
            if delay_s > 0:
                time.sleep(delay_s)
            if rows is not None and count >= rows:
                break
    return count


def main():
    p = argparse.ArgumentParser(description="Stream multiple feature CSVs into data/features.csv")
    p.add_argument("inputs", nargs="+", help="Input CSVs (e.g., data/ciciot_benign.csv data/ciciot_ddos_http.csv)")
    p.add_argument("--rate", type=float, default=10.0, help="Rows per second (per file)")
    p.add_argument("--cycles", type=int, default=1, help="How many times to loop over inputs")
    p.add_argument("--rows-per-file", type=int, default=None, help="Max rows to stream per file per cycle")
    args = p.parse_args()

    inputs = [Path(x) for x in args.inputs]
    for pth in inputs:
        if not pth.exists():
            raise SystemExit(f"Input not found: {pth}")

    ensure_header()
    delay = 0.0 if args.rate <= 0 else 1.0 / args.rate

    with OUT_PATH.open("a", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=FEATURE_COLUMNS)
        total = 0
        for cycle in range(max(args.cycles, 1)):
            for pth in inputs:
                wrote = stream_file(pth, writer, args.rows_per_file, delay)
                out.flush()
                print(f"cycle {cycle+1}: streamed {wrote} rows from {pth}")
                total += wrote
        print(f"Done. Total rows appended: {total}")


if __name__ == "__main__":
    main()



