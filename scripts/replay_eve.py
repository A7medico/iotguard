# scripts/replay_eve.py
# -----------------------------------------------------------------------------
# Utility — Replay eve.json into features.csv (synthetic mapping)
#
# Purpose
#   - For quick experimentation: stream eve-like JSON and write simplified
#     feature rows at a controlled rate.
# -----------------------------------------------------------------------------
import json, time, argparse, csv
from pathlib import Path

FEATURES = ["flows","bytes_total","pkts_total","uniq_src","uniq_dst","syn_ratio","mean_bytes_flow"]

def extract(ev):
    # SUPER-simplified mapping; tweak as you like
    src = ev.get("src_ip"); dst = ev.get("dest_ip")
    pkt = int(ev.get("pktcnt", ev.get("packet_count", 1)))
    byt = int(ev.get("bytecnt", ev.get("bytes", 200)))
    sig = ev.get("alert",{}).get("severity", 1)
    syn = 1.0 if ev.get("tcp",{}).get("flags","") == "S" else 0.1
    return {
        "flows": 1,
        "bytes_total": byt,
        "pkts_total": pkt,
        "uniq_src": 1,
        "uniq_dst": 1,
        "syn_ratio": syn,
        "mean_bytes_flow": max(1, byt//max(1,pkt)),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--rate", type=float, default=5.0, help="rows per second")
    ap.add_argument("--csv", default="data/features.csv")
    args = ap.parse_args()

    out = Path(args.csv)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_header = not out.exists()
    f_out = out.open("a", newline="", encoding="utf-8")
    w = csv.DictWriter(f_out, fieldnames=FEATURES)
    if write_header: w.writeheader()

    with open(args.input, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try:
                ev = json.loads(line)
                row = extract(ev)
                w.writerow(row); f_out.flush()
                time.sleep(1.0/args.rate)
            except Exception:
                continue

if __name__ == "__main__":
    main()
