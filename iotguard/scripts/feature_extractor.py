# scripts/feature_extractor.py
import json, time, os
from pathlib import Path
from collections import deque, Counter
from datetime import datetime, timezone
import pandas as pd

DATA = Path("data")
DATA.mkdir(parents=True, exist_ok=True)

EVE_PATH   = DATA / "fake_eve.json"          # pretend Suricata eve.json
FEAT_CSV   = DATA / "features.csv"
WINDOW_SEC = 30

FEATURES = ["flows","bytes_total","pkts_total","uniq_src","uniq_dst","syn_ratio","mean_bytes_flow"]

# ring buffer of (ts, src, dst, bytes_total, pkts_total, is_syn)
buf = deque()

def parse_line(line: str):
    try:
        e = json.loads(line)
    except Exception:
        return None
    if e.get("event_type") != "flow":
        return None
    f = e.get("flow", {})
    ts = e.get("timestamp")
    try:
        ts_epoch = datetime.fromisoformat(ts.replace("Z","+00:00")).timestamp()
    except Exception:
        ts_epoch = time.time()

    bytes_ts = int(f.get("bytes_toserver", 0) or 0)
    bytes_tc = int(f.get("bytes_toclient", 0) or 0)
    pkts_ts  = int(f.get("pkts_toserver", 0) or 0)
    pkts_tc  = int(f.get("pkts_toclient", 0) or 0)
    state    = str(f.get("state", "")).upper()

    return dict(
        ts=ts_epoch,
        src=str(e.get("src_ip","0.0.0.0")),
        dst=str(e.get("dest_ip","0.0.0.0")),
        bytes_total=bytes_ts + bytes_tc,
        pkts_total=pkts_ts + pkts_tc,
        is_syn=1 if "SYN" in state else 0
    )

def ensure_header():
    if not FEAT_CSV.exists() or FEAT_CSV.stat().st_size == 0:
        FEAT_CSV.write_text(",".join(FEATURES) + "\n", encoding="utf-8")

def append_row(row_dict):
    # append as CSV line fast (avoid pandas locks)
    line = ",".join(str(row_dict[k]) for k in FEATURES) + "\n"
    with FEAT_CSV.open("a", encoding="utf-8") as f:
        f.write(line)

def compute_features(now_ts: float):
    # drop expired
    while buf and (now_ts - buf[0]["ts"] > WINDOW_SEC):
        buf.popleft()

    flows = len(buf)
    if flows == 0:
        return dict(flows=0, bytes_total=0, pkts_total=0,
                    uniq_src=0, uniq_dst=0, syn_ratio=0.0, mean_bytes_flow=0.0)

    bytes_total = sum(x["bytes_total"] for x in buf)
    pkts_total  = sum(x["pkts_total"] for x in buf)
    uniq_src    = len({x["src"] for x in buf})
    uniq_dst    = len({x["dst"] for x in buf})
    syn_ratio   = sum(x["is_syn"] for x in buf) / flows
    mean_bytes  = bytes_total / flows

    return dict(
        flows=flows,
        bytes_total=bytes_total,
        pkts_total=pkts_total,
        uniq_src=uniq_src,
        uniq_dst=uniq_dst,
        syn_ratio=round(syn_ratio, 3),
        mean_bytes_flow=round(mean_bytes, 3)
    )

def tail_file(path: Path):
    path.touch(exist_ok=True)
    with path.open("r", encoding="utf-8") as f:
        # seek to end; this acts like `tail -f`
        f.seek(0, os.SEEK_END)
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                time.sleep(0.05)
                f.seek(pos)
                continue
            yield line

def main():
    print(f"🟢 Feature extractor reading {EVE_PATH} → {FEAT_CSV}")
    ensure_header()
    for line in tail_file(EVE_PATH):
        rec = parse_line(line)
        if not rec: 
            continue
        buf.append(rec)
        feats = compute_features(rec["ts"])
        append_row(feats)

if __name__ == "__main__":
    main()
