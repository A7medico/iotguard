# scripts/eve_to_features_once.py
import io, json, sys, time, pandas as pd
from pathlib import Path
from datetime import datetime, timedelta, timezone

IN = Path("data/suricata/eve.json")   # <-- corrected
OUT = Path("data/features.csv")
WINDOW_SEC = 10

def parse_ts(ts: str):
    # Suricata timestamps: "2025-01-02T03:04:05.123456+0000" or "...Z"
    if ts.endswith("Z"):
        ts = ts.replace("Z", "+00:00")
    elif ts.endswith("+0000"):
        ts = ts[:-5] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)

def rows_from_eve(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                if e.get("event_type") != "flow":
                    continue
                flow = e.get("flow", {}) or {}
                yield {
                    "ts": parse_ts(e["timestamp"]),
                    "src": e.get("src_ip"),
                    "dst": e.get("dest_ip"),
                    "bytes_toserver": flow.get("bytes_toserver", 0) or 0,
                    "bytes_toclient": flow.get("bytes_toclient", 0) or 0,
                    "pkts_toserver": flow.get("pkts_toserver", 0) or 0,
                    "pkts_toclient": flow.get("pkts_toclient", 0) or 0,
                    "state": flow.get("state", "") or "",
                }
            except Exception:
                continue

def aggregate(window):
    df = pd.DataFrame(window)
    if df.empty:
        return None
    bytes_total = (df["bytes_toserver"] + df["bytes_toclient"])
    pkts_total  = (df["pkts_toserver"] + df["pkts_toclient"])
    return pd.DataFrame([{
        "flows": len(df),
        "bytes_total": int(bytes_total.sum()),
        "pkts_total": int(pkts_total.sum()),
        "uniq_src": df["src"].nunique(),
        "uniq_dst": df["dst"].nunique(),
        "syn_ratio": float((df["state"].fillna("").eq("new")).mean()),
        "mean_bytes_flow": float(bytes_total.mean()),
    }])

def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(rows_from_eve(IN), key=lambda r: r["ts"])
    if not rows:
        print(f"No flow events found in {IN}")
        return
    start   = rows[0]["ts"]
    win_end = start + timedelta(seconds=WINDOW_SEC)
    buf     = []
    frames  = []

    for r in rows:
        if r["ts"] < win_end:
            buf.append(r)
        else:
            agg = aggregate(buf)
            if agg is not None:
                frames.append(agg)
            while r["ts"] >= win_end:
                win_end += timedelta(seconds=WINDOW_SEC)
            buf = [r]

    agg = aggregate(buf)
    if agg is not None:
        frames.append(agg)

    out = pd.concat(frames, ignore_index=True)
    out.to_csv(OUT, index=False)
    print(f"✅ wrote {OUT} with {len(out)} rows")

if __name__ == "__main__":
    main()
