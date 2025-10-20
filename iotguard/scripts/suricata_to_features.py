# scripts/suricata_to_features.py
import json, time
from pathlib import Path
from datetime import datetime, timedelta, timezone
import pandas as pd

IN    = Path("data/suricata/eve.json")
OUT   = Path("data/features.csv")
STATE = Path("data/eve_tail_state.json")

WINDOW_SEC = 10
SLEEP = 0.3

FEATURE_HEADER = ["flows","bytes_total","pkts_total","uniq_src","uniq_dst","syn_ratio","mean_bytes_flow"]

def parse_ts(ts: str):
    # Suricata: "...Z" or "...+0000"
    if ts.endswith("Z"):
        ts = ts.replace("Z", "+00:00")
    elif ts.endswith("+0000"):
        ts = ts[:-5] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)

def to_row(e: dict):
    if e.get("event_type") != "flow":
        return None
    flow = e.get("flow", {}) or {}
    try:
        return {
            "ts": parse_ts(e["timestamp"]),
            "src": e.get("src_ip"),
            "dst": e.get("dest_ip"),
            "bytes_toserver": flow.get("bytes_toserver", 0) or 0,
            "bytes_toclient": flow.get("bytes_toclient", 0) or 0,
            "pkts_toserver":  flow.get("pkts_toserver", 0)  or 0,
            "pkts_toclient":  flow.get("pkts_toclient", 0)  or 0,
            "state":          flow.get("state", "")         or "",
        }
    except Exception:
        return None

def aggregate(window):
    df = pd.DataFrame(window)
    if df.empty: return None
    bytes_total = df["bytes_toserver"] + df["bytes_toclient"]
    pkts_total  = df["pkts_toserver"]  + df["pkts_toclient"]
    return {
        "flows": len(df),
        "bytes_total": int(bytes_total.sum()),
        "pkts_total": int(pkts_total.sum()),
        "uniq_src": int(df["src"].nunique()),
        "uniq_dst": int(df["dst"].nunique()),
        "syn_ratio": float((df["state"].fillna("").eq("new")).mean()),
        "mean_bytes_flow": float(bytes_total.mean()),
    }

def ensure_csv_header():
    if not OUT.exists() or OUT.stat().st_size == 0:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(columns=FEATURE_HEADER).to_csv(OUT, index=False)

def load_state():
    if STATE.exists():
        try:
            s = json.loads(STATE.read_text(encoding="utf-8"))
            return {"pos": int(s.get("pos", 0)), "inode": s.get("inode")}
        except Exception:
            pass
    return {"pos": 0, "inode": None}

def save_state(pos, inode):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({"pos": int(pos), "inode": inode}), encoding="utf-8")

def file_inode(path: Path):
    try:
        st = path.stat()
        return (st.st_ino, st.st_size, st.st_mtime)
    except FileNotFoundError:
        return None

def run():
    ensure_csv_header()
    state = load_state()
    win_start = None
    buf = []

    print(f"🟢 Tailing {IN}")
    while True:
        id_now = file_inode(IN)
        if not id_now:
            time.sleep(0.5); continue

        with IN.open("r", encoding="utf-8") as f:
            rotated = (state["inode"] != id_now[0]) or (state["pos"] > id_now[1])
            if rotated:
                state["pos"] = 0
                state["inode"] = id_now[0]
                # reset in-memory windowing on rotation
                win_start = None
                buf = []

            f.seek(state["pos"])

            while True:
                line = f.readline()
                if not line:
                    # EOF
                    state["pos"] = f.tell()
                    save_state(state["pos"], state["inode"])
                    break

                try:
                    e = json.loads(line)
                except Exception:
                    continue

                r = to_row(e)
                if not r: 
                    continue

                ts = r["ts"]
                if win_start is None:
                    win_start = ts
                win_end = win_start + timedelta(seconds=WINDOW_SEC)

                if ts < win_end:
                    buf.append(r)
                else:
                    # flush current window
                    agg = aggregate(buf)
                    if agg:
                        pd.DataFrame([agg]).to_csv(OUT, mode="a", header=False, index=False)
                    # advance window until current ts fits
                    while ts >= win_end:
                        win_start += timedelta(seconds=WINDOW_SEC)
                        win_end = win_start + timedelta(seconds=WINDOW_SEC)
                    buf = [r]

        time.sleep(SLEEP)

if __name__ == "__main__":
    run()
