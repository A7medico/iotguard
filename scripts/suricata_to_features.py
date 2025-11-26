"""
scripts/suricata_to_features.py
-----------------------------------------------------------------------------
IoTGuard Pipeline — Suricata eve.json → Rolling Window Features

Position in pipeline
    Suricata (PCAP / live interface)
        →  data/suricata/eve.json   (JSON events per flow)
        →  [THIS FILE]              (10‑second aggregation into 13 features)
        →  data/features.csv        (consumed by decision_loop.py)
        →  alerts.jsonl / dashboard

High‑level responsibilities
    - Tail Suricata's eve.json safely across log rotations (using inode + offset tracking).
    - Group incoming `flow` events into fixed‑size time windows (default 10 seconds).
    - For each window, compute the 13 numeric features the model expects:
        flows, bytes_total, pkts_total, syn_ratio, mean_bytes_flow,
        ack_ratio, fin_ratio, rst_ratio,
        http_ratio, tcp_ratio, protocol_diversity,
        std_bytes, iat_mean.
    - Append one row per window to data/features.csv (header written once on first run).
    - Derive additional **meta context** (top_src_ip and simple HTTP/DNS/TLS stats)
      and write it to data/window_meta.json so the decision loop can:
        * decide which IP to block,
        * display light DPI context in the UI.

Key inputs
    - data/suricata/eve.json   – produced by Suricata with eve-log enabled.

Key outputs
    - data/features.csv        – streaming feature matrix aligned with the ML model.
    - data/window_meta.json    – per-window meta: top_src_ip and protocol mix (http/dns/tls).
-----------------------------------------------------------------------------
"""
import json, time
from pathlib import Path
from datetime import datetime, timedelta, timezone
import pandas as pd

IN    = Path("data/suricata/eve.json")
OUT   = Path("data/features.csv")
STATE = Path("data/eve_tail_state.json")
WIN_META = Path("data/window_meta.json")

WINDOW_SEC = 10
SLEEP = 0.3

FEATURE_HEADER = [
    # Core features
    "flows","bytes_total","pkts_total","syn_ratio","mean_bytes_flow",
    # Flag ratios (3)
    "ack_ratio","fin_ratio","rst_ratio",
    # Protocol features (3)
    "http_ratio","tcp_ratio","protocol_diversity",
    # Statistical features (2)
    "std_bytes","iat_mean"
]

def parse_ts(ts: str):
    # Suricata: "...Z" or "...+0000"
    if ts.endswith("Z"):
        ts = ts.replace("Z", "+00:00")
    elif ts.endswith("+0000"):
        ts = ts[:-5] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)

def to_row(e: dict):
    """
    Map a Suricata eve 'flow' event into a minimal row used for aggregation.
    We keep extra fields (proto / app_proto) internally to build richer
    features like http_ratio, tcp_ratio, and protocol_diversity.
    """
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
            "proto":          (e.get("proto") or "").upper(),
            "app_proto":      (e.get("app_proto") or "").lower(),
        }
    except Exception:
        return None

def aggregate(window):
    df = pd.DataFrame(window)
    if df.empty: return None
    bytes_total = df["bytes_toserver"] + df["bytes_toclient"]
    pkts_total  = df["pkts_toserver"]  + df["pkts_toclient"]
    
    # choose a candidate IP to block: top source in this window
    try:
        top_src = df["src"].value_counts().idxmax()
    except Exception:
        top_src = None

    # --- Lightweight DPI-style context (for meta only, not fed to the model) ---
    # Use Suricata's proto / app_proto classification to summarize application traffic.
    protos = df.get("proto", "").fillna("").astype(str).str.upper()
    app_protos = df.get("app_proto", "").fillna("").astype(str).str.lower()

    http_like_mask = app_protos.isin(["http", "http_proxy"]) | protos.eq("HTTP")
    dns_mask  = app_protos.eq("dns")
    tls_mask  = app_protos.eq("tls")

    http_flows = int(http_like_mask.sum())
    dns_flows  = int(dns_mask.sum())
    tls_flows  = int(tls_mask.sum())
    app_proto_set = sorted(set(a for a in app_protos.unique() if a))
    
    # Core features
    flows = len(df)
    syn_ratio = float((df["state"].fillna("").str.contains("new|SYN", case=False, na=False)).mean())
    
    # Flag ratios (estimate from state strings)
    states = df["state"].fillna("").str.upper()
    ack_ratio = float(states.str.contains("ACK", na=False).mean())
    fin_ratio = float(states.str.contains("FIN", na=False).mean())
    rst_ratio = float(states.str.contains("RST", na=False).mean())
    
    # Protocol features from Suricata's proto/app_proto fields
    # HTTP ratio: fraction of flows where app_proto is http-like
    http_ratio = float(http_like_mask.mean())
    # TCP ratio: fraction of flows with proto == TCP
    tcp_ratio = float(protos.eq("TCP").mean())
    # Protocol diversity: number of distinct proto/app_proto values (clamped)
    proto_set = set(p for p in protos.unique() if p) | set(app_proto_set)
    protocol_diversity = min(len(proto_set), 12)
    
    # Statistical features
    std_bytes = float(bytes_total.std()) if len(bytes_total) > 1 else 0.0
    # IAT: mean inter-arrival time within the window (seconds)
    try:
        ts_sorted = df["ts"].sort_values()
        if len(ts_sorted) > 1:
            deltas = ts_sorted.diff().dt.total_seconds().dropna()
            iat_mean = float(deltas.mean())
        else:
            iat_mean = 0.0
    except Exception:
        iat_mean = 0.0
    
    return {
        # Core
        "flows": flows,
        "bytes_total": int(bytes_total.sum()),
        "pkts_total": int(pkts_total.sum()),
        # "uniq_src": int(df["src"].nunique()), # Dropped
        # "uniq_dst": int(df["dst"].nunique()), # Dropped
        "syn_ratio": syn_ratio,
        "mean_bytes_flow": float(bytes_total.mean()),
        # Flag ratios (3)
        "ack_ratio": ack_ratio,
        "fin_ratio": fin_ratio,
        "rst_ratio": rst_ratio,
        # Protocol features (3)
        "http_ratio": http_ratio,
        "tcp_ratio": tcp_ratio,
        "protocol_diversity": protocol_diversity,
        # Statistical features (2)
        "std_bytes": std_bytes,
        "iat_mean": iat_mean,
        # meta fields (not written to features.csv)
        "_top_src": top_src,
        "_http_flows": http_flows,
        "_dns_flows": dns_flows,
        "_tls_flows": tls_flows,
        "_app_protos": app_proto_set,
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
                        # write features row
                        row = {k: agg[k] for k in FEATURE_HEADER}
                        pd.DataFrame([row]).to_csv(OUT, mode="a", header=False, index=False)
                        # expose meta for decision loop (top_src_ip + light DPI context)
                        try:
                            top_src = agg.get("_top_src")
                            meta_out = {
                                "top_src_ip": top_src,
                                "http_flows": agg.get("_http_flows", 0),
                                "dns_flows":  agg.get("_dns_flows", 0),
                                "tls_flows":  agg.get("_tls_flows", 0),
                                "app_protos": agg.get("_app_protos", []),
                            }
                            WIN_META.parent.mkdir(parents=True, exist_ok=True)
                            WIN_META.write_text(json.dumps(meta_out), encoding="utf-8")
                        except Exception:
                            pass
                    # advance window until current ts fits
                    while ts >= win_end:
                        win_start += timedelta(seconds=WINDOW_SEC)
                        win_end = win_start + timedelta(seconds=WINDOW_SEC)
                    buf = [r]

        time.sleep(SLEEP)

if __name__ == "__main__":
    run()
