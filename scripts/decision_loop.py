"""
scripts/decision_loop.py
-----------------------------------------------------------------------------
IoTGuard Pipeline — Streaming Scoring & Enforcement Engine

Position in pipeline
    Suricata / simulators
        →  features.csv               (13 features per time window)
        →  [THIS FILE]                (model scoring + policies + blocking)
        →  alerts.jsonl               (structured events)
        →  api_dashboard.py / tools   (visualization, exports, metrics)

High‑level responsibilities
    - Tail data/features.csv and **only score new rows**, preserving offset across restarts.
    - For each row:
        * compute P(attack) using the trained LightGBM model,
        * optionally adjust the threshold using an **adaptive threshold** based on recent scores,
        * decide benign vs ATTACK and maintain a sliding window of hits,
        * apply policy (grace, cooldown, instant block) to decide if we should block,
        * pick an IP to block from window_meta.json (top_src_ip),
        * enrich the event with:
              XAI reason (SHAP via explainer.py),
              Threat Intel (country/flag/reputation via threat_intel.py),
              effective_threshold and action severity,
        * append a compact JSON event to alerts.jsonl for the dashboard and audits.

Key inputs
    - models/lightgbm.joblib      – trained model.
    - models/model_meta.json      – feature list + default threshold.
    - configs/model.yaml          – decision.* section (threshold, grace, window, cooldown, adaptive, dry_run).
    - data/features.csv           – streaming feature windows from suricata_to_features.py or stream_csvs.py.
    - data/window_meta.json       – per-window context: top_src_ip and light DPI stats (HTTP/DNS/TLS).

Key outputs
    - data/alerts.jsonl           – one JSON line per scored window (used by api_dashboard and CSV export).
    - Firewall rules              – via blocker.py when dry_run is False (or simulated when True).
-----------------------------------------------------------------------------
"""
import os, time, json
from pathlib import Path
from datetime import datetime
import pandas as pd
from joblib import load
import json as _json
from colorama import init, Fore, Style
import yaml
import sys

# Add scripts directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from blocker import block_ip as blocker_block_ip
from explainer import RealTimeExplainer
from threat_intel import ThreatIntel

init(autoreset=True)

# ---------- Paths ----------
DATA_DIR    = Path("data")
DATA_CSV    = DATA_DIR / "features.csv"
MODEL_PATH  = Path("models/lightgbm.joblib")
CFG_PATH    = Path("configs/model.yaml")
ALERT_LOG   = DATA_DIR / "alerts.jsonl"
STATE_FILE  = DATA_DIR / "state.json"
WIN_META    = DATA_DIR / "window_meta.json"   # optional (from suricata_to_features.py)

# ---------- Model / Features ----------
# Load features from model_meta.json if available, else use defaults
FEATURES = None
try:
    meta_path = Path("models/model_meta.json")
    if meta_path.exists():
        meta = _json.loads(meta_path.read_text(encoding="utf-8"))
        FEATURES = meta.get("features")
except Exception as e:
    print(Fore.YELLOW + f"⚠️  Could not load model_meta.json: {e}" + Style.RESET_ALL)

if not FEATURES:
    # Fallback to the 13 core features
    FEATURES = [
        "flows","bytes_total","pkts_total","syn_ratio","mean_bytes_flow",
        "ack_ratio","fin_ratio","rst_ratio",
        "http_ratio","tcp_ratio","protocol_diversity",
        "std_bytes","iat_mean"
    ]

print(Fore.CYAN + f"ℹ️  Using {len(FEATURES)} features: {FEATURES}" + Style.RESET_ALL)

MODEL = load(MODEL_PATH)
CLASSES = None
try:
    cj = Path("models/classes.json")
    if cj.exists():
        CLASSES = _json.loads(cj.read_text(encoding="utf-8"))
except Exception:
    CLASSES = None

# Initialize Explainer
print(Fore.CYAN + "ℹ️  Initializing RealTimeExplainer..." + Style.RESET_ALL)
EXPLAINER = RealTimeExplainer(MODEL, FEATURES)

# Initialize Threat Intel
print(Fore.CYAN + "ℹ️  Initializing ThreatIntel..." + Style.RESET_ALL)
THREAT_INTEL = ThreatIntel()

import numpy as np

# ---------- Defaults / constants ----------
DEFAULTS = dict(
    threshold=0.70,
    grace=2,
    window=5,
    cooldown_sec=5,
    instant_block=0.95,
    dry_run=True,               # set False to actually apply firewall blocks
    use_adaptive=False,         # enable adaptive thresholding
    adaptive_window=50,         # how many recent scores to track
    adaptive_sensitivity=2.0,   # Z-score multiplier (mean + K * std)
    adaptive_min=0.50           # never drop threshold below this
)
LOG_ROTATE_BYTES = 5_000_000
PRINT_IDLE_SECS  = 5.0

# ---------- Config (hot-reload) ----------
def load_cfg():
    try:
        mtime = CFG_PATH.stat().st_mtime
        cfg = yaml.safe_load(CFG_PATH.read_text(encoding="utf-8")) or {}
        dec = dict(cfg.get("decision") or {})
        out = DEFAULTS | {
            "threshold":     float(dec.get("threshold",     DEFAULTS["threshold"])),
            "grace":         int(  dec.get("grace",         DEFAULTS["grace"])),
            "window":        int(  dec.get("window",        DEFAULTS["window"])),
            "cooldown_sec":  int(  dec.get("cooldown_sec",  DEFAULTS["cooldown_sec"])),
            "instant_block": float(dec.get("instant_block", DEFAULTS["instant_block"])),
            "dry_run":       bool( dec.get("dry_run",       DEFAULTS["dry_run"])),
            "use_adaptive":        bool( dec.get("use_adaptive",        DEFAULTS["use_adaptive"])),
            "adaptive_window":     int(  dec.get("adaptive_window",     DEFAULTS["adaptive_window"])),
            "adaptive_sensitivity":float(dec.get("adaptive_sensitivity",DEFAULTS["adaptive_sensitivity"])),
            "adaptive_min":        float(dec.get("adaptive_min",        DEFAULTS["adaptive_min"])),
        }
        return out, mtime
    except Exception:
        return DEFAULTS.copy(), 0.0

decision, cfg_mtime = load_cfg()
THRESHOLD    = decision["threshold"]
GRACE        = decision["grace"]
WINDOW       = decision["window"]
COOLDOWN_SEC = decision["cooldown_sec"]
INSTANT_BLK  = decision["instant_block"]
DRY_RUN      = decision["dry_run"]
USE_ADAPTIVE = decision["use_adaptive"]
ADAPT_WIN    = decision["adaptive_window"]
ADAPT_SENS   = decision["adaptive_sensitivity"]
ADAPT_MIN    = decision["adaptive_min"]

def maybe_reload():
    global decision, cfg_mtime, THRESHOLD, GRACE, WINDOW, COOLDOWN_SEC, INSTANT_BLK, DRY_RUN
    global USE_ADAPTIVE, ADAPT_WIN, ADAPT_SENS, ADAPT_MIN
    try:
        mtime = CFG_PATH.stat().st_mtime
    except FileNotFoundError:
        mtime = 0.0
    if mtime != cfg_mtime:
        decision, cfg_mtime = load_cfg()
        THRESHOLD    = decision["threshold"]
        GRACE        = decision["grace"]
        WINDOW       = decision["window"]
        COOLDOWN_SEC = decision["cooldown_sec"]
        INSTANT_BLK  = decision["instant_block"]
        DRY_RUN      = decision["dry_run"]
        USE_ADAPTIVE = decision["use_adaptive"]
        ADAPT_WIN    = decision["adaptive_window"]
        ADAPT_SENS   = decision["adaptive_sensitivity"]
        ADAPT_MIN    = decision["adaptive_min"]
        print(Fore.CYAN + f"🔁 Reloaded config:"
              f" thr={THRESHOLD} adapt={USE_ADAPTIVE} dry={DRY_RUN}" + Style.RESET_ALL)

# ---------- State ----------
def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"offset_rows": 0, "csv_mtime": 0.0, "last_block_idx": None}

def save_state(s):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(s), encoding="utf-8")

state = load_state()

# ---------- Helpers ----------
def rotate_alerts():
    try:
        if ALERT_LOG.exists() and ALERT_LOG.stat().st_size > LOG_ROTATE_BYTES:
            ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            ALERT_LOG.rename(ALERT_LOG.with_name(f"alerts-{ts}.jsonl"))
            print(Fore.MAGENTA + "🗂️  Rotated alerts log" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.YELLOW + f"Log rotate warn: {e}" + Style.RESET_ALL)

def log_event(idx, score, state_text, hits, action, pred_class=None, reason=None, effective_thr=None, threat_info=None):
    evt = {
        "ts": time.time(),
        "index": int(idx),
        "score": float(score),
        "state": state_text,
        "hits_in_window": int(hits),
        "action": action,
    }
    if effective_thr is not None:
        evt["effective_threshold"] = float(effective_thr)
    if pred_class is not None:
        evt["pred_class"] = str(pred_class)
    if reason:
        evt["reason"] = str(reason)
    if threat_info:
        evt["threat"] = threat_info
        
    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with ALERT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(evt) + "\n")

def to_numeric(df: pd.DataFrame) -> pd.DataFrame:
    for c in FEATURES:
        df[c] = pd.to_numeric(df[c].astype(str).str.strip(), errors="coerce")
    return df

def has_required_cols(df): 
    return set(FEATURES).issubset(df.columns)

def read_top_src_ip() -> str | None:
    """Optional: top source IP from the most recent Suricata window, saved by the tailer."""
    try:
        if WIN_META.exists():
            meta = json.loads(WIN_META.read_text(encoding="utf-8"))
            return meta.get("top_src_ip")
    except Exception:
        pass
    return None

# ---------- Blocker ----------
# Use blocker.py module for better cross-platform support (nftables, etc.)
def block_ip_wrapper(ip: str, dry_run: bool, severity: str = "hard") -> tuple[bool, str]:
    """
    Wrapper around blocker.py that respects dry_run mode and severity.
    Severity: 'soft' (temp), 'hard' (permanent), 'kill' (connection reset)
    """
    if not ip:
        return False, "no-ip"
    if dry_run:
        return True, f"dry-run-{severity}"
    
    # For now, map all to standard block, but log intention
    # In a real system, you'd call different firewall commands here
    return blocker_block_ip(ip)

def classify_attack_heuristic(row: pd.Series) -> str:
    """
    Infer attack type based on feature values if model is generic binary.
    """
    # Extract values (safe get)
    syn = float(row.get("syn_ratio", 0))
    rst = float(row.get("rst_ratio", 0))
    http = float(row.get("http_ratio", 0))
    bytes_t = float(row.get("bytes_total", 0))
    pkts = float(row.get("pkts_total", 0))
    mean_b = float(row.get("mean_bytes_flow", 0))
    
    # 1. Web Attacks (SQLi, XSS, Brute Force Web)
    if http > 0.5:
        return "Web Attack (HTTP)"
        
    # 2. SYN Flood (High SYN, low packet count per flow usually, but high volume)
    if syn > 0.6:
        return "DDoS: SYN Flood"
        
    # 3. Port Scan (High RST or very small flows)
    if rst > 0.5:
        return "Recon: Port Scan (RST)"
    if pkts < 3 and flows > 20: # Many small flows
        return "Recon: Port Scan (Stealth)"

    # 4. Volumetric DDoS (UDP/Mirai)
    # If not TCP/HTTP and massive bytes/pkts
    if bytes_t > 5_000_000 or pkts > 10_000:
        return "DDoS: Volumetric (Mirai/UDP)"
        
    # 5. Uploading / Exfiltration
    if mean_b > 5000 and syn < 0.1:
        return "Exfiltration / Upload"

    return "General Anomaly"

# ---------- Main loop ----------
print(Fore.GREEN + f"🟢 Decision loop watching {DATA_CSV}" + Style.RESET_ALL)

recent = [0] * WINDOW
adaptive_history = [] # stores recent scores
last_block_t = 0.0
last_idle_print = 0.0

while True:
    now = time.time()
    maybe_reload()
    rotate_alerts()

    if not DATA_CSV.exists():
        time.sleep(0.4)
        continue

    # Read CSV and protect against concurrent writes
    try:
        csv_mtime = DATA_CSV.stat().st_mtime
        df = pd.read_csv(DATA_CSV)
    except Exception:
        time.sleep(0.4)
        continue

    # Reset offset only if file was truncated/rotated (length shrank)
    if state["offset_rows"] > len(df):
        state["offset_rows"] = 0

    # Nothing new?
    if df.empty or state["offset_rows"] >= len(df):
        if now - last_idle_print > PRINT_IDLE_SECS:
            print(Style.DIM + "…idle (no new rows)" + Style.RESET_ALL)
            last_idle_print = now
        time.sleep(0.4)
        continue

    # Schema check
    if not has_required_cols(df):
        missing = list(set(FEATURES) - set(df.columns))
        print(Fore.YELLOW + f"⚠️  Missing columns: {missing} — waiting…" + Style.RESET_ALL)
        time.sleep(1.0)
        continue

    # Take new rows
    batch = df.iloc[state["offset_rows"] : ].copy()
    state["offset_rows"] = len(df)
    state["csv_mtime"] = csv_mtime
    save_state(state)

    # Clean -> numeric only
    before = len(batch)
    batch = to_numeric(batch).dropna(subset=FEATURES)
    if before - len(batch) > 0:
        print(Fore.YELLOW + f"  Dropped {before - len(batch)} malformed rows" + Style.RESET_ALL)

    for idx, row in batch.iterrows():
        # Fix 'flows' variable access for heuristic
        flows = float(row.get("flows", 0))
        
        x = pd.DataFrame([row[FEATURES]])
        proba = MODEL.predict_proba(x)
        pred_label = None
        try:
            vec = proba[0]
            # Multiclass with classes mapping
            if CLASSES and isinstance(CLASSES.get("classes"), list):
                classes = CLASSES.get("classes") or []
                benign_index = int(CLASSES.get("benign_index", 0) or 0)
                p = float(1.0 - float(vec[benign_index]))
                pred_idx = int(getattr(vec, "argmax", lambda: 0)())
                pred_label = classes[pred_idx] if 0 <= pred_idx < len(classes) else None
            else:
                # Binary: use column 1 if available
                p = float(vec[1]) if len(vec) > 1 else float(vec)
                pred_label = "attack" if p >= THRESHOLD else "benign"
        except Exception:
            # Fallback: score as probability of positive
            try:
                p = float(MODEL.predict_proba(x)[0,1])
            except Exception:
                p = float(MODEL.predict(x)[0])
        
        # Heuristic Classification (override pred_label if binary)
        heuristic_label = None
        if p >= THRESHOLD: # Only classify if it's suspicious
             heuristic_label = classify_attack_heuristic(row)
             if heuristic_label:
                 pred_label = heuristic_label
                 
        # Adaptive Threshold Logic
        effective_thr = THRESHOLD
        
        # update history
        adaptive_history.append(p)
        if len(adaptive_history) > ADAPT_WIN:
            adaptive_history.pop(0)
            
        if USE_ADAPTIVE and len(adaptive_history) > 10:
            # Calculate stats
            mu = np.mean(adaptive_history)
            sigma = np.std(adaptive_history)
            # Dynamic threshold = mean + K * std
            dyn_thr = mu + (ADAPT_SENS * sigma)
            
            # Ensure it doesn't drop too low (safety floor)
            dyn_thr = max(dyn_thr, ADAPT_MIN)
            
            # Effective threshold is dynamic, but never lower than config threshold if that's desired
            # Or we can let it float. Let's use the stricter of (Dynamic, Config) to be safe?
            # Actually, adaptive usually implies raising the bar when noise is high.
            # Let's take the MAX of (ConfigThreshold, DynamicThreshold) so we never become LESS secure than base config.
            effective_thr = max(THRESHOLD, dyn_thr)

        is_attack = p >= effective_thr
        state_txt = "ATTACK" if is_attack else "benign"

        # Explain high scores (XAI)
        reason_str = None
        if is_attack:
             reason_str = EXPLAINER.explain_row(x)

        # rolling window
        recent.append(1 if is_attack else 0)
        if len(recent) > WINDOW:
            recent = recent[-WINDOW:]
        hits = sum(recent)

        # --- Policy: burst OR instant, and respect cooldown ---
        now = time.time()
        time_ok   = (now - last_block_t) > COOLDOWN_SEC
        burst_ok  = (hits >= GRACE and time_ok)
        instant   = (p >= INSTANT_BLK) and time_ok
        
        response_type = "NONE"
        if is_attack:
            if p >= 0.98:
                response_type = "KILL" # Highest severity
            elif p >= INSTANT_BLK:
                response_type = "HARD" # Permanent block
            elif burst_ok:
                response_type = "SOFT" # Temporary/Standard block
        
        should_block = (response_type != "NONE")

        # Debug reason (why not blocked)
        debug_reason = None
        if not is_attack:
            debug_reason = "benign"
        elif not time_ok:
            debug_reason = f"cooldown {COOLDOWN_SEC}s"
        elif response_type == "NONE":
            debug_reason = f"below criteria (hits={hits}<{GRACE}, score={p:.3f}<{INSTANT_BLK})"

        # Optional: choose an IP to block (best guess from Suricata window)
        ip_to_block = read_top_src_ip()
        
        # Threat Intel Enrichment
        threat_ctx = None
        if ip_to_block:
             threat_ctx = THREAT_INTEL.enrich_ip(ip_to_block)

        # Debounce: don't spam for the same CSV index
        action = "NONE"
        if should_block and state.get("last_block_idx") != int(idx):
            # Pass severity to blocker
            ok, how = block_ip_wrapper(ip_to_block, DRY_RUN, severity=response_type.lower())
            last_block_t = time.time()
            state["last_block_idx"] = int(idx)
            save_state(state)
            action = f"BLOCK-{response_type}"
            print(Fore.YELLOW + f"🚫 {action} triggered — ip={ip_to_block} via {how}, ok={ok}" + Style.RESET_ALL)

        # Console line
        color = Fore.RED if is_attack else Fore.GREEN
        thr_str = f"{effective_thr:.3f}" if USE_ADAPTIVE else f"{THRESHOLD:.2f}"
        print(f"{idx}: score={p:.3f} (thr={thr_str}) → {color}{state_txt}{Style.RESET_ALL} (hits last{WINDOW}={hits})")
        if action == "NONE" and debug_reason:
            print(Style.DIM + f"   └─ no BLOCK: {debug_reason}" + Style.RESET_ALL)
        
        if reason_str:
             print(Fore.MAGENTA + f"   🔍 Why? {reason_str}" + Style.RESET_ALL)
        if heuristic_label:
             print(Fore.BLUE + f"   🏷️  Type: {heuristic_label}" + Style.RESET_ALL)

        # Event log (dashboard)
        log_event(idx, p, state_txt, hits, action, pred_label, reason_str, effective_thr, threat_ctx)

    time.sleep(0.4)
