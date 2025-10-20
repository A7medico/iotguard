# scripts/decision_loop.py
import os, time, json
from pathlib import Path
from datetime import datetime
import pandas as pd
from joblib import load
from colorama import init, Fore, Style
import yaml
import platform
import subprocess

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
FEATURES = [
    "flows","bytes_total","pkts_total",
    "uniq_src","uniq_dst","syn_ratio","mean_bytes_flow"
]
MODEL = load(MODEL_PATH)

# ---------- Defaults / constants ----------
DEFAULTS = dict(
    threshold=0.70,
    grace=2,
    window=5,
    cooldown_sec=5,
    instant_block=0.95,
    dry_run=True                # set False to actually apply firewall blocks
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

def maybe_reload():
    global decision, cfg_mtime, THRESHOLD, GRACE, WINDOW, COOLDOWN_SEC, INSTANT_BLK, DRY_RUN
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
        print(Fore.CYAN + f"🔁 Reloaded config:"
              f" thr={THRESHOLD} grace={GRACE} window={WINDOW}"
              f" cooldown={COOLDOWN_SEC}s instant={INSTANT_BLK} dry_run={DRY_RUN}" + Style.RESET_ALL)

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

def log_event(idx, score, state_text, hits, action):
    evt = {
        "ts": time.time(),
        "index": int(idx),
        "score": float(score),
        "state": state_text,
        "hits_in_window": int(hits),
        "action": action,
    }
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
class Blocker:
    def __init__(self, dry_run: bool):
        self.os = platform.system().lower()
        self.dry = dry_run

    def block_ip(self, ip: str) -> tuple[bool, str]:
        if not ip:
            return False, "no-ip"
        if self.dry:
            return True, "dry-run"

        try:
            if "windows" in self.os:
                # Windows: netsh advfirewall
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                       f"name=IoTGuard_Block_{ip}",
                       "dir=in", "action=block", f"remoteip={ip}"]
                out = subprocess.run(cmd, capture_output=True, text=True)
                ok = (out.returncode == 0)
                return ok, (out.stdout.strip() or out.stderr.strip())

            else:
                # Linux: try iptables, fallback to ufw
                # iptables (requires sudo privileges)
                cmd = ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
                out = subprocess.run(cmd, capture_output=True, text=True)
                if out.returncode == 0:
                    return True, "iptables"

                # ufw (if iptables failed / not available)
                cmd = ["sudo", "ufw", "deny", "from", ip]
                out = subprocess.run(cmd, capture_output=True, text=True)
                ok = (out.returncode == 0)
                return ok, (out.stdout.strip() or out.stderr.strip())

        except Exception as e:
            return False, str(e)

blocker = Blocker(DRY_RUN)

# ---------- Main loop ----------
print(Fore.GREEN + f"🟢 Decision loop watching {DATA_CSV}" + Style.RESET_ALL)

recent = [0] * WINDOW
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

    # Reset offset if truncated/rotated
    if state["offset_rows"] > len(df) or csv_mtime != state.get("csv_mtime", 0.0):
        state["offset_rows"] = 0
        state["csv_mtime"] = csv_mtime

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
        x = pd.DataFrame([row[FEATURES]])
        p = float(MODEL.predict_proba(x)[0, 1])
        is_attack = p >= THRESHOLD
        state_txt = "ATTACK" if is_attack else "benign"

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
        should_block = (is_attack and (burst_ok or instant))

        # Debug reason (why not blocked)
        debug_reason = None
        if not is_attack:
            debug_reason = "benign"
        elif not time_ok:
            debug_reason = f"cooldown {COOLDOWN_SEC}s"
        elif hits < GRACE and p < INSTANT_BLK:
            debug_reason = f"below burst/instant (hits={hits}<{GRACE}, score={p:.3f}<{INSTANT_BLK})"

        # Optional: choose an IP to block (best guess from Suricata window)
        ip_to_block = read_top_src_ip()

        # Debounce: don’t spam for the same CSV index
        action = "NONE"
        if should_block and state.get("last_block_idx") != int(idx):
            ok, how = blocker.block_ip(ip_to_block) if ip_to_block else (False, "no-ip")
            last_block_t = time.time()
            state["last_block_idx"] = int(idx)
            save_state(state)
            action = "BLOCK"
            print(Fore.YELLOW + f"🚫 BLOCK triggered — ip={ip_to_block} via {how}, ok={ok}" + Style.RESET_ALL)

        # Console line
        color = Fore.RED if is_attack else Fore.GREEN
        print(f"{idx}: score={p:.3f} → {color}{state_txt}{Style.RESET_ALL} (hits last{WINDOW}={hits})")
        if action == "NONE" and debug_reason:
            print(Style.DIM + f"   └─ no BLOCK: {debug_reason}" + Style.RESET_ALL)

        # Event log (dashboard)
        log_event(idx, p, state_txt, hits, action)

    time.sleep(0.4)
