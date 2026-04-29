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
        * compute P(attack) using the trained LightGBM model (supervised),
        * optionally compute anomaly score using IsolationForest (unsupervised),
        * support hybrid mode: flag if EITHER model detects an issue,
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
    - models/lightgbm.joblib      – trained supervised model.
    - models/model_meta.json      – feature list + default threshold.
    - models/unsup_isoforest.joblib – trained unsupervised model (optional).
    - models/unsup_meta.json      – unsupervised feature list + threshold (optional).
    - configs/model.yaml          – decision.* section + hybrid.* section.
    - data/features.csv           – streaming feature windows from suricata_to_features.py or stream_csvs.py.
    - data/window_meta.json       – per-window context: top_src_ip and light DPI stats (HTTP/DNS/TLS).

Key outputs
    - data/alerts.jsonl           – one JSON line per scored window (used by api_dashboard and CSV export).
    - Firewall rules              – via blocker.py when dry_run is False (or simulated when True).
-----------------------------------------------------------------------------
"""
import os, time, json, io
from pathlib import Path
from datetime import datetime
import pandas as pd
from joblib import load
import json as _json
import yaml
import sys

# Reconfigure stdout/stderr to UTF-8 to prevent UnicodeEncodeError on Windows (cp1252)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from colorama import init, Fore, Style

# Add scripts directory and subdirectories to path for imports
_scripts_dir = Path(__file__).parent.parent
sys.path.insert(0, str(_scripts_dir))
sys.path.insert(0, str(_scripts_dir / "9_utilities"))
sys.path.insert(0, str(_scripts_dir / "3_inference"))
sys.path.insert(0, str(_scripts_dir / "4_response"))
sys.path.insert(0, str(_scripts_dir / "6_threat_intel"))
from blocker import block_ip as blocker_block_ip
from explainer import RealTimeExplainer
from threat_intel import ThreatIntel
from logging_config import get_logger, get_audit_logger

# Optional: Alerting system for notifications
try:
    from alerting import send_alert
    ALERTING_AVAILABLE = True
except ImportError:
    ALERTING_AVAILABLE = False
    send_alert = lambda *args, **kwargs: {}  # No-op fallback

init(autoreset=True)

# ---------- Logging ----------
logger = get_logger("decision_loop")
audit_logger = get_audit_logger()

# ---------- Paths ----------
DATA_DIR    = Path("data")
DATA_CSV    = DATA_DIR / "features.csv"
# Allow overriding config path via env for profiles (lab/prod)
CFG_PATH    = Path(os.getenv("IOTGUARD_CONFIG") or "configs/model.yaml")
ALERT_LOG   = DATA_DIR / "alerts.jsonl"
STATE_FILE  = DATA_DIR / "state.json"
WIN_META    = DATA_DIR / "window_meta.json"   # optional (from suricata_to_features.py)
LOG_DIR     = Path("logs")
AUDIT_LOG   = LOG_DIR / "audit.jsonl"         # structured internal log
HEALTH_FILE = DATA_DIR / "decision_health.json"

# ---------- Dynamic Model Loading ----------
# Select environment: "iot" (default) or "it"
ENV_MODE = os.getenv("IOTGUARD_ENV", "iot").lower()

# Load config to get model paths
_CFG = {}
try:
    if CFG_PATH.exists():
        _CFG = yaml.safe_load(CFG_PATH.read_text(encoding="utf-8")) or {}
except Exception as e:
    logger.warning(f"Could not load config: {e}")

# Resolve paths based on environment
_models_cfg = _CFG.get("models", {})
_env_cfg = _models_cfg.get(ENV_MODE, {})

# Default to IoT paths if not specified
MODEL_PATH = Path(_env_cfg.get("path", "models/lightgbm.joblib"))
META_PATH  = Path(_env_cfg.get("meta", "models/model_meta.json"))

logger.info(f"🌍 Environment: {ENV_MODE.upper()}")
logger.info(f"📂 Loading model: {MODEL_PATH}")

UNSUP_MODEL_PATH = Path("models/unsup_isoforest.joblib")
UNSUP_META_PATH  = Path("models/unsup_meta.json")

# ---------- Model / Features ----------
# Load features from model metadata
FEATURES = None
try:
    if META_PATH.exists():
        meta = _json.loads(META_PATH.read_text(encoding="utf-8"))
        FEATURES = meta.get("features")
        logger.info(f"✅ Loaded features from {META_PATH}")
except Exception as e:
    print(Fore.YELLOW + f"⚠️  Could not load model meta: {e}" + Style.RESET_ALL)

if not FEATURES:
    # Fallback to the 13 core features
    FEATURES = [
        "flows","bytes_total","pkts_total","syn_ratio","mean_bytes_flow",
        "ack_ratio","fin_ratio","rst_ratio",
        "http_ratio","tcp_ratio","protocol_diversity",
        "std_bytes","iat_mean"
    ]

print(Fore.CYAN + f"ℹ️  Using {len(FEATURES)} features: {FEATURES}" + Style.RESET_ALL)

# ---------- Model Loading (Multi-Model) ----------
MODELS = {}
MODEL_META = {}

def load_models():
    """Load all defined models (iot, it) from config."""
    global MODELS, MODEL_META
    
    # Reload config to get latest paths
    cfg = _load_yaml_cfg()
    models_cfg = cfg.get("models", {})
    
    # Default fallback if config is missing
    if not models_cfg:
        models_cfg = {
            "iot": {"path": "models/lightgbm.joblib", "threshold": 0.90}
        }
        
    for name, info in models_cfg.items():
        path = Path(info.get("path", ""))
        if path.exists():
            try:
                MODELS[name] = load(path)
                print(Fore.CYAN + f"ℹ️  Loaded model '{name}' from {path}" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.RED + f"❌ Failed to load model '{name}': {e}" + Style.RESET_ALL)
        else:
            if name == "iot": # Core model must exist
                print(Fore.YELLOW + f"⚠️  Model '{name}' not found at {path}" + Style.RESET_ALL)

def _load_yaml_cfg() -> dict:
    try:
        if CFG_PATH.exists():
            return yaml.safe_load(CFG_PATH.read_text(encoding="utf-8")) or {}
    except Exception:
        pass
    return {}

load_models()

# Global CLASSES (shared for now, or could be per-model)
CLASSES = None
try:
    cj = Path("models/classes.json")
    if cj.exists():
        CLASSES = _json.loads(cj.read_text(encoding="utf-8"))
except Exception:
    CLASSES = None

# ---------- Unsupervised Model (optional) ----------
UNSUP_MODEL = None
UNSUP_META = None
UNSUP_THRESHOLD = None

def load_unsupervised_model():
    """Load unsupervised model and metadata if available."""
    global UNSUP_MODEL, UNSUP_META, UNSUP_THRESHOLD
    try:
        if UNSUP_MODEL_PATH.exists() and UNSUP_META_PATH.exists():
            UNSUP_MODEL = load(UNSUP_MODEL_PATH)
            UNSUP_META = _json.loads(UNSUP_META_PATH.read_text(encoding="utf-8"))
            UNSUP_THRESHOLD = float(UNSUP_META.get("threshold", 0.0))
            print(Fore.CYAN + f"ℹ️  Loaded unsupervised model: IsolationForest (threshold={UNSUP_THRESHOLD:.4f})" + Style.RESET_ALL)
            return True
    except Exception as e:
        print(Fore.YELLOW + f"⚠️  Could not load unsupervised model: {e}" + Style.RESET_ALL)
    return False

UNSUP_AVAILABLE = load_unsupervised_model()

# Initialize Explainer (Default to IoT model for now)
print(Fore.CYAN + "ℹ️  Initializing RealTimeExplainer..." + Style.RESET_ALL)
# Use the first available model for the explainer initialization
_default_model = next(iter(MODELS.values())) if MODELS else None
EXPLAINER = RealTimeExplainer(_default_model, FEATURES) if _default_model else None

# Initialize Threat Intel
print(Fore.CYAN + "ℹ️  Initializing ThreatIntel..." + Style.RESET_ALL)
THREAT_INTEL = ThreatIntel()

# Device Mapping
DEVICES_CFG = Path("configs/devices.yaml")
DEVICE_MAP = {}
DEFAULT_TYPE = "iot"

def load_device_map():
    global DEVICE_MAP, DEFAULT_TYPE
    try:
        if DEVICES_CFG.exists():
            d = yaml.safe_load(DEVICES_CFG.read_text(encoding="utf-8")) or {}
            DEVICE_MAP = d.get("device_map", {})
            DEFAULT_TYPE = d.get("default_type", "iot")
    except Exception:
        pass

load_device_map()

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
    adaptive_min=0.50,          # never drop threshold below this
    ip_anomaly_z=3.0,           # per-IP z-score for bytes_total anomaly
    # Hybrid mode defaults
    hybrid_mode="hybrid",       # "supervised", "unsupervised", or "hybrid"
    hybrid_combine="or",        # "or", "and", or "weighted"
    supervised_weight=0.7,
    unsupervised_weight=0.3,
    unsup_enabled=True,
    unsup_only_label="ANOMALY (unsupervised)",
)
LOG_ROTATE_BYTES = 5_000_000
PRINT_IDLE_SECS  = 5.0

# ---------- Config (hot-reload) ----------
def load_cfg():
    try:
        mtime = CFG_PATH.stat().st_mtime
        cfg = yaml.safe_load(CFG_PATH.read_text(encoding="utf-8")) or {}
        dec = dict(cfg.get("decision") or {})
        unsup_cfg = dict(cfg.get("unsupervised") or {})
        hybrid_cfg = dict(cfg.get("hybrid") or {})
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
            "ip_anomaly_z":        float(dec.get("ip_anomaly_z",        DEFAULTS["ip_anomaly_z"])),
            # Hybrid mode settings
            "unsup_enabled":       bool( unsup_cfg.get("enabled",       DEFAULTS["unsup_enabled"])),
            "hybrid_mode":         str(  hybrid_cfg.get("mode",         DEFAULTS["hybrid_mode"])),
            "hybrid_combine":      str(  hybrid_cfg.get("combine_strategy", DEFAULTS["hybrid_combine"])),
            "supervised_weight":   float(hybrid_cfg.get("supervised_weight", DEFAULTS["supervised_weight"])),
            "unsupervised_weight": float(hybrid_cfg.get("unsupervised_weight", DEFAULTS["unsupervised_weight"])),
            "unsup_only_label":    str(  hybrid_cfg.get("unsup_only_label", DEFAULTS["unsup_only_label"])),
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
IP_ANOM_Z    = decision["ip_anomaly_z"]
# Hybrid mode globals
UNSUP_ENABLED    = decision["unsup_enabled"]
HYBRID_MODE      = decision["hybrid_mode"]
HYBRID_COMBINE   = decision["hybrid_combine"]
SUP_WEIGHT       = decision["supervised_weight"]
UNSUP_WEIGHT     = decision["unsupervised_weight"]
UNSUP_ONLY_LABEL = decision["unsup_only_label"]

def maybe_reload():
    global decision, cfg_mtime, THRESHOLD, GRACE, WINDOW, COOLDOWN_SEC, INSTANT_BLK, DRY_RUN
    global USE_ADAPTIVE, ADAPT_WIN, ADAPT_SENS, ADAPT_MIN, IP_ANOM_Z
    global UNSUP_ENABLED, HYBRID_MODE, HYBRID_COMBINE, SUP_WEIGHT, UNSUP_WEIGHT, UNSUP_ONLY_LABEL
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
        IP_ANOM_Z    = decision["ip_anomaly_z"]
        UNSUP_ENABLED    = decision["unsup_enabled"]
        HYBRID_MODE      = decision["hybrid_mode"]
        HYBRID_COMBINE   = decision["hybrid_combine"]
        SUP_WEIGHT       = decision["supervised_weight"]
        UNSUP_WEIGHT     = decision["unsupervised_weight"]
        UNSUP_ONLY_LABEL = decision["unsup_only_label"]
        print(Fore.CYAN + f"🔁 Reloaded config:"
              f" thr={THRESHOLD} adapt={USE_ADAPTIVE} dry={DRY_RUN} mode={HYBRID_MODE}" + Style.RESET_ALL)

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

# ---------- Per-IP rolling stats (for simple baselining) ----------
from collections import deque

IP_STATS: dict[str, dict] = {}

# ---------- Helpers ----------
def rotate_alerts():
    try:
        if ALERT_LOG.exists() and ALERT_LOG.stat().st_size > LOG_ROTATE_BYTES:
            ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            ALERT_LOG.rename(ALERT_LOG.with_name(f"alerts-{ts}.jsonl"))
            print(Fore.MAGENTA + "🗂️  Rotated alerts log" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.YELLOW + f"Log rotate warn: {e}" + Style.RESET_ALL)

def log_event(
    idx,
    score,
    state_text,
    hits,
    action,
    pred_class=None,
    reason=None,
    effective_thr=None,
    threat_info=None,
    src_ip=None,
    ip_anomaly=None,
    device_type=None,
    detection_source=None,
    unsup_score=None,
):
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
    if src_ip is not None:
        evt["src_ip"] = src_ip
    if ip_anomaly is not None:
        evt["ip_anomaly"] = bool(ip_anomaly)
        
    if device_type is not None:
        evt["device_type"] = str(device_type)
    
    # Hybrid / unsupervised fields
    if detection_source is not None:
        evt["detection_source"] = str(detection_source)
    if device_type:
        evt["model_used"] = str(device_type)
    if unsup_score is not None:
        evt["unsup_score"] = float(unsup_score)

    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with ALERT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(evt) + "\n")


def log_internal(kind: str, msg: str, **extra) -> None:
    """
    Append a structured internal log event to logs/audit.jsonl.
    This is lightweight observability that can be tailed or ingested later.
    """
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        evt = {
            "ts": time.time(),
            "kind": kind,
            "msg": msg,
        }
        if extra:
            evt.update(extra)
        with AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(evt) + "\n")
    except Exception:
        # Logging must never crash the loop
        pass

def to_numeric(df: pd.DataFrame) -> pd.DataFrame:
    for c in FEATURES:
        df[c] = pd.to_numeric(df[c].astype(str).str.strip(), errors="coerce")
    # Basic sanity: clamp obviously invalid negatives to 0
    for c in ("flows", "bytes_total", "pkts_total"):
        if c in df.columns:
            df[c] = df[c].clip(lower=0)
    return df

def has_required_cols(df): 
    return set(FEATURES).issubset(df.columns)

def read_window_meta() -> dict:
    """
    Optional: latest window meta written by suricata_to_features.py.
    Includes top_src_ip, device_type, and lightweight protocol stats.
    """
    try:
        if not WIN_META.exists():
            return {}
        meta = json.loads(WIN_META.read_text(encoding="utf-8"))
        return meta if isinstance(meta, dict) else {}
    except Exception:
        return {}


def read_top_src_ip() -> str | None:
    """Backward-compatible helper that just returns top_src_ip."""
    meta = read_window_meta()
    return meta.get("top_src_ip")


def write_health(now_ts: float) -> None:
    """
    Write a small health/heartbeat file that external tools can check.
    Contains last-seen timestamps and basic loop state.
    """
    try:
        payload = {
            "ts": now_ts,
            "offset_rows": int(state.get("offset_rows", 0)),
            "csv_mtime": float(state.get("csv_mtime", 0.0)),
            "last_block_idx": state.get("last_block_idx"),
            "cfg_mtime": float(cfg_mtime),
            "dry_run": bool(DRY_RUN),
        }
        HEALTH_FILE.parent.mkdir(parents=True, exist_ok=True)
        HEALTH_FILE.write_text(json.dumps(payload), encoding="utf-8")
    except Exception:
        # Health reporting is best-effort only
        pass

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
    flows = float(row.get("flows", 0))
    
    # 1. Web Attacks (SQLi, XSS, Brute Force Web)
    if http > 0.5:
        return "Web Attack (HTTP)"
        
    # 2. SYN Flood (High SYN, low packet count per flow usually, but high volume)
    if syn > 0.6:
        return "DDoS: SYN Flood"
        
    # 3. Port Scan (High RST or very small flows)
    if rst > 0.5:
        return "Recon: Port Scan (RST)"
    # Many small flows: low packets but lots of distinct flows in the window
    if pkts < 3 and flows > 20:
        return "Recon: Port Scan (Stealth)"

    # 4. Volumetric DDoS (UDP/Mirai)
    # If not TCP/HTTP and massive bytes/pkts
    if bytes_t > 5_000_000 or pkts > 10_000:
        return "DDoS: Volumetric (Mirai/UDP)"
        
    # 5. Uploading / Exfiltration
    if mean_b > 5000 and syn < 0.1:
        return "Exfiltration / Upload"

    return "General Anomaly"


def compute_adaptive_threshold(
    scores: list[float],
    base_threshold: float,
    sensitivity: float,
    min_threshold: float,
) -> float:
    """
    Compute an adaptive threshold from recent scores.

    - If there are fewer than 10 scores, returns base_threshold.
    - Otherwise: mean + sensitivity * std, with a floor at min_threshold and
      never lower than base_threshold (we prefer stricter thresholds).
    """
    if len(scores) < 10:
        return float(base_threshold)
    arr = np.array(scores, dtype=float)
    mu = float(arr.mean())
    sigma = float(arr.std())
    dyn_thr = mu + (sensitivity * sigma)
    dyn_thr = max(dyn_thr, float(min_threshold))
    return max(float(base_threshold), dyn_thr)


def compute_unsupervised_score(x: pd.DataFrame) -> tuple[float, bool]:
    """
    Compute anomaly score using the unsupervised IsolationForest model.
    
    Returns:
        (anomaly_score, is_anomaly) where:
        - anomaly_score: higher = more anomalous (inverted from IsolationForest)
        - is_anomaly: True if score >= threshold
    """
    if UNSUP_MODEL is None or UNSUP_THRESHOLD is None:
        return 0.0, False
    
    try:
        # IsolationForest.score_samples: higher = less abnormal
        # We invert so higher = more anomalous
        raw_score = UNSUP_MODEL.score_samples(x.values)[0]
        anomaly_score = -raw_score
        is_anomaly = anomaly_score >= UNSUP_THRESHOLD
        return float(anomaly_score), bool(is_anomaly)
    except Exception as e:
        print(Fore.YELLOW + f"⚠️  Unsupervised scoring error: {e}" + Style.RESET_ALL)
        return 0.0, False


def compute_hybrid_decision(
    sup_score: float,
    sup_threshold: float,
    unsup_score: float,
    unsup_is_anomaly: bool,
    mode: str,
    combine: str,
    sup_weight: float,
    unsup_weight: float,
) -> tuple[float, bool, str]:
    """
    Combine supervised and unsupervised scores based on hybrid mode.
    
    Returns:
        (effective_score, is_attack, detection_source) where:
        - effective_score: the score used for decision (for logging)
        - is_attack: final binary decision
        - detection_source: "supervised", "unsupervised", "both", or "none"
    """
    sup_attack = sup_score >= sup_threshold
    
    if mode == "supervised":
        return sup_score, sup_attack, "supervised" if sup_attack else "none"
    
    if mode == "unsupervised":
        # Normalize unsup_score to 0-1 range for consistency (rough heuristic)
        # IsolationForest scores typically range from -0.5 to 0.5 after inversion
        norm_unsup = min(1.0, max(0.0, (unsup_score + 0.5)))
        return norm_unsup, unsup_is_anomaly, "unsupervised" if unsup_is_anomaly else "none"
    
    # Hybrid mode
    if combine == "or":
        is_attack = sup_attack or unsup_is_anomaly
        if sup_attack and unsup_is_anomaly:
            source = "both"
        elif sup_attack:
            source = "supervised"
        elif unsup_is_anomaly:
            source = "unsupervised"
        else:
            source = "none"
        return sup_score, is_attack, source
    
    elif combine == "and":
        is_attack = sup_attack and unsup_is_anomaly
        source = "both" if is_attack else "none"
        return sup_score, is_attack, source
    
    elif combine == "weighted":
        # Normalize unsup_score to 0-1 range
        norm_unsup = min(1.0, max(0.0, (unsup_score + 0.5)))
        combined = (sup_weight * sup_score) + (unsup_weight * norm_unsup)
        # Use supervised threshold for combined score
        is_attack = combined >= sup_threshold
        if sup_attack and unsup_is_anomaly:
            source = "both"
        elif sup_attack:
            source = "supervised"
        elif unsup_is_anomaly:
            source = "unsupervised"
        else:
            source = "none"
        return combined, is_attack, source
    
    # Fallback to supervised
    return sup_score, sup_attack, "supervised" if sup_attack else "none"

def main() -> None:
    # Print mode info
    mode_str = HYBRID_MODE if UNSUP_AVAILABLE and UNSUP_ENABLED else "supervised"
    if UNSUP_AVAILABLE and UNSUP_ENABLED:
        print(Fore.GREEN + f"🟢 Decision loop watching {DATA_CSV} [MODE: {mode_str.upper()}]" + Style.RESET_ALL)
        print(Fore.CYAN + f"   Hybrid combine strategy: {HYBRID_COMBINE}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + f"🟢 Decision loop watching {DATA_CSV} [MODE: SUPERVISED]" + Style.RESET_ALL)
        if not UNSUP_AVAILABLE:
            print(Fore.YELLOW + "   ⚠️  Unsupervised model not available (run train_unsupervised.py first)" + Style.RESET_ALL)
    
    # Log startup with structured logging
    logger.info(f"Decision loop started in {mode_str.upper()} mode, watching {DATA_CSV}")
    log_internal("startup", "decision_loop_started", data_csv=str(DATA_CSV), mode=mode_str)

    recent = [0] * WINDOW
    adaptive_history = []  # stores recent scores
    last_block_t = 0.0
    last_idle_print = 0.0
    last_health_write = 0.0

    while True:
        now = time.time()
        maybe_reload()
        rotate_alerts()

        if not DATA_CSV.exists():
            if now - last_idle_print > PRINT_IDLE_SECS:
                print(Style.DIM + "…waiting for data/features.csv" + Style.RESET_ALL)
                last_idle_print = now
            time.sleep(0.4)
            continue

        # Read CSV and protect against concurrent writes
        try:
            csv_mtime = DATA_CSV.stat().st_mtime
            df = pd.read_csv(DATA_CSV)
        except Exception as e:
            log_internal("read_error", "failed_to_read_features_csv", error=str(e))
            time.sleep(0.4)
            continue

        # Reset offset only if file was truncated/rotated (length shrank)
        if state["offset_rows"] > len(df):
            log_internal(
                "csv_rotated",
                "features_csv_truncated_or_rotated",
                old_offset=int(state["offset_rows"]),
                new_len=int(len(df)),
            )
            state["offset_rows"] = 0

        # Nothing new?
        if df.empty or state["offset_rows"] >= len(df):
            if now - last_idle_print > PRINT_IDLE_SECS:
                print(Style.DIM + "…idle (no new rows)" + Style.RESET_ALL)
                last_idle_print = now
            if now - last_health_write > 2.0:
                write_health(now)
                last_health_write = now
            time.sleep(0.4)
            continue

        # Schema check
        if not has_required_cols(df):
            missing = list(set(FEATURES) - set(df.columns))
            msg = f"Missing columns: {missing} — waiting…"
            print(Fore.YELLOW + f"⚠️  {msg}" + Style.RESET_ALL)
            log_internal("schema_mismatch", msg, missing=missing)
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
        dropped = before - len(batch)
        if dropped > 0:
            msg = f"Dropped {dropped} malformed rows"
            print(Fore.YELLOW + f"  {msg}" + Style.RESET_ALL)
            log_internal("dropped_rows", msg, dropped=int(dropped))

        for idx, row in batch.iterrows():
            x = pd.DataFrame([row[FEATURES]])
            
            # ---------- Multi-Model Selection ----------
            # 1. Identify Device Type
            meta_ctx = read_window_meta()
            top_src = meta_ctx.get("top_src_ip")
            
            # Look up in device map, or use default
            device_type = DEVICE_MAP.get(top_src, DEFAULT_TYPE) if top_src else DEFAULT_TYPE
            
            # 2. Select Model
            active_model = MODELS.get(device_type)
            if not active_model:
                # Fallback to 'iot' or first available
                active_model = MODELS.get("iot") or next(iter(MODELS.values()), None)
                
            if not active_model:
                # No models loaded? Skip scoring
                continue

            # ---------- Supervised scoring ----------
            proba = active_model.predict_proba(x)
            pred_label = None
            try:
                vec = proba[0]
                # Multiclass with classes mapping
                if CLASSES and isinstance(CLASSES.get("classes"), list):
                    classes = CLASSES.get("classes") or []
                    benign_index = int(CLASSES.get("benign_index", 0) or 0)
                    sup_score = float(1.0 - float(vec[benign_index]))
                    pred_idx = int(getattr(vec, "argmax", lambda: 0)())
                    pred_label = classes[pred_idx] if 0 <= pred_idx < len(classes) else None
                else:
                    # Binary: use column 1 if available
                    sup_score = float(vec[1]) if len(vec) > 1 else float(vec)
                    pred_label = "attack" if sup_score >= THRESHOLD else "benign"
            except Exception:
                # Fallback: score as probability of positive
                try:
                    sup_score = float(MODEL.predict_proba(x)[0,1])
                except Exception:
                    sup_score = float(MODEL.predict(x)[0])
            
            # ---------- Unsupervised scoring (if enabled) ----------
            unsup_score = 0.0
            unsup_is_anomaly = False
            detection_source = "supervised"
            
            if UNSUP_AVAILABLE and UNSUP_ENABLED:
                unsup_score, unsup_is_anomaly = compute_unsupervised_score(x)
            
            # ---------- Adaptive Threshold Logic ----------
            effective_thr = THRESHOLD
        
            # update history (using supervised score for adaptive)
            adaptive_history.append(sup_score)
            if len(adaptive_history) > ADAPT_WIN:
                adaptive_history.pop(0)

            if USE_ADAPTIVE:
                effective_thr = compute_adaptive_threshold(
                    adaptive_history,
                    base_threshold=THRESHOLD,
                    sensitivity=ADAPT_SENS,
                    min_threshold=ADAPT_MIN,
                )

            # ---------- Hybrid decision ----------
            if UNSUP_AVAILABLE and UNSUP_ENABLED:
                p, is_attack, detection_source = compute_hybrid_decision(
                    sup_score=sup_score,
                    sup_threshold=effective_thr,
                    unsup_score=unsup_score,
                    unsup_is_anomaly=unsup_is_anomaly,
                    mode=HYBRID_MODE,
                    combine=HYBRID_COMBINE,
                    sup_weight=SUP_WEIGHT,
                    unsup_weight=UNSUP_WEIGHT,
                )
            else:
                p = sup_score
                is_attack = sup_score >= effective_thr
                detection_source = "supervised" if is_attack else "none"
            
            # Update label based on detection source
            if is_attack and detection_source == "unsupervised":
                pred_label = UNSUP_ONLY_LABEL
            elif is_attack and detection_source == "both":
                pred_label = "ATTACK (hybrid)"
            
            state_txt = "ATTACK" if is_attack else "benign"
            
            # Heuristic Classification (override pred_label if attack detected)
            heuristic_label = None
            if is_attack and detection_source in ("supervised", "both"):
                heuristic_label = classify_attack_heuristic(row)
                if heuristic_label:
                    pred_label = heuristic_label

            # Explain high scores (XAI)
            reason_str = None
            if is_attack and EXPLAINER:
                # Temporarily swap model in explainer if needed (optimization: only if different)
                if hasattr(EXPLAINER, "model") and EXPLAINER.model != active_model:
                     EXPLAINER.model = active_model
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
                    response_type = "KILL"  # Highest severity
                elif p >= INSTANT_BLK:
                    response_type = "HARD"  # Permanent block
                elif burst_ok:
                    response_type = "SOFT"  # Temporary/Standard block
        
            should_block = (response_type != "NONE")

            # Debug reason (why not blocked)
            debug_reason = None
            if not is_attack:
                debug_reason = "benign"
            elif not time_ok:
                debug_reason = f"cooldown {COOLDOWN_SEC}s"
            elif response_type == "NONE":
                debug_reason = f"below criteria (hits={hits}<{GRACE}, score={p:.3f}<{INSTANT_BLK})"

            # Optional: choose an IP to block and get window meta (best guess from Suricata window)
            meta_ctx = read_window_meta()
            ip_to_block = meta_ctx.get("top_src_ip")
            device_type = meta_ctx.get("device_type")
        
            # Threat Intel Enrichment
            threat_ctx = None
            if ip_to_block:
                threat_ctx = THREAT_INTEL.enrich_ip(ip_to_block)

            # Per-IP baseline using rolling bytes_total history (simple anomaly flag)
            ip_anom_flag = None
            if ip_to_block and "bytes_total" in row:
                stats = IP_STATS.setdefault(ip_to_block, {"bytes": deque(maxlen=20)})
                series = stats["bytes"]
                series.append(float(row.get("bytes_total", 0.0)))
                if len(series) >= 5:
                    arr = np.array(series, dtype=float)
                    mu = float(arr.mean())
                    sigma = float(arr.std()) or 1.0
                    z = (series[-1] - mu) / sigma
                    ip_anom_flag = bool(z >= IP_ANOM_Z)
                    if ip_anom_flag:
                        log_internal(
                            "ip_anomaly",
                            "per-ip-bytes-anomaly",
                            ip=ip_to_block,
                            z_score=float(z),
                            bytes_total=float(series[-1]),
                        )

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
                
                # Audit log for security events (always logged, even in dry_run)
                audit_logger.warning(
                    f"BLOCK action: ip={ip_to_block}, severity={response_type}, "
                    f"score={p:.3f}, dry_run={DRY_RUN}, success={ok}"
                )
                logger.info(f"Block triggered for {ip_to_block} (score={p:.3f}, severity={response_type})")
                
                log_internal(
                    "block_action",
                    "block_triggered",
                    ip=ip_to_block,
                    severity=response_type,
                    ok=bool(ok),
                    how=how,
                    dry_run=bool(DRY_RUN),
                    score=float(p),
                )
                
                # Send alert via configured channels (Email/Slack/Telegram)
                if ALERTING_AVAILABLE:
                    attack_type = classify_attack_heuristic(row) if is_attack else "Unknown"
                    send_alert(
                        title=f"Attack Blocked: {attack_type}",
                        message=f"Score: {p:.2%}\nIP: {ip_to_block}\nSeverity: {response_type}\nDry Run: {DRY_RUN}",
                        severity="high" if response_type == "hard" else "medium",
                        src_ip=ip_to_block
                    )

            # Console line
            color = Fore.RED if is_attack else Fore.GREEN
            thr_str = f"{effective_thr:.3f}" if USE_ADAPTIVE else f"{THRESHOLD:.2f}"
            
            # Build score string based on mode
            if UNSUP_AVAILABLE and UNSUP_ENABLED and HYBRID_MODE != "supervised":
                score_str = f"sup={sup_score:.3f} unsup={unsup_score:.3f}"
                if detection_source != "none":
                    score_str += f" [{detection_source}]"
            else:
                score_str = f"score={p:.3f}"
            
            print(f"{idx}: {score_str} (thr={thr_str}) → {color}{state_txt}{Style.RESET_ALL} (hits last{WINDOW}={hits})")
            if action == "NONE" and debug_reason:
                print(Style.DIM + f"   └─ no BLOCK: {debug_reason}" + Style.RESET_ALL)
        
            if reason_str:
                print(Fore.MAGENTA + f"   🔍 Why? {reason_str}" + Style.RESET_ALL)
            if heuristic_label:
                print(Fore.BLUE + f"   🏷️  Type: {heuristic_label}" + Style.RESET_ALL)
            if detection_source == "unsupervised":
                print(Fore.YELLOW + f"   🔶 Detected by unsupervised model (novel anomaly)" + Style.RESET_ALL)

            # Event log (dashboard)
            log_event(
                idx,
                p,
                state_txt,
                hits,
                action,
                pred_class=pred_label,
                reason=reason_str,
                effective_thr=effective_thr,
                threat_info=threat_ctx,
                src_ip=ip_to_block,
                ip_anomaly=ip_anom_flag,
                device_type=device_type,
                detection_source=detection_source if UNSUP_AVAILABLE and UNSUP_ENABLED else None,
                unsup_score=unsup_score if UNSUP_AVAILABLE and UNSUP_ENABLED else None,
            )

        if now - last_health_write > 2.0:
            write_health(now)
            last_health_write = now

        time.sleep(0.4)


def graceful_shutdown(signum=None, frame=None):
    """Handle graceful shutdown on SIGTERM/SIGINT."""
    signal_name = "SIGTERM" if signum == 15 else "SIGINT" if signum == 2 else str(signum)
    print(Fore.YELLOW + f"\n🛑 Received {signal_name}, shutting down gracefully…" + Style.RESET_ALL)
    logger.info(f"Graceful shutdown initiated (signal={signal_name})")
    
    # Save state
    try:
        save_state(state)
        logger.info("State saved successfully")
    except Exception as e:
        logger.error(f"Failed to save state: {e}")
    
    # Write final health status
    try:
        health = {
            "ts": time.time(),
            "status": "shutdown",
            "reason": signal_name,
        }
        HEALTH_FILE.write_text(json.dumps(health), encoding="utf-8")
    except Exception:
        pass
    
    log_internal("shutdown", "decision_loop_stopped", signal=signal_name)
    audit_logger.info(f"Decision loop shutdown: signal={signal_name}")
    sys.exit(0)


if __name__ == "__main__":
    import signal
    
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)
    
    try:
        main()
    except KeyboardInterrupt:
        graceful_shutdown(signum=2)
    except Exception as e:
        logger.exception(f"Unexpected error in decision loop: {e}")
        audit_logger.error(f"Decision loop crashed: {e}")
        save_state(state)
        log_internal("crash", "decision_loop_crashed", error=str(e))
        sys.exit(1)
