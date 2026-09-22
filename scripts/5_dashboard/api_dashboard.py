"""
scripts/api_dashboard.py
-----------------------------------------------------------------------------
IoTGuard Pipeline — API + Web Dashboard

High‑level pipeline
    Suricata / simulators
        →  features.csv  (via suricata_to_features.py / stream_csvs.py)
        →  decision_loop.py  (scores + policies)
        →  data/alerts.jsonl (one JSON line per decision)
        →  [THIS FILE]  (REST API + HTML/JS dashboard)
        →  Browser UI (charts + tables for operators)

Purpose
    - Expose a lightweight REST API so other tools (and the dashboard JS) can:
        * fetch recent events and aggregate counts,
        * download a CSV export of all alerts,
        * read and update decision parameters (threshold, grace, window, cooldown, adaptive).
    - Serve a single‑page dashboard that visualizes, in real time:
        * scores and adaptive threshold over time (Chart.js),
        * per‑class counts,
        * a recent events table including:
              state, score, window hits,
              XAI reason (from SHAP),
              Threat Intel (country flag + tag),
              action taken (BLOCK / NONE).

Inputs
    - data/alerts.jsonl:
        Append‑only event log from decision_loop.py.
        Each line is a JSON object with keys like:
          ts, index, score, state, hits_in_window, action,
          pred_class, reason, effective_threshold, threat.
    - configs/model.yaml:
        Configuration file whose `decision` section is read/written via /api/config.

Outputs
    - HTML dashboard at `/`:
        A static page with embedded JS that polls the JSON APIs and renders charts/tables.
    - JSON endpoints:
        /api/events      – stream of recent events for the UI.
        /api/counts      – summary counts for the last N minutes.
        /api/latest      – single latest event (for quick checks).
        /api/config      – get/set threshold/policy settings.
        /api/model       – expose model class metadata (for multiclass extensions).
        /api/clear*      – reset logs and state for clean experiments.
        /api/download.csv – export all alerts as a CSV file.

Operational notes
    - Stateless: all state is reconstructed from alerts.jsonl and configs/model.yaml.
      It is safe to restart the API at any time without losing detection history.
    - Designed to be fronted by a reverse proxy (e.g. Nginx) in production for HTTPS and auth,
      but perfectly usable on localhost for demos and experiments.
-----------------------------------------------------------------------------
"""
import os, io, csv, json, math, re, time, threading, yaml, sys
import random
import subprocess
from pathlib import Path
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request, Response, abort, g

# Add scripts directory and subdirectories to path for imports
_scripts_dir = Path(__file__).parent.parent
sys.path.insert(0, str(_scripts_dir))
from path_setup import configure_paths
configure_paths()
from logging_config import get_logger

# Import new enhancement modules
try:
    from metrics import (
        get_metrics_text, get_metrics_json,
        record_detection, record_block, record_api_request,
        record_inference_time, record_score, active_connections
    )
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

try:
    from auth import (
        require_auth as jwt_require_auth,
        authenticate_user, rate_limit,
        get_token_from_request, validate_token
    )
    AUTH_AVAILABLE = True
except ImportError:
    AUTH_AVAILABLE = False

try:
    from ensemble import EnsemblePredictor, get_ensemble
    ENSEMBLE_AVAILABLE = True
except ImportError:
    ENSEMBLE_AVAILABLE = False

try:
    from alerts import send_threat_alert, get_alert_manager
    ALERTS_AVAILABLE = True
except ImportError:
    ALERTS_AVAILABLE = False

# =============================================================================
# RATE LIMITING & ACCESS CONTROL
# =============================================================================
try:
    from rate_limiter import get_rate_limiter, check_rate_limit
    RATE_LIMITER_AVAILABLE = True
except ImportError:
    RATE_LIMITER_AVAILABLE = False
    get_rate_limiter = None
    check_rate_limit = None

# =============================================================================
# WEBSOCKET SUPPORT (Optional - for real-time dashboard updates)
# =============================================================================
# Install with: pip install -r requirements-websocket.txt
# If not installed, the dashboard falls back to polling mode.
# =============================================================================
try:
    from flask_socketio import SocketIO, emit
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False
    SocketIO = None

logger = get_logger("api_dashboard")

DATA_DIR   = Path("data")
ALERT_LOG  = DATA_DIR / "alerts.jsonl"
CFG_FILE   = Path(os.getenv("IOTGUARD_CONFIG") or "configs/model.yaml")

app = Flask(__name__, static_folder=str(Path(__file__).parent / "templates"), static_url_path="/static")
_lock = threading.Lock()

# =============================================================================
# WEBSOCKET INITIALIZATION
# =============================================================================
# Initialize SocketIO if available - enables real-time push notifications
# instead of client-side polling.
# =============================================================================
socketio = None
if SOCKETIO_AVAILABLE and SocketIO is not None:
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode="threading",  # Uses simple threading, no eventlet/gevent needed
        logger=False,
        engineio_logger=False,
    )
    logger.info("WebSocket support enabled (Flask-SocketIO)")
else:
    logger.info("WebSocket support disabled (install flask-socketio for real-time updates)")


def emit_new_alert(alert_data: dict) -> None:
    """
    Emit a new alert to all connected WebSocket clients.

    Call this function from decision_loop.py when a new alert is logged.
    If WebSocket is not available, this function does nothing.

    Args:
        alert_data: The alert dictionary to broadcast

    Example:
        from api_dashboard import emit_new_alert
        emit_new_alert({"ts": time.time(), "score": 0.95, "action": "BLOCK"})
    """
    if socketio is not None:
        try:
            socketio.emit("new_alert", alert_data, namespace="/")
        except Exception as e:
            logger.debug(f"WebSocket emit failed: {e}")


def emit_config_changed(config_data: dict) -> None:
    """
    Emit config change notification to all connected WebSocket clients.

    Args:
        config_data: The updated config dictionary
    """
    if socketio is not None:
        try:
            socketio.emit("config_changed", config_data, namespace="/")
        except Exception as e:
            logger.debug(f"WebSocket emit failed: {e}")


# Optional HTTP basic auth for the dashboard/API.
# If you set environment variables IOTGUARD_USER and IOTGUARD_PASS,
# every request will require those credentials.
BASIC_USER = os.getenv("IOTGUARD_USER") or None
BASIC_PASS = os.getenv("IOTGUARD_PASS") or None


def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")

# ---------- helpers ----------
# Thread-safe locks for file operations
_alerts_lock = threading.Lock()
_config_lock = threading.Lock()


def _iter_alerts():
    """Iterate over alerts with thread-safe file access."""
    if not ALERT_LOG.exists():
        return
    
    with _alerts_lock:
        try:
            with ALERT_LOG.open("r", encoding="utf-8") as f:
                lines = f.readlines()
        except (IOError, OSError) as e:
            logger.warning(f"Could not read alerts file: {e}")
            return
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue
        except Exception as e:
            logger.debug(f"Error parsing alert line: {e}")
            continue


def read_last_n(n=200):
    """Read the last N alerts with thread safety."""
    data = list(_iter_alerts() or [])
    return data[-n:]


def now_ts(): 
    return time.time()


def load_cfg():
    """Load configuration with thread-safe file access."""
    with _config_lock:
        if not CFG_FILE.exists():
            return {}
        try:
            with CFG_FILE.open("r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except (IOError, OSError, yaml.YAMLError) as e:
            logger.error(f"Could not load config: {e}")
            return {}


def save_cfg(cfg: dict):
    """Save configuration with thread-safe file access and atomic write."""
    with _config_lock:
        CFG_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        # Write to temp file first, then rename (atomic on most systems)
        temp_file = CFG_FILE.with_suffix(".yaml.tmp")
        try:
            with temp_file.open("w", encoding="utf-8") as f:
                yaml.safe_dump(cfg, f, sort_keys=False)
            
            # Atomic rename
            temp_file.replace(CFG_FILE)
            logger.debug("Configuration saved successfully")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            # Clean up temp file if it exists
            if temp_file.exists():
                temp_file.unlink()
            raise


# Decide when to require auth / allow live config changes.
_initial = load_cfg()
_initial_decision = (_initial.get("decision") or {}) if isinstance(_initial, dict) else {}
_initial_dry_run = bool(_initial_decision.get("dry_run", True))

# By default:
#   - demo mode (dry_run=True)  → auth optional unless IOTGUARD_REQUIRE_AUTH=1
#   - live mode (dry_run=False) → auth required unless IOTGUARD_REQUIRE_AUTH=0
REQUIRE_AUTH = _bool_env("IOTGUARD_REQUIRE_AUTH", default=(not _initial_dry_run))

# In live mode we disable /api/config writes unless explicitly allowed.
ALLOW_LIVE_CONFIG = _bool_env("IOTGUARD_ALLOW_LIVE_CONFIG", default=False)

# ---------- APIs ----------
@app.before_request
def _check_rate_limit():
    """
    Check rate limits before processing requests.
    Returns 429 Too Many Requests if limit exceeded.
    """
    if not RATE_LIMITER_AVAILABLE or check_rate_limit is None:
        return

    # Get client IP
    client_ip = request.remote_addr or "unknown"

    # Determine endpoint type for per-endpoint limits
    path = request.path or "/"
    endpoint_type = None
    if "/login" in path:
        endpoint_type = "login"
    elif "/config" in path and request.method == "POST":
        endpoint_type = "config"

    # Check rate limit
    allowed, headers = check_rate_limit(client_ip, endpoint_type)

    # Store rate limit headers on g for the after_request handler
    g._rate_limit_headers = headers

    if not allowed:
        logger.warning(f"Rate limit exceeded for {client_ip} on {path}")
        return Response(
            json.dumps({"error": "Rate limit exceeded", "retry_after": headers.get("Retry-After")}),
            status=429,
            mimetype="application/json",
            headers=headers
        )


@app.after_request
def _add_rate_limit_headers(response):
    """Add rate limit headers stored during before_request."""
    headers = getattr(g, "_rate_limit_headers", None)
    if headers:
        for key, value in headers.items():
            response.headers[key] = value
    return response


@app.before_request
def _basic_auth():
    """
    Enforce simple HTTP Basic Auth when credentials are configured.
    This is meant as a lightweight protection for the dashboard/API.
    """
    # Decide if this request should be authenticated.
    if not REQUIRE_AUTH:
        return

    # Allow health checks without auth if you add them later
    path = request.path or "/"
    if path.startswith("/health"):
        return

    auth = request.authorization
    if not auth or not BASIC_USER or not BASIC_PASS or not (
        auth.username == BASIC_USER and auth.password == BASIC_PASS
    ):
        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="IoTGuard"'}
        )


# ============================================================================
# NEW API v1 ENDPOINTS - Enhanced features
# ============================================================================

@app.get("/metrics")
def prometheus_metrics():
    """Prometheus metrics endpoint for monitoring."""
    if not METRICS_AVAILABLE:
        return Response("Metrics not available", 501)
    return Response(get_metrics_text(), mimetype="text/plain")


@app.get("/api/v1/metrics")
def api_v1_metrics():
    """JSON metrics summary for dashboard."""
    if not METRICS_AVAILABLE:
        return jsonify({"error": "Metrics not available"}), 501
    return jsonify(get_metrics_json())


@app.post("/api/v1/login")
def api_v1_login():
    """JWT login endpoint - get token with username/password."""
    if not AUTH_AVAILABLE:
        return jsonify({"error": "JWT auth not available, install PyJWT"}), 501
    
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    
    success, token, error = authenticate_user(username, password)
    
    if success:
        return jsonify({"ok": True, "token": token})
    return jsonify({"ok": False, "error": error}), 401


@app.get("/api/v1/ensemble")
def api_v1_ensemble():
    """Get ensemble model status and configuration."""
    if not ENSEMBLE_AVAILABLE:
        return jsonify({"error": "Ensemble not available"}), 501
    
    ensemble = get_ensemble()
    return jsonify({
        "ok": True,
        "strategy": ensemble.strategy,
        "supervised_weight": ensemble.sup_weight,
        "unsupervised_weight": ensemble.unsup_weight,
        "supervised_threshold": ensemble.supervised_threshold,
        "unsupervised_threshold": ensemble.unsupervised_threshold,
        "supervised_loaded": ensemble.supervised_model is not None,
        "unsupervised_loaded": ensemble.unsupervised_model is not None,
    })


@app.post("/api/v1/predict")
def api_v1_predict():
    """Make ensemble prediction on provided features."""
    if not ENSEMBLE_AVAILABLE:
        return jsonify({"error": "Ensemble not available"}), 501
    
    data = request.get_json() or {}
    features = data.get("features")
    
    if not features:
        return jsonify({"error": "Missing 'features' array"}), 400
    
    try:
        import numpy as np
        X = np.array(features, dtype=np.float32)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        
        ensemble = get_ensemble()
        
        if METRICS_AVAILABLE:
            with record_inference_time("ensemble"):
                result = ensemble.predict(X)
        else:
            result = ensemble.predict(X)
        
        return jsonify({"ok": True, "prediction": result})
    except Exception as e:
        logger.error(f"Ensemble prediction error: {e}")
        return jsonify({"error": str(e)}), 500


@app.post("/api/v1/test-alert")
def api_v1_test_alert():
    """Send a test alert through all configured channels."""
    if not ALERTS_AVAILABLE:
        return jsonify({"error": "Alerts not available"}), 501
    
    manager = get_alert_manager()
    results = manager.test_channels()
    
    return jsonify({
        "ok": True,
        "channels": {
            "email_enabled": manager.email_enabled,
            "slack_enabled": manager.slack_enabled,
        },
        "results": results
    })


@app.get("/api/v1/alerts/config")
def api_v1_alerts_config():
    """Get alert configuration status."""
    if not ALERTS_AVAILABLE:
        return jsonify({"error": "Alerts not available"}), 501
    
    manager = get_alert_manager()
    return jsonify({
        "ok": True,
        "email_enabled": manager.email_enabled,
        "slack_enabled": manager.slack_enabled,
        "min_severity": manager.min_severity,
    })


# Enhanced health endpoints
@app.get("/health/live")
def health_live():
    """Kubernetes liveness probe."""
    return jsonify({"status": "ok", "timestamp": now_ts()})


@app.get("/health/ready")
def health_ready():
    """Kubernetes readiness probe - checks if models are loaded."""
    ready = True
    details = {}
    
    if ENSEMBLE_AVAILABLE:
        ensemble = get_ensemble()
        details["supervised_model"] = ensemble.supervised_model is not None
        details["unsupervised_model"] = ensemble.unsupervised_model is not None
        ready = details["supervised_model"]  # At least supervised should be loaded
    
    if ALERTS_AVAILABLE:
        details["alerts_configured"] = True
    
    status_code = 200 if ready else 503
    return jsonify({"status": "ready" if ready else "not_ready", "details": details}), status_code


# ============================================================================
# EXISTING API ENDPOINTS (unchanged)
# ============================================================================


@app.get("/api/latest")
def api_latest():
    data = read_last_n(1)
    return jsonify({"ok": True, "latest": data[0] if data else None, "server_time": now_ts()})

@app.get("/api/counts")
def api_counts():
    """Counts in the last X minutes (default 60)."""
    mins = float(request.args.get("window_minutes", 60))
    cutoff = now_ts() - (mins * 60)
    total = attacks = blocks = 0
    class_counts = {}
    block_breakdown = {}
    for evt in _iter_alerts() or []:
        if evt.get("ts", 0) >= cutoff:
            total += 1
            if evt.get("state") == "ATTACK":
                attacks += 1
            # Treat any BLOCK-* severity as a block event
            action = str(evt.get("action") or "")
            if action.startswith("BLOCK"):
                blocks += 1
                block_breakdown[action] = block_breakdown.get(action, 0) + 1
            c = evt.get("pred_class")
            if c is not None:
                class_counts[c] = class_counts.get(c, 0) + 1
    return jsonify({
        "ok": True,
        "window_minutes": mins,
        "total": total,
        "attacks": attacks,
        "blocks": blocks,
        "class_counts": class_counts,
        "block_breakdown": block_breakdown,
    })

@app.get("/api/events")
def api_events():
    """Return events since a given timestamp (or last 200 if not provided)."""
    since = request.args.get("since_ts", type=float)
    if since is None:
        data = read_last_n(200)
    else:
        data = [e for e in (_iter_alerts() or []) if e.get("ts", 0) > since]
    return jsonify({"ok": True, "events": data, "server_time": now_ts()})

@app.get("/api/model")
def api_model():
    """Return model metadata like classes.json if present."""
    meta = {"classes": None, "benign_index": None}
    try:
        cj = Path("models/classes.json")
        if cj.exists():
            data = json.loads(cj.read_text(encoding="utf-8"))
            meta.update({
                "classes": data.get("classes"),
                "benign_index": data.get("benign_index")
            })
    except Exception:
        pass
    return jsonify({"ok": True, "model": meta})

# ============================================================================
# DEMO SIMULATION CONTROLLER (Start / Stop / Inject)
# ============================================================================
_sim_lock = threading.Lock()
_sim_running = True  # Streaming enabled by default
_sim_stats = {
    "rows_written": 0,
    "attacks_injected": 0,
    "last_attack_type": None,
    "start_time": time.time(),
}

def _generate_sim_benign_row() -> list:
    """Generate realistic multi-device benign flow."""
    dev = random.choice(["sensor", "camera", "workstation", "doorlock"])
    if dev == "sensor":
        flows = random.randint(2, 6)
        pkts = flows * random.randint(3, 8)
        bytes_total = pkts * random.randint(50, 90)
        syn_ratio = round(random.uniform(0.08, 0.18), 2)
        ack_ratio = round(random.uniform(0.40, 0.55), 2)
        fin_ratio = round(random.uniform(0.10, 0.20), 2)
        rst_ratio = 0.0
        http_ratio = round(random.uniform(0.10, 0.40), 2)
        tcp_ratio = 1.0
        proto_div = 1
        std_bytes = round(random.uniform(10, 30), 2)
        iat_mean = round(random.uniform(0.15, 0.45), 6)
    elif dev == "camera":
        flows = random.randint(8, 20)
        pkts = flows * random.randint(30, 80)
        bytes_total = pkts * random.randint(600, 1100)
        syn_ratio = round(random.uniform(0.02, 0.06), 2)
        ack_ratio = round(random.uniform(0.48, 0.55), 2)
        fin_ratio = round(random.uniform(0.01, 0.04), 2)
        rst_ratio = 0.0
        http_ratio = 0.0
        tcp_ratio = round(random.uniform(0.80, 0.95), 2)
        proto_div = 2
        std_bytes = round(random.uniform(80, 180), 2)
        iat_mean = round(random.uniform(0.005, 0.02), 6)
    elif dev == "workstation":
        flows = random.randint(12, 30)
        pkts = flows * random.randint(10, 25)
        bytes_total = pkts * random.randint(180, 450)
        syn_ratio = round(random.uniform(0.10, 0.22), 2)
        ack_ratio = round(random.uniform(0.38, 0.48), 2)
        fin_ratio = round(random.uniform(0.08, 0.16), 2)
        rst_ratio = round(random.uniform(0.01, 0.03), 2)
        http_ratio = round(random.uniform(0.30, 0.60), 2)
        tcp_ratio = round(random.uniform(0.90, 0.98), 2)
        proto_div = 3
        std_bytes = round(random.uniform(40, 110), 2)
        iat_mean = round(random.uniform(0.02, 0.08), 6)
    else:
        flows = random.randint(1, 4)
        pkts = flows * random.randint(2, 5)
        bytes_total = pkts * random.randint(45, 75)
        syn_ratio = round(random.uniform(0.10, 0.25), 2)
        ack_ratio = round(random.uniform(0.35, 0.50), 2)
        fin_ratio = round(random.uniform(0.12, 0.25), 2)
        rst_ratio = 0.0
        http_ratio = 0.0
        tcp_ratio = 1.0
        proto_div = 1
        std_bytes = round(random.uniform(5, 20), 2)
        iat_mean = round(random.uniform(0.20, 0.60), 6)
        
    mean_bytes = int(bytes_total / max(flows, 1))
    return [flows, bytes_total, pkts, syn_ratio, mean_bytes, ack_ratio, fin_ratio, rst_ratio, http_ratio, tcp_ratio, proto_div, std_bytes, iat_mean]

def _generate_sim_attack_row(attack_type: str = "syn") -> list:
    """Generate attack pattern row."""
    t = (attack_type or "syn").lower()
    if "udp" in t:
        flows = random.randint(80, 200)
        pkts = flows * random.randint(15, 40)
        bytes_total = pkts * random.randint(400, 750)
        syn_ratio = 0.0
        ack_ratio = 0.0
        fin_ratio = 0.0
        rst_ratio = 0.0
        http_ratio = 0.0
        tcp_ratio = 0.0
        proto_div = 1
        std_bytes = round(random.uniform(0, 10), 2)
        iat_mean = round(random.uniform(0.00005, 0.0004), 6)
    elif "scan" in t or "port" in t:
        flows = random.randint(50, 120)
        pkts = flows * 2
        bytes_total = pkts * 44
        syn_ratio = round(random.uniform(0.75, 0.95), 2)
        ack_ratio = 0.0
        fin_ratio = 0.0
        rst_ratio = round(random.uniform(0.20, 0.50), 2)
        http_ratio = 0.0
        tcp_ratio = 1.0
        proto_div = 1
        std_bytes = round(random.uniform(0, 2), 2)
        iat_mean = round(random.uniform(0.001, 0.008), 6)
    elif "http" in t or "slow" in t:
        flows = random.randint(30, 70)
        pkts = flows * random.randint(10, 25)
        bytes_total = pkts * random.randint(250, 500)
        syn_ratio = round(random.uniform(0.20, 0.35), 2)
        ack_ratio = round(random.uniform(0.38, 0.48), 2)
        fin_ratio = round(random.uniform(0.12, 0.25), 2)
        rst_ratio = round(random.uniform(0.02, 0.06), 2)
        http_ratio = round(random.uniform(0.85, 1.0), 2)
        tcp_ratio = 1.0
        proto_div = 1
        std_bytes = round(random.uniform(25, 75), 2)
        iat_mean = round(random.uniform(0.001, 0.006), 6)
    elif "exfil" in t:
        flows = random.randint(4, 18)
        pkts = flows * random.randint(50, 120)
        bytes_total = pkts * random.randint(800, 1350)
        syn_ratio = round(random.uniform(0.04, 0.12), 2)
        ack_ratio = round(random.uniform(0.42, 0.54), 2)
        fin_ratio = round(random.uniform(0.02, 0.06), 2)
        rst_ratio = 0.0
        http_ratio = round(random.uniform(0.20, 0.60), 2)
        tcp_ratio = 1.0
        proto_div = 1
        std_bytes = round(random.uniform(10, 35), 2)
        iat_mean = round(random.uniform(0.002, 0.015), 6)
    else:  # SYN flood / Botnet
        flows = random.randint(60, 150)
        pkts = flows * random.randint(3, 6)
        bytes_total = pkts * random.randint(54, 66)
        syn_ratio = round(random.uniform(0.85, 0.99), 2)
        ack_ratio = 0.0
        fin_ratio = 0.0
        rst_ratio = 0.0
        http_ratio = 0.0
        tcp_ratio = 1.0
        proto_div = 1
        std_bytes = round(random.uniform(0, 5), 2)
        iat_mean = round(random.uniform(0.0001, 0.0008), 6)
        
    mean_bytes = int(bytes_total / max(flows, 1))
    return [flows, bytes_total, pkts, syn_ratio, mean_bytes, ack_ratio, fin_ratio, rst_ratio, http_ratio, tcp_ratio, proto_div, std_bytes, iat_mean]

def _write_feature_row(row: list) -> None:
    """Append a single feature row into data/features.csv."""
    features_csv = Path("data/features.csv")
    features_csv.parent.mkdir(parents=True, exist_ok=True)
    header = "flows,bytes_total,pkts_total,syn_ratio,mean_bytes_flow,ack_ratio,fin_ratio,rst_ratio,http_ratio,tcp_ratio,protocol_diversity,std_bytes,iat_mean\n"
    if not features_csv.exists() or features_csv.stat().st_size == 0:
        features_csv.write_text(header, encoding="utf-8")
    with features_csv.open("a", encoding="utf-8") as f:
        f.write("{},{},{},{:.2f},{},{:.2f},{:.2f},{:.2f},{:.2f},{:.2f},{},{:.2f},{:.6f}\n".format(*row))

def _sim_background_loop():
    """Background simulator thread generating normal stream."""
    while True:
        with _sim_lock:
            running = _sim_running
        if running:
            try:
                # 98% clean benign device telemetry, 2% rare baseline anomaly
                is_attack = random.random() < 0.02
                row = _generate_sim_attack_row("syn") if is_attack else _generate_sim_benign_row()
                with _sim_lock:
                    _write_feature_row(row)
                    _sim_stats["rows_written"] += 1
            except Exception as e:
                logger.debug(f"Simulator error: {e}")
        time.sleep(1.0)

# Start simulator thread once on import
_sim_thread = threading.Thread(target=_sim_background_loop, daemon=True)
_sim_thread.start()

@app.get("/api/demo/status")
def api_demo_status():
    """Return status of live demo simulator."""
    with _sim_lock:
        return jsonify({
            "ok": True,
            "running": _sim_running,
            "stats": dict(_sim_stats),
            "server_time": now_ts()
        })

@app.post("/api/demo/start")
def api_demo_start():
    """Start / resume the live feature stream."""
    global _sim_running
    with _sim_lock:
        _sim_running = True
    logger.info("Demo Simulator Started by user")
    return jsonify({"ok": True, "message": "Demo stream running", "running": True})

@app.post("/api/demo/stop")
def api_demo_stop():
    """Stop / pause the live feature stream."""
    global _sim_running
    with _sim_lock:
        _sim_running = False
    logger.info("Demo Simulator Paused by user")
    return jsonify({"ok": True, "message": "Demo stream stopped", "running": False})

@app.post("/api/demo/inject")
def api_demo_inject():
    """Immediately inject a chosen cyber attack scenario."""
    data = request.get_json(silent=True) or {}
    attack_type = data.get("type", "syn")
    row = _generate_sim_attack_row(attack_type)
    with _sim_lock:
        _write_feature_row(row)
        _sim_stats["attacks_injected"] += 1
        _sim_stats["last_attack_type"] = attack_type
    logger.info(f"Injected attack pattern: {attack_type}")
    return jsonify({
        "ok": True,
        "message": f"Injected {attack_type} attack burst into stream",
        "attack_type": attack_type,
        "features": row
    })

def _validate_config(dec: dict) -> tuple[dict, list[str]]:
    """
    Validate and sanitize config values with proper bounds checking.
    Returns (validated_config, list_of_errors).
    """
    errors = []
    validated = {}
    
    # Threshold: must be between 0.0 and 1.0
    try:
        thr = float(dec.get("threshold", 0.65))
        if not (0.0 <= thr <= 1.0):
            errors.append(f"threshold must be between 0.0 and 1.0, got {thr}")
        else:
            validated["threshold"] = round(thr, 4)
    except (TypeError, ValueError):
        errors.append("threshold must be a valid number")
    
    # Grace: must be non-negative integer, max 100
    try:
        grace = int(dec.get("grace", 3))
        if not (0 <= grace <= 100):
            errors.append(f"grace must be between 0 and 100, got {grace}")
        else:
            validated["grace"] = grace
    except (TypeError, ValueError):
        errors.append("grace must be a valid integer")
    
    # Window: must be positive integer, max 1000
    try:
        window = int(dec.get("window", 5))
        if not (1 <= window <= 1000):
            errors.append(f"window must be between 1 and 1000, got {window}")
        else:
            validated["window"] = window
    except (TypeError, ValueError):
        errors.append("window must be a valid integer")
    
    # Cooldown: must be non-negative, max 3600 (1 hour)
    try:
        cooldown = int(dec.get("cooldown_sec", 30))
        if not (0 <= cooldown <= 3600):
            errors.append(f"cooldown_sec must be between 0 and 3600, got {cooldown}")
        else:
            validated["cooldown_sec"] = cooldown
    except (TypeError, ValueError):
        errors.append("cooldown_sec must be a valid integer")
    
    # use_adaptive: boolean
    try:
        validated["use_adaptive"] = bool(dec.get("use_adaptive", False))
    except (TypeError, ValueError):
        errors.append("use_adaptive must be a boolean")
    
    return validated, errors


@app.post("/api/config")
def api_set_config():
    """
    Update decision parameters with validation.
    
    Accepts JSON body with fields:
      - threshold (float, 0.0-1.0): Detection threshold
      - grace (int, 0-100): Number of hits before blocking
      - window (int, 1-1000): Sliding window size
      - cooldown_sec (int, 0-3600): Cooldown between blocks
      - use_adaptive (bool): Enable adaptive thresholding
    
    Returns 400 if validation fails, 403 if live mode without permission.
    """
    # In live mode (dry_run=False) we block config writes unless explicitly enabled.
    cfg = load_cfg()
    decision = cfg.get("decision", {}) if isinstance(cfg, dict) else {}
    dry_run = bool(decision.get("dry_run", True))
    if not dry_run and not ALLOW_LIVE_CONFIG:
        return jsonify({
            "ok": False,
            "error": "Config updates are disabled when dry_run=False. "
                     "Set IOTGUARD_ALLOW_LIVE_CONFIG=1 to override."
        }), 403

    body = request.get_json(silent=True) or {}
    dec = (body.get("decision") or body)
    
    # Validate with proper bounds checking
    new_dec, errors = _validate_config(dec)
    
    if errors:
        return jsonify({
            "ok": False,
            "error": "Validation failed",
            "details": errors
        }), 400

    cfg.setdefault("decision", {}).update(new_dec)
    save_cfg(cfg)
    return jsonify({
        "ok": True,
        "saved": new_dec,
        "note": "Restart decision loop to apply (or enable hot-reload there)."
    })


@app.get("/health")
def api_health():
    """
    Lightweight health endpoint for monitoring / load balancers / Kubernetes probes.
    Returns:
      - System status (ok/degraded)
      - Model version and metadata
      - Decision loop health
      - Feature extractor health
      - Current mode (demo/live)
    """
    health_path = DATA_DIR / "decision_health.json"
    feat_health_path = DATA_DIR / "features_health.json"
    model_meta_path = Path("models/model_meta.json")
    
    loop_health = None
    feat_health = None
    model_info = None
    
    # Load decision loop health
    try:
        if health_path.exists():
            loop_health = json.loads(health_path.read_text(encoding="utf-8"))
    except Exception:
        loop_health = None
    
    # Load feature extractor health
    try:
        if feat_health_path.exists():
            feat_health = json.loads(feat_health_path.read_text(encoding="utf-8"))
    except Exception:
        feat_health = None
    
    # Load model metadata (version, training info)
    try:
        if model_meta_path.exists():
            meta = json.loads(model_meta_path.read_text(encoding="utf-8"))
            model_info = {
                "version": meta.get("model_version", "unknown"),
                "type": meta.get("model_type", "LightGBM"),
                "trained_at": meta.get("trained_at"),
                "roc_auc": meta.get("roc_auc"),
                "pr_auc": meta.get("pr_auc"),
                "features_count": len(meta.get("features", [])),
                "threshold": meta.get("threshold"),
            }
    except Exception:
        model_info = {"version": "unknown", "error": "Could not load model metadata"}

    cfg = load_cfg()
    decision = cfg.get("decision", {}) if isinstance(cfg, dict) else {}
    mode = "demo" if bool(decision.get("dry_run", True)) else "live"
    
    # Determine overall system status
    model_loaded = Path("models/lightgbm.joblib").exists()
    status = "ok" if model_loaded else "degraded"
    
    # Check if decision loop is stale (no heartbeat in 60s)
    if loop_health and loop_health.get("last_ts"):
        age = now_ts() - loop_health["last_ts"]
        if age > 60:
            status = "degraded"
            loop_health["stale"] = True
    
    return jsonify({
        "status": status,
        "ok": status == "ok",
        "mode": mode,
        "require_auth": REQUIRE_AUTH,
        "model": model_info,
        "loop_health": loop_health,
        "features_health": feat_health,
        "server_time": now_ts(),
        "uptime_info": "Use /health/ready for Kubernetes readiness probe"
    })




# =============================================================================
# NEW ENHANCED API ENDPOINTS
# =============================================================================


@app.get("/api/topology")
def api_topology():
    """
    Return simulated network topology with devices and connections.
    Used by the canvas-based network visualization in the dashboard.
    """
    # Build a set of device nodes (mix of IoT and IT)
    devices = [
        {"id": "gw", "label": "Gateway Router", "type": "router", "x": 0.5, "y": 0.15},
        {"id": "fw", "label": "IoTGuard Firewall", "type": "firewall", "x": 0.5, "y": 0.35},
        {"id": "cam1", "label": "IP Camera 1", "type": "iot", "x": 0.15, "y": 0.6},
        {"id": "cam2", "label": "IP Camera 2", "type": "iot", "x": 0.3, "y": 0.7},
        {"id": "sensor1", "label": "Temp Sensor", "type": "iot", "x": 0.1, "y": 0.85},
        {"id": "thermo", "label": "Smart Thermostat", "type": "iot", "x": 0.25, "y": 0.9},
        {"id": "lock", "label": "Smart Lock", "type": "iot", "x": 0.42, "y": 0.8},
        {"id": "hub", "label": "IoT Hub", "type": "iot", "x": 0.35, "y": 0.55},
        {"id": "srv", "label": "File Server", "type": "it", "x": 0.7, "y": 0.6},
        {"id": "ws1", "label": "Workstation", "type": "it", "x": 0.85, "y": 0.7},
        {"id": "ws2", "label": "Laptop", "type": "it", "x": 0.75, "y": 0.85},
        {"id": "nas", "label": "NAS Storage", "type": "it", "x": 0.9, "y": 0.55},
    ]
    # Connections (from → to)
    connections = [
        {"from": "gw", "to": "fw", "active": True},
        {"from": "fw", "to": "hub", "active": True},
        {"from": "fw", "to": "srv", "active": True},
        {"from": "hub", "to": "cam1", "active": True},
        {"from": "hub", "to": "cam2", "active": True},
        {"from": "hub", "to": "sensor1", "active": True},
        {"from": "hub", "to": "thermo", "active": True},
        {"from": "hub", "to": "lock", "active": True},
        {"from": "srv", "to": "ws1", "active": True},
        {"from": "srv", "to": "ws2", "active": True},
        {"from": "srv", "to": "nas", "active": True},
    ]

    # Check recent alerts for active attacks — mark connections as attacked
    recent = read_last_n(20)
    attack_count = sum(1 for e in recent if e.get("state") == "ATTACK")
    if attack_count > 0:
        # Mark gateway→firewall as under attack
        connections[0]["attack"] = True
        # Randomly mark some IoT connections as attacked
        for c in connections[2:7]:
            if random.random() < 0.4:
                c["attack"] = True

    return jsonify({
        "ok": True,
        "devices": devices,
        "connections": connections,
        "attack_active": attack_count > 0,
    })


@app.get("/api/top_attackers")
def api_top_attackers():
    """
    Return top source IPs ranked by attack frequency.
    Includes country/flag info from threat_intel data embedded in alerts.
    """
    ip_stats = {}
    for evt in _iter_alerts() or []:
        if evt.get("state") != "ATTACK":
            continue
        ip = evt.get("src_ip") or evt.get("threat", {}).get("ip")
        if not ip:
            # Generate a deterministic pseudo-IP from the event index
            idx = evt.get("index", 0)
            ip = f"192.168.{(idx * 7 + 3) % 256}.{(idx * 13 + 11) % 256}"
        if ip not in ip_stats:
            ip_stats[ip] = {
                "ip": ip,
                "count": 0,
                "blocked": False,
                "country": "",
                "flag": "",
                "threat": "",
                "last_seen": 0,
            }
        ip_stats[ip]["count"] += 1
        ip_stats[ip]["last_seen"] = max(ip_stats[ip]["last_seen"], evt.get("ts", 0))
        action = str(evt.get("action") or "")
        if action.startswith("BLOCK"):
            ip_stats[ip]["blocked"] = True
        # Extract threat intel if available
        threat = evt.get("threat")
        if threat and isinstance(threat, dict):
            ip_stats[ip]["country"] = threat.get("country", "")
            ip_stats[ip]["flag"] = threat.get("flag", "")
            ip_stats[ip]["threat"] = threat.get("threat", "")

    # Sort by count descending, return top 10
    ranked = sorted(ip_stats.values(), key=lambda x: x["count"], reverse=True)[:10]
    return jsonify({"ok": True, "attackers": ranked})


@app.get("/api/shap_detail")
def api_shap_detail():
    """
    Return SHAP-style feature contribution data for a specific event.
    Parses the 'reason' field from alerts to extract feature contributions.
    """
    index = request.args.get("index", type=int)
    if index is None:
        return jsonify({"ok": False, "error": "index parameter required"}), 400

    for evt in _iter_alerts() or []:
        if evt.get("index") == index:
            reason = evt.get("reason", "")
            contributions = []
            if reason:
                # Parse "feature (+value), feature (+value)" format
                matches = re.findall(r'(\w+)\s*\(([+\-][\d.]+)\)', reason)
                for feat_name, val_str in matches:
                    contributions.append({
                        "feature": feat_name,
                        "value": float(val_str),
                    })
            # Sort by absolute value descending
            contributions.sort(key=lambda x: abs(x["value"]), reverse=True)
            return jsonify({
                "ok": True,
                "index": index,
                "score": evt.get("score"),
                "state": evt.get("state"),
                "pred_class": evt.get("pred_class"),
                "contributions": contributions,
            })
    return jsonify({"ok": False, "error": "Event not found"}), 404


@app.get("/api/timeline_heatmap")
def api_timeline_heatmap():
    """
    Return hourly-bucketed attack counts for heatmap rendering.
    Returns data for the last 7 days, broken into hourly cells.
    """
    now = now_ts()
    days = int(request.args.get("days", 7))
    cutoff = now - (days * 86400)
    # Buckets: [day_index][hour] = count
    buckets = {}
    for evt in _iter_alerts() or []:
        ts = evt.get("ts", 0)
        if ts < cutoff:
            continue
        if evt.get("state") != "ATTACK":
            continue
        dt = datetime.utcfromtimestamp(ts)
        day_key = dt.strftime("%Y-%m-%d")
        hour = dt.hour
        if day_key not in buckets:
            buckets[day_key] = [0] * 24
        buckets[day_key][hour] += 1

    # Build ordered list of day data
    result = []
    for i in range(days):
        dt = datetime.utcfromtimestamp(now - (days - 1 - i) * 86400)
        day_key = dt.strftime("%Y-%m-%d")
        day_label = dt.strftime("%a")
        hours = buckets.get(day_key, [0] * 24)
        result.append({"date": day_key, "label": day_label, "hours": hours})

    return jsonify({"ok": True, "days": result})


@app.get("/api/feature_radar")
def api_feature_radar():
    """
    Return normalized feature values for the latest (or specified) event.
    Used by the radar/spider chart in the dashboard.
    """
    # Read feature names from config
    cfg = load_cfg()
    features = cfg.get("features", [
        "flows", "bytes_total", "pkts_total", "syn_ratio", "mean_bytes_flow",
        "ack_ratio", "fin_ratio", "rst_ratio", "http_ratio", "tcp_ratio",
        "protocol_diversity", "std_bytes", "iat_mean"
    ])

    # Read the latest feature row from features.csv
    csv_path = DATA_DIR / "features.csv"
    if not csv_path.exists():
        return jsonify({"ok": True, "features": features, "values": [0] * len(features)})

    try:
        import pandas as pd
        df = pd.read_csv(csv_path, encoding="utf-8")
        if df.empty:
            return jsonify({"ok": True, "features": features, "values": [0] * len(features)})

        row = df.iloc[-1]
        raw_values = []
        for f in features:
            v = float(row.get(f, 0)) if f in row.index else 0.0
            raw_values.append(v)

        # Normalize to 0-1 range using column min/max from entire dataframe
        norm_values = []
        for i, f in enumerate(features):
            if f in df.columns:
                col = pd.to_numeric(df[f], errors="coerce")
                cmin = col.min()
                cmax = col.max()
                if cmax > cmin:
                    norm_values.append(round((raw_values[i] - cmin) / (cmax - cmin), 3))
                else:
                    norm_values.append(0.5)
            else:
                norm_values.append(0)

        return jsonify({
            "ok": True,
            "features": features,
            "values": norm_values,
            "raw_values": [round(v, 4) for v in raw_values],
        })
    except Exception as e:
        return jsonify({"ok": True, "features": features, "values": [0] * len(features), "error": str(e)})


# =============================================================================
# ATTACK SIMULATION (Feature-Injection Based — No Scapy Required)
# =============================================================================

# Attack signature profiles: realistic feature patterns for each attack type
_ATTACK_PROFILES = {
    "syn": {
        "name": "SYN Flood",
        "rows": 8,
        "gen": lambda: {
            "flows": random.randint(40, 80),
            "bytes_total": random.randint(20000, 60000),
            "pkts_total": random.randint(200, 500),
            "syn_ratio": round(random.uniform(0.85, 0.99), 2),
            "mean_bytes_flow": random.randint(300, 800),
            "ack_ratio": 0.0,
            "fin_ratio": 0.0,
            "rst_ratio": round(random.uniform(0.0, 0.1), 2),
            "http_ratio": 0.0,
            "tcp_ratio": 1.0,
            "protocol_diversity": 1,
            "std_bytes": round(random.uniform(0, 10), 2),
            "iat_mean": round(random.uniform(0.0001, 0.002), 6),
        },
    },
    "udp": {
        "name": "UDP Flood",
        "rows": 8,
        "gen": lambda: {
            "flows": random.randint(50, 100),
            "bytes_total": random.randint(40000, 120000),
            "pkts_total": random.randint(400, 1000),
            "syn_ratio": 0.0,
            "mean_bytes_flow": random.randint(600, 1200),
            "ack_ratio": 0.0,
            "fin_ratio": 0.0,
            "rst_ratio": 0.0,
            "http_ratio": 0.0,
            "tcp_ratio": 0.0,
            "protocol_diversity": 1,
            "std_bytes": round(random.uniform(0, 20), 2),
            "iat_mean": round(random.uniform(0.0001, 0.001), 6),
        },
    },
    "http": {
        "name": "HTTP Slowloris",
        "rows": 6,
        "gen": lambda: {
            "flows": random.randint(30, 60),
            "bytes_total": random.randint(5000, 15000),
            "pkts_total": random.randint(100, 300),
            "syn_ratio": round(random.uniform(0.3, 0.5), 2),
            "mean_bytes_flow": random.randint(100, 300),
            "ack_ratio": round(random.uniform(0.1, 0.3), 2),
            "fin_ratio": 0.0,
            "rst_ratio": 0.0,
            "http_ratio": round(random.uniform(0.8, 1.0), 2),
            "tcp_ratio": 1.0,
            "protocol_diversity": 1,
            "std_bytes": round(random.uniform(50, 200), 2),
            "iat_mean": round(random.uniform(0.5, 5.0), 6),
        },
    },
    "scan": {
        "name": "Port Scan",
        "rows": 5,
        "gen": lambda: {
            "flows": random.randint(60, 150),
            "bytes_total": random.randint(3000, 10000),
            "pkts_total": random.randint(120, 300),
            "syn_ratio": round(random.uniform(0.7, 0.95), 2),
            "mean_bytes_flow": random.randint(40, 80),
            "ack_ratio": 0.0,
            "fin_ratio": 0.0,
            "rst_ratio": round(random.uniform(0.5, 0.9), 2),
            "http_ratio": 0.0,
            "tcp_ratio": 1.0,
            "protocol_diversity": 1,
            "std_bytes": round(random.uniform(0, 5), 2),
            "iat_mean": round(random.uniform(0.001, 0.01), 6),
        },
    },
    "botnet": {
        "name": "IoT Botnet C2",
        "rows": 6,
        "gen": lambda: {
            "flows": random.randint(15, 35),
            "bytes_total": random.randint(8000, 25000),
            "pkts_total": random.randint(60, 150),
            "syn_ratio": round(random.uniform(0.4, 0.7), 2),
            "mean_bytes_flow": random.randint(200, 600),
            "ack_ratio": round(random.uniform(0.2, 0.5), 2),
            "fin_ratio": round(random.uniform(0.0, 0.1), 2),
            "rst_ratio": 0.0,
            "http_ratio": round(random.uniform(0.0, 0.2), 2),
            "tcp_ratio": round(random.uniform(0.7, 1.0), 2),
            "protocol_diversity": random.randint(1, 2),
            "std_bytes": round(random.uniform(100, 500), 2),
            "iat_mean": round(random.uniform(0.01, 0.1), 6),
        },
    },
    "exfil": {
        "name": "Data Exfiltration",
        "rows": 5,
        "gen": lambda: {
            "flows": random.randint(3, 8),
            "bytes_total": random.randint(100000, 500000),
            "pkts_total": random.randint(500, 2000),
            "syn_ratio": round(random.uniform(0.05, 0.15), 2),
            "mean_bytes_flow": random.randint(15000, 60000),
            "ack_ratio": round(random.uniform(0.3, 0.6), 2),
            "fin_ratio": round(random.uniform(0.1, 0.3), 2),
            "rst_ratio": 0.0,
            "http_ratio": round(random.uniform(0.0, 0.3), 2),
            "tcp_ratio": 1.0,
            "protocol_diversity": random.randint(1, 2),
            "std_bytes": round(random.uniform(500, 5000), 2),
            "iat_mean": round(random.uniform(0.001, 0.01), 6),
        },
    },
}

FEATURES_HEADER = "flows,bytes_total,pkts_total,syn_ratio,mean_bytes_flow,ack_ratio,fin_ratio,rst_ratio,http_ratio,tcp_ratio,protocol_diversity,std_bytes,iat_mean\n"


@app.post("/api/simulate")
def api_simulate():
    """
    Inject attack-pattern feature rows directly into data/features.csv.
    This replaces the old subprocess-based simulator that required Scapy.
    The decision loop will pick up these rows and score them.
    """
    attack_type = request.args.get("type", "syn")
    profile = _ATTACK_PROFILES.get(attack_type)
    if not profile:
        return jsonify({"ok": False, "error": f"Unknown attack type: {attack_type}. Available: {list(_ATTACK_PROFILES.keys())}"}), 400

    csv_path = DATA_DIR / "features.csv"
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Ensure CSV has header
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        csv_path.write_text(FEATURES_HEADER, encoding="utf-8")

    # Generate and append attack rows
    rows_written = 0
    with csv_path.open("a", encoding="utf-8") as f:
        for _ in range(profile["rows"]):
            row_data = profile["gen"]()
            line = ",".join(str(row_data[k]) for k in [
                "flows", "bytes_total", "pkts_total", "syn_ratio", "mean_bytes_flow",
                "ack_ratio", "fin_ratio", "rst_ratio", "http_ratio", "tcp_ratio",
                "protocol_diversity", "std_bytes", "iat_mean"
            ])
            f.write(line + "\n")
            rows_written += 1

    logger.info(f"Simulated {profile['name']}: injected {rows_written} attack rows into features.csv")
    return jsonify({
        "ok": True,
        "attack": profile["name"],
        "rows_injected": rows_written,
        "message": f"Injected {rows_written} {profile['name']} attack rows. Decision loop will score them shortly."
    })

@app.post("/api/clear")
def api_clear():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ALERT_LOG.write_text("", encoding="utf-8")
    return jsonify({"ok": True})

@app.post("/api/clear_all")
def api_clear_all():
    # clear alerts
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ALERT_LOG.write_text("", encoding="utf-8")

    # reset offset state so the decision loop won’t re-score old rows
    (DATA_DIR / "state.json").write_text('{"offset_rows":0,"csv_mtime":0}', encoding="utf-8")

    # (optional) also reset features.csv to header for a fresh run:
    # (DATA_DIR / "features.csv").write_text(
    #   "flows,bytes_total,pkts_total,uniq_src,uniq_dst,syn_ratio,mean_bytes_flow\n", encoding="utf-8"
    # )

    return jsonify({"ok": True})

@app.get("/api/download.csv")
def api_download_csv():
    if not ALERT_LOG.exists():
        abort(404)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["ts","index","score","state","hits_in_window","action","pred_class","reason","threat"])
    writer.writeheader()
    for e in _iter_alerts() or []:
        t = e.get("threat") or {}
        t_str = f"{t.get('flag','')} {t.get('country','')} {t.get('threat','')}".strip()
        writer.writerow({
            "ts": e.get("ts"),
            "index": e.get("index"),
            "score": e.get("score"),
            "state": e.get("state"),
            "hits_in_window": e.get("hits_in_window"),
            "action": e.get("action"),
            "pred_class": e.get("pred_class"),
            "reason": e.get("reason", ""),
            "threat": t_str
        })
    output.seek(0)
    return Response(
        output.read(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=iotguard_alerts.csv"}
    )

@app.get("/")
def website():
    # Serve the project landing page from website/index.html
    _site = Path(__file__).resolve().parent.parent.parent / "website" / "index.html"
    if _site.exists():
        html = _site.read_text(encoding="utf-8")
        resp = Response(html, mimetype="text/html")
        resp.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
        return resp
    # Fallback to dashboard if website not found
    return dashboard()

@app.get("/dashboard")
def dashboard():
    # Load dashboard HTML from template file
    _tmpl = Path(__file__).parent / "templates" / "index.html"
    html = _tmpl.read_text(encoding="utf-8")
    resp = Response(html, mimetype="text/html")
    # Prevent stale cached UI — always fetch latest HTML/JS
    resp.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

if __name__ == "__main__":
    host = os.environ.get("IOTGUARD_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT") or os.environ.get("IOTGUARD_PORT") or "5001")
    logger.info(f"Starting IoTGuard API Dashboard on http://{host}:{port}")
    logger.info(f"Mode: {'DEMO (dry_run)' if _initial_dry_run else 'LIVE'}, Auth required: {REQUIRE_AUTH}")

    # Use SocketIO runner if WebSocket support is enabled, otherwise use Flask directly
    if socketio is not None:
        logger.info("Running with WebSocket support enabled")
        socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
    else:
        logger.info("Running without WebSocket support (polling mode)")
        app.run(host=host, port=port, debug=False)
