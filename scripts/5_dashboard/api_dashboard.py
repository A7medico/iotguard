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
import os, io, csv, json, time, threading, yaml, sys
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, jsonify, request, Response, abort, g

# Add scripts directory and subdirectories to path for imports
_scripts_dir = Path(__file__).parent.parent
sys.path.insert(0, str(_scripts_dir))
sys.path.insert(0, str(_scripts_dir / "9_utilities"))
sys.path.insert(0, str(_scripts_dir / "3_inference"))
sys.path.insert(0, str(_scripts_dir / "4_response"))
sys.path.insert(0, str(_scripts_dir / "5_dashboard"))
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

@app.get("/api/config")
def api_get_config():
    """
    Return the current decision parameters used by the scoring loop.
    Includes fields that the UI may choose to render read-only (e.g. dry_run).
    """
    cfg = load_cfg()
    decision = cfg.get("decision", {})
    return jsonify({
        "ok": True,
        "decision": {
            "threshold":     float(decision.get("threshold", 0.65)),
            "grace":         int(decision.get("grace", 3)),
            "window":        int(decision.get("window", 5)),
            "cooldown_sec":  int(decision.get("cooldown_sec", 30)),
            "use_adaptive":  bool(decision.get("use_adaptive", False)),
            "dry_run":       bool(decision.get("dry_run", True)),
        }
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


import subprocess

@app.post("/api/simulate")
def api_simulate():
    attack_type = request.args.get("type", "syn")
    type_map = {
        "syn": "syn_flood",
        "udp": "udp_flood",
        "http": "http_flood",
        "scan": "port_scan"
    }
    real_type = type_map.get(attack_type, "syn_flood")
    target_ip = os.environ.get("IOTGUARD_SIM_TARGET", "127.0.0.1")
    sim_script = str(_scripts_dir / "8_simulation" / "attack_simulator.py")
    
    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        subprocess.Popen(
            [sys.executable, sim_script, "--target", target_ip, "--attack", real_type, "--duration", "10"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return jsonify({"ok": True, "message": f"Started {real_type} against {target_ip}"})
    except Exception as e:
        logger.error(f"Failed to launch simulator: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

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
    _old_html = """
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>IoTGuard — Live Alerts</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<link rel="icon" href="data:,">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #020617;
    --ink: #e5e7eb;
    --muted: #9ca3af;
    --row: #020617;
    --panel: rgba(15,23,42,0.95);
    --accent: #38bdf8;
    --accent2: #a855f7;
    --good: #4ade80;
    --warn: #facc15;
    --bad: #f97373;
  }
  * { box-sizing: border-box; }
  body {
    font-family: "Inter", system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
    margin: 0;
    color: var(--ink);
    background:
      radial-gradient(1200px 600px at 80% -10%, #1e293b 0%, transparent 40%),
      radial-gradient(800px 500px at -10% 20%, #0ea5e9 0%, transparent 35%),
      linear-gradient(180deg, #020617 0%, #020617 55%, #020617 100%);
    min-height: 100vh;
  }
  .nav {
    position: sticky;
    top: 0;
    z-index: 10;
    backdrop-filter: blur(10px);
    background: linear-gradient(90deg, rgba(15,23,42,.9), rgba(15,23,42,.7));
    border-bottom: 1px solid rgba(148,163,184,.35);
    padding: 10px 20px;
  }
  .brand {
    font-weight: 800;
    letter-spacing: .03em;
    font-size: 18px;
  }
  .container {
    max-width: 1180px;
    margin: 0 auto;
    padding: 18px 20px;
  }
  .hero h1 {
    margin: 8px 0 6px;
    font-size: 36px;
    line-height: 1.1;
  }
  .hero .grad {
    background: linear-gradient(110deg, var(--accent), var(--accent2));
    -webkit-background-clip:text;
    background-clip:text;
    color: transparent;
  }
  .sub {
    color: var(--muted);
    margin-top: 4px;
    font-size: 14px;
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0,1fr));
    gap: 12px;
  }
  .card {
    background: radial-gradient(circle at 0% 0%, rgba(56,189,248,0.14), transparent 55%), var(--panel);
    padding: 14px 16px;
    border-radius: 16px;
    box-shadow: 0 18px 45px rgba(0,0,0,.6);
    border: 1px solid rgba(148,163,184,.2);
    transition: transform .14s ease-out, box-shadow .14s ease-out, border-color .14s ease-out;
  }
  .card:hover {
    transform: translateY(-2px);
    box-shadow: 0 24px 55px rgba(0,0,0,.75);
    border-color: rgba(148,163,184,.45);
  }

  .row {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
    border-radius: 12px;
    overflow: hidden;
    background: rgba(15,23,42,0.9);
  }
  thead {
    background: linear-gradient(90deg, rgba(15,23,42,0.95), rgba(15,23,42,0.8));
  }
  th, td {
    padding: 9px 11px;
    border-bottom: 1px solid rgba(30,64,175,0.45);
    font-size: 13px;
    white-space: nowrap;
  }
  th {
    text-align: left;
    color: var(--muted);
    font-weight: 600;
  }
  tbody tr:nth-child(even) {
    background-color: rgba(15,23,42,0.8);
  }
  tbody tr:nth-child(odd) {
    background-color: rgba(15,23,42,0.6);
  }
  tbody tr:hover {
    background-color: rgba(30,64,175,0.45);
  }

  .tag {
    padding: 2px 8px;
    border-radius: 999px;
    font-weight: 600;
    font-size: 11px;
  }
  .ok   { background: #064e3b; color: var(--good); }
  .warn { background: #3f2a0a; color: var(--warn); }
  .bad  { background: #450a0a; color: var(--bad); }

  .footer {
    color: var(--muted);
    font-size: 12px;
    margin-top: 10px;
  }
  .btn {
    background: radial-gradient(circle at 0% 0%, rgba(56,189,248,0.2), transparent 60%), #020617;
    color: #e5e7eb;
    border: 1px solid #1f2937;
    padding: 8px 12px;
    border-radius: 999px;
    cursor: pointer;
    font-size: 13px;
  }
  .btn:hover {
    filter: brightness(1.1);
    border-color: #38bdf8;
  }
  input[type=number] {
    width: 90px;
    background: #020617;
    color: #e5e7eb;
    border: 1px solid #1f2937;
    border-radius: 999px;
    padding: 7px 10px;
    font-size: 13px;
  }
  input[type=text] {
    background: #020617;
    color: #e5e7eb;
    border: 1px solid #1f2937;
    border-radius: 999px;
    padding: 7px 10px;
    font-size: 13px;
  }
  select {
    background: #020617;
    color: #e5e7eb;
    border: 1px solid #1f2937;
    border-radius: 999px;
    padding: 4px 8px;
    font-size: 13px;
  }
  .chart-box { height: 240px; }
  .chips {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }
  .chip {
    background: rgba(15,23,42,.9);
    border: 1px solid rgba(148,163,184,.25);
    color: #e5e7eb;
    padding: 6px 10px;
    border-radius: 999px;
    font-size: 12px;
  }

  @media (max-width: 900px) {
    .grid {
      grid-template-columns: repeat(2, minmax(0,1fr));
    }
  }
  @media (max-width: 640px) {
    .container {
      padding: 14px 14px;
    }
    .hero h1 {
      font-size: 26px;
    }
    .grid {
      grid-template-columns: minmax(0,1fr);
    }
    table {
      font-size: 12px;
    }
    th, td {
      padding: 7px 8px;
    }
  }
</style>
</head>
<body>
  <div class="nav">
  <div class="container">
      <span class="brand">IoTGuard</span>
      <span id="mode_badge" class="tag warn" style="margin-left:10px;font-size:11px;">mode</span>
  </div>
  </div>
  <div class="container hero">
    <h1><span class="grad">IoTGuard — Live Alerts</span></h1>
    <div class="sub">Realtime scoring, per-class insights, and controls.</div>
  </div>
  <div class="container grid">
    <div class="card"><div>Last 60 min — Total</div><div id="mt_total" style="font-size:24px;font-weight:700">0</div></div>
    <div class="card"><div>Last 60 min — Attacks</div><div id="mt_attacks" style="font-size:24px;font-weight:700;color:#f28f8f">0</div></div>
    <div class="card"><div>Last 60 min — Blocks</div><div id="mt_blocks" style="font-size:24px;font-weight:700;color:#f2d28f">0</div></div>
  </div>

  <div class="container" style="margin-top:12px;">
    <div class="card">
    <div class="row" style="justify-content:space-between;">
      <div class="row">
        <div style="font-weight:700;">Controls</div>
        <div class="row" style="gap:6px;margin-left:14px;">
          <label>threshold <input id="ctl_threshold" type="number" step="0.01" min="0" max="1"/></label>
          <label>adaptive <input id="ctl_adaptive" type="checkbox" style="width:auto;transform:scale(1.2);margin-right:6px;"/></label>
          <label>grace <input id="ctl_grace" type="number" min="1" max="20"/></label>
          <label>window <input id="ctl_window" type="number" min="1" max="50"/></label>
          <label>cooldown <input id="ctl_cool" type="number" min="0" max="3600"/></label>
          <button class="btn" id="btn_save">Save</button>
          <div id="save_msg" class="footer"></div>
        </div>
      </div>
      <div class="row">
        <button class="btn" id="btn_download">Download CSV</button>
        <button class="btn" id="btn_clear">Clear Log</button>
        <button class="btn" id="btn_clear_all">Clear All</button>
        <div id="clock" class="footer">—</div>
      </div>
    </div>
    </div>
  </div>

  <div class="container">
    <div class="card chart-box"><canvas id="scoreChart" style="width:100%;height:100%;"></canvas></div>
  </div>

  <div class="container" style="margin-top:12px;">
    <div class="card" style="margin-bottom:12px;">
      <div style="font-weight:700; margin-bottom:6px;">Per-class Counts (last 60m)</div>
      <div id="class_chips" class="chips"></div>
      <div style="font-weight:700; margin:10px 0 6px;">Block severities (last 60m)</div>
      <div id="block_chips" class="chips"></div>
    </div>
    <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <div style="font-weight:700;">Recent Events</div>
      <div class="row" style="gap:8px;font-size:12px;">
        <label>state
          <select id="flt_state" style="background:#0f172a;color:#e5e7eb;border:1px solid #334155;border-radius:999px;padding:4px 8px;">
            <option value="all">all</option>
            <option value="ATTACK">ATTACK</option>
            <option value="benign">benign</option>
          </select>
        </label>
        <label><input id="flt_blocked" type="checkbox" style="width:auto;transform:scale(1.1);margin-right:4px;"/>only blocked</label>
        <label>search
          <input id="flt_text" type="text" placeholder="pred / reason / threat" style="background:#0f172a;color:#e5e7eb;border:1px solid #334155;border-radius:999px;padding:4px 8px;min-width:180px;"/>
        </label>
      </div>
    </div>
    <table>
      <thead>
        <tr>
            <th>Time (UTC)</th>
            <th>Index</th>
            <th>Score</th>
            <th>State</th>
            <th>Threat Intel</th>
            <th>Reason (XAI)</th>
            <th>Pred</th>
            <th>Window Hits</th>
            <th>Action</th>
        </tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
    </div>
  </div>

  <div class="footer">Auto-refreshing every 2s. Backed by alerts.jsonl.</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script>
let lastTs = null;
let chart, chartData = {labels: [], scores: [], thresholds: []};
let lastBlockTs = 0;
let modelMeta = { classes: null, benign_index: null };
let allEvents = [];
let fltState = 'all';
let fltBlockedOnly = false;
let fltText = '';

// --- audio alert for BLOCK ---
const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
function beep() {
  const o = audioCtx.createOscillator();
  const g = audioCtx.createGain();
  o.connect(g); g.connect(audioCtx.destination);
  o.type = 'square'; o.frequency.value = 880;
  g.gain.value = 0.05;
  o.start(); setTimeout(()=>{ o.stop(); }, 180);
}

// --- utils ---
function iso(ts){ try{ return new Date(ts*1000).toISOString(); }catch(e){ return '—'; } }
function tag(text, cls){ return '<span class="tag '+cls+'">'+text+'</span>'; }
function stateTag(s){ return s==='ATTACK' ? tag('ATTACK','bad') : tag('benign','ok'); }
function actionTag(a){
  if (!a) return tag('NONE','ok');
  if (!a.startsWith('BLOCK')) return tag('NONE','ok');
  let text = a;
  let cls = 'warn';
  if (a === 'BLOCK-KILL') { text = 'BLOCK KILL'; cls = 'bad'; }
  else if (a === 'BLOCK-HARD') { text = 'BLOCK HARD'; cls = 'bad'; }
  else if (a === 'BLOCK-SOFT') { text = 'BLOCK SOFT'; cls = 'warn'; }
  return tag(text, cls);
}
function reasonTag(r){
  if (!r) return '<span style="color:#555">—</span>';
  // Highlight positive contributions
  return '<span style="font-size:12px;color:#a78bfa;">' + r + '</span>';
}
function threatTag(t){
  if (!t || (!t.country && !t.threat)) return '<span style="color:#555">—</span>';
  let html = '';
  if (t.flag) html += `<span style="font-size:14px;margin-right:4px;">${t.flag}</span>`;
  if (t.country) html += `<span style="font-size:11px;color:#94a3b8;margin-right:6px;">${t.country}</span>`;
  if (t.threat) html += `<span class="tag bad" style="font-size:10px;">${t.threat}</span>`;
  return html;
}
function rowHtml(e){
  return '<tr>'
    + '<td>'+iso(e.ts)+'</td>'
    + '<td>'+e.index+'</td>'
    + '<td>'+((e.score ?? 0).toFixed(3))+'</td>'
    + '<td>'+stateTag(e.state)+'</td>'
    + '<td>'+threatTag(e.threat)+'</td>'
    + '<td>'+reasonTag(e.reason)+'</td>'
    + '<td>'+(e.pred_class ?? '—')+'</td>'
    + '<td>'+(e.hits_in_window ?? 0)+'</td>'
    + '<td>'+actionTag(e.action)+'</td>'
  + '</tr>';
}

function toast(msg){
  const el = document.getElementById('save_msg');
  if (!el) return;
  el.textContent = msg;
  setTimeout(()=> el.textContent = '', 2500);
}

async function refreshCounts(){
  const r = await fetch('/api/counts?window_minutes=60');
  const j = await r.json();
  document.getElementById('mt_total').innerText = j.total ?? 0;
  document.getElementById('mt_attacks').innerText = j.attacks ?? 0;
  document.getElementById('mt_blocks').innerText = j.blocks ?? 0;
  // Optionally render class counts if present
  const chips = document.getElementById('class_chips');
  if (chips) {
    let html = '';
    if (j.class_counts) {
      const entries = Object.entries(j.class_counts).sort((a,b)=> b[1]-a[1]);
      for (const [name, cnt] of entries) {
        html += `<span class="chip">${name}: ${cnt}</span>`;
      }
    }
    chips.innerHTML = html || '<span class="chip">No class data</span>';
  }
  // Block severities
  const blockChips = document.getElementById('block_chips');
  if (blockChips) {
    let html = '';
    if (j.block_breakdown) {
      const entries = Object.entries(j.block_breakdown).sort((a,b)=> b[1]-a[1]);
      for (const [name, cnt] of entries) {
        html += `<span class="chip">${name}: ${cnt}</span>`;
      }
    }
    blockChips.innerHTML = html || '<span class="chip">No blocks</span>';
  }
}

function passesFilters(e){
  if (fltState !== 'all' && e.state !== fltState) return false;
  if (fltBlockedOnly && !(e.action && String(e.action).startsWith('BLOCK'))) return false;
  if (fltText){
    const t = fltText.toLowerCase();
    const hay = [
      e.pred_class || '',
      e.reason || '',
      (e.threat && (e.threat.threat || e.threat.country || '')) || ''
    ].join(' ').toLowerCase();
    if (!hay.includes(t)) return false;
  }
  return true;
}

function renderTable(){
  const tbody = document.getElementById('rows');
  if (!tbody) return;
  let html = '';
  const src = allEvents.slice(-200).reverse(); // newest first
  for (const e of src){
    if (!passesFilters(e)) continue;
    html += rowHtml(e);
  }
  tbody.innerHTML = html;
}

async function refreshEvents(){
  const q = lastTs ? ('?since_ts='+encodeURIComponent(lastTs)) : '';
  const r = await fetch('/api/events'+q);
  const j = await r.json();
  const list = j.events || [];
  if (!list.length) return;

  // accumulate events and re-render table with filters
  allEvents = allEvents.concat(list);
  if (allEvents.length > 500) {
    allEvents = allEvents.slice(-500);
  }
  renderTable();

  // chart update (cap 100)
  for (const e of list){
    chartData.labels.push(iso(e.ts));
    chartData.scores.push(e.score ?? 0);
    chartData.thresholds.push(e.effective_threshold ?? null);
  }
  if (chartData.labels.length > 100){
    chartData.labels.splice(0, chartData.labels.length-100);
    chartData.scores.splice(0, chartData.scores.length-100);
    chartData.thresholds.splice(0, chartData.thresholds.length-100);
  }
  chart.data.labels = chartData.labels;
  chart.data.datasets[0].data = chartData.scores;
  chart.data.datasets[1].data = chartData.thresholds;
  chart.update('none');

  // alerts on new BLOCK (any BLOCK-*)
  for (const e of list){
    if (e.action && String(e.action).startsWith('BLOCK') && (e.ts > lastBlockTs)){
      lastBlockTs = e.ts;
      beep();
      document.body.style.boxShadow = 'inset 0 0 0 4px #f2d28f55';
      setTimeout(()=>document.body.style.boxShadow='none', 200);
    }
  }

  lastTs = list[list.length-1].ts;
}

async function loadConfig(){
  const r = await fetch('/api/config'); const j = await r.json();
  const d = j.decision || {};
  document.getElementById('ctl_threshold').value = d.threshold ?? 0.65;
  document.getElementById('ctl_adaptive').checked = d.use_adaptive ?? false;
  document.getElementById('ctl_grace').value     = d.grace ?? 3;
  document.getElementById('ctl_window').value    = d.window ?? 5;
  document.getElementById('ctl_cool').value      = d.cooldown_sec ?? 30;
  // Update mode badge based on dry_run (demo vs live)
  const badge = document.getElementById('mode_badge');
  if (badge){
    if (d.dry_run){
      badge.textContent = 'DEMO MODE (no real blocking)';
      badge.className = 'tag warn';
    } else {
      badge.textContent = 'LIVE MODE (firewall active)';
      badge.className = 'tag bad';
    }
  }
  // fetch model metadata
  try { const m = await (await fetch('/api/model')).json(); modelMeta = (m.model || {}); } catch {}
}

async function saveConfig(){
  const body = {
    decision: {
      threshold: parseFloat(document.getElementById('ctl_threshold').value),
      use_adaptive: document.getElementById('ctl_adaptive').checked,
      grace: parseInt(document.getElementById('ctl_grace').value),
      window: parseInt(document.getElementById('ctl_window').value),
      cooldown_sec: parseInt(document.getElementById('ctl_cool').value),
    }
  };
  const r = await fetch('/api/config', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  const j = await r.json();
  const msg = document.getElementById('save_msg');
  msg.textContent = j.ok ? 'Saved (restart decision loop to apply)' : ('Error: '+(j.error||'')); 
  setTimeout(()=> msg.textContent='', 3500);
}

function tickClock(){ document.getElementById('clock').innerText = new Date().toISOString(); }

async function tick(){
  tickClock();
  await refreshCounts();
  await refreshEvents();
}

function setupChart(){
  const ctx = document.getElementById('scoreChart').getContext('2d');
  chart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Score',
        data: [],
        borderWidth: 2,
        pointRadius: 0,
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        fill: true
      },
      {
        label: 'Adaptive Threshold',
        data: [],
        borderWidth: 2,
        pointRadius: 0,
        borderColor: '#f59e0b',
        borderDash: [5, 5],
        fill: false
      }]
    },
    options: {
      animation: false,
      responsive: true,
      scales: {
        x: { ticks: { display:false } },
        y: { min:0, max:1 }
      },
      plugins:{ legend:{ display:false } }
    }
  });
}

document.getElementById('btn_download').onclick = ()=>{ window.location='/api/download.csv'; };

document.getElementById('btn_clear').onclick = async ()=>{
  if (!confirm('Clear alerts log? This cannot be undone.')) return;
  const r = await fetch('/api/clear', {method:'POST'});
  const j = await r.json();
  if (j.ok){
    allEvents = [];
    lastTs = 0;
    document.getElementById('rows').innerHTML='';
    chartData.labels = []; chartData.scores = []; chartData.thresholds = []; chart.update();
    toast('Alerts cleared');
  } else {
    toast('Error clearing alerts');
  }
};

document.getElementById('btn_clear_all').onclick = async ()=>{
  if (!confirm('Clear alerts AND reset state? The decision loop offset will reset.')) return;
  const r = await fetch('/api/clear_all', {method:'POST'});
  const j = await r.json();
  if (j.ok){
    allEvents = [];
    lastTs = 0;
    document.getElementById('rows').innerHTML='';
    chartData.labels = []; chartData.scores = []; chartData.thresholds = []; chart.update();
    toast('Alerts + state cleared');
  } else {
    toast('Error clearing all');
  }
};

document.getElementById('btn_save').onclick = saveConfig;

// filter handlers
document.getElementById('flt_state').onchange = (e)=>{
  fltState = e.target.value || 'all';
  renderTable();
};
document.getElementById('flt_blocked').onchange = (e)=>{
  fltBlockedOnly = !!e.target.checked;
  renderTable();
};
document.getElementById('flt_text').oninput = (e)=>{
  fltText = (e.target.value || '').trim().toLowerCase();
  renderTable();
};

// init
setupChart();
loadConfig();
setInterval(tick, 2000);
tick();
</script>
</body>
</html>
    """
    resp = Response(html, mimetype="text/html")
    # Prevent stale cached UI — always fetch latest HTML/JS
    resp.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

if __name__ == "__main__":
    host = os.environ.get("IOTGUARD_HOST", "0.0.0.0")
    port = int(os.environ.get("IOTGUARD_PORT", "5001"))
    logger.info(f"Starting IoTGuard API Dashboard on http://{host}:{port}")
    logger.info(f"Mode: {'DEMO (dry_run)' if _initial_dry_run else 'LIVE'}, Auth required: {REQUIRE_AUTH}")

    # Use SocketIO runner if WebSocket support is enabled, otherwise use Flask directly
    if socketio is not None:
        logger.info("Running with WebSocket support enabled")
        socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
    else:
        logger.info("Running without WebSocket support (polling mode)")
        app.run(host=host, port=port, debug=False)
