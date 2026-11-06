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
        record_inference_time, record_score, active_connections,
        update_firewall_telemetry
    )
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False
    update_firewall_telemetry = lambda *a, **kw: None

try:
    from auth import (
        require_auth as jwt_require_auth,
        require_role,
        register_api_key,
        validate_api_key,
        list_api_keys,
        revoke_api_key,
        ROLE_ADMIN,
        ROLE_SOC_ANALYST,
        ROLE_AUDITOR,
        ROLE_EDGE_SENSOR,
        ALL_ROLES,
        authenticate_user,
        rate_limit,
        get_token_from_request,
        validate_token,
    )
    AUTH_AVAILABLE = True
except ImportError:
    AUTH_AVAILABLE = False
    ROLE_ADMIN = "ADMIN"
    ROLE_SOC_ANALYST = "SOC_ANALYST"
    ROLE_AUDITOR = "AUDITOR"
    ROLE_EDGE_SENSOR = "EDGE_SENSOR"
    ALL_ROLES = {ROLE_ADMIN, ROLE_SOC_ANALYST, ROLE_AUDITOR, ROLE_EDGE_SENSOR}
    require_role = lambda *a, **k: (lambda f: f)
    register_api_key = lambda *a, **k: "dummy_key"
    validate_api_key = lambda *a, **k: None
    list_api_keys = lambda *a, **k: []
    revoke_api_key = lambda *a, **k: False

# Enterprise Relational Storage Engine
try:
    from storage_engine import get_storage_engine, SQLiteStorageEngine
    STORAGE_AVAILABLE = True
except ImportError:
    try:
        import importlib
        _storage_mod = importlib.import_module("scripts.9_utilities.storage_engine")
        get_storage_engine = _storage_mod.get_storage_engine
        SQLiteStorageEngine = _storage_mod.SQLiteStorageEngine
        STORAGE_AVAILABLE = True
    except ImportError:
        STORAGE_AVAILABLE = False
        get_storage_engine = lambda *a, **k: None

# Cryptographic Audit Ledger
try:
    from audit_ledger import (
        get_audit_ledger,
        record_audit_event,
        verify_audit_ledger,
    )
    AUDIT_AVAILABLE = True
except ImportError:
    try:
        import importlib
        _audit_mod = importlib.import_module("scripts.9_utilities.audit_ledger")
        get_audit_ledger = _audit_mod.get_audit_ledger
        record_audit_event = _audit_mod.record_audit_event
        verify_audit_ledger = _audit_mod.verify_audit_ledger
        AUDIT_AVAILABLE = True
    except ImportError:
        AUDIT_AVAILABLE = False
        record_audit_event = lambda *a, **k: {}
        verify_audit_ledger = lambda *a, **k: (True, "AUDIT_UNAVAILABLE", None)
        get_audit_ledger = lambda *a, **k: None

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

try:
    from playbooks import (
        TAXONOMIES,
        REMEDIATION_PLAYBOOKS,
        normalize_taxonomy,
        get_remediation_playbook,
    )
    PLAYBOOKS_AVAILABLE = True
except ImportError:
    PLAYBOOKS_AVAILABLE = False
    TAXONOMIES = []
    REMEDIATION_PLAYBOOKS = {}
    normalize_taxonomy = lambda x, src=None: "ZeroDay-Anomaly"
    get_remediation_playbook = lambda x, src_ip=None: {}

try:
    from blocker import (
        block_ip, unblock_ip, get_active_blocks, is_ip_blocked,
        get_active_driver, get_driver_telemetry
    )
    BLOCKER_AVAILABLE = True
except ImportError:
    BLOCKER_AVAILABLE = False
    block_ip = lambda ip, **kw: (False, "blocker not available")
    unblock_ip = lambda ip, **kw: (False, "blocker not available")
    get_active_blocks = lambda: []
    is_ip_blocked = lambda ip: False
    get_active_driver = lambda dry_run=False: "none"
    get_driver_telemetry = lambda: {
        "active_driver": "none",
        "os": "unknown",
        "ebpf_available": False,
        "ebpf_attached": False,
        "xdp_interface": "eth0",
        "drop_stats": {},
        "total_xdp_drops": 0,
    }

try:
    from threat_intel import ThreatIntel
    THREAT_INTEL = ThreatIntel()
except ImportError:
    THREAT_INTEL = None

try:
    from federated_learning import get_federated_coordinator
    FEDERATED_AVAILABLE = True
except ImportError:
    try:
        import importlib
        _fl = importlib.import_module("scripts.2_training.federated_learning")
        get_federated_coordinator = _fl.get_federated_coordinator
        FEDERATED_AVAILABLE = True
    except Exception:
        FEDERATED_AVAILABLE = False
        get_federated_coordinator = None

# =============================================================================
# OPENAPI & SIEM EXPORTER INTEGRATION
# =============================================================================
try:
    from openapi_spec import get_openapi_spec, get_swagger_ui_html
    OPENAPI_AVAILABLE = True
except ImportError:
    try:
        import importlib
        _oas = importlib.import_module("scripts.5_dashboard.openapi_spec")
        get_openapi_spec = _oas.get_openapi_spec
        get_swagger_ui_html = _oas.get_swagger_ui_html
        OPENAPI_AVAILABLE = True
    except Exception:
        OPENAPI_AVAILABLE = False
        get_openapi_spec = lambda: {}
        get_swagger_ui_html = lambda *a, **k: "<h1>OpenAPI Docs Not Available</h1>"

try:
    from siem_exporter import format_cef_event, generate_stix_bundle, send_syslog
    SIEM_AVAILABLE = True
except ImportError:
    try:
        import importlib
        _siem = importlib.import_module("scripts.4_response.siem_exporter")
        format_cef_event = _siem.format_cef_event
        generate_stix_bundle = _siem.generate_stix_bundle
        send_syslog = _siem.send_syslog
        SIEM_AVAILABLE = True
    except Exception:
        SIEM_AVAILABLE = False
        format_cef_event = lambda e: ""
        generate_stix_bundle = lambda *a, **k: {"type": "bundle", "objects": []}
        send_syslog = lambda *a, **k: (False, "SIEM exporter not available")

# =============================================================================
# FLEET CONTROL PLANE & DISTRIBUTED EDGE SENSORS (Phase 10)
# =============================================================================
try:
    from edge_agent import (
        get_fleet_control_plane,
        FleetControlPlane,
        verify_hmac_request,
        compute_hmac_signature,
    )
    FLEET_AVAILABLE = True
except ImportError:
    try:
        import importlib
        _ea = importlib.import_module("scripts.9_utilities.edge_agent")
        get_fleet_control_plane = _ea.get_fleet_control_plane
        FleetControlPlane = _ea.FleetControlPlane
        verify_hmac_request = _ea.verify_hmac_request
        compute_hmac_signature = _ea.compute_hmac_signature
        FLEET_AVAILABLE = True
    except Exception:
        FLEET_AVAILABLE = False
        get_fleet_control_plane = None
        FleetControlPlane = None
        verify_hmac_request = None
        compute_hmac_signature = None

# =============================================================================
# SOC EXECUTIVE SLA TELEMETRY & COMPLIANCE (Phase 11)
# =============================================================================
try:
    from soc_metrics import get_soc_metrics_tracker, generate_executive_report
    SOC_METRICS_AVAILABLE = True
except ImportError:
    try:
        import importlib
        _soc = importlib.import_module("scripts.5_dashboard.soc_metrics")
        get_soc_metrics_tracker = _soc.get_soc_metrics_tracker
        generate_executive_report = _soc.generate_executive_report
        SOC_METRICS_AVAILABLE = True
    except Exception:
        SOC_METRICS_AVAILABLE = False
        get_soc_metrics_tracker = None
        generate_executive_report = None

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


def _iter_alerts(limit=None):
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
    
    if limit is not None and isinstance(limit, int) and limit > 0:
        lines = lines[-limit:]

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

    try:
        dt = get_driver_telemetry()
        blocks = get_active_blocks()
        update_firewall_telemetry(
            driver=dt.get("active_driver", "auto"),
            blocked_ips_count=len(blocks),
            os_name=dt.get("os", "linux"),
            xdp_drops=dt.get("total_xdp_drops", 0),
            interface=dt.get("xdp_interface", "eth0"),
        )
    except Exception:
        pass

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
        if AUDIT_AVAILABLE and record_audit_event is not None:
            record_audit_event(
                actor=username,
                action="USER_LOGIN",
                role=ROLE_ADMIN,
                payload={"ip": request.remote_addr},
            )
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


# ============================================================================
# FEDERATED LEARNING & DRIFT MONITORING (Phase 6)
# ============================================================================

@app.get("/api/v1/federated/status")
@app.get("/api/federated/status")
def api_federated_status():
    """Return status of edge federated learning fleet and online feature drift."""
    if not FEDERATED_AVAILABLE or get_federated_coordinator is None:
        return jsonify({"ok": False, "error": "Federated learning subsystem not available"}), 503
    coord = get_federated_coordinator()
    return jsonify(coord.get_fleet_status())


@app.post("/api/v1/federated/round")
@app.post("/api/federated/round")
@require_role([ROLE_ADMIN, ROLE_SOC_ANALYST])
def api_federated_round():
    """Trigger a federated aggregation round and drift check."""
    if not FEDERATED_AVAILABLE or get_federated_coordinator is None:
        return jsonify({"ok": False, "error": "Federated learning subsystem not available"}), 503

    data = request.get_json(silent=True) or {}
    epochs = int(data.get("epochs", 3))
    lr = float(data.get("lr", 0.02))
    reason = str(data.get("reason", "operator_trigger"))

    coord = get_federated_coordinator()
    result = coord.execute_round(epochs=epochs, lr=lr, trigger_reason=reason)

    if AUDIT_AVAILABLE and record_audit_event is not None:
        record_audit_event(
            actor=getattr(g, "current_user", "operator"),
            action="FEDERATED_ROUND_TRIGGERED",
            role=getattr(g, "current_role", ROLE_SOC_ANALYST),
            payload={"round": result.get("round"), "reason": reason}
        )

    if SOCKETIO_AVAILABLE:
        try:
            socketio.emit("federated_update", result)
        except Exception:
            pass

    return jsonify({
        "ok": True,
        "message": f"Federated aggregation round {result['round']} completed",
        "round_report": result,
    })


# ============================================================================
# FLEET CONTROL PLANE & DISTRIBUTED EDGE SENSORS (Phase 10)
# ============================================================================

@app.post("/api/v1/fleet/register")
@app.post("/api/fleet/register")
def api_fleet_register():
    """Register an edge sensor gateway with the central SOC control plane."""
    if not FLEET_AVAILABLE or get_fleet_control_plane is None:
        return jsonify({"ok": False, "error": "Fleet control plane not available"}), 503

    data = request.get_json(silent=True) or {}
    node_id = data.get("node_id")
    if not node_id:
        return jsonify({"ok": False, "error": "Missing required field: node_id"}), 400

    site_type = data.get("site_type", "smart_home")
    hostname = data.get("hostname", "")
    ip = data.get("ip", request.remote_addr or "127.0.0.1")
    capabilities = data.get("capabilities", [])
    model_hash = data.get("model_hash", "")
    secret = data.get("secret")

    cp = get_fleet_control_plane()
    res = cp.register_node(
        node_id=node_id,
        site_type=site_type,
        hostname=hostname,
        ip=ip,
        capabilities=capabilities,
        model_hash=model_hash,
        secret=secret,
    )
    return jsonify(res), 201


@app.post("/api/v1/fleet/heartbeat")
@app.post("/api/fleet/heartbeat")
def api_fleet_heartbeat():
    """
    Ingest periodic health & telemetry heartbeat from an edge sensor gateway.
    Enforces HMAC-SHA256 request signing and 60-second replay protection.
    """
    if not FLEET_AVAILABLE or get_fleet_control_plane is None:
        return jsonify({"ok": False, "error": "Fleet control plane not available"}), 503

    node_id = request.headers.get("X-IoTGuard-Node-Id")
    signature = request.headers.get("X-IoTGuard-Signature")
    timestamp = request.headers.get("X-IoTGuard-Timestamp")

    if not node_id or not signature or not timestamp:
        return jsonify({
            "ok": False,
            "error": "Missing HMAC authentication headers (X-IoTGuard-Node-Id, X-IoTGuard-Signature, X-IoTGuard-Timestamp)"
        }), 401

    cp = get_fleet_control_plane()
    secret = cp.get_node_secret(node_id)
    if not secret:
        return jsonify({
            "ok": False,
            "error": f"Node '{node_id}' is not registered with fleet control plane"
        }), 404

    # Verify HMAC signature & replay clock skew (60s max window)
    raw_body = request.get_data(as_text=True)
    is_valid, reason = verify_hmac_request(
        secret=secret,
        signature=signature,
        timestamp_val=timestamp,
        body=raw_body,
        max_skew_sec=60.0
    )
    if not is_valid:
        return jsonify({"ok": False, "error": reason}), 401

    # Ingest telemetry payload
    data = request.get_json(silent=True) or {}
    try:
        ack = cp.record_heartbeat(node_id, data)
        return jsonify(ack), 200
    except KeyError as e:
        return jsonify({"ok": False, "error": str(e)}), 404
    except Exception as e:
        logger.error(f"Error recording heartbeat for {node_id}: {e}")
        return jsonify({"ok": False, "error": f"Internal error: {e}"}), 500


def _seed_default_fleet_if_empty(cp):
    """Seed the 4 standard enterprise edge gateways if the fleet registry is empty."""
    with cp._lock:
        if not cp.nodes:
            default_nodes = [
                {
                    "node_id": "gw-smarthome-01",
                    "site_type": "smart_home",
                    "hostname": "edge-smarthome.iotguard.internal",
                    "ip": "192.168.1.1",
                    "outdated": False,
                    "cpu": 18.4,
                    "ram": 34.2,
                    "latency": 2.1,
                    "drops": 420
                },
                {
                    "node_id": "gw-factory-02",
                    "site_type": "factory_floor",
                    "hostname": "edge-factory.corp.internal",
                    "ip": "10.0.40.1",
                    "outdated": False,
                    "cpu": 42.6,
                    "ram": 58.1,
                    "latency": 4.8,
                    "drops": 1850
                },
                {
                    "node_id": "gw-substation-03",
                    "site_type": "substation_edge",
                    "hostname": "edge-substation.scada.internal",
                    "ip": "10.0.50.1",
                    "outdated": True,
                    "cpu": 24.1,
                    "ram": 38.9,
                    "latency": 8.3,
                    "drops": 930
                },
                {
                    "node_id": "gw-hospital-04",
                    "site_type": "hospital_iot_vlan",
                    "hostname": "edge-hospital.health.internal",
                    "ip": "172.16.20.1",
                    "outdated": False,
                    "cpu": 29.5,
                    "ram": 46.7,
                    "latency": 3.0,
                    "drops": 610
                },
            ]
            c_hash = cp.get_central_model_hash()
            now = time.time()
            for g_node in default_nodes:
                m_hash = c_hash if not g_node["outdated"] else "a1b2c3d4e5f60000"
                cp.register_node(
                    node_id=g_node["node_id"],
                    site_type=g_node["site_type"],
                    hostname=g_node["hostname"],
                    ip=g_node["ip"],
                    model_hash=m_hash,
                )
                cp.record_heartbeat(g_node["node_id"], {
                    "cpu_pct": g_node["cpu"],
                    "ram_pct": g_node["ram"],
                    "latency_ms": g_node["latency"],
                    "active_xdp_drops": g_node["drops"],
                    "active_blocks_count": 0,
                    "local_model_hash": m_hash,
                    "timestamp": now,
                })


@app.get("/api/v1/fleet/nodes")
@app.get("/api/fleet/nodes")
def api_fleet_nodes():
    """Return live health, latency, model sync status, and XDP drop stats for all edge gateways."""
    if not FLEET_AVAILABLE or get_fleet_control_plane is None:
        return jsonify({"ok": False, "error": "Fleet control plane not available"}), 503

    cp = get_fleet_control_plane()
    if not os.environ.get("PYTEST_CURRENT_TEST"):
        _seed_default_fleet_if_empty(cp)
    nodes = cp.get_fleet_nodes()
    online_count = sum(1 for n in nodes if n.get("status") == "online")
    total_xdp_drops = sum(n.get("active_xdp_drops", 0) for n in nodes)

    return jsonify({
        "ok": True,
        "nodes": nodes,
        "total_nodes": len(nodes),
        "online_nodes": online_count,
        "total_fleet_xdp_drops": total_xdp_drops,
        "central_model_hash": cp.get_central_model_hash(),
        "timestamp": time.time(),
    })


@app.post("/api/v1/fleet/broadcast_block")
@app.post("/api/fleet/broadcast_block")
@require_role([ROLE_ADMIN, ROLE_SOC_ANALYST])
def api_fleet_broadcast_block():
    """Broadcast an attacker IP to all remote edge sensors for herd immunity quarantine."""
    if not FLEET_AVAILABLE or get_fleet_control_plane is None:
        return jsonify({"ok": False, "error": "Fleet control plane not available"}), 503

    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"ok": False, "error": "No IP provided"}), 400

    severity = data.get("severity", "KILL")
    reason = data.get("reason", "Central SOC Fleet Quarantine")
    dry_run = data.get("dry_run", load_cfg().get("decision", {}).get("dry_run", True))

    ok, msg = block_ip(ip, severity=severity, reason=reason, dry_run=dry_run)

    cp = get_fleet_control_plane()
    block_entry = cp.broadcast_global_block(
        ip=ip,
        reason=reason,
        severity=severity,
        source=f"soc:{getattr(g, 'current_user', 'operator')}"
    )

    if SOCKETIO_AVAILABLE:
        try:
            socketio.emit("topology_update", {"action": "fleet_block", "ip": ip, "severity": severity})
        except Exception:
            pass

    return jsonify({
        "ok": True,
        "ip": ip,
        "severity": severity,
        "message": f"Global herd immunity block broadcasted to fleet: {msg}",
        "block_entry": block_entry,
        "dry_run": dry_run,
    })


@app.get("/api/v1/fleet/blocks")
@app.get("/api/fleet/blocks")
def api_fleet_blocks():
    """Return active fleet-wide broadcast quarantine blocks."""
    if not FLEET_AVAILABLE or get_fleet_control_plane is None:
        return jsonify({"ok": False, "error": "Fleet control plane not available"}), 503

    cp = get_fleet_control_plane()
    blocks = cp.get_global_blocks()
    return jsonify({
        "ok": True,
        "global_blocks": blocks,
        "count": len(blocks),
    })


@app.post("/api/v1/fleet/simulate")
@app.post("/api/fleet/simulate")
def api_fleet_simulate():
    """
    Simulate or generate a fresh telemetry heartbeat from an edge gateway.
    Auto-seeds the 4 enterprise branch gateways (smart_home, factory_floor, substation_edge, hospital_iot_vlan)
    if the fleet is currently empty.
    """
    if not FLEET_AVAILABLE or get_fleet_control_plane is None:
        return jsonify({"ok": False, "error": "Fleet control plane not available"}), 503

    cp = get_fleet_control_plane()
    _seed_default_fleet_if_empty(cp)

    data = request.get_json(silent=True) or {}
    node_id = data.get("node_id")

    with cp._lock:
        if not node_id or node_id not in cp.nodes:
            if cp.nodes:
                node_id = random.choice(list(cp.nodes.keys()))
            else:
                node_id = "gw-smarthome-01"

        node = cp.nodes[node_id]
        cpu = round(random.uniform(14.0, 78.5), 1)
        ram = round(random.uniform(25.0, 68.0), 1)
        latency = round(random.uniform(1.2, 14.5), 1)
        drops = int(node.get("active_xdp_drops", 0)) + random.randint(15, 120)

        telemetry = {
            "cpu_pct": cpu,
            "ram_pct": ram,
            "latency_ms": latency,
            "active_xdp_drops": drops,
            "active_blocks_count": len(cp.global_blocks),
            "local_model_hash": node.get("local_model_hash"),
            "timestamp": time.time(),
        }
        ack = cp.record_heartbeat(node_id, telemetry)

    return jsonify({
        "ok": True,
        "node_id": node_id,
        "telemetry": telemetry,
        "ack": ack,
    })


# ============================================================================
# SOC EXECUTIVE SLA & COMPLIANCE REPORTING (Phase 11)
# ============================================================================

@app.get("/api/v1/soc/kpis")
@app.get("/api/soc/kpis")
def api_soc_kpis():
    """Return live Enterprise SecOps KPIs (MTTD, MTTR, MITRE matrix, Fleet Immunity)."""
    if not SOC_METRICS_AVAILABLE or get_soc_metrics_tracker is None:
        return jsonify({"ok": False, "error": "SOC metrics engine not available"}), 503

    tracker = get_soc_metrics_tracker()
    return jsonify(tracker.get_soc_kpis())


@app.get("/api/v1/reports/executive")
@app.get("/api/reports/executive")
def api_reports_executive():
    """
    Generate an Executive Security Posture & Compliance Report.
    Formats supported: 'json', 'html', 'markdown'.
    """
    if not SOC_METRICS_AVAILABLE or generate_executive_report is None:
        return jsonify({"ok": False, "error": "Executive report generator not available"}), 503

    fmt = request.args.get("format", "json").lower()
    report = generate_executive_report(format=fmt)

    if fmt == "html":
        return Response(report, mimetype="text/html")
    elif fmt in ("markdown", "md"):
        return Response(
            report,
            mimetype="text/markdown",
            headers={"Content-Disposition": "inline; filename=soc_executive_report.md"}
        )
    else:
        if isinstance(report, dict):
            res_dict = dict(report)
            res_dict["ok"] = True
            res_dict["report"] = report
            return jsonify(res_dict)
        return jsonify({"ok": True, "report": report})


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
    """Counts in the last X minutes (default 60) with taxonomy breakdown."""
    mins = float(request.args.get("window_minutes", 60))
    cutoff = now_ts() - (mins * 60)
    total = attacks = blocks = 0
    class_counts = {}
    category_counts = {}
    block_breakdown = {}
    for evt in _iter_alerts() or []:
        if evt.get("ts", 0) >= cutoff:
            total += 1
            is_atk = evt.get("state") == "ATTACK"
            if is_atk:
                attacks += 1
            # Treat any BLOCK-* severity as a block event
            action = str(evt.get("action") or "")
            if action.startswith("BLOCK"):
                blocks += 1
                block_breakdown[action] = block_breakdown.get(action, 0) + 1
            c = evt.get("pred_class")
            if c is not None:
                class_counts[c] = class_counts.get(c, 0) + 1
            
            # Taxonomy breakdown
            cat = evt.get("attack_category")
            if not cat and is_atk:
                cat = normalize_taxonomy(c, evt.get("detection_source"))
            if cat and is_atk:
                category_counts[cat] = category_counts.get(cat, 0) + 1

    return jsonify({
        "ok": True,
        "window_minutes": mins,
        "total": total,
        "attacks": attacks,
        "blocks": blocks,
        "class_counts": class_counts,
        "category_counts": category_counts,
        "block_breakdown": block_breakdown,
    })

@app.get("/api/events")
def api_events():
    """Return events with sub-millisecond indexed queries (via storage_engine) or file tailing fallback, enriched with playbooks."""
    src_ip = request.args.get("ip") or request.args.get("src_ip")
    category = request.args.get("category") or request.args.get("attack_category")
    min_score = request.args.get("min_score", type=float)
    max_score = request.args.get("max_score", type=float)
    response_tier = request.args.get("tier") or request.args.get("response_tier")
    start_ts = request.args.get("start_ts", type=float) or request.args.get("since_ts", type=float)
    end_ts = request.args.get("end_ts", type=float)
    limit = request.args.get("limit", default=200, type=int)

    has_filters = any([src_ip, category, min_score is not None, max_score is not None, response_tier, end_ts is not None])

    raw = None
    # 1. High-Performance Relational Query if storage engine is active
    if STORAGE_AVAILABLE and get_storage_engine is not None:
        try:
            engine = get_storage_engine()
            if engine is not None:
                db_results = engine.query_events(
                    src_ip=src_ip,
                    category=category,
                    min_score=min_score,
                    max_score=max_score,
                    response_tier=response_tier,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    limit=limit,
                )
                if db_results:
                    raw = db_results
        except Exception:
            pass

    # 2. File / memory fallback for backwards compatibility
    if raw is None:
        if start_ts is None:
            all_raw = read_last_n(max(limit, 200))
        else:
            all_raw = [e for e in (_iter_alerts() or []) if e.get("ts", 0) > start_ts]

        if has_filters:
            filtered = []
            for e in all_raw:
                if src_ip and e.get("src_ip") != src_ip:
                    continue
                if category and e.get("attack_category") != category and e.get("pred_class") != category:
                    continue
                if min_score is not None and e.get("score", 0.0) < min_score:
                    continue
                if max_score is not None and e.get("score", 0.0) > max_score:
                    continue
                if response_tier and e.get("response_tier") != response_tier and e.get("state") != response_tier and e.get("action") != response_tier:
                    continue
                if end_ts is not None and e.get("ts", 0) > end_ts:
                    continue
                filtered.append(e)
                if len(filtered) >= limit:
                    break
            raw = filtered
        else:
            raw = all_raw[:limit]

    data = []
    for e in raw:
        evt = dict(e)
        if evt.get("state") == "ATTACK":
            if not evt.get("attack_category"):
                evt["attack_category"] = normalize_taxonomy(evt.get("pred_class"), evt.get("detection_source"))
            if not evt.get("remediation_playbook") and evt.get("attack_category"):
                evt["remediation_playbook"] = get_remediation_playbook(evt["attack_category"], src_ip=evt.get("src_ip"))
        data.append(evt)

    return jsonify({"ok": True, "events": data, "count": len(data), "server_time": now_ts()})

@app.get("/api/playbooks")
def api_playbooks():
    """Return all available remediation playbooks and canonical taxonomies."""
    return jsonify({
        "ok": True,
        "taxonomies": TAXONOMIES,
        "playbooks": REMEDIATION_PLAYBOOKS,
    })

@app.get("/api/playbook/<category>")
def api_playbook_detail(category: str):
    """Return the structured remediation playbook for a specific attack category."""
    canon = normalize_taxonomy(category)
    src_ip = request.args.get("src_ip")
    pb = get_remediation_playbook(canon, src_ip=src_ip)
    return jsonify({"ok": True, "category": canon, "playbook": pb})

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
                "benign_index": data.get("benign_index"),
            })
    except Exception:
        pass

    try:
        mc_path = Path("models/multiclass_classes.json")
        if mc_path.exists():
            mc_data = json.loads(mc_path.read_text(encoding="utf-8"))
            meta["multiclass_classes"] = mc_data.get("classes", [])
    except Exception:
        pass
    meta["taxonomies"] = TAXONOMIES
    return jsonify({"ok": True, "model": meta, "server_time": now_ts()})

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


@app.get("/api/config")
def api_get_config():
    """
    Retrieve current system configuration.
    Returns the complete configuration dictionary including decision parameters,
    features, and operational thresholds.
    """
    return jsonify(load_cfg())


@app.post("/api/config")
@require_role([ROLE_ADMIN])
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

    if AUDIT_AVAILABLE and record_audit_event is not None:
        record_audit_event(
            actor=getattr(g, "current_user", "operator"),
            action="POLICY_UPDATE",
            role=getattr(g, "current_role", ROLE_ADMIN),
            payload=new_dec,
        )

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
    Return comprehensive, live network topology combining:
      - Device fingerprint classifications (data/device_fingerprints.json)
      - Window metadata & active IPs (data/window_meta.json)
      - Active firewall blocks from blocker.py (data/active_blocks.json)
      - Real-time traffic state (Benign, Grace/Warning, Blocked)
      - Threat intelligence enrichment (GeoIP, Flag, ISP, Abuse score)
    """
    # 1. Load Device Fingerprints (IoT vs. IT)
    fingerprints = {}
    fp_path = Path("data/device_fingerprints.json")
    if fp_path.exists():
        try:
            fp_data = json.loads(fp_path.read_text(encoding="utf-8")) or {}
            fingerprints = fp_data.get("cache", {})
        except Exception:
            pass

    # 2. Load Window Meta Context
    win_meta = {}
    wm_path = Path("data/window_meta.json")
    if wm_path.exists():
        try:
            win_meta = json.loads(wm_path.read_text(encoding="utf-8")) or {}
        except Exception:
            pass

    # 3. Load Active Blocks
    active_blocks = get_active_blocks()
    blocked_ips = {b["ip"]: b for b in active_blocks}

    # 4. Read recent alerts for traffic states and active source IPs
    recent_alerts = read_last_n(40)
    recent_ips = {}
    for alert in recent_alerts:
        ip = alert.get("src_ip")
        if ip and ip not in ("none", "unknown"):
            if ip not in recent_ips:
                recent_ips[ip] = {
                    "last_state": alert.get("state", "BENIGN"),
                    "last_action": alert.get("action", "NONE"),
                    "last_score": alert.get("score", 0.0),
                    "attack_category": alert.get("attack_category"),
                    "hits": alert.get("hits_in_window", 0),
                    "pred_class": alert.get("pred_class"),
                    "count": 1,
                }
            else:
                recent_ips[ip]["count"] += 1

    # Base Core Infrastructure Nodes (fixed positions)
    devices = [
        {"id": "gw", "label": "Edge IoT Gateway", "type": "router", "ip": "192.168.1.1", "state": "BENIGN", "x": 0.5, "y": 0.12},
        {"id": "fw", "label": "IoTGuard Firewall", "type": "firewall", "ip": "192.168.1.2", "state": "BENIGN", "x": 0.5, "y": 0.28},
        {"id": "hub", "label": "IoT Smart Hub", "type": "iot", "ip": "192.168.1.10", "state": "BENIGN", "x": 0.3, "y": 0.48},
        {"id": "srv", "label": "Corporate IT Server", "type": "it", "ip": "192.168.1.20", "state": "BENIGN", "x": 0.7, "y": 0.48},
    ]

    # Pre-defined known inventory / seed devices
    seed_devices = [
        {"id": "cam1", "ip": "192.168.1.50", "label": "Smart Camera 1", "type": "iot", "parent": "hub", "x": 0.12, "y": 0.68},
        {"id": "cam2", "ip": "192.168.1.51", "label": "Smart Camera 2", "type": "iot", "parent": "hub", "x": 0.24, "y": 0.78},
        {"id": "sensor1", "ip": "192.168.1.52", "label": "Env Sensor", "type": "iot", "parent": "hub", "x": 0.10, "y": 0.90},
        {"id": "thermo", "ip": "192.168.1.53", "label": "Thermostat", "type": "iot", "parent": "hub", "x": 0.32, "y": 0.88},
        {"id": "lock", "ip": "192.168.1.54", "label": "Smart Lock", "type": "iot", "parent": "hub", "x": 0.40, "y": 0.72},
        {"id": "ws1", "ip": "192.168.1.100", "label": "Admin PC", "type": "it", "parent": "srv", "x": 0.62, "y": 0.72},
        {"id": "ws2", "ip": "192.168.1.101", "label": "Office Laptop", "type": "it", "parent": "srv", "x": 0.76, "y": 0.88},
        {"id": "nas", "ip": "192.168.1.102", "label": "Backup NAS", "type": "it", "parent": "srv", "x": 0.90, "y": 0.68},
    ]

    # Also discover any dynamic IPs from recent alerts or window_meta
    known_ips = {d["ip"]: d for d in seed_devices}
    for dev in devices:
        known_ips[dev["ip"]] = dev

    all_dynamic_ips = set(recent_ips.keys()) | set(blocked_ips.keys()) | set(fingerprints.keys())
    if win_meta.get("top_src_ip"):
        all_dynamic_ips.add(win_meta.get("top_src_ip"))

    # Add dynamic nodes that aren't in seed devices
    extra_devices = []
    slot = 0
    for dyn_ip in all_dynamic_ips:
        if dyn_ip not in known_ips and dyn_ip not in ("0.0.0.0", "127.0.0.1", "none", "unknown"):
            dev_type = fingerprints.get(dyn_ip, "iot")
            angle = (slot * 0.7) % 6.28
            slot += 1
            is_it = (dev_type == "it")
            base_x = 0.75 if is_it else 0.25
            base_y = 0.75
            x = max(0.08, min(0.92, base_x + 0.15 * math.cos(angle)))
            y = max(0.55, min(0.95, base_y + 0.15 * math.sin(angle)))

            clean_id = f"node_{dyn_ip.replace('.', '_')}"
            extra_devices.append({
                "id": clean_id,
                "ip": dyn_ip,
                "label": f"{'IT' if is_it else 'IoT'} Node ({dyn_ip})",
                "type": dev_type,
                "parent": "srv" if is_it else "hub",
                "x": round(x, 2),
                "y": round(y, 2),
            })

    all_devices = devices + seed_devices + extra_devices

    # Compute State & Threat Intel for every device
    nodes = []
    connections = [
        {"from": "gw", "to": "fw", "active": True},
        {"from": "fw", "to": "hub", "active": True},
        {"from": "fw", "to": "srv", "active": True},
    ]

    attack_active = False

    for d in all_devices:
        ip = d.get("ip")
        # Determine status
        is_blocked = (ip in blocked_ips) or (recent_ips.get(ip, {}).get("last_action", "").startswith("BLOCK"))
        is_grace = (not is_blocked) and (
            recent_ips.get(ip, {}).get("last_state") == "ATTACK" or 
            recent_ips.get(ip, {}).get("hits", 0) > 0
        )

        if is_blocked:
            state = "BLOCKED"  # Red Pulsing
            attack_active = True
        elif is_grace:
            state = "GRACE"    # Amber
            attack_active = True
        else:
            state = "BENIGN"   # Green

        d["state"] = state
        d["blocked"] = is_blocked

        # Enrich with ThreatIntel
        if THREAT_INTEL and ip:
            ti = THREAT_INTEL.enrich_ip(ip)
            d["country"] = ti.get("country", "Unknown")
            d["country_name"] = ti.get("country_name", "Unknown")
            d["flag"] = ti.get("flag", "🏳️")
            d["threat"] = ti.get("threat")
            d["isp"] = ti.get("isp")
            d["asn"] = ti.get("asn")
            d["abuse_score"] = ti.get("abuse_confidence_score", 0)
        else:
            d["country"] = "LAN"
            d["country_name"] = "Private Network"
            d["flag"] = "🏠"
            d["threat"] = None
            d["isp"] = None
            d["asn"] = None
            d["abuse_score"] = 0

        if ip in recent_ips:
            d["last_score"] = recent_ips[ip].get("last_score", 0.0)
            d["attack_category"] = recent_ips[ip].get("attack_category")
            d["hits"] = recent_ips[ip].get("hits", 0)

        nodes.append(d)

        parent = d.get("parent")
        if parent:
            conn_attack = (state in ("BLOCKED", "GRACE"))
            connections.append({
                "from": parent,
                "to": d["id"],
                "active": True,
                "attack": conn_attack,
                "state": state.lower(),
            })

    # If attack is active, mark gateway -> firewall as attacked
    if attack_active:
        connections[0]["attack"] = True
        connections[0]["state"] = "attack"

    # Build summary
    driver_telemetry = get_driver_telemetry()
    summary = {
        "total_nodes": len(nodes),
        "total_devices": len(nodes),
        "iot_count": sum(1 for n in nodes if n["type"] == "iot"),
        "iot_nodes": sum(1 for n in nodes if n["type"] == "iot"),
        "it_count": sum(1 for n in nodes if n["type"] == "it"),
        "it_nodes": sum(1 for n in nodes if n["type"] == "it"),
        "blocked_count": sum(1 for n in nodes if n["state"] == "BLOCKED"),
        "blocked_nodes": sum(1 for n in nodes if n["state"] == "BLOCKED"),
        "grace_count": sum(1 for n in nodes if n["state"] == "GRACE"),
        "grace_nodes": sum(1 for n in nodes if n["state"] == "GRACE"),
        "benign_count": sum(1 for n in nodes if n["state"] == "BENIGN"),
        "attack_active": attack_active,
        "firewall_driver": driver_telemetry.get("active_driver", "auto"),
        "xdp_drops": driver_telemetry.get("total_xdp_drops", 0),
    }

    return jsonify({
        "ok": True,
        "nodes": nodes,
        "edges": connections,
        "devices": nodes,
        "connections": connections,
        "summary": summary,
        "attack_active": attack_active,
    })


@app.post("/api/block")
@app.post("/api/v1/block")
@require_role([ROLE_ADMIN, ROLE_SOC_ANALYST])
def api_block_ip():
    """Manual quarantine endpoint for dashboard operators."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"ok": False, "error": "No IP provided"}), 400

    severity = data.get("severity", "hard")
    reason = data.get("reason", "Manual Operator Quarantine")
    dry_run = data.get("dry_run", load_cfg().get("decision", {}).get("dry_run", True))

    ok, msg = block_ip(ip, severity=severity, reason=reason, dry_run=dry_run)
    if ok:
        if AUDIT_AVAILABLE and record_audit_event is not None:
            record_audit_event(
                actor=getattr(g, "current_user", "operator"),
                action="MANUAL_BLOCK",
                role=getattr(g, "current_role", ROLE_SOC_ANALYST),
                payload={"ip": ip, "severity": severity, "reason": reason, "dry_run": dry_run}
            )

        if SOCKETIO_AVAILABLE:
            try:
                socketio.emit("topology_update", {"action": "block", "ip": ip, "severity": severity})
            except Exception:
                pass

        # Phase 10: Fleet-Wide Global Block Broadcast ("Herd Immunity")
        is_global = bool(data.get("is_global", False)) or str(severity).lower() in ("kill", "global")
        if is_global and FLEET_AVAILABLE and get_fleet_control_plane is not None:
            try:
                cp = get_fleet_control_plane()
                cp.broadcast_global_block(
                    ip=ip,
                    reason=reason,
                    severity=severity,
                    source=f"soc:{getattr(g, 'current_user', 'operator')}"
                )
            except Exception as e:
                logger.warning(f"Could not broadcast fleet block: {e}")

        return jsonify({
            "ok": True,
            "ip": ip,
            "severity": severity,
            "message": msg,
            "dry_run": dry_run,
            "fleet_broadcast": is_global,
        })
    return jsonify({"ok": False, "error": msg}), 400


@app.post("/api/unblock")
@app.post("/api/v1/unblock")
@require_role([ROLE_ADMIN, ROLE_SOC_ANALYST])
def api_unblock_ip():
    """Manual unblock / restore endpoint for dashboard operators."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"ok": False, "error": "No IP provided"}), 400

    dry_run = data.get("dry_run", load_cfg().get("decision", {}).get("dry_run", True))
    ok, msg = unblock_ip(ip, dry_run=dry_run)
    if ok:
        if AUDIT_AVAILABLE and record_audit_event is not None:
            record_audit_event(
                actor=getattr(g, "current_user", "operator"),
                action="MANUAL_UNBLOCK",
                role=getattr(g, "current_role", ROLE_SOC_ANALYST),
                payload={"ip": ip, "dry_run": dry_run}
            )

        if SOCKETIO_AVAILABLE:
            try:
                socketio.emit("topology_update", {"action": "unblock", "ip": ip})
            except Exception:
                pass
        return jsonify({
            "ok": True,
            "ip": ip,
            "message": msg,
            "dry_run": dry_run,
        })
    return jsonify({"ok": False, "error": msg}), 400


@app.get("/api/blocks")
@app.get("/api/v1/blocks")
def api_get_blocks():
    """Return currently active blocked IPs along with active firewall driver telemetry."""
    driver_telemetry = get_driver_telemetry()
    return jsonify({
        "ok": True,
        "driver": driver_telemetry.get("active_driver", "auto"),
        "blocks": get_active_blocks(),
        "driver_telemetry": driver_telemetry,
        "xdp_total_drops": driver_telemetry.get("total_xdp_drops", 0),
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
@require_role([ROLE_ADMIN])
def api_clear():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ALERT_LOG.write_text("", encoding="utf-8")
    if AUDIT_AVAILABLE and record_audit_event is not None:
        record_audit_event(
            actor=getattr(g, "current_user", "operator"),
            action="LOG_CLEAR",
            role=getattr(g, "current_role", ROLE_ADMIN),
            payload={"scope": "alerts"}
        )
    return jsonify({"ok": True})

@app.post("/api/clear_all")
@require_role([ROLE_ADMIN])
def api_clear_all():
    # clear alerts
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ALERT_LOG.write_text("", encoding="utf-8")

    # reset offset state so the decision loop won’t re-score old rows
    (DATA_DIR / "state.json").write_text('{"offset_rows":0,"csv_mtime":0}', encoding="utf-8")

    if AUDIT_AVAILABLE and record_audit_event is not None:
        record_audit_event(
            actor=getattr(g, "current_user", "operator"),
            action="LOG_CLEAR",
            role=getattr(g, "current_role", ROLE_ADMIN),
            payload={"scope": "all"}
        )

    return jsonify({"ok": True})


# ── Enterprise Audit Ledger & RBAC API Endpoints ─────────────────────────────

@app.get("/api/v1/audit")
@app.get("/api/audit")
@require_role([ROLE_ADMIN, ROLE_AUDITOR, ROLE_SOC_ANALYST])
def api_get_audit():
    """Retrieve entries from the immutable cryptographic audit ledger."""
    limit = request.args.get("limit", default=100, type=int)
    offset = request.args.get("offset", default=0, type=int)
    trail = []
    if AUDIT_AVAILABLE and get_audit_ledger is not None:
        ledger = get_audit_ledger()
        if ledger is not None:
            trail = ledger.get_trail(limit=limit, offset=offset)
    return jsonify({
        "ok": True,
        "count": len(trail),
        "ledger": trail,
        "entries": trail,
        "limit": limit,
        "offset": offset,
        "server_time": now_ts(),
    })


@app.get("/api/v1/audit/verify")
@app.get("/api/audit/verify")
@require_role([ROLE_ADMIN, ROLE_AUDITOR])
def api_verify_audit():
    """Cryptographically verify the entire audit ledger hash chain."""
    if not AUDIT_AVAILABLE or verify_audit_ledger is None:
        return jsonify({"ok": False, "error": "Audit ledger subsystem not available"}), 503

    ok, status, tampered_idx = verify_audit_ledger()
    return jsonify({
        "ok": ok,
        "status": status,
        "tampered_block_index": tampered_idx,
        "verified_at": now_ts(),
    }), (200 if ok else 409)


@app.post("/api/v1/keys")
@require_role([ROLE_ADMIN])
def api_create_api_key():
    """Create a scoped enterprise API key."""
    if not AUTH_AVAILABLE:
        return jsonify({"ok": False, "error": "Auth subsystem not available"}), 503

    data = request.get_json(silent=True) or {}
    name = data.get("name", "sensor_key")
    role = data.get("role", ROLE_SOC_ANALYST)
    new_key = register_api_key(name=name, role=role)

    if AUDIT_AVAILABLE and record_audit_event is not None:
        record_audit_event(
            actor=getattr(g, "current_user", "admin"),
            action="API_KEY_CREATED",
            role=getattr(g, "current_role", ROLE_ADMIN),
            payload={"name": name, "role": role}
        )

    return jsonify({
        "ok": True,
        "api_key": new_key,
        "name": name,
        "role": role,
    })


@app.get("/api/v1/keys")
@require_role([ROLE_ADMIN])
def api_list_keys():
    """List active enterprise API keys."""
    if not AUTH_AVAILABLE:
        return jsonify({"ok": False, "error": "Auth subsystem not available"}), 503
    return jsonify({"ok": True, "keys": list_api_keys()})


# ── OpenAPI 3.1 & Interactive Swagger UI Endpoints ───────────────────────────

@app.get("/api/openapi.json")
@app.get("/openapi.json")
def api_openapi_json():
    """Return complete OpenAPI 3.1.0 JSON specification."""
    return jsonify(get_openapi_spec())


@app.get("/api/docs")
@app.get("/docs")
def api_docs_ui():
    """Serve interactive Swagger UI documentation for IoTGuard Enterprise APIs."""
    html = get_swagger_ui_html(openapi_url="/api/openapi.json", title="IoTGuard Enterprise API Documentation")
    return Response(html, mimetype="text/html")


# ── SIEM & Threat Intelligence Export Endpoints ──────────────────────────────

@app.get("/api/v1/export/stix")
@app.get("/api/export/stix")
def api_export_stix():
    """
    Export active threat indicators as an OASIS STIX 2.1 Threat Sharing Bundle.
    
    Includes:
      - identity: IoTGuard Edge IPS
      - attack-pattern: MITRE ATT&CK techniques with external references
      - indicator: Active malicious IPs ([ipv4-addr:value = '...'])
      - relationship: indicates linking indicators to attack patterns
      - sighting: edge observation records
    """
    recent_events = list(_iter_alerts(limit=50))
    blocks = {}
    if BLOCKER_AVAILABLE and get_active_blocks is not None:
        try:
            b_list = get_active_blocks()
            if isinstance(b_list, list):
                blocks = {b["ip"]: b for b in b_list if isinstance(b, dict) and "ip" in b}
            elif isinstance(b_list, dict):
                blocks = b_list
        except Exception:
            pass

    bundle = generate_stix_bundle(events=recent_events, active_blocks=blocks)
    return jsonify(bundle)


@app.get("/api/v1/export/cef")
@app.get("/api/export/cef")
def api_export_cef():
    """Export recent security alerts in ArcSight Common Event Format (CEF:0)."""
    limit = request.args.get("limit", default=100, type=int)
    events = list(_iter_alerts(limit=limit))
    cef_lines = [format_cef_event(e) for e in events]
    return Response(
        "\n".join(cef_lines) + ("\n" if cef_lines else ""),
        mimetype="text/plain",
        headers={"Content-Disposition": "inline; filename=iotguard_alerts.cef"}
    )


# ============================================================================
# INCIDENT TIME-MACHINE & FORENSIC SNAPSHOT ENDPOINTS
# ============================================================================

@app.get("/api/v1/forensics/<int:event_index>")
@app.get("/api/forensics/<int:event_index>")
def api_forensic_snapshot(event_index: int):
    """
    Generate or retrieve a cryptographically signed Forensic Evidence Bundle for an event.
    Returns:
        JSON response with ok=True and complete forensic bundle including
        sliding windows, SHAP attributions, zero-day contributors, MITRE mapping,
        threat intel, and SHA-256 evidence signature.
    """
    try:
        try:
            from forensic_snapshot import get_forensic_snapshot, generate_forensic_snapshot
        except ImportError:
            import importlib
            _fs_mod = importlib.import_module("scripts.4_response.forensic_snapshot")
            get_forensic_snapshot = _fs_mod.get_forensic_snapshot
            generate_forensic_snapshot = _fs_mod.generate_forensic_snapshot

        # Look up existing or generate on demand
        snapshot = get_forensic_snapshot(event_index)
        if not snapshot:
            ev = None
            for alert in _iter_alerts() or []:
                if alert.get("index") == event_index:
                    ev = alert
                    break
            bundle = generate_forensic_snapshot(event_index=event_index, event_meta=ev)
            snapshot = bundle.to_dict()

        if not snapshot:
            return jsonify({"ok": False, "error": f"Event {event_index} not found"}), 404

        # Check for download request
        if request.args.get("download") in ("1", "true", "yes"):
            filename = f"forensic_evidence_event_{event_index}.json"
            return Response(
                json.dumps(snapshot, indent=2, sort_keys=True),
                mimetype="application/json",
                headers={"Content-Disposition": f"attachment; filename={filename}"}
            )

        return jsonify(snapshot)
    except Exception as e:
        logger.error(f"Error handling forensics snapshot for event {event_index}: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.get("/api/v1/forensics")
@app.get("/api/forensics")
def api_list_forensics():
    """List all available forensic snapshots generated across the system."""
    try:
        try:
            from forensic_snapshot import list_forensic_snapshots
        except ImportError:
            import importlib
            _fs_mod = importlib.import_module("scripts.4_response.forensic_snapshot")
            list_forensic_snapshots = _fs_mod.list_forensic_snapshots

        snapshots = list_forensic_snapshots()
        return jsonify({
            "ok": True,
            "count": len(snapshots),
            "snapshots": snapshots,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.post("/api/v1/forensics/<int:event_index>/verify")
@app.post("/api/forensics/<int:event_index>/verify")
def api_verify_forensic_snapshot(event_index: int):
    """Verify cryptographic SHA-256 evidence integrity signature of a forensic bundle."""
    try:
        try:
            import forensic_snapshot as fs_mod
        except ImportError:
            import importlib
            fs_mod = importlib.import_module("scripts.4_response.forensic_snapshot")

        file_path = fs_mod.FORENSICS_DIR / f"snapshot_{event_index}.json"
        if not file_path.exists():
            return jsonify({"ok": False, "error": f"Forensic snapshot for event {event_index} not found"}), 404

        with open(file_path, "r", encoding="utf-8") as f:
            snapshot = json.load(f)

        is_valid, reason = fs_mod.verify_bundle_integrity(snapshot)
        return jsonify({
            "ok": True,
            "event_index": event_index,
            "verified": is_valid,
            "status": reason,
            "sha256": snapshot.get("evidence_integrity", {}).get("sha256_hash"),
            "audit_ledger_entry_hash": snapshot.get("evidence_integrity", {}).get("audit_ledger_entry_hash"),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

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
