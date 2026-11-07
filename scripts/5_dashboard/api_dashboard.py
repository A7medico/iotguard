"""
scripts/5_dashboard/api_dashboard.py
-----------------------------------------------------------------------------
IoTGuard Pipeline — API + Web Dashboard Orchestrator (Layer 4)

Clean Layered DAG Architecture:
This orchestrator initializes the Flask application and SocketIO server,
registers modular Blueprints (events, defense, fleet, governance, soc_siem, demo),
and subscribes to the Layer 0 event bus for zero-circular-dependency alert broadcasting.
-----------------------------------------------------------------------------
"""

import os
import sys
import json
import threading
from pathlib import Path
from flask import Flask, Response, request, g

# Ensure sys.path includes all scripts subdirectories
_scripts_dir = Path(__file__).resolve().parent.parent
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))
from path_setup import configure_paths
configure_paths()

import event_bus
from dashboard_shared import (
    DATA_DIR,
    ALERT_LOG,
    CFG_FILE,
    REQUIRE_AUTH,
    ALLOW_LIVE_CONFIG,
    BASIC_USER,
    BASIC_PASS,
    _alerts_lock,
    _config_lock,
    _iter_alerts,
    read_last_n,
    now_ts,
    load_cfg,
    save_cfg,
    _validate_config,
    emit_new_alert,
    emit_config_changed,
    set_socketio,
    get_socketio,
    SOCKETIO_AVAILABLE,
    logger,
    RATE_LIMITER_AVAILABLE,
    check_rate_limit,
    AUTH_AVAILABLE,
    METRICS_AVAILABLE,
    STORAGE_AVAILABLE,
    AUDIT_AVAILABLE,
    ENSEMBLE_AVAILABLE,
    ALERTS_AVAILABLE,
    PLAYBOOKS_AVAILABLE,
    BLOCKER_AVAILABLE,
    FLEET_AVAILABLE,
    SOC_METRICS_AVAILABLE,
    ROLE_ADMIN,
    ROLE_SOC_ANALYST,
    ROLE_AUDITOR,
    ROLE_EDGE_SENSOR,
    ALL_ROLES,
    require_role,
    register_api_key,
    list_api_keys,
    revoke_api_key,
    authenticate_user,
    get_storage_engine,
    record_audit_event,
    verify_audit_ledger,
    get_audit_ledger,
    get_active_blocks,
    block_ip,
    unblock_ip,
    get_driver_telemetry,
    TAXONOMIES,
    REMEDIATION_PLAYBOOKS,
    normalize_taxonomy,
    get_remediation_playbook,
    _initial_dry_run,
)

# Optional Flask-SocketIO
try:
    from flask_socketio import SocketIO
except ImportError:
    SocketIO = None

# Initialize Flask application
app = Flask(
    __name__,
    static_folder=str(Path(__file__).parent / "templates"),
    static_url_path="/static"
)
_lock = threading.Lock()

# Initialize SocketIO if available
socketio = None
if SOCKETIO_AVAILABLE and SocketIO is not None:
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode="threading",
        logger=False,
        engineio_logger=False,
    )
    set_socketio(socketio)
    logger.info("WebSocket support enabled (Flask-SocketIO)")
else:
    logger.info("WebSocket support disabled (install flask-socketio for real-time updates)")

# Subscribe WebSocket alert emitter to Layer 0 event bus (breaks circular dependency!)
event_bus.subscribe("new_alert", emit_new_alert)

# ── Register Modular Blueprints ─────────────────────────────────────────────
from routes import (
    events_bp,
    defense_bp,
    fleet_bp,
    governance_bp,
    soc_siem_bp,
    demo_bp,
)

app.register_blueprint(events_bp)
app.register_blueprint(defense_bp)
app.register_blueprint(fleet_bp)
app.register_blueprint(governance_bp)
app.register_blueprint(soc_siem_bp)
app.register_blueprint(demo_bp)


# ── Global Request Hooks ────────────────────────────────────────────────────

@app.before_request
def _check_rate_limit():
    """Check rate limits before processing requests."""
    if not RATE_LIMITER_AVAILABLE or check_rate_limit is None:
        return

    client_ip = request.remote_addr or "unknown"
    path = request.path or "/"
    endpoint_type = None
    if "/login" in path:
        endpoint_type = "login"
    elif "/config" in path and request.method == "POST":
        endpoint_type = "config"

    allowed, headers = check_rate_limit(client_ip, endpoint_type)
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
    """Enforce simple HTTP Basic Auth when credentials are configured."""
    if not REQUIRE_AUTH:
        return

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


# ── Web UI Pages ────────────────────────────────────────────────────────────

@app.get("/")
def website():
    """Serve the project landing page from website/index.html or fallback to dashboard."""
    _site = Path(__file__).resolve().parent.parent.parent / "website" / "index.html"
    if _site.exists():
        html = _site.read_text(encoding="utf-8")
        resp = Response(html, mimetype="text/html")
        resp.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
        return resp
    return dashboard()


@app.get("/dashboard")
def dashboard():
    """Load dashboard HTML from template file."""
    _tmpl = Path(__file__).parent / "templates" / "index.html"
    html = _tmpl.read_text(encoding="utf-8")
    resp = Response(html, mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


if __name__ == "__main__":
    host = os.environ.get("IOTGUARD_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT") or os.environ.get("IOTGUARD_PORT") or "5001")
    logger.info(f"Starting IoTGuard API Dashboard on http://{host}:{port}")
    logger.info(f"Mode: {'DEMO (dry_run)' if _initial_dry_run else 'LIVE'}, Auth required: {REQUIRE_AUTH}")

    if socketio is not None:
        logger.info("Running with WebSocket support enabled")
        socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
    else:
        logger.info("Running without WebSocket support (polling mode)")
        app.run(host=host, port=port, debug=False)
