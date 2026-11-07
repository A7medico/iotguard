"""
scripts/5_dashboard/dashboard_shared.py
-----------------------------------------------------------------------------
IoTGuard Enterprise — Shared Dashboard State, Helpers & Subsystem Adapters

Contains shared configuration, thread-safe file helpers, SocketIO emitters,
and subsystem adapters for modular Flask Blueprints.
-----------------------------------------------------------------------------
"""

import os
import io
import csv
import json
import math
import re
import time
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union

import yaml
from flask import Flask, jsonify, request, Response, abort, g

# Ensure sys.path contains all scripts directories
from path_setup import configure_paths
configure_paths()

from logging_config import get_logger

logger = get_logger("api_dashboard")

# ── Paths ───────────────────────────────────────────────────────────────────
DATA_DIR = Path("data")
ALERT_LOG = DATA_DIR / "alerts.jsonl"
CFG_FILE = Path(os.getenv("IOTGUARD_CONFIG") or "configs/model.yaml")

# ── Locks ───────────────────────────────────────────────────────────────────
_alerts_lock = threading.Lock()
_config_lock = threading.Lock()

# ── Helpers ─────────────────────────────────────────────────────────────────
def now_ts() -> float:
    """Current unix timestamp."""
    return time.time()


def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _iter_alerts(limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
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


def read_last_n(n: int = 200) -> List[Dict[str, Any]]:
    """Read the last N alerts with thread safety."""
    data = list(_iter_alerts() or [])
    return data[-n:]


def load_cfg() -> Dict[str, Any]:
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


def save_cfg(cfg: dict) -> None:
    """Save configuration with thread-safe file access and atomic write."""
    with _config_lock:
        CFG_FILE.parent.mkdir(parents=True, exist_ok=True)
        temp_file = CFG_FILE.with_suffix(".yaml.tmp")
        try:
            with temp_file.open("w", encoding="utf-8") as f:
                yaml.safe_dump(cfg, f, sort_keys=False)
            temp_file.replace(CFG_FILE)
            logger.debug("Configuration saved successfully")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            if temp_file.exists():
                temp_file.unlink()
            raise


def _validate_config(dec: dict) -> Tuple[dict, List[str]]:
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


# ── Configuration Flags ─────────────────────────────────────────────────────
BASIC_USER = os.getenv("IOTGUARD_USER") or None
BASIC_PASS = os.getenv("IOTGUARD_PASS") or None

_initial = load_cfg()
_initial_decision = (_initial.get("decision") or {}) if isinstance(_initial, dict) else {}
_initial_dry_run = bool(_initial_decision.get("dry_run", True))

REQUIRE_AUTH = _bool_env("IOTGUARD_REQUIRE_AUTH", default=(not _initial_dry_run))
ALLOW_LIVE_CONFIG = _bool_env("IOTGUARD_ALLOW_LIVE_CONFIG", default=False)


# ── WebSocket / SocketIO Support ─────────────────────────────────────────────
_socketio_instance = None
SOCKETIO_AVAILABLE = False

try:
    from flask_socketio import SocketIO, emit
    SOCKETIO_AVAILABLE = True
except ImportError:
    SocketIO = None


def set_socketio(sio) -> None:
    """Register the global SocketIO instance."""
    global _socketio_instance
    _socketio_instance = sio


def get_socketio():
    """Retrieve the global SocketIO instance."""
    return _socketio_instance


def emit_new_alert(alert_data: dict) -> None:
    """Emit a new alert to all connected WebSocket clients."""
    sio = get_socketio()
    if sio is not None:
        try:
            sio.emit("new_alert", alert_data, namespace="/")
        except Exception as e:
            logger.debug(f"WebSocket emit failed: {e}")


def emit_config_changed(config_data: dict) -> None:
    """Emit config change notification to all connected WebSocket clients."""
    sio = get_socketio()
    if sio is not None:
        try:
            sio.emit("config_changed", config_data, namespace="/")
        except Exception as e:
            logger.debug(f"WebSocket emit failed: {e}")


# ── Subsystem Integrations (with clean fallbacks) ───────────────────────────

# Metrics
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
    record_api_request = lambda *a, **kw: None
    record_inference_time = lambda *a, **kw: (lambda f: f)
    get_metrics_text = lambda: "iotguard_metrics_available 0\n"
    get_metrics_json = lambda: {}

# Auth & RBAC
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
    authenticate_user = lambda u, p: (False, None, "Auth not available")

# Storage Engine
try:
    from storage_engine import get_storage_engine, SQLiteStorageEngine
    STORAGE_AVAILABLE = True
except ImportError:
    STORAGE_AVAILABLE = False
    get_storage_engine = lambda *a, **k: None
    SQLiteStorageEngine = None

# Audit Ledger
try:
    from audit_ledger import (
        get_audit_ledger,
        record_audit_event,
        verify_audit_ledger,
    )
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False
    record_audit_event = lambda *a, **k: {}
    verify_audit_ledger = lambda *a, **k: (True, "AUDIT_UNAVAILABLE", None)
    get_audit_ledger = lambda *a, **k: None

# ML Ensemble
try:
    from ensemble import EnsemblePredictor, get_ensemble
    ENSEMBLE_AVAILABLE = True
except ImportError:
    ENSEMBLE_AVAILABLE = False
    EnsemblePredictor = None
    get_ensemble = lambda: None

# Alerts
try:
    from alerts import send_threat_alert, get_alert_manager
    ALERTS_AVAILABLE = True
except ImportError:
    ALERTS_AVAILABLE = False
    send_threat_alert = lambda *a, **kw: None
    get_alert_manager = lambda: None

# Playbooks
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

# Blocker / Active Defense
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

# Threat Intel
try:
    from threat_intel import ThreatIntel
    THREAT_INTEL = ThreatIntel()
except ImportError:
    ThreatIntel = None
    THREAT_INTEL = None

# Federated Learning
try:
    from federated_learning import get_federated_coordinator
    FEDERATED_AVAILABLE = True
except ImportError:
    FEDERATED_AVAILABLE = False
    get_federated_coordinator = None

# OpenAPI Spec
try:
    from openapi_spec import get_openapi_spec, get_swagger_ui_html
    OPENAPI_AVAILABLE = True
except ImportError:
    OPENAPI_AVAILABLE = False
    get_openapi_spec = lambda: {}
    get_swagger_ui_html = lambda *a, **k: "<h1>OpenAPI Docs Not Available</h1>"

# SIEM Exporters
try:
    from siem_exporter import format_cef_event, generate_stix_bundle, send_syslog
    SIEM_AVAILABLE = True
except ImportError:
    SIEM_AVAILABLE = False
    format_cef_event = lambda e: ""
    generate_stix_bundle = lambda *a, **k: {"type": "bundle", "objects": []}
    send_syslog = lambda *a, **k: (False, "SIEM exporter not available")

# Fleet Control Plane
try:
    from edge_agent import (
        get_fleet_control_plane,
        FleetControlPlane,
        verify_hmac_request,
        compute_hmac_signature,
    )
    FLEET_AVAILABLE = True
except ImportError:
    FLEET_AVAILABLE = False
    get_fleet_control_plane = None
    FleetControlPlane = None
    verify_hmac_request = None
    compute_hmac_signature = None

# SOC Metrics
try:
    from soc_metrics import get_soc_metrics_tracker, generate_executive_report
    SOC_METRICS_AVAILABLE = True
except ImportError:
    SOC_METRICS_AVAILABLE = False
    get_soc_metrics_tracker = None
    generate_executive_report = None

# Rate Limiter
try:
    from rate_limiter import get_rate_limiter, check_rate_limit
    RATE_LIMITER_AVAILABLE = True
except ImportError:
    RATE_LIMITER_AVAILABLE = False
    get_rate_limiter = None
    check_rate_limit = None

