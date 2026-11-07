"""
scripts/5_dashboard/routes/governance_bp.py
-----------------------------------------------------------------------------
IoTGuard Enterprise — Governance, RBAC, Audit & Config Blueprint (Layer 4)
-----------------------------------------------------------------------------
"""

from flask import Blueprint, jsonify, request, g

from dashboard_shared import (
    load_cfg,
    save_cfg,
    _validate_config,
    now_ts,
    ALLOW_LIVE_CONFIG,
    AUTH_AVAILABLE,
    authenticate_user,
    register_api_key,
    list_api_keys,
    AUDIT_AVAILABLE,
    get_audit_ledger,
    record_audit_event,
    verify_audit_ledger,
    ROLE_ADMIN,
    ROLE_AUDITOR,
    ROLE_SOC_ANALYST,
    require_role,
    ALERTS_AVAILABLE,
    get_alert_manager,
    emit_config_changed,
)

governance_bp = Blueprint("governance_bp", __name__)


@governance_bp.post("/api/v1/login")
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


# ── Audit Ledger Endpoints ──────────────────────────────────────────────────

@governance_bp.get("/api/v1/audit")
@governance_bp.get("/api/audit")
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


@governance_bp.get("/api/v1/audit/verify")
@governance_bp.get("/api/audit/verify")
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


# ── API Key Management ──────────────────────────────────────────────────────

@governance_bp.post("/api/v1/keys")
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


@governance_bp.get("/api/v1/keys")
@require_role([ROLE_ADMIN])
def api_list_keys():
    """List active enterprise API keys."""
    if not AUTH_AVAILABLE:
        return jsonify({"ok": False, "error": "Auth subsystem not available"}), 503
    return jsonify({"ok": True, "keys": list_api_keys()})


# ── Configuration Management ────────────────────────────────────────────────

@governance_bp.get("/api/config")
def api_get_config():
    """Retrieve current system configuration."""
    return jsonify(load_cfg())


@governance_bp.post("/api/config")
@require_role([ROLE_ADMIN])
def api_set_config():
    """Update decision parameters with validation."""
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

    emit_config_changed(cfg)

    return jsonify({
        "ok": True,
        "saved": new_dec,
        "note": "Restart decision loop to apply (or enable hot-reload there)."
    })


# ── Alerts Configuration ────────────────────────────────────────────────────

@governance_bp.get("/api/v1/alerts/config")
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

