"""
scripts/5_dashboard/routes/demo_bp.py
-----------------------------------------------------------------------------
IoTGuard Enterprise — Demo Traffic Simulation Flask Blueprint (Layer 4)
-----------------------------------------------------------------------------
"""

from flask import Blueprint, jsonify, request

from dashboard_shared import now_ts, logger
from demo_stream_service import (
    get_simulation_status,
    start_simulation,
    stop_simulation,
    inject_attack_burst,
    simulate_attack_features,
    _ATTACK_PROFILES,
)

demo_bp = Blueprint("demo_bp", __name__)


@demo_bp.get("/api/demo/status")
def api_demo_status():
    """Return status of live demo simulator."""
    status = get_simulation_status()
    return jsonify({
        "ok": True,
        "running": status["running"],
        "stats": status["stats"],
        "server_time": now_ts(),
    })


@demo_bp.post("/api/demo/start")
def api_demo_start():
    """Start / resume the live feature stream."""
    start_simulation()
    return jsonify({"ok": True, "message": "Demo stream running", "running": True})


@demo_bp.post("/api/demo/stop")
def api_demo_stop():
    """Stop / pause the live feature stream."""
    stop_simulation()
    return jsonify({"ok": True, "message": "Demo stream stopped", "running": False})


@demo_bp.post("/api/demo/inject")
def api_demo_inject():
    """Immediately inject a chosen cyber attack scenario."""
    data = request.get_json(silent=True) or {}
    attack_type = data.get("type", "syn")
    atk_name, row = inject_attack_burst(attack_type)
    return jsonify({
        "ok": True,
        "message": f"Injected {atk_name} attack burst into stream",
        "attack_type": atk_name,
        "features": row,
    })


@demo_bp.post("/api/simulate")
def api_simulate():
    """
    Inject attack-pattern feature rows directly into data/features.csv.
    This replaces the old subprocess-based simulator that required Scapy.
    """
    attack_type = request.args.get("type", "syn")
    ok, name, rows_written, error = simulate_attack_features(attack_type)
    if not ok:
        return jsonify({"ok": False, "error": error}), 400

    return jsonify({
        "ok": True,
        "attack": name,
        "rows_injected": rows_written,
        "message": f"Injected {rows_written} {name} attack rows. Decision loop will score them shortly."
    })

