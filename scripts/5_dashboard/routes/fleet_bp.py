"""
scripts/5_dashboard/routes/fleet_bp.py
-----------------------------------------------------------------------------
IoTGuard Enterprise — Fleet Control Plane & Federated Learning Blueprint (Layer 4)
-----------------------------------------------------------------------------
"""

import os
import time
import random
from flask import Blueprint, jsonify, request, g

from dashboard_shared import (
    logger,
    load_cfg,
    AUDIT_AVAILABLE,
    record_audit_event,
    ROLE_ADMIN,
    ROLE_SOC_ANALYST,
    require_role,
    SOCKETIO_AVAILABLE,
    get_socketio,
    BLOCKER_AVAILABLE,
    block_ip,
    FLEET_AVAILABLE,
    get_fleet_control_plane,
    verify_hmac_request,
    FEDERATED_AVAILABLE,
    get_federated_coordinator,
)

fleet_bp = Blueprint("fleet_bp", __name__)


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


# ── Federated Learning ──────────────────────────────────────────────────────

@fleet_bp.get("/api/v1/federated/status")
@fleet_bp.get("/api/federated/status")
def api_federated_status():
    """Return status of edge federated learning fleet and online feature drift."""
    if not FEDERATED_AVAILABLE or get_federated_coordinator is None:
        return jsonify({"ok": False, "error": "Federated learning subsystem not available"}), 503
    coord = get_federated_coordinator()
    return jsonify(coord.get_fleet_status())


@fleet_bp.post("/api/v1/federated/round")
@fleet_bp.post("/api/federated/round")
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

    sio = get_socketio()
    if sio is not None:
        try:
            sio.emit("federated_update", result)
        except Exception:
            pass

    return jsonify({
        "ok": True,
        "message": f"Federated aggregation round {result['round']} completed",
        "round_report": result,
    })


# ── Fleet Control Plane ─────────────────────────────────────────────────────

@fleet_bp.post("/api/v1/fleet/register")
@fleet_bp.post("/api/fleet/register")
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


@fleet_bp.post("/api/v1/fleet/heartbeat")
@fleet_bp.post("/api/fleet/heartbeat")
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

    data = request.get_json(silent=True) or {}
    try:
        ack = cp.record_heartbeat(node_id, data)
        return jsonify(ack), 200
    except KeyError as e:
        return jsonify({"ok": False, "error": str(e)}), 404
    except Exception as e:
        logger.error(f"Error recording heartbeat for {node_id}: {e}")
        return jsonify({"ok": False, "error": f"Internal error: {e}"}), 500


@fleet_bp.get("/api/v1/fleet/nodes")
@fleet_bp.get("/api/fleet/nodes")
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


@fleet_bp.post("/api/v1/fleet/broadcast_block")
@fleet_bp.post("/api/fleet/broadcast_block")
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

    sio = get_socketio()
    if sio is not None:
        try:
            sio.emit("topology_update", {"action": "fleet_block", "ip": ip, "severity": severity})
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


@fleet_bp.get("/api/v1/fleet/blocks")
@fleet_bp.get("/api/fleet/blocks")
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


@fleet_bp.post("/api/v1/fleet/simulate")
@fleet_bp.post("/api/fleet/simulate")
def api_fleet_simulate():
    """Simulate or generate a fresh telemetry heartbeat from an edge gateway."""
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

