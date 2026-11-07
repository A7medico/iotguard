"""
scripts/5_dashboard/routes/defense_bp.py
-----------------------------------------------------------------------------
IoTGuard Enterprise — Active Defense & Network Topology Blueprint (Layer 4)
-----------------------------------------------------------------------------
"""

import json
import math
from pathlib import Path
from flask import Blueprint, jsonify, request, g

from dashboard_shared import (
    DATA_DIR,
    read_last_n,
    load_cfg,
    logger,
    now_ts,
    AUDIT_AVAILABLE,
    record_audit_event,
    ROLE_ADMIN,
    ROLE_SOC_ANALYST,
    require_role,
    SOCKETIO_AVAILABLE,
    get_socketio,
    BLOCKER_AVAILABLE,
    block_ip,
    unblock_ip,
    get_active_blocks,
    get_driver_telemetry,
    THREAT_INTEL,
    FLEET_AVAILABLE,
    get_fleet_control_plane,
    TAXONOMIES,
    REMEDIATION_PLAYBOOKS,
    normalize_taxonomy,
    get_remediation_playbook,
)

defense_bp = Blueprint("defense_bp", __name__)


@defense_bp.get("/api/topology")
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

    known_ips = {d["ip"]: d for d in seed_devices}
    for dev in devices:
        known_ips[dev["ip"]] = dev

    all_dynamic_ips = set(recent_ips.keys()) | set(blocked_ips.keys()) | set(fingerprints.keys())
    if win_meta.get("top_src_ip"):
        all_dynamic_ips.add(win_meta.get("top_src_ip"))

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

    nodes = []
    connections = [
        {"from": "gw", "to": "fw", "active": True},
        {"from": "fw", "to": "hub", "active": True},
        {"from": "fw", "to": "srv", "active": True},
    ]

    attack_active = False

    for d in all_devices:
        ip = d.get("ip")
        is_blocked = (ip in blocked_ips) or (recent_ips.get(ip, {}).get("last_action", "").startswith("BLOCK"))
        is_grace = (not is_blocked) and (
            recent_ips.get(ip, {}).get("last_state") == "ATTACK" or 
            recent_ips.get(ip, {}).get("hits", 0) > 0
        )

        if is_blocked:
            state = "BLOCKED"
            attack_active = True
        elif is_grace:
            state = "GRACE"
            attack_active = True
        else:
            state = "BENIGN"

        d["state"] = state
        d["blocked"] = is_blocked

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

    if attack_active:
        connections[0]["attack"] = True
        connections[0]["state"] = "attack"

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


@defense_bp.post("/api/block")
@defense_bp.post("/api/v1/block")
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

        sio = get_socketio()
        if sio is not None:
            try:
                sio.emit("topology_update", {"action": "block", "ip": ip, "severity": severity})
            except Exception:
                pass

        # Fleet-Wide Global Block Broadcast ("Herd Immunity")
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


@defense_bp.post("/api/unblock")
@defense_bp.post("/api/v1/unblock")
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

        sio = get_socketio()
        if sio is not None:
            try:
                sio.emit("topology_update", {"action": "unblock", "ip": ip})
            except Exception:
                pass
        return jsonify({
            "ok": True,
            "ip": ip,
            "message": msg,
            "dry_run": dry_run,
        })
    return jsonify({"ok": False, "error": msg}), 400


@defense_bp.get("/api/blocks")
@defense_bp.get("/api/v1/blocks")
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


@defense_bp.get("/api/playbooks")
def api_playbooks():
    """Return all available remediation playbooks and canonical taxonomies."""
    return jsonify({
        "ok": True,
        "taxonomies": TAXONOMIES,
        "playbooks": REMEDIATION_PLAYBOOKS,
    })


@defense_bp.get("/api/playbook/<category>")
def api_playbook_detail(category: str):
    """Return the structured remediation playbook for a specific attack category."""
    canon = normalize_taxonomy(category)
    src_ip = request.args.get("src_ip")
    pb = get_remediation_playbook(canon, src_ip=src_ip)
    return jsonify({"ok": True, "category": canon, "playbook": pb})

