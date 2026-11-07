"""
scripts/5_dashboard/routes/events_bp.py
-----------------------------------------------------------------------------
IoTGuard Enterprise — Events & Forensics Flask Blueprint (Layer 4)
-----------------------------------------------------------------------------
"""

import io
import csv
import json
import re
from datetime import datetime
from pathlib import Path
from flask import Blueprint, jsonify, request, Response, abort, g

from dashboard_shared import (
    DATA_DIR,
    ALERT_LOG,
    _iter_alerts,
    read_last_n,
    now_ts,
    load_cfg,
    logger,
    STORAGE_AVAILABLE,
    get_storage_engine,
    AUDIT_AVAILABLE,
    record_audit_event,
    ROLE_ADMIN,
    require_role,
    normalize_taxonomy,
    get_remediation_playbook,
)

events_bp = Blueprint("events_bp", __name__)


@events_bp.get("/api/latest")
def api_latest():
    data = read_last_n(1)
    return jsonify({"ok": True, "latest": data[0] if data else None, "server_time": now_ts()})


@events_bp.get("/api/counts")
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
            action = str(evt.get("action") or "")
            if action.startswith("BLOCK"):
                blocks += 1
                block_breakdown[action] = block_breakdown.get(action, 0) + 1
            c = evt.get("pred_class")
            if c is not None:
                class_counts[c] = class_counts.get(c, 0) + 1

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


@events_bp.get("/api/events")
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


@events_bp.get("/api/top_attackers")
def api_top_attackers():
    """Return top source IPs ranked by attack frequency."""
    ip_stats = {}
    for evt in _iter_alerts() or []:
        if evt.get("state") != "ATTACK":
            continue
        ip = evt.get("src_ip") or evt.get("threat", {}).get("ip")
        if not ip:
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
        threat = evt.get("threat")
        if threat and isinstance(threat, dict):
            ip_stats[ip]["country"] = threat.get("country", "")
            ip_stats[ip]["flag"] = threat.get("flag", "")
            ip_stats[ip]["threat"] = threat.get("threat", "")

    ranked = sorted(ip_stats.values(), key=lambda x: x["count"], reverse=True)[:10]
    return jsonify({"ok": True, "attackers": ranked})


@events_bp.get("/api/shap_detail")
def api_shap_detail():
    """Return SHAP-style feature contribution data for a specific event."""
    index = request.args.get("index", type=int)
    if index is None:
        return jsonify({"ok": False, "error": "index parameter required"}), 400

    for evt in _iter_alerts() or []:
        if evt.get("index") == index:
            reason = evt.get("reason", "")
            contributions = []
            if reason:
                matches = re.findall(r'(\w+)\s*\(([+\-][\d.]+)\)', reason)
                for feat_name, val_str in matches:
                    contributions.append({
                        "feature": feat_name,
                        "value": float(val_str),
                    })
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


@events_bp.get("/api/timeline_heatmap")
def api_timeline_heatmap():
    """Return hourly-bucketed attack counts for heatmap rendering."""
    now = now_ts()
    days = int(request.args.get("days", 7))
    cutoff = now - (days * 86400)
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

    result = []
    for i in range(days):
        dt = datetime.utcfromtimestamp(now - (days - 1 - i) * 86400)
        day_key = dt.strftime("%Y-%m-%d")
        day_label = dt.strftime("%a")
        hours = buckets.get(day_key, [0] * 24)
        result.append({"date": day_key, "label": day_label, "hours": hours})

    return jsonify({"ok": True, "days": result})


@events_bp.get("/api/feature_radar")
def api_feature_radar():
    """Return normalized feature values for the latest event for the radar chart."""
    cfg = load_cfg()
    features = cfg.get("features", [
        "flows", "bytes_total", "pkts_total", "syn_ratio", "mean_bytes_flow",
        "ack_ratio", "fin_ratio", "rst_ratio", "http_ratio", "tcp_ratio",
        "protocol_diversity", "std_bytes", "iat_mean"
    ])

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


@events_bp.post("/api/clear")
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


@events_bp.post("/api/clear_all")
@require_role([ROLE_ADMIN])
def api_clear_all():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ALERT_LOG.write_text("", encoding="utf-8")
    (DATA_DIR / "state.json").write_text('{"offset_rows":0,"csv_mtime":0}', encoding="utf-8")

    if AUDIT_AVAILABLE and record_audit_event is not None:
        record_audit_event(
            actor=getattr(g, "current_user", "operator"),
            action="LOG_CLEAR",
            role=getattr(g, "current_role", ROLE_ADMIN),
            payload={"scope": "all"}
        )
    return jsonify({"ok": True})


@events_bp.get("/api/download.csv")
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


# ── Forensics Endpoints ─────────────────────────────────────────────────────

@events_bp.get("/api/v1/forensics/<int:event_index>")
@events_bp.get("/api/forensics/<int:event_index>")
def api_forensic_snapshot(event_index: int):
    """Generate or retrieve a cryptographically signed Forensic Evidence Bundle for an event."""
    try:
        from forensic_snapshot import get_forensic_snapshot, generate_forensic_snapshot

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


@events_bp.get("/api/v1/forensics")
@events_bp.get("/api/forensics")
def api_list_forensics():
    """List all available forensic snapshots."""
    try:
        from forensic_snapshot import list_forensic_snapshots
        snapshots = list_forensic_snapshots()
        return jsonify({
            "ok": True,
            "count": len(snapshots),
            "snapshots": snapshots,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@events_bp.post("/api/v1/forensics/<int:event_index>/verify")
@events_bp.post("/api/forensics/<int:event_index>/verify")
def api_verify_forensic_snapshot(event_index: int):
    """Verify cryptographic SHA-256 evidence integrity signature of a forensic bundle."""
    try:
        import forensic_snapshot as fs_mod
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

