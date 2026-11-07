"""
scripts/5_dashboard/routes/soc_siem_bp.py
-----------------------------------------------------------------------------
IoTGuard Enterprise — SOC SLA, SIEM Exports & OpenAPI Blueprint (Layer 4)
-----------------------------------------------------------------------------
"""

import json
from pathlib import Path
from flask import Blueprint, jsonify, request, Response

from dashboard_shared import (
    DATA_DIR,
    load_cfg,
    now_ts,
    logger,
    REQUIRE_AUTH,
    _iter_alerts,
    METRICS_AVAILABLE,
    get_metrics_text,
    get_metrics_json,
    update_firewall_telemetry,
    record_inference_time,
    BLOCKER_AVAILABLE,
    get_active_blocks,
    get_driver_telemetry,
    ENSEMBLE_AVAILABLE,
    get_ensemble,
    ALERTS_AVAILABLE,
    get_alert_manager,
    OPENAPI_AVAILABLE,
    get_openapi_spec,
    get_swagger_ui_html,
    SIEM_AVAILABLE,
    format_cef_event,
    generate_stix_bundle,
    SOC_METRICS_AVAILABLE,
    get_soc_metrics_tracker,
    generate_executive_report,
    TAXONOMIES,
)

soc_siem_bp = Blueprint("soc_siem_bp", __name__)


# ── Metrics Endpoints ───────────────────────────────────────────────────────

@soc_siem_bp.get("/metrics")
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


@soc_siem_bp.get("/api/v1/metrics")
def api_v1_metrics():
    """JSON metrics summary for dashboard."""
    if not METRICS_AVAILABLE:
        return jsonify({"error": "Metrics not available"}), 501
    return jsonify(get_metrics_json())


# ── Health Probes ───────────────────────────────────────────────────────────

@soc_siem_bp.get("/health/live")
def health_live():
    """Kubernetes liveness probe."""
    return jsonify({"status": "ok", "timestamp": now_ts()})


@soc_siem_bp.get("/health/ready")
def health_ready():
    """Kubernetes readiness probe - checks if models are loaded."""
    ready = True
    details = {}

    if ENSEMBLE_AVAILABLE:
        ensemble = get_ensemble()
        details["supervised_model"] = ensemble.supervised_model is not None if ensemble else False
        details["unsupervised_model"] = ensemble.unsupervised_model is not None if ensemble else False
        ready = details["supervised_model"]

    if ALERTS_AVAILABLE:
        details["alerts_configured"] = True

    status_code = 200 if ready else 503
    return jsonify({"status": "ready" if ready else "not_ready", "details": details}), status_code


@soc_siem_bp.get("/health")
def api_health():
    """Lightweight health endpoint for monitoring / load balancers."""
    health_path = DATA_DIR / "decision_health.json"
    feat_health_path = DATA_DIR / "features_health.json"
    model_meta_path = Path("models/model_meta.json")

    loop_health = None
    feat_health = None
    model_info = None

    try:
        if health_path.exists():
            loop_health = json.loads(health_path.read_text(encoding="utf-8"))
    except Exception:
        loop_health = None

    try:
        if feat_health_path.exists():
            feat_health = json.loads(feat_health_path.read_text(encoding="utf-8"))
    except Exception:
        feat_health = None

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

    model_loaded = Path("models/lightgbm.joblib").exists()
    status = "ok" if model_loaded else "degraded"

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


# ── ML Model & Prediction Endpoints ─────────────────────────────────────────

@soc_siem_bp.get("/api/model")
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


@soc_siem_bp.get("/api/v1/ensemble")
def api_v1_ensemble():
    """Get ensemble model status and configuration."""
    if not ENSEMBLE_AVAILABLE:
        return jsonify({"error": "Ensemble not available"}), 501

    ensemble = get_ensemble()
    if ensemble is None:
        return jsonify({"ok": False, "error": "Ensemble instance not found"}), 500

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


@soc_siem_bp.post("/api/v1/predict")
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


@soc_siem_bp.post("/api/v1/test-alert")
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


# ── SOC SecOps KPIs & Executive Reporting ────────────────────────────────────

@soc_siem_bp.get("/api/v1/soc/kpis")
@soc_siem_bp.get("/api/soc/kpis")
def api_soc_kpis():
    """Return live Enterprise SecOps KPIs."""
    if not SOC_METRICS_AVAILABLE or get_soc_metrics_tracker is None:
        return jsonify({"ok": False, "error": "SOC metrics engine not available"}), 503

    tracker = get_soc_metrics_tracker()
    return jsonify(tracker.get_soc_kpis())


@soc_siem_bp.get("/api/v1/reports/executive")
@soc_siem_bp.get("/api/reports/executive")
def api_reports_executive():
    """Generate an Executive Security Posture & Compliance Report."""
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


# ── OpenAPI 3.1 & Swagger Documentation ──────────────────────────────────────

@soc_siem_bp.get("/api/openapi.json")
@soc_siem_bp.get("/openapi.json")
def api_openapi_json():
    """Return complete OpenAPI 3.1.0 JSON specification."""
    return jsonify(get_openapi_spec())


@soc_siem_bp.get("/api/docs")
@soc_siem_bp.get("/docs")
def api_docs_ui():
    """Serve interactive Swagger UI documentation for IoTGuard Enterprise APIs."""
    html = get_swagger_ui_html(openapi_url="/api/openapi.json", title="IoTGuard Enterprise API Documentation")
    return Response(html, mimetype="text/html")


# ── SIEM & Threat Intelligence Exports ───────────────────────────────────────

@soc_siem_bp.get("/api/v1/export/stix")
@soc_siem_bp.get("/api/export/stix")
def api_export_stix():
    """Export active threat indicators as an OASIS STIX 2.1 Threat Sharing Bundle."""
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


@soc_siem_bp.get("/api/v1/export/cef")
@soc_siem_bp.get("/api/export/cef")
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

