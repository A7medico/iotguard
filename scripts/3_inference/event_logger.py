"""
scripts/3_inference/event_logger.py
-----------------------------------------------------------------------------
IoTGuard Component — Event Logging & Alert Persistence

Extracted from decision_loop.py for modularity and testability.

Responsibilities:
    - Append structured events to alerts.jsonl
    - Rotate alert log when it exceeds size limit
    - Write internal audit events to logs/audit.jsonl
    - Write health/heartbeat files
    - Manage state persistence (offset tracking)
-----------------------------------------------------------------------------
"""

import sys
import json
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_scripts_dir = Path(__file__).resolve().parent.parent
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))
from path_setup import configure_paths
configure_paths()

logger = logging.getLogger("iotguard.event_logger")

# ── Constants ───────────────────────────────────────────────────────────────
LOG_ROTATE_BYTES = 5_000_000


class EventLogger:
    """
    Manages all event persistence for the decision loop.

    Replaces the scattered file I/O in the monolithic decision_loop.py
    with a cohesive interface.
    """

    def __init__(
        self,
        alert_path: str = "data/alerts.jsonl",
        state_path: str = "data/state.json",
        audit_path: str = "logs/audit.jsonl",
        health_path: str = "data/decision_health.json",
        emit_callback=None,
    ):
        self.alert_path = Path(alert_path)
        self.state_path = Path(state_path)
        self.audit_path = Path(audit_path)
        self.health_path = Path(health_path)
        self._emit_callback = emit_callback or (lambda x: None)

    # ── Alert events (dashboard-visible) ─────────────────────────────────

    def log_event(
        self,
        idx: int,
        score: float,
        state_text: str,
        hits: int,
        action: str,
        pred_class: Optional[str] = None,
        reason: Optional[str] = None,
        effective_thr: Optional[float] = None,
        threat_info: Optional[dict] = None,
        src_ip: Optional[str] = None,
        ip_anomaly: Optional[bool] = None,
        device_type: Optional[str] = None,
        detection_source: Optional[str] = None,
        unsup_score: Optional[float] = None,
        attack_category: Optional[str] = None,
        confidence: Optional[float] = None,
        remediation_playbook: Optional[dict] = None,
        temporal_score: Optional[float] = None,
        temporal_drifting: Optional[list[str]] = None,
        mitre: Optional[dict] = None,
        anomaly_contributors: Optional[list] = None,
    ) -> dict:
        """Append a structured event to alerts.jsonl and emit via callback."""
        evt: dict[str, Any] = {
            "ts": time.time(),
            "index": int(idx),
            "score": float(score),
            "state": state_text,
            "hits_in_window": int(hits),
            "action": action,
        }
        if effective_thr is not None:
            evt["effective_threshold"] = float(effective_thr)
        if pred_class is not None:
            evt["pred_class"] = str(pred_class)
        if reason:
            evt["reason"] = str(reason)
        if threat_info:
            evt["threat"] = threat_info
        if src_ip is not None:
            evt["src_ip"] = src_ip
        if ip_anomaly is not None:
            evt["ip_anomaly"] = bool(ip_anomaly)
        if device_type is not None:
            evt["device_type"] = str(device_type)
        if detection_source is not None:
            evt["detection_source"] = str(detection_source)
        if device_type:
            evt["model_used"] = str(device_type)
        if unsup_score is not None:
            evt["unsup_score"] = float(unsup_score)
        if attack_category is not None:
            evt["attack_category"] = str(attack_category)
        if confidence is not None:
            evt["confidence"] = float(confidence)
        if remediation_playbook is not None:
            evt["remediation_playbook"] = remediation_playbook
        if temporal_score is not None:
            evt["temporal_score"] = float(temporal_score)
        if temporal_drifting:
            evt["temporal_drifting"] = temporal_drifting
        if anomaly_contributors:
            evt["anomaly_contributors"] = [
                {"feature": f, "contribution": float(c)} if isinstance(f, str) else dict(f)
                for f, c in (anomaly_contributors if isinstance(anomaly_contributors[0], (tuple, list)) else [(x.get("feature", ""), x.get("contribution", 0.0)) for x in anomaly_contributors])
            ] if anomaly_contributors else []

        # MITRE ATT&CK Enrichment
        if mitre is not None:
            evt["mitre"] = mitre
        else:
            try:
                from playbooks import get_mitre_attack
                target_cat = attack_category or pred_class
                if target_cat and str(target_cat).lower() not in ("benign", "normal"):
                    evt["mitre"] = get_mitre_attack(target_cat)
                elif remediation_playbook and "mitre" in remediation_playbook:
                    evt["mitre"] = remediation_playbook["mitre"]
            except Exception:
                pass

        self.alert_path.parent.mkdir(parents=True, exist_ok=True)
        with self.alert_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(evt) + "\n")

        # Enterprise Dual-Write Contract: Indexed Relational Storage Engine
        try:
            from storage_engine import get_storage_engine
            engine = get_storage_engine()
            if engine is not None:
                engine.insert_event(evt)
        except Exception:
            pass  # Dual-write error must never disrupt stream scoring

        self._emit_callback(evt)
        return evt

    # ── Log rotation ─────────────────────────────────────────────────────

    def rotate_alerts(self) -> bool:
        """Rotate alerts.jsonl if it exceeds the size limit. Returns True if rotated."""
        try:
            if self.alert_path.exists() and self.alert_path.stat().st_size > LOG_ROTATE_BYTES:
                ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
                self.alert_path.rename(
                    self.alert_path.with_name(f"alerts-{ts}.jsonl")
                )
                logger.info("Rotated alerts log")
                return True
        except Exception as e:
            logger.warning(f"Log rotate warn: {e}")
        return False

    # ── Internal audit log ───────────────────────────────────────────────

    def log_internal(self, kind: str, msg: str, **extra) -> None:
        """Append a structured internal log event to logs/audit.jsonl."""
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            evt = {"ts": time.time(), "kind": kind, "msg": msg}
            if extra:
                evt.update(extra)
            with self.audit_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(evt) + "\n")
        except Exception:
            pass  # Logging must never crash the loop

    # ── State persistence ────────────────────────────────────────────────

    def load_state(self) -> dict:
        """Load the loop state (CSV offset, last block index) from disk."""
        if self.state_path.exists():
            try:
                return json.loads(self.state_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"offset_rows": 0, "csv_mtime": 0.0, "last_block_idx": None}

    def save_state(self, state: dict) -> None:
        """Persist the loop state to disk."""
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(state), encoding="utf-8")

    # ── Health heartbeat ─────────────────────────────────────────────────

    def write_health(
        self,
        now_ts: float,
        state: dict,
        cfg_mtime: float,
        dry_run: bool,
    ) -> None:
        """Write a small health/heartbeat file that external tools can check."""
        try:
            payload = {
                "ts": now_ts,
                "offset_rows": int(state.get("offset_rows", 0)),
                "csv_mtime": float(state.get("csv_mtime", 0.0)),
                "last_block_idx": state.get("last_block_idx"),
                "cfg_mtime": float(cfg_mtime),
                "dry_run": bool(dry_run),
            }
            self.health_path.parent.mkdir(parents=True, exist_ok=True)
            self.health_path.write_text(json.dumps(payload), encoding="utf-8")
        except Exception:
            pass  # Health reporting is best-effort only

    def write_shutdown_health(self, reason: str) -> None:
        """Write final health status on shutdown."""
        try:
            health = {
                "ts": time.time(),
                "status": "shutdown",
                "reason": reason,
            }
            self.health_path.write_text(json.dumps(health), encoding="utf-8")
        except Exception:
            pass
