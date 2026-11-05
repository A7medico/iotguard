"""
scripts/3_inference/decision_loop.py
-----------------------------------------------------------------------------
IoTGuard Pipeline — Streaming Scoring & Enforcement Engine

Position in pipeline
    Suricata / simulators
        →  features.csv               (13 features per time window)
        →  [THIS FILE]                (model scoring + policies + blocking)
        →  alerts.jsonl               (structured events)
        →  api_dashboard.py / tools   (visualization, exports, metrics)

High‑level responsibilities
    - Tail data/features.csv and **only score new rows**, preserving offset across restarts.
    - For each row:
        * compute P(attack) using the trained LightGBM model (supervised),
        * optionally compute anomaly score using IsolationForest (unsupervised),
        * support hybrid mode: flag if EITHER model detects an issue,
        * optionally adjust the threshold using an **adaptive threshold** based on recent scores,
        * decide benign vs ATTACK and maintain a sliding window of hits,
        * apply policy (grace, cooldown, instant block) to decide if we should block,
        * pick an IP to block from window_meta.json (top_src_ip),
        * enrich the event with:
              XAI reason (SHAP via explainer.py),
              Threat Intel (country/flag/reputation via threat_intel.py),
              effective_threshold and action severity,
        * append a compact JSON event to alerts.jsonl for the dashboard and audits.

Key inputs
    - models/lightgbm.joblib      – trained supervised model.
    - models/model_meta.json      – feature list + default threshold.
    - models/unsup_isoforest.joblib – trained unsupervised model (optional).
    - models/unsup_meta.json      – unsupervised feature list + threshold (optional).
    - configs/model.yaml          – decision.* section + hybrid.* section.
    - data/features.csv           – streaming feature windows from suricata_to_features.py or stream_csvs.py.
    - data/window_meta.json       – per-window context: top_src_ip and light DPI stats (HTTP/DNS/TLS).

Key outputs
    - data/alerts.jsonl           – one JSON line per scored window (used by api_dashboard and CSV export).
    - Firewall rules              – via blocker.py when dry_run is False (or simulated when True).
-----------------------------------------------------------------------------
"""
import os, time, json, sys
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
import pandas as pd
import numpy as np

# Reconfigure stdout/stderr to UTF-8 to prevent UnicodeEncodeError on Windows (cp1252)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from colorama import init, Fore, Style

# Add scripts directory and subdirectories to path for imports
_scripts_dir = Path(__file__).parent.parent
sys.path.insert(0, str(_scripts_dir))
from path_setup import configure_paths
configure_paths()

# ── Import extracted modules ────────────────────────────────────────────────
from scoring import (
    ModelManager,
    classify_attack_heuristic,
    compute_adaptive_threshold,
    compute_unsupervised_score,
    compute_hybrid_decision,
    infer_attack_taxonomy,
)
from policy import (
    PolicyConfig,
    load_policy,
    evaluate_response,
    debug_no_block_reason,
    IPBaselineTracker,
    get_remediation_playbook,
    normalize_taxonomy,
)
from temporal_detector import TemporalDetector
from event_logger import EventLogger

try:
    from stream_reader import FastCSVStreamReader, AsyncSIEMDispatcher
except ImportError:
    try:
        import importlib
        _sr = importlib.import_module("scripts.3_inference.stream_reader")
        FastCSVStreamReader = _sr.FastCSVStreamReader
        AsyncSIEMDispatcher = _sr.AsyncSIEMDispatcher
    except Exception:
        FastCSVStreamReader = None
        AsyncSIEMDispatcher = None

siem_dispatcher: Optional[AsyncSIEMDispatcher] = None

# ── Import other pipeline components ────────────────────────────────────────
from blocker import block_ip as blocker_block_ip

try:
    from api_dashboard import emit_new_alert
except ImportError:
    emit_new_alert = lambda x: None

from explainer import RealTimeExplainer
from threat_intel import ThreatIntel
from logging_config import get_logger, get_audit_logger

# Optional: Alerting system for notifications
try:
    from alerting import send_alert
    ALERTING_AVAILABLE = True
except ImportError:
    ALERTING_AVAILABLE = False
    send_alert = lambda *args, **kwargs: {}

init(autoreset=True)

# ── Logging ─────────────────────────────────────────────────────────────────
logger = get_logger("decision_loop")
audit_logger = get_audit_logger()

# ── Paths ───────────────────────────────────────────────────────────────────
DATA_DIR = Path("data")
DATA_CSV = DATA_DIR / "features.csv"
CFG_PATH = Path(os.getenv("IOTGUARD_CONFIG") or "configs/model.yaml")
WIN_META = DATA_DIR / "window_meta.json"
PRINT_IDLE_SECS = 5.0

# ── Initialise core components ──────────────────────────────────────────────
print(Fore.CYAN + "ℹ️  Loading models and configuration..." + Style.RESET_ALL)

mgr = ModelManager(str(CFG_PATH))
print(Fore.CYAN + f"ℹ️  Using {len(mgr.features)} features: {mgr.features}" + Style.RESET_ALL)

policy, cfg_mtime = load_policy(str(CFG_PATH))

# Explainer
print(Fore.CYAN + "ℹ️  Initializing RealTimeExplainer..." + Style.RESET_ALL)
_default_model = next(iter(mgr.models.values())) if mgr.models else None
EXPLAINER = RealTimeExplainer(_default_model, mgr.features) if _default_model else None

# Threat Intel
print(Fore.CYAN + "ℹ️  Initializing ThreatIntel..." + Style.RESET_ALL)
THREAT_INTEL = ThreatIntel()

# Event Logger
evt_logger = EventLogger(emit_callback=emit_new_alert)

# Per-IP baseline tracker
ip_tracker = IPBaselineTracker()

# Temporal sequence & drift detector (Phase 2 Upgrade)
temporal_detector = TemporalDetector(
    window_size=policy.temporal_window_size,
    min_windows=policy.temporal_min_windows,
    drift_threshold=policy.temporal_drift_threshold,
    boost_weight=policy.temporal_boost_weight,
)


# ── Helpers ─────────────────────────────────────────────────────────────────

def to_numeric(df: pd.DataFrame) -> pd.DataFrame:
    for c in mgr.features:
        df[c] = pd.to_numeric(df[c].astype(str).str.strip(), errors="coerce")
    for c in ("flows", "bytes_total", "pkts_total"):
        if c in df.columns:
            df[c] = df[c].clip(lower=0)
    return df


def has_required_cols(df: pd.DataFrame) -> bool:
    return set(mgr.features).issubset(df.columns)


def read_window_meta() -> dict:
    """Optional: latest window meta written by suricata_to_features.py."""
    try:
        if not WIN_META.exists():
            return {}
        meta = json.loads(WIN_META.read_text(encoding="utf-8"))
        return meta if isinstance(meta, dict) else {}
    except Exception:
        return {}


def maybe_reload_config():
    """Hot-reload config if the YAML file changed on disk."""
    global policy, cfg_mtime, temporal_detector
    try:
        mtime = CFG_PATH.stat().st_mtime
    except FileNotFoundError:
        mtime = 0.0
    if mtime != cfg_mtime:
        policy, cfg_mtime = load_policy(str(CFG_PATH))
        temporal_detector.window_size = policy.temporal_window_size
        temporal_detector.min_windows = policy.temporal_min_windows
        temporal_detector.drift_threshold = policy.temporal_drift_threshold
        temporal_detector.boost_weight = policy.temporal_boost_weight
        print(
            Fore.CYAN
            + f"🔄 Reloaded config: thr={policy.threshold} "
            f"adapt={policy.use_adaptive} dry={policy.dry_run} "
            f"mode={policy.hybrid_mode} temporal={policy.temporal_enabled}"
            + Style.RESET_ALL
        )


def block_ip_wrapper(ip: str, dry_run: bool, severity: str = "hard") -> tuple[bool, str]:
    """Wrapper around blocker.py that respects dry_run mode."""
    if not ip:
        return False, "no-ip"
    if dry_run:
        return True, f"dry-run-{severity}"
    return blocker_block_ip(ip)


# ── Main loop ───────────────────────────────────────────────────────────────

def main() -> None:
    mode_str = (
        policy.hybrid_mode
        if mgr.unsup_available and policy.unsup_enabled
        else "supervised"
    )
    print(
        Fore.GREEN
        + f"🟢 Decision loop watching {DATA_CSV} [MODE: {mode_str.upper()}]"
        + Style.RESET_ALL
    )
    if mgr.unsup_available and policy.unsup_enabled:
        print(Fore.CYAN + f"   Hybrid combine strategy: {policy.hybrid_combine}" + Style.RESET_ALL)
    elif not mgr.unsup_available:
        print(Fore.YELLOW + "   ⚠️  Unsupervised model not available" + Style.RESET_ALL)

    logger.info(f"Decision loop started in {mode_str.upper()} mode, watching {DATA_CSV}")
    evt_logger.log_internal("startup", "decision_loop_started", data_csv=str(DATA_CSV), mode=mode_str)

    global siem_dispatcher
    fast_reader = FastCSVStreamReader(DATA_CSV, mgr.features) if FastCSVStreamReader is not None else None
    siem_dispatcher = AsyncSIEMDispatcher() if AsyncSIEMDispatcher is not None else None

    state = evt_logger.load_state()
    recent = [0] * policy.window
    adaptive_history: list[float] = []
    last_block_t = 0.0
    last_idle_print = 0.0
    last_health_write = 0.0

    while True:
        now = time.time()
        maybe_reload_config()
        evt_logger.rotate_alerts()

        # ── Wait for data ────────────────────────────────────────────────
        if not DATA_CSV.exists():
            if now - last_idle_print > PRINT_IDLE_SECS:
                print(Style.DIM + "…waiting for data/features.csv" + Style.RESET_ALL)
                last_idle_print = now
            time.sleep(0.4)
            continue

        # ── Read CSV with O(1) byte-offset seek ──────────────────────────
        saved_row_offset = int(state.get("offset_rows", 0))
        saved_byte_offset = int(state.get("byte_offset", 0))

        try:
            csv_mtime = DATA_CSV.stat().st_mtime
            if fast_reader is not None:
                batch, new_row_offset, new_byte_offset = fast_reader.read_new_rows(
                    saved_row_offset=saved_row_offset,
                    saved_byte_offset=saved_byte_offset,
                )
            else:
                df = pd.read_csv(DATA_CSV)
                if saved_row_offset > len(df):
                    saved_row_offset = 0
                batch = df.iloc[saved_row_offset:].copy()
                new_row_offset = len(df)
                new_byte_offset = 0
        except Exception as e:
            evt_logger.log_internal("read_error", "failed_to_read_features_csv", error=str(e))
            time.sleep(0.4)
            continue

        # If file was truncated/rotated
        if new_row_offset < saved_row_offset:
            evt_logger.log_internal(
                "csv_rotated", "features_csv_truncated_or_rotated",
                old_offset=saved_row_offset, new_len=new_row_offset,
            )

        # Nothing new?
        if batch.empty:
            if now - last_idle_print > PRINT_IDLE_SECS:
                print(Style.DIM + "…idle (no new rows)" + Style.RESET_ALL)
                last_idle_print = now
            if now - last_health_write > 2.0:
                evt_logger.write_health(now, state, cfg_mtime, policy.dry_run)
                last_health_write = now
            time.sleep(0.4)
            continue

        # Schema check
        if not has_required_cols(batch):
            missing = list(set(mgr.features) - set(batch.columns))
            msg = f"Missing columns: {missing} — waiting…"
            print(Fore.YELLOW + f"⚠️  {msg}" + Style.RESET_ALL)
            evt_logger.log_internal("schema_mismatch", msg, missing=missing)
            time.sleep(1.0)
            continue

        # Update offsets (both row and byte offsets)
        state["offset_rows"] = new_row_offset
        state["byte_offset"] = new_byte_offset
        state["csv_mtime"] = csv_mtime
        evt_logger.save_state(state)

        # Clean → numeric only
        before = len(batch)
        batch = to_numeric(batch).dropna(subset=mgr.features)
        dropped = before - len(batch)
        if dropped > 0:
            msg = f"Dropped {dropped} malformed rows"
            print(Fore.YELLOW + f"  {msg}" + Style.RESET_ALL)
            evt_logger.log_internal("dropped_rows", msg, dropped=int(dropped))

        # ── Score each row ───────────────────────────────────────────────
        for idx, row in batch.iterrows():
            x = pd.DataFrame([row[mgr.features]])

            # 1. Device-aware model selection
            meta_ctx = read_window_meta()
            top_src = meta_ctx.get("top_src_ip")
            active_model, device_type = mgr.select_model(top_src)
            if not active_model:
                continue

            # 2. Supervised scoring
            proba = active_model.predict_proba(x)
            pred_label = None
            try:
                vec = proba[0]
                if mgr.classes and isinstance(mgr.classes.get("classes"), list):
                    classes = mgr.classes.get("classes") or []
                    benign_index = int(mgr.classes.get("benign_index", 0) or 0)
                    sup_score = float(1.0 - float(vec[benign_index]))
                    pred_idx = int(getattr(vec, "argmax", lambda: 0)())
                    pred_label = classes[pred_idx] if 0 <= pred_idx < len(classes) else None
                else:
                    sup_score = float(vec[1]) if len(vec) > 1 else float(vec)
                    pred_label = "attack" if sup_score >= policy.threshold else "benign"
            except Exception:
                try:
                    sup_score = float(active_model.predict_proba(x)[0, 1])
                except Exception:
                    sup_score = float(active_model.predict(x)[0])

            # 3. Unsupervised scoring (if enabled)
            unsup_score = 0.0
            unsup_is_anomaly = False
            detection_source = "supervised"

            if mgr.unsup_available and policy.unsup_enabled:
                unsup_score, unsup_is_anomaly = compute_unsupervised_score(
                    x, mgr.unsup_model, mgr.unsup_threshold
                )

            # 4. Temporal Sequence Drift Evaluation (Phase 2 Upgrade)
            temporal_score = 0.0
            temporal_is_anomaly = False
            temp_res = None
            if policy.temporal_enabled:
                temp_res = temporal_detector.update(row[mgr.features], ip=top_src)
                temporal_score = temp_res.temporal_score
                temporal_is_anomaly = temp_res.is_temporal_anomaly

            # 5. Adaptive threshold
            effective_thr = policy.threshold
            adaptive_history.append(sup_score)
            if len(adaptive_history) > policy.adaptive_window:
                adaptive_history.pop(0)

            if policy.use_adaptive:
                effective_thr = compute_adaptive_threshold(
                    adaptive_history,
                    base_threshold=policy.threshold,
                    sensitivity=policy.adaptive_sensitivity,
                    min_threshold=policy.adaptive_min,
                )

            # 6. Hybrid decision with Temporal Boost
            if mgr.unsup_available and policy.unsup_enabled:
                p, is_attack, detection_source = compute_hybrid_decision(
                    sup_score=sup_score,
                    sup_threshold=effective_thr,
                    unsup_score=unsup_score,
                    unsup_is_anomaly=unsup_is_anomaly,
                    mode=policy.hybrid_mode,
                    combine=policy.hybrid_combine,
                    sup_weight=policy.supervised_weight,
                    unsup_weight=policy.unsupervised_weight,
                    temporal_score=temporal_score,
                    temporal_boost_weight=policy.temporal_boost_weight,
                    temporal_is_anomaly=temporal_is_anomaly,
                )
            else:
                p, is_attack, detection_source = compute_hybrid_decision(
                    sup_score=sup_score,
                    sup_threshold=effective_thr,
                    unsup_score=0.0,
                    unsup_is_anomaly=False,
                    mode="supervised",
                    combine="or",
                    sup_weight=1.0,
                    unsup_weight=0.0,
                    temporal_score=temporal_score,
                    temporal_boost_weight=policy.temporal_boost_weight,
                    temporal_is_anomaly=temporal_is_anomaly,
                )

            # Update label based on detection source
            if is_attack and detection_source == "unsupervised":
                pred_label = policy.unsup_only_label
            elif is_attack and detection_source == "both":
                pred_label = "ATTACK (hybrid)"
            elif is_attack and detection_source == "temporal":
                pred_label = "ATTACK (temporal drift)"

            state_txt = "ATTACK" if is_attack else "benign"

            # 7. Attack Taxonomy & Playbook Determination
            attack_category = None
            category_conf = None
            playbook = None

            if is_attack:
                attack_category, category_conf = infer_attack_taxonomy(
                    row=row,
                    x_df=x,
                    detection_source=detection_source,
                    multiclass_model=getattr(mgr, "multiclass_model", None),
                    multiclass_classes=getattr(mgr, "multiclass_classes", None),
                    heuristic_fallback=True,
                    drifting_features=temp_res.drifting_features if temp_res else None,
                )
                pred_label = attack_category

            # 7. XAI explanation
            reason_str = None
            if is_attack and EXPLAINER:
                if hasattr(EXPLAINER, "model") and EXPLAINER.model != active_model:
                    EXPLAINER.model = active_model
                reason_str = EXPLAINER.explain_row(x)

            # 8. Rolling window
            recent.append(1 if is_attack else 0)
            if len(recent) > policy.window:
                recent = recent[-policy.window:]
            hits = sum(recent)

            # 9. Policy evaluation
            response_type, should_block = evaluate_response(
                is_attack, p, hits, policy, last_block_t
            )
            debug_reason = debug_no_block_reason(
                is_attack, response_type, hits, p, policy, last_block_t
            )

            # 10. Enrichment (IP, threat intel, per-IP baseline, playbook)
            meta_ctx = read_window_meta()
            ip_to_block = meta_ctx.get("top_src_ip")
            device_type = meta_ctx.get("device_type")

            threat_ctx = None
            if ip_to_block:
                threat_ctx = THREAT_INTEL.enrich_ip(ip_to_block)

            if is_attack and attack_category:
                playbook = get_remediation_playbook(attack_category, src_ip=ip_to_block)

            ip_anom_flag = None
            if ip_to_block and "bytes_total" in row:
                ip_anom_flag = ip_tracker.update_and_check(
                    ip_to_block,
                    float(row.get("bytes_total", 0.0)),
                    policy.ip_anomaly_z,
                )
                if ip_anom_flag:
                    evt_logger.log_internal(
                        "ip_anomaly", "per-ip-bytes-anomaly",
                        ip=ip_to_block,
                        bytes_total=float(row.get("bytes_total", 0.0)),
                    )

            # 11. Execute block
            action = "NONE"
            if should_block and state.get("last_block_idx") != int(idx):
                ok, how = block_ip_wrapper(ip_to_block, policy.dry_run, severity=response_type.lower())
                last_block_t = time.time()
                state["last_block_idx"] = int(idx)
                evt_logger.save_state(state)
                action = f"BLOCK-{response_type}"
                print(Fore.YELLOW + f"🚫 {action} triggered — ip={ip_to_block} via {how}, ok={ok}" + Style.RESET_ALL)

                audit_logger.warning(
                    f"BLOCK action: ip={ip_to_block}, severity={response_type}, "
                    f"score={p:.3f}, dry_run={policy.dry_run}, success={ok}"
                )
                logger.info(f"Block triggered for {ip_to_block} (score={p:.3f}, severity={response_type})")

                evt_logger.log_internal(
                    "block_action", "block_triggered",
                    ip=ip_to_block, severity=response_type,
                    ok=bool(ok), how=how, dry_run=bool(policy.dry_run), score=float(p),
                    taxonomy=attack_category,
                )

                # Send alert via configured channels
                if ALERTING_AVAILABLE:
                    attack_type = attack_category or (classify_attack_heuristic(row) if is_attack else "Unknown")
                    pb_action = playbook.get("recommended_action") if playbook else "N/A"
                    send_alert(
                        title=f"Attack Blocked: {attack_type}",
                        message=f"Category: {attack_type}\nScore: {p:.2%}\nIP: {ip_to_block}\nSeverity: {response_type}\nDry Run: {policy.dry_run}\nPlaybook: {pb_action}",
                        severity="high" if response_type in ("hard", "kill") else "medium",
                        src_ip=ip_to_block,
                    )

            # 12. Console output
            color = Fore.RED if is_attack else Fore.GREEN
            thr_str = f"{effective_thr:.3f}" if policy.use_adaptive else f"{policy.threshold:.2f}"

            if mgr.unsup_available and policy.unsup_enabled and policy.hybrid_mode != "supervised":
                score_str = f"sup={sup_score:.3f} unsup={unsup_score:.3f}"
                if detection_source != "none":
                    score_str += f" [{detection_source}]"
            else:
                score_str = f"score={p:.3f}"

            print(f"{idx}: {score_str} (thr={thr_str}) → {color}{state_txt}{Style.RESET_ALL} (hits last{policy.window}={hits})")
            if action == "NONE" and debug_reason:
                print(Style.DIM + f"   └─ no BLOCK: {debug_reason}" + Style.RESET_ALL)
            if reason_str:
                print(Fore.MAGENTA + f"   🔍 Why? {reason_str}" + Style.RESET_ALL)
            if attack_category:
                conf_str = f" ({category_conf:.1%})" if category_conf else ""
                print(Fore.BLUE + f"   🏷️  Taxonomy: {attack_category}{conf_str}" + Style.RESET_ALL)
                if playbook:
                    print(Style.CYAN + f"   📋 Playbook: {playbook.get('recommended_action')}" + Style.RESET_ALL)
                    mitre_info = playbook.get("mitre")
                    if mitre_info:
                        print(Fore.CYAN + f"   🎯 MITRE ATT&CK: {mitre_info.get('technique_id')} {mitre_info.get('technique_name')} [{mitre_info.get('tactic_name')}]" + Style.RESET_ALL)
            if detection_source == "unsupervised":
                print(Fore.YELLOW + f"   🔶 Detected by unsupervised model (novel anomaly)" + Style.RESET_ALL)
            if temp_res and temp_res.is_temporal_anomaly:
                print(Fore.MAGENTA + f"   ⏱️  Temporal Sequence Drift: {temp_res.drifting_features} (score={temporal_score:.2f}, boost=+{temp_res.boost:.2f})" + Style.RESET_ALL)

            # 13. Persist event
            logged_evt = evt_logger.log_event(
                idx, p, state_txt, hits, action,
                pred_class=pred_label,
                reason=reason_str,
                effective_thr=effective_thr,
                threat_info=threat_ctx,
                src_ip=ip_to_block,
                ip_anomaly=ip_anom_flag,
                device_type=device_type,
                detection_source=detection_source if mgr.unsup_available and policy.unsup_enabled else None,
                unsup_score=unsup_score if mgr.unsup_available and policy.unsup_enabled else None,
                attack_category=attack_category,
                confidence=category_conf,
                remediation_playbook=playbook,
                temporal_score=temporal_score if policy.temporal_enabled else None,
                temporal_drifting=temp_res.drifting_features if temp_res and temp_res.drifting_features else None,
                mitre=playbook.get("mitre") if playbook else None,
            )

            # 14. Asynchronous Live SIEM Dispatch
            if (
                siem_dispatcher is not None
                and siem_dispatcher.enabled
                and logged_evt
            ):
                if is_attack or action != "NONE" or p >= 0.80:
                    siem_dispatcher.enqueue(logged_evt)

        if now - last_health_write > 2.0:
            evt_logger.write_health(now, state, cfg_mtime, policy.dry_run)
            last_health_write = now

        time.sleep(0.4)


# ── Graceful shutdown ───────────────────────────────────────────────────────

def graceful_shutdown(signum=None, frame=None):
    """Handle graceful shutdown on SIGTERM/SIGINT."""
    signal_name = "SIGTERM" if signum == 15 else "SIGINT" if signum == 2 else str(signum)
    print(Fore.YELLOW + f"\n🛑 Received {signal_name}, shutting down gracefully…" + Style.RESET_ALL)
    logger.info(f"Graceful shutdown initiated (signal={signal_name})")

    # Stop SIEM worker
    try:
        if "siem_dispatcher" in globals() and siem_dispatcher is not None:
            siem_dispatcher.stop(timeout=1.0)
    except Exception:
        pass

    try:
        state = evt_logger.load_state()
        evt_logger.save_state(state)
        logger.info("State saved successfully")
    except Exception as e:
        logger.error(f"Failed to save state: {e}")

    evt_logger.write_shutdown_health(signal_name)
    evt_logger.log_internal("shutdown", "decision_loop_stopped", signal=signal_name)
    audit_logger.info(f"Decision loop shutdown: signal={signal_name}")
    sys.exit(0)


if __name__ == "__main__":
    import signal

    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    try:
        main()
    except KeyboardInterrupt:
        graceful_shutdown(signum=2)
    except Exception as e:
        logger.exception(f"Unexpected error in decision loop: {e}")
        audit_logger.error(f"Decision loop crashed: {e}")
        evt_logger.log_internal("crash", "decision_loop_crashed", error=str(e))
        sys.exit(1)
