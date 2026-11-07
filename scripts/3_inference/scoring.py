"""
scripts/3_inference/scoring.py
-----------------------------------------------------------------------------
IoTGuard Component — Model Scoring & Adaptive Threshold

Extracted from decision_loop.py for modularity and testability.

Responsibilities:
    - Load and manage supervised/unsupervised models
    - Compute supervised scores (LightGBM predict_proba)
    - Compute unsupervised anomaly scores (IsolationForest)
    - Combine scores via hybrid decision logic
    - Adaptive threshold computation
    - Heuristic attack classification
-----------------------------------------------------------------------------
"""

import json
import os
import sys
import logging
from pathlib import Path
from typing import Optional, Union, List, Tuple, Dict, Any

_scripts_dir = Path(__file__).resolve().parent.parent
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))
from path_setup import configure_paths
configure_paths()

import numpy as np
import pandas as pd
import yaml
from joblib import load

logger = logging.getLogger("iotguard.scoring")


# ── Feature defaults ────────────────────────────────────────────────────────
DEFAULT_FEATURES = [
    "flows", "bytes_total", "pkts_total", "syn_ratio", "mean_bytes_flow",
    "ack_ratio", "fin_ratio", "rst_ratio",
    "http_ratio", "tcp_ratio", "protocol_diversity",
    "std_bytes", "iat_mean",
]


# ── Model Manager ───────────────────────────────────────────────────────────
class ModelManager:
    """
    Centralised loader and registry for all IoTGuard ML models.

    Holds:
        - Supervised models dict  (keyed by env name: 'iot', 'it')
        - Unsupervised model      (IsolationForest)
        - Feature list
        - Class mapping
        - Device map
    """

    def __init__(self, cfg_path: str = "configs/model.yaml"):
        self.cfg_path = Path(cfg_path)
        self._cfg: dict = {}
        self.features: list[str] = []
        self.models: dict = {}
        self.classes: Optional[dict] = None

        # Unsupervised & Tri-Modal Zero-Day Engine
        self.unsup_model = None
        self.unsup_threshold: Optional[float] = None
        self.unsup_available: bool = False
        self.zero_day_engine = None

        # Multi-class attack taxonomy model
        self.multiclass_model = None
        self.multiclass_classes: list[str] = []
        self.multiclass_available: bool = False

        # Device mapping
        self.device_map: dict = {}
        self.default_device_type: str = "iot"

        # Load everything
        self._load_config()
        self._load_features()
        self._load_supervised_models()
        self._load_classes()
        self._load_multiclass_model()
        self._load_unsupervised_model()
        self._load_device_map()

    # ── Config ───────────────────────────────────────────────────────────
    def _load_config(self) -> None:
        try:
            if self.cfg_path.exists():
                self._cfg = yaml.safe_load(
                    self.cfg_path.read_text(encoding="utf-8")
                ) or {}
        except Exception as e:
            logger.warning(f"Could not load config: {e}")

    def reload_config(self) -> dict:
        """Hot-reload the YAML config and return it."""
        self._load_config()
        return self._cfg

    @property
    def config(self) -> dict:
        return self._cfg

    # ── Features ─────────────────────────────────────────────────────────
    def _load_features(self) -> None:
        env_mode = os.getenv("IOTGUARD_ENV", "iot").lower()
        models_cfg = self._cfg.get("models", {})
        env_cfg = models_cfg.get(env_mode, {})
        meta_path = Path(env_cfg.get("meta", "models/model_meta.json"))

        try:
            if meta_path.exists():
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                self.features = meta.get("features", [])
                logger.info(f"Loaded features from {meta_path}")
        except Exception as e:
            logger.warning(f"Could not load model meta: {e}")

        if not self.features:
            self.features = list(DEFAULT_FEATURES)

    # ── Supervised models ────────────────────────────────────────────────
    def _load_supervised_models(self) -> None:
        models_cfg = self._cfg.get("models", {})
        if not models_cfg:
            models_cfg = {"iot": {"path": "models/lightgbm.joblib", "threshold": 0.90}}

        for name, info in models_cfg.items():
            path = Path(info.get("path", ""))
            if path.exists():
                try:
                    self.models[name] = load(path)
                    logger.info(f"Loaded model '{name}' from {path}")
                except Exception as e:
                    logger.error(f"Failed to load model '{name}': {e}")

    # ── Classes ──────────────────────────────────────────────────────────
    def _load_classes(self) -> None:
        try:
            cj = Path("models/classes.json")
            if cj.exists():
                self.classes = json.loads(cj.read_text(encoding="utf-8"))
        except Exception:
            self.classes = None

    # ── Multiclass Attack Taxonomy Model ──────────────────────────────────
    def _load_multiclass_model(self) -> None:
        mc_path = Path("models/multiclass.joblib")
        classes_path = Path("models/multiclass_classes.json")
        if not classes_path.exists():
            classes_path = Path("models/classes.json")

        try:
            if mc_path.exists():
                self.multiclass_model = load(mc_path)
                if classes_path.exists():
                    data = json.loads(classes_path.read_text(encoding="utf-8"))
                    self.multiclass_classes = data.get("classes", [])
                self.multiclass_available = True
                logger.info(
                    f"Loaded multiclass taxonomy model from {mc_path} with {len(self.multiclass_classes)} classes"
                )
        except Exception as e:
            logger.warning(f"Could not load multiclass model: {e}")
            self.multiclass_available = False

    # ── Unsupervised & Tri-Modal Zero-Day Engine ────────────────────────
    def _load_unsupervised_model(self) -> None:
        try:
            from zero_day_engine import build_or_load_zero_day_engine
        except ImportError:
            build_or_load_zero_day_engine = None

        unsup_meta = Path("models/unsup_meta.json")
        default_thr = 0.65
        if unsup_meta.exists():
            try:
                meta = json.loads(unsup_meta.read_text(encoding="utf-8"))
                default_thr = float(meta.get("threshold", 0.65))
            except Exception:
                pass

        if build_or_load_zero_day_engine is not None:
            try:
                self.zero_day_engine = build_or_load_zero_day_engine(threshold=default_thr)
                self.unsup_model = self.zero_day_engine
                self.unsup_threshold = default_thr
                self.unsup_available = True
                logger.info(
                    f"Loaded Tri-Modal ZeroDayAnomalyEngine (threshold={self.unsup_threshold:.4f})"
                )
                return
            except Exception as e:
                logger.warning(f"Could not load ZeroDayAnomalyEngine, falling back to IsoForest: {e}")

        unsup_path = Path("models/unsup_isoforest.joblib")
        try:
            if unsup_path.exists():
                self.unsup_model = load(unsup_path)
                self.unsup_threshold = default_thr
                self.unsup_available = True
                logger.info(
                    f"Loaded unsupervised model (threshold={self.unsup_threshold:.4f})"
                )
        except Exception as e:
            logger.warning(f"Could not load unsupervised model: {e}")

    # ── Device map ───────────────────────────────────────────────────────
    def _load_device_map(self) -> None:
        devices_cfg = Path("configs/devices.yaml")
        try:
            if devices_cfg.exists():
                d = yaml.safe_load(devices_cfg.read_text(encoding="utf-8")) or {}
                self.device_map = d.get("device_map", {})
                self.default_device_type = d.get("default_type", "iot")
        except Exception:
            pass

    # ── Model selection ──────────────────────────────────────────────────
    def select_model(self, src_ip: Optional[str] = None):
        """Pick the right model based on device type mapping."""
        device_type = self.default_device_type
        if src_ip:
            device_type = self.device_map.get(src_ip, self.default_device_type)

        model = self.models.get(device_type)
        if not model:
            model = self.models.get("iot") or next(iter(self.models.values()), None)
        return model, device_type


# ── Scoring functions ───────────────────────────────────────────────────────

def supervised_score(
    x: pd.DataFrame,
    active_model,
    threshold: float,
    classes: Optional[dict] = None,
) -> tuple[float, Optional[str]]:
    """
    Compute P(attack) using the supervised model.

    Returns:
        (score, pred_label)
    """
    proba = active_model.predict_proba(x)
    pred_label = None
    try:
        vec = proba[0]
        if classes and isinstance(classes.get("classes"), list):
            cls_list = classes.get("classes") or []
            benign_index = int(classes.get("benign_index", 0) or 0)
            score = float(1.0 - float(vec[benign_index]))
            pred_idx = int(getattr(vec, "argmax", lambda: 0)())
            pred_label = cls_list[pred_idx] if 0 <= pred_idx < len(cls_list) else None
        else:
            score = float(vec[1]) if len(vec) > 1 else float(vec)
            pred_label = "attack" if score >= threshold else "benign"
    except Exception:
        try:
            score = float(active_model.predict_proba(x)[0, 1])
        except Exception:
            score = float(active_model.predict(x)[0])
    return score, pred_label


def classify_attack_heuristic(row: pd.Series) -> str:
    """
    Infer attack type based on feature values if model is generic binary.
    """
    syn = float(row.get("syn_ratio", 0))
    rst = float(row.get("rst_ratio", 0))
    http = float(row.get("http_ratio", 0))
    bytes_t = float(row.get("bytes_total", 0))
    pkts = float(row.get("pkts_total", 0))
    mean_b = float(row.get("mean_bytes_flow", 0))
    flows = float(row.get("flows", 0))

    if http > 0.5:
        return "Web Attack (HTTP)"
    if syn > 0.6:
        return "DDoS: SYN Flood"
    if rst > 0.5:
        return "Recon: Port Scan (RST)"
    if pkts < 3 and flows > 20:
        return "Recon: Port Scan (Stealth)"
    if bytes_t > 5_000_000 or pkts > 10_000:
        return "DDoS: Volumetric (Mirai/UDP)"
    if mean_b > 5000 and syn < 0.1:
        return "Exfiltration / Upload"
    return "General Anomaly"


def compute_adaptive_threshold(
    scores: list[float],
    base_threshold: float,
    sensitivity: float,
    min_threshold: float,
    max_threshold: float = 0.92,
) -> float:
    """
    Compute an adaptive threshold from recent scores.

    - If there are fewer than 10 scores, returns base_threshold.
    - Otherwise: mean + sensitivity * std, bounded between min_threshold and max_threshold.
      Never drops below base_threshold, and never exceeds max_threshold.
    """
    if len(scores) < 10:
        return float(base_threshold)
    arr = np.array(scores, dtype=float)
    mu = float(arr.mean())
    sigma = float(arr.std())
    dyn_thr = mu + (sensitivity * sigma)
    dyn_thr = max(dyn_thr, float(min_threshold))
    dyn_thr = min(dyn_thr, float(max_threshold))
    return max(float(base_threshold), dyn_thr)


def compute_unsupervised_score(
    x: pd.DataFrame,
    model,
    threshold: float,
    return_contributors: bool = False,
) -> tuple[float, bool] | tuple[float, bool, list[tuple[str, float]]]:
    """
    Compute anomaly score using the unsupervised IsolationForest model or
    the Tri-Modal ZeroDayAnomalyEngine.

    Returns:
        (anomaly_score, is_anomaly) if return_contributors is False
        (anomaly_score, is_anomaly, anomaly_contributors) if return_contributors is True
    """
    if model is None or threshold is None:
        if return_contributors:
            return 0.0, False, []
        return 0.0, False

    try:
        # Check if model is ZeroDayAnomalyEngine or custom multi-detector
        if hasattr(model, "score") and ("ZeroDayAnomalyEngine" in str(type(model)) or hasattr(model, "ecod")):
            score, is_anom, contribs = model.score(x)
            if return_contributors:
                return float(score), bool(is_anom), contribs
            return float(score), bool(is_anom)

        # Standard scikit-learn IsolationForest
        if hasattr(model, "score_samples"):
            raw_score = model.score_samples(x.values)[0]
            anomaly_score = -raw_score
            is_anomaly = anomaly_score >= threshold
            if return_contributors:
                return float(anomaly_score), bool(is_anomaly), []
            return float(anomaly_score), bool(is_anomaly)

        if return_contributors:
            return 0.0, False, []
        return 0.0, False
    except Exception as e:
        logger.warning(f"Unsupervised scoring error: {e}")
        if return_contributors:
            return 0.0, False, []
        return 0.0, False


def compute_hybrid_decision(
    sup_score: float,
    sup_threshold: float,
    unsup_score: float,
    unsup_is_anomaly: bool,
    mode: str,
    combine: str,
    sup_weight: float,
    unsup_weight: float,
    temporal_score: float = 0.0,
    temporal_boost_weight: float = 0.25,
    temporal_is_anomaly: bool = False,
) -> tuple[float, bool, str]:
    """
    Combine supervised, unsupervised, and temporal sequence scores based on hybrid mode.

    The temporal anomaly score boosts the effective risk score when multi-window
    stealth campaigns (e.g. slow scans or creeping connection accumulation) are detected,
    allowing borderline single-window events (e.g. score ~0.75-0.89) to cross the
    decision threshold without elevating false positive rates on benign baselines.

    Returns:
        (effective_score, is_attack, detection_source)
    """
    sup_attack = sup_score >= sup_threshold
    temporal_boost = float(temporal_score * temporal_boost_weight) if temporal_score > 0 else 0.0

    if mode == "supervised":
        effective_score = min(1.0, sup_score + temporal_boost)
        is_attack = effective_score >= sup_threshold
        source = "supervised" if sup_score >= sup_threshold else ("temporal" if is_attack else "none")
        return effective_score, is_attack, source

    if mode == "unsupervised":
        norm_unsup = min(1.0, max(0.0, (unsup_score + 0.5)))
        return norm_unsup, unsup_is_anomaly, "unsupervised" if unsup_is_anomaly else "none"

    # Hybrid mode
    if combine == "or":
        effective_score = min(1.0, sup_score + temporal_boost)
        sup_or_boost = effective_score >= sup_threshold
        is_attack = sup_or_boost or unsup_is_anomaly or temporal_is_anomaly
        if sup_score >= sup_threshold and unsup_is_anomaly:
            source = "both"
        elif sup_score >= sup_threshold:
            source = "supervised"
        elif unsup_is_anomaly:
            source = "unsupervised"
        elif is_attack:
            source = "temporal"
        else:
            source = "none"
        return effective_score, is_attack, source

    elif combine == "and":
        effective_score = min(1.0, sup_score + temporal_boost)
        is_attack = (effective_score >= sup_threshold) and unsup_is_anomaly
        source = "both" if is_attack else "none"
        return effective_score, is_attack, source

    elif combine == "weighted":
        norm_unsup = min(1.0, max(0.0, (unsup_score + 0.5)))
        base_combined = (sup_weight * sup_score) + (unsup_weight * norm_unsup)
        effective_score = min(1.0, base_combined + temporal_boost)
        is_attack = effective_score >= sup_threshold

        if is_attack:
            if base_combined >= sup_threshold:
                if sup_attack and unsup_is_anomaly:
                    source = "both"
                elif sup_attack:
                    source = "supervised"
                else:
                    source = "unsupervised"
            else:
                source = "temporal"
        else:
            source = "none"
        return effective_score, is_attack, source

    # Fallback to supervised
    effective_score = min(1.0, sup_score + temporal_boost)
    is_attack = effective_score >= sup_threshold
    source = "supervised" if sup_score >= sup_threshold else ("temporal" if is_attack else "none")
    return effective_score, is_attack, source


# ── Multiclass Inference & Taxonomy Mapping ─────────────────────────────────

def compute_shannon_entropy(probs: Union[np.ndarray, list[float]], base: float = 2.0) -> tuple[float, float]:
    """
    Compute Shannon entropy H(p) = -sum(p_i * log(p_i)) and normalized entropy H_norm in [0, 1].

    Returns:
        (raw_entropy, normalized_entropy)
    """
    p = np.asarray(probs, dtype=float).ravel()
    p = p[p > 0]
    if len(p) <= 1:
        return 0.0, 0.0
    p = p / np.sum(p)
    log_p = np.log2(p) if base == 2.0 else np.log(p) / np.log(base)
    raw_h = -float(np.sum(p * log_p))
    n_classes = len(probs)
    max_h = float(np.log2(n_classes) if base == 2.0 else np.log(n_classes) / np.log(base))
    norm_h = float(raw_h / max_h) if max_h > 0 else 0.0
    return raw_h, float(np.clip(norm_h, 0.0, 1.0))


def classify_multiclass(
    x: pd.DataFrame,
    model,
    classes: list[str],
) -> tuple[str, float]:
    """
    Predict specific attack taxonomy and confidence using multiclass model.

    Returns:
        (raw_class_name, confidence)
    """
    if model is None or not classes:
        return "General-Anomaly", 0.5
    try:
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(x)[0]
            best_idx = int(np.argmax(proba))
            raw_class = classes[best_idx] if 0 <= best_idx < len(classes) else "unknown"
            conf = float(proba[best_idx])
        else:
            pred = model.predict(x)[0]
            raw_class = str(pred)
            conf = 1.0
        return raw_class, conf
    except Exception as e:
        logger.warning(f"Multiclass inference error: {e}")
        return "General-Anomaly", 0.5


def infer_attack_taxonomy(
    row: pd.Series,
    x_df: pd.DataFrame,
    detection_source: str,
    multiclass_model=None,
    multiclass_classes: Optional[list[str]] = None,
    heuristic_fallback: bool = True,
    drifting_features: Optional[list[str]] = None,
    entropy_threshold: float = 0.70,
    unsup_score: Optional[float] = None,
    sup_score: Optional[float] = None,
    anomaly_contributors: Optional[list[tuple[str, float]]] = None,
) -> tuple[str, float]:
    """
    Determine canonical attack taxonomy and confidence score.

    Tiers:
      1. Unsupervised-only -> ZeroDay-Anomaly
      2. Temporal Sequence Anomaly -> PortScan / DDoS-SYN / BruteForce based on drifting features
      3. Multiclass ML classifier (models/multiclass.joblib) + Shannon Entropy unknown threat detection
      4. Heuristic feature rules fallback -> mapped to canonical taxonomy
    """
    try:
        from playbooks import normalize_taxonomy
    except ImportError:
        def normalize_taxonomy(label, src=None):
            return "ZeroDay-Anomaly" if src == "unsupervised" else "DDoS-SYN"

    if detection_source == "unsupervised":
        return "ZeroDay-Anomaly", 0.92

    if detection_source == "temporal":
        # Identify threat based on temporal drift profile
        drifting = set(drifting_features or [])
        rst = float(row.get("rst_ratio", 0.0))
        syn = float(row.get("syn_ratio", 0.0))
        http = float(row.get("http_ratio", 0.0))

        if "rst_ratio" in drifting or rst >= 0.08:
            return "PortScan", 0.90
        if "http_ratio" in drifting or http >= 0.25:
            return "BruteForce", 0.88
        if "syn_ratio" in drifting or syn >= 0.20:
            return "DDoS-SYN", 0.88
        if "flows" in drifting:
            return "PortScan", 0.85
        return "PortScan", 0.82

    # 1. Evaluate multiclass model if available
    if multiclass_model is not None and multiclass_classes:
        try:
            if hasattr(multiclass_model, "predict_proba"):
                probs = multiclass_model.predict_proba(x_df)[0]
                best_idx = int(np.argmax(probs))
                raw_pred = multiclass_classes[best_idx] if 0 <= best_idx < len(multiclass_classes) else "unknown"
                conf = float(probs[best_idx])

                # Compute Shannon entropy
                raw_h, norm_h = compute_shannon_entropy(probs)

                # High-entropy unknown threat detection:
                # If classifier is uncertain across known classes (H_norm >= entropy_threshold),
                # automatically classify as ZeroDay-Anomaly.
                if norm_h >= entropy_threshold and len(multiclass_classes) > 2:
                    zero_day_conf = round(float(np.clip(max(0.85, 1.0 - float(np.min(probs))), 0.75, 0.98)), 4)
                    logger.info(
                        f"ZeroDay-Anomaly classified via Shannon entropy (H={raw_h:.3f}, H_norm={norm_h:.3f} >= {entropy_threshold:.2f})"
                    )
                    return "ZeroDay-Anomaly", zero_day_conf

                if raw_pred.lower() != "benign":
                    canon = normalize_taxonomy(raw_pred, detection_source)
                    return canon, conf
            else:
                raw_pred, conf = classify_multiclass(x_df, multiclass_model, multiclass_classes)
                if raw_pred.lower() != "benign":
                    canon = normalize_taxonomy(raw_pred, detection_source)
                    return canon, conf
        except Exception as e:
            logger.warning(f"Multiclass inference error: {e}")

    # 2. Heuristic fallback
    if heuristic_fallback:
        h_label = classify_attack_heuristic(row)
        canon = normalize_taxonomy(h_label, detection_source)
        return canon, 0.85

    return "ZeroDay-Anomaly", 0.70
