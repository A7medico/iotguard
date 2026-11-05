"""
scripts/3_inference/policy.py
-----------------------------------------------------------------------------
IoTGuard Component — Enforcement Policy Engine

Extracted from decision_loop.py for modularity and testability.

Responsibilities:
    - PolicyConfig dataclass holding decision & enforcement parameters
    - load_policy: loads YAML configuration and returns PolicyConfig + mtime
    - evaluate_response: determine response type (NONE / SOFT / HARD / KILL)
    - debug_no_block_reason: diagnostic explanation when blocking is skipped
    - IPBaselineTracker: rolling per-IP baseline anomaly detection (bytes_total)
    - block_ip_wrapper: wrap blocker module with dry-run awareness
-----------------------------------------------------------------------------
"""

import time
import logging
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
import yaml

try:
    from blocker import block_ip as blocker_block_ip
except ImportError:
    def blocker_block_ip(ip: str) -> tuple[bool, str]:
        return False, "blocker-unavailable"

try:
    from playbooks import (
        TAXONOMIES,
        RAW_LABEL_MAP,
        REMEDIATION_PLAYBOOKS,
        DEFAULT_PLAYBOOK,
        normalize_taxonomy,
        get_remediation_playbook,
    )
except ImportError:
    TAXONOMIES = []
    RAW_LABEL_MAP = {}
    REMEDIATION_PLAYBOOKS = {}
    DEFAULT_PLAYBOOK = {}
    def normalize_taxonomy(raw_label, detection_source=None):
        return "ZeroDay-Anomaly"
    def get_remediation_playbook(category, src_ip=None):
        return {}

try:
    from temporal_detector import TemporalDetector, TemporalResult
except ImportError:
    TemporalDetector = None
    TemporalResult = None

logger = logging.getLogger("iotguard.policy")


# ── Configuration Dataclass ──────────────────────────────────────────────────

@dataclass
class PolicyConfig:
    """Holds runtime policy, decision thresholds, and enforcement settings."""

    threshold: float = 0.90
    grace: int = 2
    window: int = 5
    cooldown_sec: float = 5.0
    instant_block: float = 0.95
    dry_run: bool = True
    use_adaptive: bool = False
    adaptive_sensitivity: float = 2.0
    adaptive_history: int = 60
    adaptive_min_threshold: float = 0.50
    hybrid_mode: str = "hybrid"
    unsup_enabled: bool = True
    unsup_threshold: Optional[float] = None
    combine_strategy: str = "or"
    supervised_weight: float = 0.7
    unsupervised_weight: float = 0.3
    unsup_only_label: str = "ANOMALY (unsupervised)"
    ip_anomaly_z: float = 3.0
    temporal_enabled: bool = True
    temporal_window_size: int = 8
    temporal_min_windows: int = 4
    temporal_drift_threshold: float = 0.50
    temporal_boost_weight: float = 0.25

    # Aliases for compatibility across decision loop and API components
    @property
    def adaptive_window(self) -> int:
        return self.adaptive_history

    @adaptive_window.setter
    def adaptive_window(self, val: int) -> None:
        self.adaptive_history = val

    @property
    def adaptive_min(self) -> float:
        return self.adaptive_min_threshold

    @adaptive_min.setter
    def adaptive_min(self, val: float) -> None:
        self.adaptive_min_threshold = val

    @property
    def hybrid_combine(self) -> str:
        return self.combine_strategy

    @hybrid_combine.setter
    def hybrid_combine(self, val: str) -> None:
        self.combine_strategy = val


def load_policy(cfg_path: str = "configs/model.yaml") -> tuple[PolicyConfig, float]:
    """
    Load decision and enforcement policy parameters from YAML config.

    Returns:
        tuple[PolicyConfig, float]: (PolicyConfig instance, file modification timestamp)
    """
    p = Path(cfg_path)
    mtime = 0.0
    cfg: dict = {}

    if p.exists():
        try:
            mtime = p.stat().st_mtime
            with open(p, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"Could not load config file '{cfg_path}': {e}")

    decision = cfg.get("decision", {}) or {}
    hybrid = cfg.get("hybrid", {}) or {}
    unsup = cfg.get("unsupervised", {}) or {}
    temporal = cfg.get("temporal", {}) or {}

    policy = PolicyConfig(
        threshold=float(decision.get("threshold", 0.90)),
        grace=int(decision.get("grace", 2)),
        window=int(decision.get("window", 5)),
        cooldown_sec=float(decision.get("cooldown_sec", 5.0)),
        instant_block=float(decision.get("instant_block", 0.95)),
        dry_run=bool(decision.get("dry_run", True)),
        use_adaptive=bool(decision.get("use_adaptive", False)),
        adaptive_sensitivity=float(decision.get("adaptive_sensitivity", 2.0)),
        adaptive_history=int(decision.get("adaptive_history", decision.get("adaptive_window", 60))),
        adaptive_min_threshold=float(decision.get("adaptive_min_threshold", decision.get("adaptive_min", 0.50))),
        hybrid_mode=str(hybrid.get("mode", "hybrid")),
        unsup_enabled=bool(unsup.get("enabled", True)),
        unsup_threshold=float(hybrid["unsup_threshold"]) if hybrid.get("unsup_threshold") is not None else None,
        combine_strategy=str(hybrid.get("combine_strategy", "or")),
        supervised_weight=float(hybrid.get("supervised_weight", 0.7)),
        unsupervised_weight=float(hybrid.get("unsupervised_weight", 0.3)),
        unsup_only_label=str(hybrid.get("unsup_only_label", "ANOMALY (unsupervised)")),
        ip_anomaly_z=float(decision.get("ip_anomaly_z", 3.0)),
        temporal_enabled=bool(temporal.get("enabled", True)),
        temporal_window_size=int(temporal.get("window_size", 8)),
        temporal_min_windows=int(temporal.get("min_windows", 4)),
        temporal_drift_threshold=float(temporal.get("drift_threshold", 0.50)),
        temporal_boost_weight=float(temporal.get("boost_weight", 0.25)),
    )
    return policy, mtime


# ── Response Evaluation & Debugging ──────────────────────────────────────────

def evaluate_response(
    is_attack: bool,
    score: float,
    hits: int,
    policy: PolicyConfig,
    last_block_time: float,
) -> tuple[str, bool]:
    """
    Decide the enforcement action for the current window.

    Mitigation Tiers:
        - "NONE": Not an attack or criteria not met.
        - "SOFT": Attack detected, grace hits reached, cooldown passed.
        - "HARD": Instant block threshold reached, cooldown passed.
        - "KILL": High critical score (>=0.98), instant drop.

    Returns:
        (response_type, should_block)
    """
    now = time.time()
    time_ok = (now - last_block_time) > policy.cooldown_sec

    response_type = "NONE"
    if is_attack:
        if score >= 0.98:
            response_type = "KILL"
        elif score >= policy.instant_block:
            response_type = "HARD"
        elif hits >= policy.grace and time_ok:
            response_type = "SOFT"

    # Enforce cooldown on instant blocks as well
    if response_type in ("HARD", "KILL") and not time_ok:
        response_type = "NONE"

    should_block = response_type != "NONE"
    return response_type, should_block


def debug_no_block_reason(
    is_attack: bool,
    response_type: str,
    hits: int,
    score: float,
    policy: PolicyConfig,
    last_block_time: float,
) -> Optional[str]:
    """
    Provide human-readable explanation when blocking is not performed.

    Returns:
        Reason string, or None if a block action was taken.
    """
    if response_type != "NONE":
        return None

    now = time.time()
    time_ok = (now - last_block_time) > policy.cooldown_sec

    if not is_attack:
        return "benign"
    if not time_ok:
        cd_str = f"{int(policy.cooldown_sec)}s" if policy.cooldown_sec == int(policy.cooldown_sec) else f"{policy.cooldown_sec}s"
        return f"cooldown {cd_str}"
    return f"below criteria (hits={hits}<{policy.grace}, score={score:.3f}<{policy.instant_block})"


def determine_response(
    is_attack: bool,
    score: float,
    hits: int,
    grace: int,
    instant_block_threshold: float,
    cooldown_sec: float,
    last_block_time: float,
) -> tuple[str, bool, Optional[str]]:
    """Legacy helper for backward compatibility."""
    temp_policy = PolicyConfig(
        grace=grace,
        instant_block=instant_block_threshold,
        cooldown_sec=cooldown_sec,
    )
    resp_type, should_blk = evaluate_response(is_attack, score, hits, temp_policy, last_block_time)
    reason = debug_no_block_reason(is_attack, resp_type, hits, score, temp_policy, last_block_time)
    return resp_type, should_blk, reason


# ── Per-IP Rolling Baseline Tracker ──────────────────────────────────────────

class IPBaselineTracker:
    """Tracks per-IP baseline byte metrics and flags volumetric anomalies via z-score."""

    def __init__(self, maxlen: int = 20, min_samples: int = 5):
        self.maxlen = maxlen
        self.min_samples = min_samples
        self.stats: dict[str, deque] = {}

    def update_and_check(
        self,
        ip: str,
        bytes_total: float,
        z_threshold: float = 3.0,
    ) -> Optional[bool]:
        """
        Track bytes_total for a given IP and test for z-score anomaly.

        Returns:
            None if insufficient history (< min_samples),
            True if anomalous (z >= z_threshold),
            False otherwise.
        """
        if not ip:
            return None

        if ip not in self.stats:
            self.stats[ip] = deque(maxlen=self.maxlen)
        series = self.stats[ip]
        series.append(float(bytes_total))

        if len(series) < self.min_samples:
            return None

        arr = np.array(series, dtype=float)
        mu = float(arr.mean())
        sigma = float(arr.std())
        if sigma <= 0.0 or np.isnan(sigma):
            sigma = 1.0
        z = (series[-1] - mu) / sigma
        return bool(z >= z_threshold)

    def reset(self) -> None:
        """Clear all tracked IP baselines."""
        self.stats.clear()


IP_STATS: dict[str, dict] = {}


def update_ip_baseline(
    ip: str,
    bytes_total: float,
    z_threshold: float = 3.0,
    maxlen: int = 20,
) -> Optional[bool]:
    """Legacy module-level IP baseline tracker."""
    if not ip:
        return None

    stats = IP_STATS.setdefault(ip, {"bytes": deque(maxlen=maxlen)})
    series = stats["bytes"]
    series.append(float(bytes_total))

    if len(series) < 5:
        return None

    arr = np.array(series, dtype=float)
    mu = float(arr.mean())
    sigma = float(arr.std())
    if sigma <= 0.0 or np.isnan(sigma):
        sigma = 1.0
    z = (series[-1] - mu) / sigma
    return bool(z >= z_threshold)


# ── Block Wrapper ────────────────────────────────────────────────────────────

def block_ip_wrapper(
    ip: str,
    dry_run: bool,
    severity: str = "hard",
) -> tuple[bool, str]:
    """
    Wrapper around blocker.py that respects dry_run mode and severity.

    Severity: 'soft' (temp), 'hard' (permanent), 'kill' (connection reset)
    """
    if not ip:
        return False, "no-ip"
    if dry_run:
        return True, f"dry-run-{severity}"

    return blocker_block_ip(ip)
