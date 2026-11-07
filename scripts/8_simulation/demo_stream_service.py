"""
scripts/8_simulation/demo_stream_service.py
-----------------------------------------------------------------------------
IoTGuard Enterprise — Demo Traffic Simulation Service (Layer 3 Simulation)

Provides background synthetic flow generation (benign device telemetry and
attack scenario injection) directly into data/features.csv without requiring
Scapy or raw packet captures.
-----------------------------------------------------------------------------
"""

import os
import time
import random
import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("demo_stream_service")

# Data path
DATA_DIR = Path("data")
FEATURES_CSV = DATA_DIR / "features.csv"
FEATURES_HEADER = (
    "flows,bytes_total,pkts_total,syn_ratio,mean_bytes_flow,ack_ratio,"
    "fin_ratio,rst_ratio,http_ratio,tcp_ratio,protocol_diversity,std_bytes,iat_mean\n"
)

# ── Attack signature profiles for feature-injection simulation ───────────────
_ATTACK_PROFILES: Dict[str, Dict[str, Any]] = {
    "syn": {
        "name": "SYN Flood",
        "rows": 8,
        "gen": lambda: {
            "flows": random.randint(40, 80),
            "bytes_total": random.randint(20000, 60000),
            "pkts_total": random.randint(200, 500),
            "syn_ratio": round(random.uniform(0.85, 0.99), 2),
            "mean_bytes_flow": random.randint(300, 800),
            "ack_ratio": 0.0,
            "fin_ratio": 0.0,
            "rst_ratio": round(random.uniform(0.0, 0.1), 2),
            "http_ratio": 0.0,
            "tcp_ratio": 1.0,
            "protocol_diversity": 1,
            "std_bytes": round(random.uniform(0, 10), 2),
            "iat_mean": round(random.uniform(0.0001, 0.002), 6),
        },
    },
    "udp": {
        "name": "UDP Flood",
        "rows": 8,
        "gen": lambda: {
            "flows": random.randint(50, 100),
            "bytes_total": random.randint(40000, 120000),
            "pkts_total": random.randint(400, 1000),
            "syn_ratio": 0.0,
            "mean_bytes_flow": random.randint(600, 1200),
            "ack_ratio": 0.0,
            "fin_ratio": 0.0,
            "rst_ratio": 0.0,
            "http_ratio": 0.0,
            "tcp_ratio": 0.0,
            "protocol_diversity": 1,
            "std_bytes": round(random.uniform(0, 20), 2),
            "iat_mean": round(random.uniform(0.0001, 0.001), 6),
        },
    },
    "http": {
        "name": "HTTP Slowloris",
        "rows": 6,
        "gen": lambda: {
            "flows": random.randint(30, 60),
            "bytes_total": random.randint(5000, 15000),
            "pkts_total": random.randint(100, 300),
            "syn_ratio": round(random.uniform(0.3, 0.5), 2),
            "mean_bytes_flow": random.randint(100, 300),
            "ack_ratio": round(random.uniform(0.1, 0.3), 2),
            "fin_ratio": 0.0,
            "rst_ratio": 0.0,
            "http_ratio": round(random.uniform(0.8, 1.0), 2),
            "tcp_ratio": 1.0,
            "protocol_diversity": 1,
            "std_bytes": round(random.uniform(50, 200), 2),
            "iat_mean": round(random.uniform(0.5, 5.0), 6),
        },
    },
    "scan": {
        "name": "Port Scan",
        "rows": 5,
        "gen": lambda: {
            "flows": random.randint(60, 150),
            "bytes_total": random.randint(3000, 10000),
            "pkts_total": random.randint(120, 300),
            "syn_ratio": round(random.uniform(0.7, 0.95), 2),
            "mean_bytes_flow": random.randint(40, 80),
            "ack_ratio": 0.0,
            "fin_ratio": 0.0,
            "rst_ratio": round(random.uniform(0.5, 0.9), 2),
            "http_ratio": 0.0,
            "tcp_ratio": 1.0,
            "protocol_diversity": 1,
            "std_bytes": round(random.uniform(0, 5), 2),
            "iat_mean": round(random.uniform(0.001, 0.01), 6),
        },
    },
    "botnet": {
        "name": "IoT Botnet C2",
        "rows": 6,
        "gen": lambda: {
            "flows": random.randint(15, 35),
            "bytes_total": random.randint(8000, 25000),
            "pkts_total": random.randint(60, 150),
            "syn_ratio": round(random.uniform(0.4, 0.7), 2),
            "mean_bytes_flow": random.randint(200, 600),
            "ack_ratio": round(random.uniform(0.2, 0.5), 2),
            "fin_ratio": round(random.uniform(0.0, 0.1), 2),
            "rst_ratio": 0.0,
            "http_ratio": round(random.uniform(0.0, 0.2), 2),
            "tcp_ratio": round(random.uniform(0.7, 1.0), 2),
            "protocol_diversity": random.randint(1, 2),
            "std_bytes": round(random.uniform(100, 500), 2),
            "iat_mean": round(random.uniform(0.01, 0.1), 6),
        },
    },
    "exfil": {
        "name": "Data Exfiltration",
        "rows": 5,
        "gen": lambda: {
            "flows": random.randint(3, 8),
            "bytes_total": random.randint(100000, 500000),
            "pkts_total": random.randint(500, 2000),
            "syn_ratio": round(random.uniform(0.05, 0.15), 2),
            "mean_bytes_flow": random.randint(15000, 60000),
            "ack_ratio": round(random.uniform(0.3, 0.6), 2),
            "fin_ratio": round(random.uniform(0.1, 0.3), 2),
            "rst_ratio": 0.0,
            "http_ratio": round(random.uniform(0.0, 0.3), 2),
            "tcp_ratio": 1.0,
            "protocol_diversity": random.randint(1, 2),
            "std_bytes": round(random.uniform(500, 5000), 2),
            "iat_mean": round(random.uniform(0.001, 0.01), 6),
        },
    },
}


# ── Simulation Controller State ──────────────────────────────────────────────
_sim_lock = threading.Lock()
_sim_running = True  # Streaming enabled by default
_sim_stats = {
    "rows_written": 0,
    "attacks_injected": 0,
    "last_attack_type": None,
    "start_time": time.time(),
}


def generate_sim_benign_row() -> list:
    """Generate realistic multi-device benign flow."""
    dev = random.choice(["sensor", "camera", "workstation", "doorlock"])
    if dev == "sensor":
        flows = random.randint(2, 6)
        pkts = flows * random.randint(3, 8)
        bytes_total = pkts * random.randint(50, 90)
        syn_ratio = round(random.uniform(0.08, 0.18), 2)
        ack_ratio = round(random.uniform(0.40, 0.55), 2)
        fin_ratio = round(random.uniform(0.10, 0.20), 2)
        rst_ratio = 0.0
        http_ratio = round(random.uniform(0.10, 0.40), 2)
        tcp_ratio = 1.0
        proto_div = 1
        std_bytes = round(random.uniform(10, 30), 2)
        iat_mean = round(random.uniform(0.15, 0.45), 6)
    elif dev == "camera":
        flows = random.randint(8, 20)
        pkts = flows * random.randint(30, 80)
        bytes_total = pkts * random.randint(600, 1100)
        syn_ratio = round(random.uniform(0.02, 0.06), 2)
        ack_ratio = round(random.uniform(0.48, 0.55), 2)
        fin_ratio = round(random.uniform(0.01, 0.04), 2)
        rst_ratio = 0.0
        http_ratio = 0.0
        tcp_ratio = round(random.uniform(0.80, 0.95), 2)
        proto_div = 2
        std_bytes = round(random.uniform(80, 180), 2)
        iat_mean = round(random.uniform(0.005, 0.02), 6)
    elif dev == "workstation":
        flows = random.randint(12, 30)
        pkts = flows * random.randint(10, 25)
        bytes_total = pkts * random.randint(180, 450)
        syn_ratio = round(random.uniform(0.10, 0.22), 2)
        ack_ratio = round(random.uniform(0.38, 0.48), 2)
        fin_ratio = round(random.uniform(0.08, 0.16), 2)
        rst_ratio = round(random.uniform(0.01, 0.03), 2)
        http_ratio = round(random.uniform(0.30, 0.60), 2)
        tcp_ratio = round(random.uniform(0.90, 0.98), 2)
        proto_div = 3
        std_bytes = round(random.uniform(40, 110), 2)
        iat_mean = round(random.uniform(0.02, 0.08), 6)
    else:
        flows = random.randint(1, 4)
        pkts = flows * random.randint(2, 5)
        bytes_total = pkts * random.randint(45, 75)
        syn_ratio = round(random.uniform(0.10, 0.25), 2)
        ack_ratio = round(random.uniform(0.35, 0.50), 2)
        fin_ratio = round(random.uniform(0.12, 0.25), 2)
        rst_ratio = 0.0
        http_ratio = 0.0
        tcp_ratio = 1.0
        proto_div = 1
        std_bytes = round(random.uniform(5, 20), 2)
        iat_mean = round(random.uniform(0.20, 0.60), 6)

    mean_bytes = int(bytes_total / max(flows, 1))
    return [
        flows, bytes_total, pkts, syn_ratio, mean_bytes, ack_ratio,
        fin_ratio, rst_ratio, http_ratio, tcp_ratio, proto_div, std_bytes, iat_mean
    ]


def generate_sim_attack_row(attack_type: str = "syn") -> list:
    """Generate attack pattern row."""
    t = (attack_type or "syn").lower()
    if "udp" in t:
        flows = random.randint(80, 200)
        pkts = flows * random.randint(15, 40)
        bytes_total = pkts * random.randint(400, 750)
        syn_ratio = 0.0
        ack_ratio = 0.0
        fin_ratio = 0.0
        rst_ratio = 0.0
        http_ratio = 0.0
        tcp_ratio = 0.0
        proto_div = 1
        std_bytes = round(random.uniform(0, 10), 2)
        iat_mean = round(random.uniform(0.00005, 0.0004), 6)
    elif "scan" in t or "port" in t:
        flows = random.randint(50, 120)
        pkts = flows * 2
        bytes_total = pkts * 44
        syn_ratio = round(random.uniform(0.75, 0.95), 2)
        ack_ratio = 0.0
        fin_ratio = 0.0
        rst_ratio = round(random.uniform(0.20, 0.50), 2)
        http_ratio = 0.0
        tcp_ratio = 1.0
        proto_div = 1
        std_bytes = round(random.uniform(0, 2), 2)
        iat_mean = round(random.uniform(0.001, 0.008), 6)
    elif "http" in t or "slow" in t:
        flows = random.randint(30, 70)
        pkts = flows * random.randint(10, 25)
        bytes_total = pkts * random.randint(250, 500)
        syn_ratio = round(random.uniform(0.20, 0.35), 2)
        ack_ratio = round(random.uniform(0.38, 0.48), 2)
        fin_ratio = round(random.uniform(0.12, 0.25), 2)
        rst_ratio = round(random.uniform(0.02, 0.06), 2)
        http_ratio = round(random.uniform(0.85, 1.0), 2)
        tcp_ratio = 1.0
        proto_div = 1
        std_bytes = round(random.uniform(25, 75), 2)
        iat_mean = round(random.uniform(0.001, 0.006), 6)
    elif "exfil" in t:
        flows = random.randint(4, 18)
        pkts = flows * random.randint(50, 120)
        bytes_total = pkts * random.randint(800, 1350)
        syn_ratio = round(random.uniform(0.04, 0.12), 2)
        ack_ratio = round(random.uniform(0.42, 0.54), 2)
        fin_ratio = round(random.uniform(0.02, 0.06), 2)
        rst_ratio = 0.0
        http_ratio = round(random.uniform(0.20, 0.60), 2)
        tcp_ratio = 1.0
        proto_div = 1
        std_bytes = round(random.uniform(10, 35), 2)
        iat_mean = round(random.uniform(0.002, 0.015), 6)
    else:  # SYN flood / Botnet
        flows = random.randint(60, 150)
        pkts = flows * random.randint(3, 6)
        bytes_total = pkts * random.randint(54, 66)
        syn_ratio = round(random.uniform(0.85, 0.99), 2)
        ack_ratio = 0.0
        fin_ratio = 0.0
        rst_ratio = 0.0
        http_ratio = 0.0
        tcp_ratio = 1.0
        proto_div = 1
        std_bytes = round(random.uniform(0, 5), 2)
        iat_mean = round(random.uniform(0.0001, 0.0008), 6)

    mean_bytes = int(bytes_total / max(flows, 1))
    return [
        flows, bytes_total, pkts, syn_ratio, mean_bytes, ack_ratio,
        fin_ratio, rst_ratio, http_ratio, tcp_ratio, proto_div, std_bytes, iat_mean
    ]


def write_feature_row(row: list, csv_path: Optional[Path] = None) -> None:
    """Append a single feature row into features.csv."""
    path = csv_path or FEATURES_CSV
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.stat().st_size == 0:
        path.write_text(FEATURES_HEADER, encoding="utf-8")
    with path.open("a", encoding="utf-8") as f:
        f.write("{},{},{},{:.2f},{},{:.2f},{:.2f},{:.2f},{:.2f},{:.2f},{},{:.2f},{:.6f}\n".format(*row))


def sim_background_loop() -> None:
    """Background simulator thread generating normal stream."""
    while True:
        with _sim_lock:
            running = _sim_running
        if running:
            try:
                # 98% clean benign device telemetry, 2% rare baseline anomaly
                is_attack = random.random() < 0.02
                row = generate_sim_attack_row("syn") if is_attack else generate_sim_benign_row()
                with _sim_lock:
                    write_feature_row(row)
                    _sim_stats["rows_written"] += 1
            except Exception as e:
                logger.debug(f"Simulator error: {e}")
        time.sleep(1.0)


# Thread instance
_sim_thread: Optional[threading.Thread] = None


def ensure_simulator_started() -> None:
    """Ensure background simulator thread is running."""
    global _sim_thread
    with _sim_lock:
        if _sim_thread is None or not _sim_thread.is_alive():
            _sim_thread = threading.Thread(target=sim_background_loop, daemon=True)
            _sim_thread.start()


def get_simulation_status() -> Dict[str, Any]:
    """Return status of live demo simulator."""
    with _sim_lock:
        return {
            "running": _sim_running,
            "stats": dict(_sim_stats),
        }


def start_simulation() -> None:
    """Start or resume the live feature stream."""
    global _sim_running
    with _sim_lock:
        _sim_running = True
    ensure_simulator_started()
    logger.info("Demo Simulator Started")


def stop_simulation() -> None:
    """Stop or pause the live feature stream."""
    global _sim_running
    with _sim_lock:
        _sim_running = False
    logger.info("Demo Simulator Paused")


def inject_attack_burst(attack_type: str = "syn") -> Tuple[str, list]:
    """Immediately inject a chosen cyber attack scenario row."""
    row = generate_sim_attack_row(attack_type)
    with _sim_lock:
        write_feature_row(row)
        _sim_stats["attacks_injected"] += 1
        _sim_stats["last_attack_type"] = attack_type
    logger.info(f"Injected attack pattern: {attack_type}")
    return attack_type, row


def simulate_attack_features(attack_type: str = "syn") -> Tuple[bool, Optional[str], int, Optional[str]]:
    """
    Inject full attack profile rows directly into data/features.csv.
    Returns (ok, attack_name, rows_written, error_message).
    """
    profile = _ATTACK_PROFILES.get(attack_type)
    if not profile:
        return False, None, 0, f"Unknown attack type: {attack_type}. Available: {list(_ATTACK_PROFILES.keys())}"

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not FEATURES_CSV.exists() or FEATURES_CSV.stat().st_size == 0:
        FEATURES_CSV.write_text(FEATURES_HEADER, encoding="utf-8")

    rows_written = 0
    with FEATURES_CSV.open("a", encoding="utf-8") as f:
        for _ in range(profile["rows"]):
            row_data = profile["gen"]()
            line = ",".join(str(row_data[k]) for k in [
                "flows", "bytes_total", "pkts_total", "syn_ratio", "mean_bytes_flow",
                "ack_ratio", "fin_ratio", "rst_ratio", "http_ratio", "tcp_ratio",
                "protocol_diversity", "std_bytes", "iat_mean"
            ])
            f.write(line + "\n")
            rows_written += 1

    logger.info(f"Simulated {profile['name']}: injected {rows_written} attack rows into features.csv")
    return True, profile["name"], rows_written, None


# Backward-compatible private aliases
_generate_sim_benign_row = generate_sim_benign_row
_generate_sim_attack_row = generate_sim_attack_row
_write_feature_row = write_feature_row
_sim_background_loop = sim_background_loop

# Start background thread automatically
ensure_simulator_started()

