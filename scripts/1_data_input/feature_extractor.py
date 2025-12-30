"""
scripts/feature_extractor.py
-----------------------------------------------------------------------------
IoTGuard Component — Simulated EVE.json Feature Extraction

Position in pipeline
    Simulated Suricata events (data/fake_eve.json)
        →  [THIS FILE] (parse + aggregate into feature windows)
        →  data/features.csv (consumed by decision_loop.py)
        →  alerts.jsonl / dashboard

High-level responsibilities
    - Tail a simulated Suricata eve.json file for incoming flow events.
    - Parse each JSON line and extract relevant fields:
        * timestamp, source/destination IPs
        * bytes transferred, packet counts
        * TCP connection state (SYN, ACK, FIN, RST flags)
    - Maintain a sliding time window (default 30 seconds) of recent flows.
    - Compute aggregated features for each window:
        * Core: flows, bytes_total, pkts_total, syn_ratio, mean_bytes_flow
        * Flag ratios: ack_ratio, fin_ratio, rst_ratio
        * Protocol: http_ratio, tcp_ratio, protocol_diversity
        * Statistical: std_bytes, iat_mean (inter-arrival time)
    - Append computed features to data/features.csv for ML scoring.

Key inputs
    - data/fake_eve.json: Simulated Suricata eve.json (one JSON object per line)
    - configs/model.yaml: Feature list definition (optional, for alignment)

Key outputs
    - data/features.csv: Streaming feature matrix for the decision loop

Note
    This is a simplified feature extractor for testing/demo purposes.
    For production with real Suricata, use suricata_to_features.py instead.
-----------------------------------------------------------------------------
"""
import json
import time
import os
from pathlib import Path
from collections import deque
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Generator
import pandas as pd
import yaml


# ---------- Configuration ----------
# Directory for data files
DATA = Path("data")
DATA.mkdir(parents=True, exist_ok=True)

# Input: simulated Suricata eve.json
EVE_PATH = DATA / "fake_eve.json"

# Output: features CSV for decision loop
FEAT_CSV = DATA / "features.csv"

# Time window for feature aggregation (seconds)
WINDOW_SEC = 30


# ---------- Feature Schema ----------
def _load_feature_list() -> list:
    """
    Load the canonical feature order from configs/model.yaml if present.
    
    Using a centralized feature list ensures alignment between:
    - Training (train_supervised.py)
    - Feature extraction (this file)
    - Inference (decision_loop.py)
    
    Returns:
        List of feature column names in the correct order.
    """
    cfg_path = Path("configs/model.yaml")
    try:
        if cfg_path.exists():
            cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            feats = cfg.get("features") or []
            if isinstance(feats, list) and feats:
                return [str(f) for f in feats]
    except Exception:
        pass

    # Fallback: keep legacy hard-coded list in sync with training/config.
    # These 13 features are the core schema used by IoTGuard.
    return [
        # Core features (5) - basic flow statistics
        "flows",          # Number of flows in the window
        "bytes_total",    # Total bytes transferred
        "pkts_total",     # Total packets transferred
        "syn_ratio",      # Ratio of SYN connections (new connections)
        "mean_bytes_flow",# Average bytes per flow
        
        # Flag ratios (3) - TCP flag analysis for attack detection
        "ack_ratio",      # ACK flag ratio (established connections)
        "fin_ratio",      # FIN flag ratio (connection terminations)
        "rst_ratio",      # RST flag ratio (connection resets - often attacks)
        
        # Protocol features (3) - traffic composition
        "http_ratio",     # Ratio of HTTP traffic
        "tcp_ratio",      # Ratio of TCP traffic
        "protocol_diversity",  # Number of distinct protocols
        
        # Statistical features (2) - traffic behavior patterns
        "std_bytes",      # Standard deviation of bytes per flow
        "iat_mean",       # Mean inter-arrival time between flows
    ]


# Global feature list (loaded once at module import)
FEATURES = _load_feature_list()

# Ring buffer for storing recent flow records within the time window
# Each entry is a dict with: ts, src, dst, bytes_total, pkts_total, is_syn
buf: deque = deque()


# ---------- Parsing ----------
def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single JSON line from the eve.json file.
    
    This function handles Suricata's flow event format and extracts
    the fields needed for feature computation.
    
    Args:
        line: A single JSON line from eve.json
        
    Returns:
        Dict with parsed fields, or None if not a flow event or parse error.
        
    Expected input format (Suricata eve.json flow event):
        {
            "event_type": "flow",
            "timestamp": "2024-01-01T00:00:00.000000+0000",
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.0.1",
            "flow": {
                "bytes_toserver": 1500,
                "bytes_toclient": 2000,
                "pkts_toserver": 10,
                "pkts_toclient": 15,
                "state": "established"
            }
        }
    """
    try:
        e = json.loads(line)
    except Exception:
        return None
    
    # Only process flow events (skip alerts, dns, http, etc.)
    if e.get("event_type") != "flow":
        return None
    
    f = e.get("flow", {})
    ts = e.get("timestamp")
    
    try:
        # Parse timestamp to epoch (handle Suricata's UTC format)
        ts_epoch = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        # Fallback to current time if parsing fails
        ts_epoch = time.time()

    # Extract byte and packet counts (bidirectional)
    bytes_ts = int(f.get("bytes_toserver", 0) or 0)
    bytes_tc = int(f.get("bytes_toclient", 0) or 0)
    pkts_ts = int(f.get("pkts_toserver", 0) or 0)
    pkts_tc = int(f.get("pkts_toclient", 0) or 0)
    
    # Connection state (used to detect SYN floods and other attacks)
    state = str(f.get("state", "")).upper()

    return {
        "ts": ts_epoch,
        "src": str(e.get("src_ip", "0.0.0.0")),
        "dst": str(e.get("dest_ip", "0.0.0.0")),
        "bytes_total": bytes_ts + bytes_tc,
        "pkts_total": pkts_ts + pkts_tc,
        "is_syn": 1 if "SYN" in state else 0  # Flag new connections
    }


# ---------- CSV Output ----------
def ensure_header():
    """
    Ensure the features CSV file exists with the correct header.
    
    Creates the file with header row if it doesn't exist or is empty.
    This is called once at startup to prepare for appending rows.
    """
    if not FEAT_CSV.exists() or FEAT_CSV.stat().st_size == 0:
        FEAT_CSV.write_text(",".join(FEATURES) + "\n", encoding="utf-8")


def append_row(row_dict: Dict[str, Any]):
    """
    Append a feature row to the CSV file.
    
    Uses direct file writing instead of pandas for performance
    (avoids locking issues in streaming scenarios).
    
    Args:
        row_dict: Dictionary of feature values keyed by feature name.
                  Missing keys default to 0 for robustness.
    """
    # Build CSV line, defaulting missing keys to 0
    line = ",".join(str(row_dict.get(k, 0)) for k in FEATURES) + "\n"
    
    with FEAT_CSV.open("a", encoding="utf-8") as f:
        f.write(line)


# ---------- Feature Computation ----------
def compute_features(now_ts: float) -> Dict[str, Any]:
    """
    Compute aggregate features from the flow buffer.
    
    This function:
    1. Drops expired flows (older than WINDOW_SEC)
    2. Computes statistics across remaining flows
    3. Returns a feature dict matching the model's expected schema
    
    Args:
        now_ts: Current timestamp (used to expire old flows)
        
    Returns:
        Dict of feature values for a single row.
        
    Feature Descriptions:
        - flows: Number of active flows in window
        - bytes_total: Sum of all bytes transferred
        - pkts_total: Sum of all packets transferred
        - syn_ratio: Fraction of flows that are new (SYN) connections
        - mean_bytes_flow: Average bytes per flow
        - ack_ratio/fin_ratio/rst_ratio: TCP flag ratios (estimates)
        - http_ratio/tcp_ratio: Protocol mix (estimates)
        - protocol_diversity: Number of distinct protocols
        - std_bytes: Standard deviation of flow sizes
        - iat_mean: Mean inter-arrival time (not computed in simplified version)
    """
    # Drop expired flows from the buffer
    while buf and (now_ts - buf[0]["ts"] > WINDOW_SEC):
        buf.popleft()

    flows = len(buf)
    
    # Handle empty buffer case
    if flows == 0:
        return {
            "flows": 0,
            "bytes_total": 0,
            "pkts_total": 0,
            "syn_ratio": 0.0,
            "mean_bytes_flow": 0.0,
            "ack_ratio": 0.0,
            "fin_ratio": 0.0,
            "rst_ratio": 0.0,
            "http_ratio": 0.0,
            "tcp_ratio": 0.0,
            "protocol_diversity": 0,
            "std_bytes": 0.0,
            "iat_mean": 0.0
        }

    # Core statistics
    bytes_total = sum(x["bytes_total"] for x in buf)
    pkts_total = sum(x["pkts_total"] for x in buf)
    syn_ratio = sum(x["is_syn"] for x in buf) / flows
    mean_bytes = bytes_total / flows
    
    # Calculate std_bytes (Standard Deviation of flow bytes)
    # This helps detect traffic anomalies like amplification attacks
    if flows > 1:
        variance = sum((x["bytes_total"] - mean_bytes) ** 2 for x in buf) / (flows - 1)
        std_bytes = variance ** 0.5
    else:
        std_bytes = 0.0
    
    # Additional features (estimates for simplified extractor)
    # In a real implementation, these would come from deeper inspection
    ack_ratio = 0.0   # Would need TCP flag info from flow
    fin_ratio = 0.0   # Would need TCP flag info from flow
    rst_ratio = 0.0   # Would need TCP flag info from flow
    http_ratio = 0.0  # Would need protocol info from flow
    tcp_ratio = syn_ratio  # Estimate: assume SYN implies TCP
    protocol_diversity = 1  # Default: single protocol
    iat_mean = 0.0    # Would calculate from timestamps (simplified)

    return {
        # Core features
        "flows": flows,
        "bytes_total": bytes_total,
        "pkts_total": pkts_total,
        "syn_ratio": round(syn_ratio, 6),
        "mean_bytes_flow": round(mean_bytes, 6),
        
        # Flag ratios
        "ack_ratio": round(ack_ratio, 6),
        "fin_ratio": round(fin_ratio, 6),
        "rst_ratio": round(rst_ratio, 6),
        
        # Protocol features
        "http_ratio": round(http_ratio, 6),
        "tcp_ratio": round(tcp_ratio, 6),
        "protocol_diversity": protocol_diversity,
        
        # Statistical features
        "std_bytes": round(std_bytes, 2),
        "iat_mean": round(iat_mean, 6)
    }


# ---------- File Tailing ----------
def tail_file(path: Path) -> Generator[str, None, None]:
    """
    Tail a file like 'tail -f' in Unix.
    
    This generator continuously reads new lines from a file,
    yielding each line as it appears. Used to stream events
    from the eve.json file in real-time.
    
    Args:
        path: Path to the file to tail
        
    Yields:
        Each new line as it's appended to the file
        
    Note:
        This function runs indefinitely. Use Ctrl+C to stop.
    """
    # Create file if it doesn't exist
    path.touch(exist_ok=True)
    
    with path.open("r", encoding="utf-8") as f:
        # Seek to end of file (skip existing content)
        f.seek(0, os.SEEK_END)
        
        while True:
            pos = f.tell()
            line = f.readline()
            
            if not line:
                # No new content - wait and retry
                time.sleep(0.05)
                f.seek(pos)
                continue
            
            yield line


# ---------- Main Entry Point ----------
def main():
    """
    Main entry point for the feature extractor.
    
    Continuously reads flow events from the simulated eve.json,
    aggregates them into time windows, and outputs features to CSV.
    
    Run with: python scripts/feature_extractor.py
    Stop with: Ctrl+C
    """
    print(f"🟢 Feature extractor reading {EVE_PATH} → {FEAT_CSV}")
    ensure_header()
    
    for line in tail_file(EVE_PATH):
        rec = parse_line(line)
        if not rec: 
            continue
        
        # Add record to buffer and compute features
        buf.append(rec)
        feats = compute_features(rec["ts"])
        append_row(feats)


if __name__ == "__main__":
    main()
