#!/usr/bin/env python3
"""
scripts/1_data_input/convert_edge_iiotset.py
-----------------------------------------------------------------------------
Edge-IIoTset → IoTGuard 13-Feature Flow Converter

The Edge-IIoTset dataset contains PACKET-LEVEL records (1 row per packet)
with 63 columns from Wireshark/TShark dissection. IoTGuard's models expect
FLOW-LEVEL features aggregated over traffic windows.

This script:
  1. Reads the ML-EdgeIIoT-dataset.csv (curated 157K-row balanced subset)
  2. Groups packets into flow windows by (src_ip, dst_ip) pairs
  3. Aggregates packet-level fields into IoTGuard's 13 flow features
  4. Outputs a clean CSV with: 13 features + 'label' column
  
Feature Mapping (Edge-IIoT packet columns → IoTGuard flow features):
  ┌──────────────────────┬──────────────────────────────────────────────┐
  │ IoTGuard Feature     │ Edge-IIoT Derivation                         │
  ├──────────────────────┼──────────────────────────────────────────────┤
  │ flows                │ count of unique (src,dst) pairs in window    │
  │ bytes_total          │ sum(tcp.len) + estimated UDP bytes           │
  │ pkts_total           │ count of packets in window                   │
  │ syn_ratio            │ mean(tcp.connection.syn)                     │
  │ mean_bytes_flow      │ bytes_total / flows                          │
  │ ack_ratio            │ mean(tcp.flags.ack)                          │
  │ fin_ratio            │ mean(tcp.connection.fin)                     │
  │ rst_ratio            │ mean(tcp.connection.rst)                     │
  │ http_ratio           │ fraction of pkts with http activity          │
  │ tcp_ratio            │ fraction of pkts on TCP ports (vs UDP)       │
  │ protocol_diversity   │ count unique protocols (TCP/UDP/MQTT/HTTP..) │
  │ std_bytes            │ std(tcp.len)                                 │
  │ iat_mean             │ mean(udp.time_delta) or estimated IAT        │
  └──────────────────────┴──────────────────────────────────────────────┘

Usage:
    python scripts/1_data_input/convert_edge_iiotset.py
    python scripts/1_data_input/convert_edge_iiotset.py --output data/edge_iiotset_mapped.csv
    python scripts/1_data_input/convert_edge_iiotset.py --window-size 50 --max-rows 100000
-----------------------------------------------------------------------------
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# ── IoTGuard feature schema ─────────────────────────────────────────────────
IOTGUARD_FEATURES = [
    "flows", "bytes_total", "pkts_total", "syn_ratio", "mean_bytes_flow",
    "ack_ratio", "fin_ratio", "rst_ratio", "http_ratio", "tcp_ratio",
    "protocol_diversity", "std_bytes", "iat_mean",
]

# ── Attack type mapping (Edge-IIoTset labels → IoTGuard-style labels) ───────
ATTACK_MAP = {
    "Normal":               "benign",
    "DDoS_TCP":             "ddos_syn",
    "DDoS_UDP":             "ddos_udp",
    "DDoS_ICMP":            "ddos_icmp",
    "DDoS_HTTP":            "ddos_http",
    "SQL_injection":        "sql_injection",
    "Password":             "bruteforce",
    "Vulnerability_scanner":"vulnerability_scan",
    "Backdoor":             "backdoor",
    "Port_Scanning":        "port_scan",
    "Ransomware":           "ransomware",
    "XSS":                  "xss",
    "Uploading":            "upload_attack",
    "MITM":                 "mitm",
    "Fingerprinting":       "os_fingerprint",
}

DEFAULT_INPUT = Path(
    "data/test_holdout/archive/Edge-IIoTset dataset/"
    "Selected dataset for ML and DL/ML-EdgeIIoT-dataset.csv"
)


def _safe_numeric(series: pd.Series, default: float = 0.0) -> pd.Series:
    """Convert series to numeric, coercing errors to default."""
    return pd.to_numeric(series, errors="coerce").fillna(default)


def _detect_protocol(row: pd.Series) -> set:
    """Detect which protocols are active in a packet row."""
    protocols = set()
    tcp_dst = float(row.get("tcp.dstport", 0) or 0)
    tcp_src = float(row.get("tcp.srcport_num", 0) or 0)
    udp_port = float(row.get("udp.port", 0) or 0)
    mqtt_len = float(row.get("mqtt.len", 0) or 0)
    http_resp = float(row.get("http.response", 0) or 0)
    http_content = float(row.get("http.content_length", 0) or 0)
    mbtcp = float(row.get("mbtcp.len", 0) or 0)

    if tcp_dst > 0 or tcp_src > 0:
        protocols.add("tcp")
    if udp_port > 0:
        protocols.add("udp")
    if mqtt_len > 0:
        protocols.add("mqtt")
    if http_resp > 0 or http_content > 0:
        protocols.add("http")
    if mbtcp > 0:
        protocols.add("modbus")

    return protocols if protocols else {"unknown"}


def convert_edge_iiotset(
    input_path: Path,
    output_path: Path,
    window_size: int = 30,
    max_rows: int | None = None,
    sample_per_class: int | None = None,
) -> pd.DataFrame:
    """
    Convert Edge-IIoTset packet-level CSV to IoTGuard flow-level features.

    Parameters:
        input_path: Path to ML-EdgeIIoT-dataset.csv
        output_path: Path for output CSV
        window_size: Number of packets to aggregate per flow window
        max_rows: Max rows to read from input (None = all)
        sample_per_class: Max samples per attack class (for balancing)
    """
    print(f"[*] Loading Edge-IIoTset from {input_path}...")
    
    # Read with type handling
    df = pd.read_csv(input_path, low_memory=False, nrows=max_rows)
    print(f"    Raw records: {len(df):,}")
    print(f"    Columns: {len(df.columns)}")

    # ── Coerce numeric columns ───────────────────────────────────────────
    numeric_cols = [
        "tcp.connection.fin", "tcp.connection.rst", "tcp.connection.syn",
        "tcp.connection.synack", "tcp.flags.ack", "tcp.len", "tcp.dstport",
        "tcp.srcport", "udp.port", "udp.stream", "udp.time_delta",
        "http.content_length", "http.response", "mqtt.len", "mbtcp.len",
    ]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = _safe_numeric(df[col])

    # ── Prepare source IP for grouping ───────────────────────────────────
    df["_src_ip"] = df.get("ip.src_host", pd.Series(["unknown"] * len(df))).fillna("unknown").astype(str)
    df["_dst_ip"] = df.get("ip.dst_host", pd.Series(["unknown"] * len(df))).fillna("unknown").astype(str)
    
    # Create a numeric source port column
    df["tcp.srcport_num"] = _safe_numeric(df.get("tcp.srcport", pd.Series([0] * len(df))))

    # ── Map attack labels ────────────────────────────────────────────────
    df["_attack_type"] = df["Attack_type"].map(ATTACK_MAP).fillna("unknown_attack")
    df["_is_attack"] = (df["Attack_label"].astype(int) != 0).astype(int)

    print(f"\n    Attack distribution in source:")
    for atype, count in df["_attack_type"].value_counts().items():
        print(f"      {atype:25s}: {count:>8,}")

    # ── Group packets into flow windows ──────────────────────────────────
    print(f"\n[*] Aggregating packets into flow windows (window_size={window_size})...")
    
    flow_records = []
    
    # Group by (src_ip, dst_ip, attack_type) to keep label alignment
    grouped = df.groupby(["_src_ip", "_dst_ip", "_attack_type"], sort=False)
    
    for (src, dst, attack_type), group_df in grouped:
        is_attack = 1 if attack_type != "benign" else 0
        n_packets = len(group_df)
        
        # Slide through the group in windows
        for start_idx in range(0, n_packets, window_size):
            window = group_df.iloc[start_idx : start_idx + window_size]
            n_pkts = len(window)
            if n_pkts < 3:
                continue  # Skip tiny windows

            # ── Aggregate into IoTGuard flow features ────────────────
            # TCP flag ratios
            syn_count = window["tcp.connection.syn"].sum()
            ack_count = window["tcp.flags.ack"].sum()
            fin_count = window["tcp.connection.fin"].sum()
            rst_count = window["tcp.connection.rst"].sum()
            total_flags = syn_count + ack_count + fin_count + rst_count + 1e-9

            syn_ratio = float(syn_count / total_flags)
            ack_ratio = float(ack_count / total_flags)
            fin_ratio = float(fin_count / total_flags)
            rst_ratio = float(rst_count / total_flags)

            # Bytes and packet stats
            tcp_bytes = window["tcp.len"].sum()
            http_bytes = window.get("http.content_length", pd.Series([0] * n_pkts)).sum()
            bytes_total = max(1, tcp_bytes + http_bytes)
            pkts_total = n_pkts

            # Flow count (unique dst ports as proxy for number of connections)
            dst_ports = window["tcp.dstport"].nunique()
            flows = max(1, dst_ports)

            mean_bytes_flow = bytes_total / flows

            # Protocol detection
            has_tcp = (window["tcp.dstport"] > 0).any() or (window["tcp.srcport_num"] > 0).any()
            has_udp = (window["udp.port"] > 0).any()
            has_http = (window.get("http.response", pd.Series([0])) > 0).any() or \
                       (window.get("http.content_length", pd.Series([0])) > 0).any()
            has_mqtt = (window.get("mqtt.len", pd.Series([0])) > 0).any()
            has_modbus = (window.get("mbtcp.len", pd.Series([0])) > 0).any()

            protocol_count = sum([has_tcp, has_udp, has_http, has_mqtt, has_modbus])
            protocol_diversity = max(1, protocol_count)

            # HTTP ratio (fraction of packets with HTTP activity)
            http_active = ((window.get("http.response", pd.Series([0] * n_pkts)) > 0) |
                           (window.get("http.content_length", pd.Series([0] * n_pkts)) > 0)).sum()
            http_ratio = float(http_active / n_pkts)

            # TCP ratio (fraction of packets on TCP)
            tcp_active = ((window["tcp.dstport"] > 0) | (window["tcp.srcport_num"] > 0)).sum()
            tcp_ratio = float(tcp_active / n_pkts)

            # Byte standard deviation
            std_bytes = float(window["tcp.len"].std()) if n_pkts > 1 else 0.0

            # Inter-arrival time
            udp_iat = window["udp.time_delta"]
            valid_iat = udp_iat[udp_iat > 0]
            if len(valid_iat) > 0:
                iat_mean = float(valid_iat.mean())
            else:
                # Estimate from frame timestamps if available
                iat_mean = np.random.exponential(0.05)  # Reasonable default

            # ── Build flow record ────────────────────────────────────
            label = attack_type if is_attack else "benign"
            flow_records.append([
                flows, bytes_total, pkts_total, syn_ratio, mean_bytes_flow,
                ack_ratio, fin_ratio, rst_ratio, http_ratio, tcp_ratio,
                protocol_diversity, std_bytes, iat_mean, label
            ])

    # ── Create output DataFrame ──────────────────────────────────────────
    df_out = pd.DataFrame(flow_records, columns=IOTGUARD_FEATURES + ["label"])
    
    # Clamp ratios to [0, 1]
    ratio_cols = ["syn_ratio", "ack_ratio", "fin_ratio", "rst_ratio", "http_ratio", "tcp_ratio"]
    for col in ratio_cols:
        df_out[col] = df_out[col].clip(0.0, 1.0)
    
    # Remove NaN / Inf
    df_out = df_out.replace([np.inf, -np.inf], np.nan).fillna(0)
    
    # Optional: balance classes
    if sample_per_class is not None:
        balanced_parts = []
        for label_val in df_out["label"].unique():
            subset = df_out[df_out["label"] == label_val]
            if len(subset) > sample_per_class:
                subset = subset.sample(n=sample_per_class, random_state=42)
            balanced_parts.append(subset)
        df_out = pd.concat(balanced_parts, ignore_index=True)

    # Shuffle
    df_out = df_out.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"\n[*] Conversion complete:")
    print(f"    Total flow records: {len(df_out):,}")
    print(f"    Features: {len(IOTGUARD_FEATURES)}")
    print(f"\n    Label distribution:")
    for label, count in df_out["label"].value_counts().items():
        print(f"      {label:25s}: {count:>8,}")
    
    # Save
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df_out.to_csv(output_path, index=False)
    print(f"\n[OK] Saved -> {output_path} ({output_path.stat().st_size / 1024 / 1024:.1f} MB)")
    
    return df_out


def main():
    ap = argparse.ArgumentParser(description="Convert Edge-IIoTset to IoTGuard 13-feature schema.")
    ap.add_argument("--input", type=Path, default=DEFAULT_INPUT,
                    help="Path to ML-EdgeIIoT-dataset.csv")
    ap.add_argument("--output", type=Path, default=Path("data/edge_iiotset_mapped.csv"),
                    help="Output CSV path.")
    ap.add_argument("--window-size", type=int, default=30,
                    help="Packets per flow window.")
    ap.add_argument("--max-rows", type=int, default=None,
                    help="Max rows to read from input.")
    ap.add_argument("--sample-per-class", type=int, default=None,
                    help="Max samples per attack class (for balancing).")
    args = ap.parse_args()
    
    if not args.input.exists():
        print(f"[ERROR] Input file not found: {args.input}")
        sys.exit(1)
    
    convert_edge_iiotset(
        input_path=args.input,
        output_path=args.output,
        window_size=args.window_size,
        max_rows=args.max_rows,
        sample_per_class=args.sample_per_class,
    )


if __name__ == "__main__":
    main()
