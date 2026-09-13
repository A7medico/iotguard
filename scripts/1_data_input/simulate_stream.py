"""
scripts/1_data_input/simulate_stream.py
-----------------------------------------------------------------------------
IoTGuard Utility — Realistic Live Network Feature Stream Simulator

Simulates real-world smart-office / enterprise IoT network traffic:
- 98% Legitimate traffic across diverse device profiles (Cameras, Locks, Sensors, PCs)
- 2% Rare, episodic attack anomalies (SYN Floods, Mirai UDP, Scans)
- Configurable attack probability via CLI: --attack-prob (default 0.02)
-----------------------------------------------------------------------------
"""

import random
import time
import argparse
import numpy as np
from pathlib import Path

CSV = Path("data/features.csv")
FEATURES_HEADER = "flows,bytes_total,pkts_total,syn_ratio,mean_bytes_flow,ack_ratio,fin_ratio,rst_ratio,http_ratio,tcp_ratio,protocol_diversity,std_bytes,iat_mean\n"

CSV.parent.mkdir(parents=True, exist_ok=True)
if not CSV.exists() or CSV.read_text(encoding="utf-8").strip() == "":
    CSV.write_text(FEATURES_HEADER, encoding="utf-8")

def generate_benign_device_flow():
    """Simulate authentic multi-device benign network traffic."""
    device_type = random.choices(["sensor", "camera", "workstation", "doorlock"], weights=[0.40, 0.25, 0.25, 0.10])[0]
    
    if device_type == "sensor":
        # Smart thermostat / temperature sensor (low rate heartbeat)
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

    elif device_type == "camera":
        # IP Video Streaming Camera
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

    elif device_type == "workstation":
        # Admin / Developer Workstation (web browsing, DB queries)
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
        # Smart Door Lock (occasional MQTT ping)
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
    return flows, bytes_total, pkts, syn_ratio, mean_bytes, ack_ratio, fin_ratio, rst_ratio, http_ratio, tcp_ratio, proto_div, std_bytes, iat_mean

def generate_attack_flow():
    """Simulate rare cyber attack incident."""
    attack_type = random.choice(["syn_flood", "udp_storm", "port_scan", "http_exploit"])
    
    if attack_type == "syn_flood":
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

    elif attack_type == "udp_storm":
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

    elif attack_type == "port_scan":
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

    else:
        # HTTP Layer-7 exploit
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

    mean_bytes = int(bytes_total / max(flows, 1))
    return flows, bytes_total, pkts, syn_ratio, mean_bytes, ack_ratio, fin_ratio, rst_ratio, http_ratio, tcp_ratio, proto_div, std_bytes, iat_mean

def main():
    parser = argparse.ArgumentParser(description="IoTGuard Live Network Traffic Simulator")
    parser.add_argument("--attack-prob", type=float, default=0.02, help="Probability of attack flow (default 0.02 = 2%)")
    parser.add_argument("--interval", type=float, default=1.0, help="Stream interval in seconds (default 1.0s)")
    args = parser.parse_args()

    print("=" * 70)
    print(f"[*] IoTGuard Network Traffic Simulator")
    print(f"    - Baseline: Normal Multi-Device IoT/IT Operations ({100 - args.attack_prob*100:.1f}%)")
    print(f"    - Attack Rate: {args.attack_prob*100:.1f}%")
    print(f"    - Target File: {CSV}")
    print("=" * 70)

    try:
        while True:
            is_attack = random.random() < args.attack_prob
            row = generate_attack_flow() if is_attack else generate_benign_device_flow()
            with CSV.open("a", encoding="utf-8") as f:
                f.write("{},{},{},{:.2f},{},{:.2f},{:.2f},{:.2f},{:.2f},{:.2f},{},{:.2f},{:.6f}\n".format(*row))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[!] Simulator stopped.")

if __name__ == "__main__":
    main()
