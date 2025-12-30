"""
scripts/simulate_stream.py
-----------------------------------------------------------------------------
IoTGuard Utility — Synthetic Live Feature Stream

Position in pipeline
    Synthetic generator
        →  [THIS FILE]  (random benign/attack‑like rows)
        →  data/features.csv
        →  decision_loop.py
        →  alerts.jsonl / api_dashboard.py

High‑level responsibilities
    - Continuously append **simulated** IoT feature rows to data/features.csv
      using the same 13‑feature schema as the real model.
    - Randomly choose between benign‑like patterns (70%) and attack‑like bursts (30%),
      so you can observe how the decision loop reacts over time without any PCAPs
      or Suricata running.

Typical use
    - Quick smoke‑test of the end‑to‑end system:
        * run decision_loop.py,
        * run api_dashboard.py,
        * run this script and watch scores/blocks appear.
-----------------------------------------------------------------------------
"""
import random, time
from pathlib import Path

CSV = Path("data/features.csv")
FEATURES_HEADER = "flows,bytes_total,pkts_total,syn_ratio,mean_bytes_flow,ack_ratio,fin_ratio,rst_ratio,http_ratio,tcp_ratio,protocol_diversity,std_bytes,iat_mean\n"

CSV.parent.mkdir(parents=True, exist_ok=True)
if not CSV.exists() or CSV.read_text(encoding="utf-8").strip() == "":
    CSV.write_text(FEATURES_HEADER, encoding="utf-8")

def benign():
    flows = random.randint(5, 20)
    pkts  = flows * random.randint(2,5)
    bytes_ = pkts * random.randint(40,80)
    syn_ratio = round(random.uniform(0.05, 0.25), 2)
    mean_bytes = int(bytes_ / max(flows,1))
    
    # New features
    ack_ratio = round(random.uniform(0.3, 0.6), 2)
    fin_ratio = round(random.uniform(0.1, 0.3), 2)
    rst_ratio = 0.0
    http_ratio = round(random.uniform(0.0, 0.5), 2)
    tcp_ratio = 1.0
    protocol_diversity = random.randint(1,3)
    std_bytes = random.uniform(10, 100)
    iat_mean = random.uniform(0.01, 0.5)
    
    return flows, bytes_, pkts, syn_ratio, mean_bytes, ack_ratio, fin_ratio, rst_ratio, http_ratio, tcp_ratio, protocol_diversity, std_bytes, iat_mean

def attack():
    flows = random.randint(20, 60)
    pkts  = flows * random.randint(3,8)
    bytes_ = pkts * random.randint(60,120)
    syn_ratio = round(random.uniform(0.7, 0.98), 2)
    mean_bytes = int(bytes_ / max(flows,1))
    
    # New features
    ack_ratio = 0.0
    fin_ratio = 0.0
    rst_ratio = 0.0
    http_ratio = 0.0
    tcp_ratio = 1.0
    protocol_diversity = 1
    std_bytes = 0.0
    iat_mean = random.uniform(0.0001, 0.001)
    
    return flows, bytes_, pkts, syn_ratio, mean_bytes, ack_ratio, fin_ratio, rst_ratio, http_ratio, tcp_ratio, protocol_diversity, std_bytes, iat_mean

print("🧪 Simulating rows → data/features.csv (Ctrl-C to stop)")
try:
    while True:
        # 70% benign, 30% attack bursts
        row = attack() if random.random() < 0.3 else benign()
        with CSV.open("a", encoding="utf-8") as f:
            f.write("{},{},{},{:.2f},{},{:.2f},{:.2f},{:.2f},{:.2f},{:.2f},{},{:.2f},{:.6f}\n".format(*row))
        time.sleep(random.uniform(0.5, 1.5))
except KeyboardInterrupt:
    print("\nStopped.")
