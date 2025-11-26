#!/usr/bin/env python3
"""
Generate a completely NEW synthetic dataset for testing robustness.
Generates traffic that falls within 'plausible' ranges but wasn't in training.
"""
import pandas as pd
import numpy as np
import random
from pathlib import Path
import argparse

def generate_dataset(rows=1000, seed=None):
    if seed is not None:
        random.seed(seed)
        np.random.seed(seed)
    data = []
    
    # 1. Generate Benign-like Traffic (but slightly different from training)
    # Training benign (from debug analysis):
    #   flows: ~10, bytes: ~5500, pkts: ~10, syn: 0.02, mean_bytes: ~550
    # We will generate "High Load Benign" - plausible but heavier
    for _ in range(rows // 2):
        flows = random.randint(15, 40)  # Higher than avg (10) but not attack level
        pkts_per_flow = random.uniform(2, 15)
        pkts_total = int(flows * pkts_per_flow)
        avg_pkt_size = random.uniform(60, 900) # Mix of small and large packets
        bytes_total = int(pkts_total * avg_pkt_size)
        
        data.append({
            "flows": flows,
            "bytes_total": bytes_total,
            "pkts_total": pkts_total,
            "syn_ratio": random.uniform(0.0, 0.3), # Normal TCP handshake ratio
            "mean_bytes_flow": bytes_total / flows,
            "ack_ratio": random.uniform(0.3, 0.6), # Normal ACK traffic
            "fin_ratio": random.uniform(0.1, 0.3), # Normal termination
            "rst_ratio": random.uniform(0.0, 0.05),
            "http_ratio": random.uniform(0.0, 0.8),
            "tcp_ratio": random.uniform(0.8, 1.0),
            "protocol_diversity": random.randint(1, 4),
            "std_bytes": random.uniform(50, 500), # Varied packet sizes
            "iat_mean": random.uniform(0.01, 0.5), # Normal spacing
            "label": "benign_synthetic"
        })

    # 2. Generate Attack-like Traffic (Subtle)
    # Training attack:
    #   flows: ~80, syn: ~0.67
    # We will generate "Low Rate Attack" - trying to sneak under radar
    for _ in range(rows // 2):
        flows = random.randint(20, 50)
        pkts_total = flows * random.randint(1, 2) # SYN flood often 1-2 pkts per flow
        bytes_total = pkts_total * random.randint(40, 60) # Small packets
        
        data.append({
            "flows": flows,
            "bytes_total": bytes_total,
            "pkts_total": pkts_total,
            "syn_ratio": random.uniform(0.8, 1.0), # High SYN is suspicious
            "mean_bytes_flow": bytes_total / flows,
            "ack_ratio": random.uniform(0.0, 0.1),
            "fin_ratio": 0.0,
            "rst_ratio": 0.0,
            "http_ratio": 0.0,
            "tcp_ratio": 1.0,
            "protocol_diversity": 1,
            "std_bytes": 0.0, # Uniform packets (robotic)
            "iat_mean": random.uniform(0.0001, 0.001), # Fast
            "label": "attack_synthetic_synflood"
        })

    df = pd.DataFrame(data)
    return df

def main():
    parser = argparse.ArgumentParser(description="Generate synthetic 13-feature test dataset")
    parser.add_argument("--rows", type=int, default=5000, help="Number of rows to generate")
    parser.add_argument("--out", type=str, default="data/test_holdout/synthetic_challenge.csv",
                        help="Output CSV path")
    parser.add_argument("--seed", type=int, default=None, help="Random seed (optional)")
    args = parser.parse_args()

    out_file = Path(args.out)
    out_file.parent.mkdir(exist_ok=True)
    
    print("=" * 60)
    print("Generating Synthetic Challenge Dataset")
    print("=" * 60)
    
    df = generate_dataset(args.rows, seed=args.seed)
    df.to_csv(out_file, index=False)
    
    print(f"[OK] Generated {len(df)} rows -> {out_file}")
    print("\nFirst 5 rows:")
    print(df.head())

if __name__ == "__main__":
    main()
