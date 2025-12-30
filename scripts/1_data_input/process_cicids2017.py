"""
scripts/process_cicids2017.py
-----------------------------------------------------------------------------
Purpose:
    Convert raw CICIDS2017 per-flow CSVs into aggregated "windowed" features
    compatible with IoTGuard's training format.

Why:
    IoTGuard models are trained on *aggregated* traffic windows (e.g., 100 flows),
    not individual flows. CICIDS2017 data is per-flow. This script bridges that gap.

Logic:
    1. Read CICIDS2017 CSVs.
    2. Group flows into chunks of N (default 100).
    3. Aggregate statistics (sum bytes, avg ratios, etc.).
    4. Assign label (Attack if > threshold% of flows are malicious).
    5. Save to data/it_training_clean.csv.
-----------------------------------------------------------------------------
"""

import pandas as pd
import numpy as np
from pathlib import Path
import os
import glob

# Configuration
CHUNK_SIZE = 100  # Flows per window
INPUT_PATTERN = "data/*_ISCX.csv"
OUTPUT_FILE = "data/it_training_clean.csv"

# Column mapping (CICIDS2017 -> Internal logic)
# We need to map these to calculate our 13 features:
# flows, bytes_total, pkts_total, syn_ratio, mean_bytes_flow, ack_ratio,
# fin_ratio, rst_ratio, http_ratio, tcp_ratio, protocol_diversity, std_bytes, iat_mean

def process_chunk(chunk):
    """Aggregate a chunk of flows into a single feature row."""
    
    # Basic sums
    fwd_pkts = chunk.get("Total Fwd Packets", 0).sum()
    bwd_pkts = chunk.get("Total Backward Packets", 0).sum()
    pkts_total = fwd_pkts + bwd_pkts
    
    fwd_bytes = chunk.get("Total Length of Fwd Packets", 0).sum()
    bwd_bytes = chunk.get("Total Length of Bwd Packets", 0).sum()
    bytes_total = fwd_bytes + bwd_bytes
    
    flows = len(chunk)
    
    # Ratios (averages across flows)
    # Note: CICIDS2017 has flag counts/flags. We assume these columns exist.
    # If columns are missing, we default to 0.
    
    def get_col(name):
        return chunk[name] if name in chunk.columns else pd.Series(0, index=chunk.index)

    syn_count = get_col("SYN Flag Count").sum()
    ack_count = get_col("ACK Flag Count").sum()
    fin_count = get_col("FIN Flag Count").sum()
    rst_count = get_col("RST Flag Count").sum()
    
    # Avoid division by zero
    safe_pkts = max(1, pkts_total)
    
    syn_ratio = syn_count / safe_pkts
    ack_ratio = ack_count / safe_pkts
    fin_ratio = fin_count / safe_pkts
    rst_ratio = rst_count / safe_pkts
    
    # Protocol inference
    # HTTP: Dest Port 80 or 8080 or 443 (approx)
    dst_port = get_col(" Destination Port")
    is_http = dst_port.isin([80, 8080, 443, 8443]).astype(int)
    http_ratio = is_http.sum() / flows
    
    # TCP: CICIDS2017 doesn't explicitly have "Protocol" column in all versions,
    # but most of these datasets are TCP/UDP. We'll assume high TCP ratio for now
    # or infer from flags (if SYN/ACK/FIN exist, it's TCP).
    is_tcp = ((get_col("SYN Flag Count") + get_col("ACK Flag Count") + get_col("FIN Flag Count")) > 0).astype(int)
    tcp_ratio = is_tcp.sum() / flows
    
    # Protocol diversity: Unique ports count
    protocol_diversity = dst_port.nunique()
    
    # Statistical
    std_bytes = get_col(" Packet Length Std").mean()
    iat_mean = get_col("Flow IAT Mean").mean()
    
    mean_bytes_flow = bytes_total / flows
    
    # Label logic
    # CICIDS2017 label column is usually " Label" or "Label"
    label_col = " Label" if " Label" in chunk.columns else "Label"
    if label_col in chunk.columns:
        # If any significant portion is attack, label as attack
        # Labels are strings like "BENIGN", "DDoS", etc.
        is_attack = (chunk[label_col].str.upper() != "BENIGN").astype(int)
        # If > 20% of flows in window are attack, mark window as attack
        label = 1 if (is_attack.sum() / flows) > 0.2 else 0
    else:
        label = 0

    return {
        "flows": flows,
        "bytes_total": bytes_total,
        "pkts_total": pkts_total,
        "syn_ratio": syn_ratio,
        "mean_bytes_flow": mean_bytes_flow,
        "ack_ratio": ack_ratio,
        "fin_ratio": fin_ratio,
        "rst_ratio": rst_ratio,
        "http_ratio": http_ratio,
        "tcp_ratio": tcp_ratio,
        "protocol_diversity": protocol_diversity,
        "std_bytes": std_bytes,
        "iat_mean": iat_mean,
        "label": label
    }

def main():
    print(f"Processing CICIDS2017 files from {INPUT_PATTERN}...")
    
    files = glob.glob(INPUT_PATTERN)
    if not files:
        print("No files found!")
        return

    all_rows = []
    
    for f in files:
        print(f"Reading {f}...")
        try:
            # Read in chunks to avoid memory issues
            # We'll just read the whole file for simplicity if it fits, 
            # or use an iterator if files are huge. 
            # Given the file sizes (50-200MB), we can read full files.
            df = pd.read_csv(f)
            
            # Clean column names (strip spaces)
            df.columns = [c.strip() for c in df.columns]
            
            # Group into windows of CHUNK_SIZE
            num_chunks = len(df) // CHUNK_SIZE
            
            for i in range(num_chunks):
                chunk = df.iloc[i*CHUNK_SIZE : (i+1)*CHUNK_SIZE]
                row = process_chunk(chunk)
                all_rows.append(row)
                
        except Exception as e:
            print(f"Error processing {f}: {e}")
            continue

    if not all_rows:
        print("No data processed.")
        return

    # Create final DataFrame
    result_df = pd.DataFrame(all_rows)
    
    # Save
    print(f"Saving {len(result_df)} aggregated samples to {OUTPUT_FILE}...")
    result_df.to_csv(OUTPUT_FILE, index=False)
    print("Done!")

if __name__ == "__main__":
    main()
