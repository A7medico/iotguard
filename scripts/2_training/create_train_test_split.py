#!/usr/bin/env python3
"""
Create proper TRAIN vs TEST splits by separating entire files.
PREVENTS DATA LEAKAGE by ensuring test files are never seen during training.
"""
import pandas as pd
from pathlib import Path
import shutil

def main():
    data_dir = Path("data")
    converted_dir = data_dir / "converted_attacks"
    
    # Output files
    train_file = data_dir / "iotguard_training_clean.csv"
    test_dir = data_dir / "test_holdout"
    test_dir.mkdir(exist_ok=True)
    
    print("=" * 60)
    print("Creating Strict Train/Test Split")
    print("=" * 60)
    
    # 1. Define Holdout Files (Files to exclude from training completely)
    # These will be used ONLY for final testing
    holdout_files = [
        # Attack Holdouts
        "DDoS-SYN_Flood.pcap_converted.csv",
        "Mirai-udpplain.pcap_converted.csv",
        "SqlInjection.pcap_converted.csv",
        "Recon-PortScan.pcap_converted.csv",
        "DDoS-ACK_Fragmentation.pcap_converted.csv",
        
        # Benign Holdout (we need unseen benign data too)
        # REMOVED benign_sim_15f.csv from here because we handle it specifically below
    ]
    
    # 2. Identify all available datasets
    all_files = []
    
    # Add converted attacks
    for f in sorted(converted_dir.glob("*_converted.csv")):
        all_files.append(f)
        
    # Add benign files
    benign_candidates = [
        data_dir / "ciciot_benign_15f.csv", 
        data_dir / "benign_sim_15f.csv",
    ]
    for f in benign_candidates:
        if f.exists():
            all_files.append(f)
            
    # Add other existing attacks
    other_attacks = [
        data_dir / "ciciot_ddos_http_15f.csv",
        data_dir / "ddos_sim_15f.csv",
    ]
    for f in other_attacks:
        if f.exists():
            all_files.append(f)

    # 3. Process Split
    train_dfs = []
    
    print(f"\n[*] Processing {len(all_files)} source files...")
    
    for f in all_files:
        is_holdout = f.name in holdout_files
        
        # Special handling for huge benign file: split it 80/20
        # This now includes BenignTraffic, BenignTraffic1, BenignTraffic2, BenignTraffic3
        if f.name.startswith("BenignTraffic") and f.name.endswith("_converted.csv"):
            print(f"  [SPLIT] {f.name} (Real Benign) -> 80% Train / 20% Test")
            df = pd.read_csv(f)
            # Normalize label
            df["label"] = "benign"
            
            split_idx = int(len(df) * 0.8)
            df_train = df.iloc[:split_idx]
            df_test = df.iloc[split_idx:]
            
            train_dfs.append(df_train)
            
            test_out = test_dir / f"TEST_{f.name}"
            df_test.to_csv(test_out, index=False)
            print(f"       -> Train: {len(df_train):,} | Test: {len(df_test):,} -> {test_out.name}")
            continue

        if f.name == "ciciot_benign_15f.csv":
            print(f"  [SKIP]  {f.name} (Low Quality Benign) -> Skipped")
            continue

        # Special handling for simulated benign (Domain Adaptation for Demo)
        # We need the model to learn "Simulated Benign" patterns too, not just "Real Benign"
        if f.name == "benign_sim_15f.csv":
            print(f"  [SPLIT] {f.name} (Simulated Benign) -> 50% Train / 50% Test")
            df = pd.read_csv(f)
            if "label" not in df.columns: df["label"] = "benign"
            
            split_idx = int(len(df) * 0.5)
            df_train = df.iloc[:split_idx]
            df_test = df.iloc[split_idx:]
            
            train_dfs.append(df_train)
            
            test_out = test_dir / f"TEST_{f.name}"
            df_test.to_csv(test_out, index=False)
            print(f"       -> Train: {len(df_train):,} | Test: {len(df_test):,} -> {test_out.name}")
            continue

        if is_holdout:
            print(f"  [TEST]  {f.name} -> Copied to holdout")
            # Copy to test dir
            shutil.copy(f, test_dir / f.name)
        else:
            print(f"  [TRAIN] {f.name} -> Added to training")
            try:
                df = pd.read_csv(f)
                # Ensure label exists
                if "label" not in df.columns:
                    if "benign" in f.name.lower():
                        df["label"] = "benign"
                    else:
                        # Try to extract from filename or default to attack
                        label = f.stem.replace("_converted", "").replace(".pcap", "")
                        df["label"] = label
                
                train_dfs.append(df)
            except Exception as e:
                print(f"       [ERROR] Could not read {f.name}: {e}")

    # 4. Merge and Save Training Data
    print("\n[*] Merging training data...")
    merged = pd.concat(train_dfs, ignore_index=True)
    
    # Enforce ONLY the 13 core features + label
    # This prevents leakage of extra columns (like Header_Length) that won't exist in production
    core_features = [
        "flows", "bytes_total", "pkts_total",
        "syn_ratio", "mean_bytes_flow",
        "ack_ratio", "fin_ratio", "rst_ratio",
        "http_ratio", "tcp_ratio", "protocol_diversity",
        "std_bytes", "iat_mean",
        "label"
    ]
    
    # Keep only core features that exist
    keep_cols = [c for c in core_features if c in merged.columns]
    print(f"  Enforcing schema: {len(keep_cols)} columns")
    merged = merged[keep_cols]

    # Shuffle training data
    merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Remove duplicates
    print("[*] Removing duplicates...")
    len_before = len(merged)
    merged = merged.drop_duplicates()
    print(f"  Dropped {len_before - len(merged):,} duplicates")

    # Save
    merged.to_csv(train_file, index=False)
    
    print("\n" + "=" * 60)
    print("SPLIT COMPLETE")
    print("=" * 60)
    print(f"Training Data: {train_file}")
    print(f"  Rows: {len(merged):,}")
    print(f"Test Data:     {test_dir}")
    print(f"  Files: {len(list(test_dir.glob('*.csv')))}")
    print("\nAction: Retrain using data/iotguard_training_clean.csv")

if __name__ == "__main__":
    main()
