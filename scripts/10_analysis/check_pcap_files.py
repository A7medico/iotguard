#!/usr/bin/env python3
"""
Check original pcap.csv files and test them with the model.
"""
import pandas as pd
from pathlib import Path

# Get all original pcap.csv files
data_dir = Path("data")
pcap_files = sorted([f for f in data_dir.glob("*.pcap.csv") if "Benign" not in f.name])

print("=" * 70)
print("Original pcap.csv Files Analysis")
print("=" * 70)
print(f"\nFound {len(pcap_files)} original pcap.csv files\n")

# Check a sample file
if pcap_files:
    sample = pcap_files[0]
    df = pd.read_csv(sample, nrows=1)
    print(f"Sample file: {sample.name}")
    print(f"  Total columns: {len(df.columns)}")
    print(f"  Has 'label' column: {'label' in df.columns}")
    print(f"  Feature count (excluding label): {len([c for c in df.columns if c != 'label'])}")
    print(f"  First 10 columns: {list(df.columns[:10])}")
    
    # Check if converted version exists
    converted_dir = data_dir / "converted_attacks"
    converted_name = sample.stem + "_converted.csv"
    converted_path = converted_dir / converted_name
    
    print(f"\n  Converted version exists: {converted_path.exists()}")
    if converted_path.exists():
        conv_df = pd.read_csv(converted_path, nrows=1)
        print(f"  Converted features: {len([c for c in conv_df.columns if c != 'label'])}")
        print(f"  Converted columns: {list(conv_df.columns)}")

print("\n" + "=" * 70)
print("Summary")
print("=" * 70)
print(f"\nOriginal pcap.csv files: {len(pcap_files)}")
print("These are the 39-feature source files.")
print("\nThey need to be converted to 15-feature format for the model.")
print("Converted versions are in: data/converted_attacks/")
print("\nTo test on original files, they would need feature mapping.")
print("Better to use the converted versions for accurate testing.")



