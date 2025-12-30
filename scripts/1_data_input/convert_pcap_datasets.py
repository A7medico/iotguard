#!/usr/bin/env python3
"""
Convert all pcap.csv attack datasets to the correct 15-feature schema.
Extracts attack type from filename and adds proper labels.
Comprehensive feature set for maximum attack detection.
"""
import pandas as pd
import numpy as np
from pathlib import Path
import re

# Target 15-feature schema (comprehensive detection)
TARGET_FEATURES = [
    # Core flow features (5)
    "flows",
    "bytes_total",
    "pkts_total",
    # "uniq_src", # Dropped
    # "uniq_dst", # Dropped
    "syn_ratio",
    "mean_bytes_flow",
    # Flag ratios for attack detection (3)
    "ack_ratio",
    "fin_ratio",
    "rst_ratio",
    # Protocol features (3)
    "http_ratio",
    "tcp_ratio",
    "protocol_diversity",
    # Statistical features (2)
    "std_bytes",
    "iat_mean",
]

def normalize_col_name(name: str) -> str:
    """Normalize column names for matching."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())

def find_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    """Find column by normalized name."""
    normed = {normalize_col_name(c): c for c in df.columns}
    for cand in candidates:
        key = normalize_col_name(cand)
        if key in normed:
            return normed[key]
    return None

def extract_attack_label(filename: str) -> str:
    """Extract attack type from filename."""
    name = Path(filename).stem
    # Remove .pcap suffix if present
    name = name.replace(".pcap", "")
    
    # Map common patterns
    name_lower = name.lower()
    
    # DDoS/DoS attacks
    if "ddos" in name_lower or "dos" in name_lower:
        if "http" in name_lower or "http" in name:
            return "ddos_http"
        elif "syn" in name_lower:
            return "ddos_syn"
        elif "tcp" in name_lower:
            return "ddos_tcp"
        elif "udp" in name_lower:
            return "ddos_udp"
        elif "icmp" in name_lower:
            return "ddos_icmp"
        elif "slowloris" in name_lower:
            return "ddos_slowloris"
        elif "ack" in name_lower:
            return "ddos_ack"
        elif "fragmentation" in name_lower:
            return "ddos_fragmentation"
        else:
            return "ddos_other"
    
    # Mirai attacks
    if "mirai" in name_lower:
        if "greeth" in name_lower:
            return "mirai_greeth"
        elif "greip" in name_lower:
            return "mirai_greip"
        elif "udp" in name_lower:
            return "mirai_udp"
        else:
            return "mirai_other"
    
    # Reconnaissance
    if "recon" in name_lower:
        if "portscan" in name_lower or "port" in name_lower:
            return "recon_portscan"
        elif "host" in name_lower:
            return "recon_hostdiscovery"
        elif "osscan" in name_lower or "os" in name_lower:
            return "recon_osscan"
        elif "ping" in name_lower:
            return "recon_pingsweep"
        else:
            return "recon_other"
    
    # Injection attacks
    if "injection" in name_lower:
        if "sql" in name_lower:
            return "injection_sql"
        elif "command" in name_lower:
            return "injection_command"
        else:
            return "injection_other"
    
    # Other attacks
    if "spoofing" in name_lower:
        if "dns" in name_lower:
            return "spoofing_dns"
        elif "arp" in name_lower or "mitm" in name_lower:
            return "spoofing_arp"
        else:
            return "spoofing_other"
    
    if "bruteforce" in name_lower or "brute" in name_lower:
        return "bruteforce"
    
    if "xss" in name_lower:
        return "xss"
    
    if "hijacking" in name_lower:
        return "hijacking"
    
    if "scan" in name_lower:
        return "vulnerability_scan"
    
    if "upload" in name_lower:
        return "upload_attack"
    
    # Default: use cleaned filename
    return name.replace("-", "_").replace(" ", "_").lower()

def convert_pcap_to_features(input_path: Path, output_path: Path, attack_label: str):
    """Convert a pcap.csv file to 7-feature schema."""
    try:
        df = pd.read_csv(input_path, low_memory=False)
        
        # Find relevant columns
        # Try to find packet/flow counts
        pkt_col = find_column(df, ["Number", "number", "pkt number", "pktnum", "packet count", "packets"])
        byte_col = find_column(df, ["Tot Sum", "totsum", "total bytes", "total length", "bytes", "length"])
        
        # Try to find SYN-related columns
        syn_flag_col = find_column(df, ["syn flag number", "synflagnumber", "syn_flag_number", "syn_proportion"])
        syn_count_col = find_column(df, ["syn count", "syncount", "syn_count"])
        
        # Try to find unique IP columns
        src_col = find_column(df, ["uniq src", "unique src", "src count", "source count"])
        dst_col = find_column(df, ["uniq dst", "unique dst", "dst count", "dest count"])
        
        # If we can't find the basic columns, try aggregating from available data
        if not pkt_col or not byte_col:
            # Try to use Rate or other aggregatable columns
            if not pkt_col:
                # Try to estimate from available columns
                numeric_cols = df.select_dtypes(include=[np.number]).columns
                if len(numeric_cols) > 0:
                    # Use first numeric column as proxy (not ideal but better than nothing)
                    pkt_col = numeric_cols[0]
                    print(f"  [WARNING] Using {pkt_col} as packet proxy for {input_path.name}")
            
            if not byte_col:
                # Try to find any byte-related column
                byte_col = find_column(df, ["bytes", "length", "size", "total"])
                if not byte_col:
                    numeric_cols = df.select_dtypes(include=[np.number]).columns
                    if len(numeric_cols) > 1:
                        byte_col = numeric_cols[1]
                        print(f"  [WARNING] Using {byte_col} as byte proxy for {input_path.name}")
        
        if not pkt_col or not byte_col:
            raise ValueError(f"Cannot find required columns in {input_path.name}")
        
        # Convert to numeric
        df[pkt_col] = pd.to_numeric(df[pkt_col], errors="coerce").fillna(0)
        df[byte_col] = pd.to_numeric(df[byte_col], errors="coerce").fillna(0)
        
        # Calculate features
        flows = df[pkt_col].astype(int).clip(lower=1)  # At least 1 flow
        bytes_total = df[byte_col].astype(float)
        pkts_total = flows.copy()
        
        # Calculate syn_ratio
        syn_ratio = pd.Series(0.0, index=df.index)
        if syn_flag_col and syn_flag_col in df.columns:
            syn_ratio = pd.to_numeric(df[syn_flag_col], errors="coerce").fillna(0).clip(lower=0, upper=1)
        elif syn_count_col and syn_count_col in df.columns:
            syn_count = pd.to_numeric(df[syn_count_col], errors="coerce").fillna(0)
            syn_ratio = (syn_count / flows).fillna(0).clip(lower=0, upper=1)
        else:
            # Try to find any flag-related column that might indicate SYN
            flag_cols = [c for c in df.columns if "flag" in normalize_col_name(c) or "syn" in normalize_col_name(c)]
            if flag_cols:
                # Use proportion if available, else estimate
                syn_ratio = pd.Series(0.1, index=df.index)  # Default estimate
                print(f"  [WARNING] Estimating syn_ratio for {input_path.name}")
        
        # Unique source/destination
        if src_col and src_col in df.columns:
            uniq_src = pd.to_numeric(df[src_col], errors="coerce").fillna(1).astype(int).clip(lower=1)
        else:
            uniq_src = pd.Series(1, index=df.index, dtype=int)
        
        if dst_col and dst_col in df.columns:
            uniq_dst = pd.to_numeric(df[dst_col], errors="coerce").fillna(1).astype(int).clip(lower=1)
        else:
            uniq_dst = pd.Series(1, index=df.index, dtype=int)
        
        # Mean bytes per flow
        mean_bytes_flow = (bytes_total / flows).fillna(0)
        
        # Calculate additional flag ratios
        ack_ratio = pd.Series(0.0, index=df.index)
        fin_ratio = pd.Series(0.0, index=df.index)
        rst_ratio = pd.Series(0.0, index=df.index)
        
        # ACK ratio
        ack_flag_col = find_column(df, ["ack flag number", "ackflagnumber", "ack_flag_number"])
        ack_count_col = find_column(df, ["ack count", "ackcount", "ack_count"])
        if ack_flag_col and ack_flag_col in df.columns:
            ack_ratio = pd.to_numeric(df[ack_flag_col], errors="coerce").fillna(0).clip(lower=0, upper=1)
        elif ack_count_col and ack_count_col in df.columns:
            ack_count = pd.to_numeric(df[ack_count_col], errors="coerce").fillna(0)
            ack_ratio = (ack_count / flows).fillna(0).clip(lower=0, upper=1)
        
        # FIN ratio
        fin_flag_col = find_column(df, ["fin flag number", "finflagnumber", "fin_flag_number"])
        fin_count_col = find_column(df, ["fin count", "fincount", "fin_count"])
        if fin_flag_col and fin_flag_col in df.columns:
            fin_ratio = pd.to_numeric(df[fin_flag_col], errors="coerce").fillna(0).clip(lower=0, upper=1)
        elif fin_count_col and fin_count_col in df.columns:
            fin_count = pd.to_numeric(df[fin_count_col], errors="coerce").fillna(0)
            fin_ratio = (fin_count / flows).fillna(0).clip(lower=0, upper=1)
        
        # RST ratio
        rst_flag_col = find_column(df, ["rst flag number", "rstflagnumber", "rst_flag_number"])
        rst_count_col = find_column(df, ["rst count", "rstcount", "rst_count"])
        if rst_flag_col and rst_flag_col in df.columns:
            rst_ratio = pd.to_numeric(df[rst_flag_col], errors="coerce").fillna(0).clip(lower=0, upper=1)
        elif rst_count_col and rst_count_col in df.columns:
            rst_count = pd.to_numeric(df[rst_count_col], errors="coerce").fillna(0)
            rst_ratio = (rst_count / flows).fillna(0).clip(lower=0, upper=1)
        
        # Protocol features
        http_ratio = pd.Series(0.0, index=df.index)
        tcp_ratio = pd.Series(0.0, index=df.index)
        protocol_diversity = pd.Series(0, index=df.index, dtype=int)
        
        # HTTP ratio
        http_col = find_column(df, ["HTTP", "http"])
        if http_col and http_col in df.columns:
            http_count = pd.to_numeric(df[http_col], errors="coerce").fillna(0)
            http_ratio = (http_count / flows).fillna(0).clip(lower=0, upper=1)
        
        # TCP ratio
        tcp_col = find_column(df, ["TCP", "tcp"])
        if tcp_col and tcp_col in df.columns:
            tcp_count = pd.to_numeric(df[tcp_col], errors="coerce").fillna(0)
            tcp_ratio = (tcp_count / flows).fillna(0).clip(lower=0, upper=1)
        
        # Protocol diversity (count of non-zero protocol columns)
        protocol_cols = [c for c in df.columns if c in ["HTTP", "HTTPS", "DNS", "TCP", "UDP", "ICMP", "SMTP", "SSH", "Telnet", "DHCP", "ARP", "IGMP"]]
        if protocol_cols:
            for col in protocol_cols:
                protocol_diversity += (pd.to_numeric(df[col], errors="coerce").fillna(0) > 0).astype(int)
        protocol_diversity = protocol_diversity.clip(lower=0, upper=12)  # Max 12 protocols
        
        # Statistical features
        std_bytes = pd.Series(0.0, index=df.index)
        iat_mean = pd.Series(0.0, index=df.index)
        
        # Std bytes
        std_col = find_column(df, ["Std", "std", "standard deviation", "stddev"])
        if std_col and std_col in df.columns:
            std_bytes = pd.to_numeric(df[std_col], errors="coerce").fillna(0).clip(lower=0)
        else:
            # Estimate from Min/Max if available
            min_col = find_column(df, ["Min", "min", "minimum"])
            max_col = find_column(df, ["Max", "max", "maximum"])
            if min_col and max_col and min_col in df.columns and max_col in df.columns:
                min_val = pd.to_numeric(df[min_col], errors="coerce").fillna(0)
                max_val = pd.to_numeric(df[max_col], errors="coerce").fillna(0)
                std_bytes = ((max_val - min_val) / 4.0).clip(lower=0)  # Rough estimate
        
        # IAT (Inter-Arrival Time) mean
        iat_col = find_column(df, ["IAT", "iat", "inter arrival time", "interarrival"])
        if iat_col and iat_col in df.columns:
            iat_mean = pd.to_numeric(df[iat_col], errors="coerce").fillna(0).clip(lower=0)
        else:
            # Estimate from Rate if available
            rate_col = find_column(df, ["Rate", "rate", "packet rate"])
            if rate_col and rate_col in df.columns:
                rate = pd.to_numeric(df[rate_col], errors="coerce").fillna(0)
                iat_mean = (1.0 / (rate + 1e-6)).clip(lower=0, upper=1000)  # Inverse of rate
        
        # Create output DataFrame with all 13 features
        out_df = pd.DataFrame({
            # Core features
            "flows": flows,
            "bytes_total": bytes_total.round(2),
            "pkts_total": pkts_total,
            # "uniq_src": uniq_src,
            # "uniq_dst": uniq_dst,
            "syn_ratio": syn_ratio.round(6),
            "mean_bytes_flow": mean_bytes_flow.round(6),
            # Flag ratios (3)
            "ack_ratio": ack_ratio.round(6),
            "fin_ratio": fin_ratio.round(6),
            "rst_ratio": rst_ratio.round(6),
            # Protocol features (3)
            "http_ratio": http_ratio.round(6),
            "tcp_ratio": tcp_ratio.round(6),
            "protocol_diversity": protocol_diversity,
            # Statistical features (2)
            "std_bytes": std_bytes.round(2),
            "iat_mean": iat_mean.round(6),
            "label": attack_label
        })
        
        # Remove any rows with invalid data
        out_df = out_df.replace([np.inf, -np.inf], np.nan).dropna()
        
        # Save
        output_path.parent.mkdir(parents=True, exist_ok=True)
        out_df.to_csv(output_path, index=False)
        
        return len(out_df)
    
    except Exception as e:
        print(f"  [ERROR] Failed to convert {input_path.name}: {e}")
        return 0

def main():
    data_dir = Path("data")
    converted_dir = data_dir / "converted_attacks"
    converted_dir.mkdir(exist_ok=True)
    
    # Find all pcap.csv files
    # pcap_files = sorted([f for f in data_dir.glob("*.pcap.csv") if "Benign" not in f.name])
    pcap_files = sorted([f for f in data_dir.glob("*.pcap.csv")])
    
    print("=" * 60)
    print("Converting Attack Datasets to 7-Feature Schema")
    print("=" * 60)
    print(f"\nFound {len(pcap_files)} attack datasets to convert\n")
    
    converted = []
    failed = []
    
    for pcap_file in pcap_files:
        attack_label = extract_attack_label(pcap_file.name)
        output_name = pcap_file.stem + "_converted.csv"
        output_path = converted_dir / output_name
        
        print(f"[*] Converting: {pcap_file.name}")
        print(f"    Label: {attack_label}")
        
        rows = convert_pcap_to_features(pcap_file, output_path, attack_label)
        
        if rows > 0:
            converted.append((pcap_file.name, attack_label, rows, output_path))
            print(f"    [OK] Converted {rows} rows -> {output_path.name}\n")
        else:
            failed.append(pcap_file.name)
            print(f"    [FAILED]\n")
    
    # Summary
    print("=" * 60)
    print("Conversion Summary")
    print("=" * 60)
    print(f"\nSuccessfully converted: {len(converted)} files")
    print(f"Failed: {len(failed)} files")
    
    if converted:
        print(f"\n[CONVERTED FILES]")
        total_rows = 0
        for name, label, rows, path in converted:
            print(f"  {name:40s} -> {label:25s} ({rows:6,} rows)")
            total_rows += rows
        print(f"\nTotal rows converted: {total_rows:,}")
        print(f"\nOutput directory: {converted_dir}")
        print(f"\nNext step: Merge these into training data or use for testing")
    
    if failed:
        print(f"\n[FAILED FILES]")
        for name in failed:
            print(f"  - {name}")

if __name__ == "__main__":
    main()

