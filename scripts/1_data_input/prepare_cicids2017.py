"""
Map CICIDS 2017 columns to IoTGuard features and create training data
"""
import pandas as pd
import numpy as np
from pathlib import Path

def map_cicids_to_iotguard(df):
    """Map CICIDS 2017 columns to IoTGuard features"""
    df.columns = [c.strip() for c in df.columns]
    
    mapped = pd.DataFrame()
    
    # flows: count of subflows or 1 per row
    mapped['flows'] = 1
    
    # bytes_total: Total Length Fwd + Bwd
    fwd_bytes = df.get('Total Length of Fwd Packets', pd.Series([0]*len(df))).fillna(0)
    bwd_bytes = df.get('Total Length of Bwd Packets', pd.Series([0]*len(df))).fillna(0)
    mapped['bytes_total'] = fwd_bytes + bwd_bytes
    
    # pkts_total: Total Fwd + Bwd packets
    fwd_pkts = df.get('Total Fwd Packets', pd.Series([0]*len(df))).fillna(0)
    bwd_pkts = df.get('Total Backward Packets', pd.Series([0]*len(df))).fillna(0)
    mapped['pkts_total'] = fwd_pkts + bwd_pkts
    
    # Flag ratios
    syn = df.get('SYN Flag Count', pd.Series([0]*len(df))).fillna(0)
    ack = df.get('ACK Flag Count', pd.Series([0]*len(df))).fillna(0)
    fin = df.get('FIN Flag Count', pd.Series([0]*len(df))).fillna(0)
    rst = df.get('RST Flag Count', pd.Series([0]*len(df))).fillna(0)
    total_flags = syn + ack + fin + rst + 1  # +1 to avoid division by zero
    
    mapped['syn_ratio'] = syn / total_flags
    mapped['ack_ratio'] = ack / total_flags
    mapped['fin_ratio'] = fin / total_flags
    mapped['rst_ratio'] = rst / total_flags
    
    # mean_bytes_flow: Average Packet Size
    mapped['mean_bytes_flow'] = df.get('Average Packet Size', pd.Series([0]*len(df))).fillna(0)
    
    # http_ratio: based on port 80/443
    mapped['http_ratio'] = 0.0
    if 'Destination Port' in df.columns:
        port = df['Destination Port'].fillna(0)
        mapped['http_ratio'] = port.isin([80, 443, 8080]).astype(float)
    
    # tcp_ratio: approximation (most CICIDS traffic is TCP)
    mapped['tcp_ratio'] = 0.9
    
    # protocol_diversity
    mapped['protocol_diversity'] = 1.0
    
    # std_bytes: Packet Length Std
    mapped['std_bytes'] = df.get('Packet Length Std', pd.Series([0]*len(df))).fillna(0)
    
    # iat_mean: Flow IAT Mean
    mapped['iat_mean'] = df.get('Flow IAT Mean', pd.Series([0]*len(df))).fillna(0)
    
    # Label
    label_col = 'Label' if 'Label' in df.columns else 'label'
    mapped['label'] = (df[label_col].astype(str).str.upper() != 'BENIGN').astype(int)
    
    return mapped

# Process all files
cicids_files = list(Path('data').glob('*ISCX*.csv'))
print(f'Processing {len(cicids_files)} CICIDS 2017 files with feature mapping...')

all_dfs = []
for f in cicids_files:
    print(f'  {f.name}...', end=' ', flush=True)
    try:
        df = pd.read_csv(f)
        mapped = map_cicids_to_iotguard(df)
        mapped = mapped.replace([np.inf, -np.inf], np.nan).fillna(0)
        benign = (mapped['label'] == 0).sum()
        attack = (mapped['label'] == 1).sum()
        print(f'{len(mapped):,} rows (B:{benign:,} A:{attack:,})')
        all_dfs.append(mapped)
    except Exception as e:
        print(f'Error: {e}')

combined = pd.concat(all_dfs, ignore_index=True)
combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

benign_count = (combined['label'] == 0).sum()
attack_count = (combined['label'] == 1).sum()
print(f'\nTotal: {len(combined):,} samples')
print(f'  Benign: {benign_count:,}')
print(f'  Attack: {attack_count:,}')

combined.to_csv('data/it_training_cicids2017_mapped.csv', index=False)
print(f'\nSaved to data/it_training_cicids2017_mapped.csv')
