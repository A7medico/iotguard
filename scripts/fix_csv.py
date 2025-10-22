import pandas as pd, os
# -----------------------------------------------------------------------------
# Utility — Clean features.csv in-place
#
# Purpose
#   - Coerce columns to numeric and drop rows with NaNs; write back to disk.
# -----------------------------------------------------------------------------

path = 'data/features.csv'
if not os.path.exists(path):
    print('No CSV found at', path)
else:
    df = pd.read_csv(path)
    # Convert all columns to numeric safely
    for c in df.columns:
        df[c] = pd.to_numeric(df[c].astype(str).str.strip(), errors='coerce')
    before = len(df)
    df.dropna(inplace=True)
    df.to_csv(path, index=False)
    print(f'✅ Cleaned {path}. Rows kept: {len(df)} / {before}')
