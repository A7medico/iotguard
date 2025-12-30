"""
Evaluate unsupervised IsolationForest model
"""
import pandas as pd
import numpy as np
import joblib
import json
from pathlib import Path
from sklearn.metrics import confusion_matrix, accuracy_score, roc_auc_score, classification_report

# Load model
model = joblib.load('models/unsup_isoforest.joblib')
meta = json.loads(Path('models/unsup_meta.json').read_text())
features = meta['features']
threshold = meta['threshold']

print("=" * 60)
print("UNSUPERVISED MODEL (IsolationForest) EVALUATION")
print("=" * 60)
print(f"\nModel: {meta['algorithm']}")
print(f"Trained on: {meta['train_on']}")
print(f"Contamination: {meta['contamination']}")
print(f"Threshold: {threshold:.4f}")

# Load IoT test data
test_dir = Path('data/test_holdout')
dfs = []
for f in test_dir.glob('*.csv'):
    df = pd.read_csv(f)
    if 'label' not in df.columns:
        df['label'] = 0 if 'benign' in f.name.lower() else 1
    else:
        df['label'] = (df['label'].astype(str).str.lower() != 'benign').astype(int)
    dfs.append(df)
full_df = pd.concat(dfs, ignore_index=True)

# Prepare features
full_df.columns = [c.strip().replace(' ', '_') for c in full_df.columns]
for f in features:
    if f not in full_df.columns:
        full_df[f] = 0.0

X = full_df[features].replace([np.inf, -np.inf], np.nan).fillna(0).values
y = full_df['label'].values

print(f"\nTest data: {len(X):,} samples")
print(f"  Benign: {(y==0).sum():,}")
print(f"  Attack: {(y==1).sum():,}")

# Get anomaly scores (higher = more anomalous)
# IsolationForest: decision_function returns negative scores for anomalies
raw_scores = model.decision_function(X)
# Invert so higher = more anomalous
scores = -raw_scores

# Normalize to 0-1 range
scores_norm = (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)

# Predict
y_pred = (scores_norm >= threshold).astype(int)

# Calculate metrics
acc = accuracy_score(y, y_pred)
cm = confusion_matrix(y, y_pred)
tn, fp, fn, tp = cm.ravel()
fpr = fp / (fp + tn)
tpr = tp / (tp + fn)

try:
    auc = roc_auc_score(y, scores_norm)
except:
    auc = 0.0

print(f"\n--- Results ---")
print(f"Accuracy:  {acc*100:.2f}%")
print(f"ROC-AUC:   {auc:.4f}")
print(f"FPR:       {fpr*100:.2f}%")
print(f"Recall:    {tpr*100:.2f}%")

print(f"\nConfusion Matrix:")
print(f"  TN={tn:,}  FP={fp:,}")
print(f"  FN={fn:,}  TP={tp:,}")

print("\nClassification Report:")
print(classification_report(y, y_pred, target_names=['Benign', 'Attack']))
