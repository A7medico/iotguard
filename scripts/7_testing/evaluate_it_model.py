"""
Evaluate IT model on holdout CICIDS 2017 data
"""
import pandas as pd
import numpy as np
import joblib
import json
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score, roc_auc_score, classification_report

# Load model
model = joblib.load('models/lightgbm_it.joblib')
meta = json.loads(Path('models/model_meta_it.json').read_text())
features = meta['features']
threshold = meta['threshold']

# Load the full mapped CICIDS data and use 20% as test
df = pd.read_csv('data/it_training_cicids2017_mapped.csv')
print(f'Total samples: {len(df):,}')

# Use a different random state than training to simulate unseen data
train_df, test_df = train_test_split(df, test_size=0.2, random_state=999, stratify=df['label'])
print(f'Test set: {len(test_df):,} samples')

X = test_df[features].values
y = test_df['label'].values

y_prob = model.predict_proba(X)[:, 1]
y_pred = (y_prob >= threshold).astype(int)

acc = accuracy_score(y, y_pred)
auc = roc_auc_score(y, y_prob)
cm = confusion_matrix(y, y_pred)

tn, fp, fn, tp = cm.ravel()
fpr = fp / (fp + tn)
tpr = tp / (tp + fn)

print(f'\nIT Model (trained on full CICIDS 2017):')
print(f'  Accuracy: {acc*100:.2f}%')
print(f'  ROC-AUC:  {auc:.4f}')
print(f'  FPR:      {fpr*100:.2f}%')
print(f'  Recall:   {tpr*100:.2f}%')
print(f'\nConfusion Matrix:')
print(f'  TN={tn:,}  FP={fp:,}')
print(f'  FN={fn:,}  TP={tp:,}')
print('\nClassification Report:')
print(classification_report(y, y_pred, target_names=['Benign', 'Attack']))
