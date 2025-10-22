# Utility — Quick scorer: tail features.csv and print scores
import io, time, joblib, yaml, pandas as pd, os

CFG = yaml.safe_load(io.open("configs/model.yaml","r",encoding="utf-8-sig"))
model = joblib.load("models/lightgbm.joblib")
path = "data/features.csv"

print("🟢 Tailing", path)
last = 0
while True:
    if os.path.exists(path):
        df = pd.read_csv(path)
        if len(df) > last:
            batch = df.iloc[last:]
            X = batch[CFG["features"]]
            proba = model.predict_proba(X)[:,1] if hasattr(model,"predict_proba") else model.predict(X)
            for idx, p in zip(batch.index, proba):
                print(f"{idx}: score={p:.3f} → {'ATTACK' if p>=0.65 else 'benign'}")
            last = len(df)
    time.sleep(1)
