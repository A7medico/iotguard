# scripts/train_supervised.py
import os, io, numpy as np, pandas as pd, joblib, yaml
from lightgbm import LGBMClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

CFG = yaml.safe_load(io.open("configs/model.yaml", "r", encoding="utf-8-sig"))
FEATURES = CFG["features"]
MODEL_PATH = "models/lightgbm.joblib"
DATA_PATH = "data/iotguard_training.csv"

def load_or_make_data():
    if os.path.exists(DATA_PATH):
        print(f"Loading {DATA_PATH}")
        df = pd.read_csv(DATA_PATH)
        # label can be 0/1 or strings (benign/attack)
        if df["label"].dtype == object:
            df["label"] = df["label"].str.lower().map({"benign":0, "attack":1})
        df["label"] = df["label"].astype(int)
        # keep only available features
        missing = [f for f in FEATURES if f not in df.columns]
        if missing:
            raise ValueError(f"Missing features in CSV: {missing}")
        return df[FEATURES + ["label"]]
    else:
        print("No CSV found - generating synthetic training data (500 rows)")
        rng = np.random.default_rng(42)
        n = 500
        flows = rng.integers(5, 60, n)
        bytes_total = flows * rng.integers(60, 140, n) + rng.normal(0, 200, n)
        pkts_total = flows * rng.integers(2, 4, n)
        uniq_src = rng.integers(1, 10, n)
        uniq_dst = rng.integers(1, 10, n)
        syn_ratio = np.clip(rng.normal(0.25, 0.15, n), 0, 1)
        mean_bytes_flow = bytes_total / np.maximum(flows, 1)
        # label rule: high flows + high syn_ratio OR very high bytes → attack
        label = ((flows > 25) & (syn_ratio > 0.45) | (bytes_total > 3500)).astype(int)

        df = pd.DataFrame(dict(
            flows=flows, bytes_total=bytes_total, pkts_total=pkts_total,
            uniq_src=uniq_src, uniq_dst=uniq_dst, syn_ratio=syn_ratio,
            mean_bytes_flow=mean_bytes_flow, label=label
        ))
        return df

def main():
    print("Training supervised model...")
    os.makedirs("models", exist_ok=True)

    df = load_or_make_data()
    X = df[FEATURES]
    y = df["label"]

    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    model = LGBMClassifier(**CFG["lgbm"])
    model.fit(Xtr, ytr)

    ypred = model.predict(Xte)
    print("Evaluation report:")
    print(classification_report(yte, ypred, digits=4))

    joblib.dump(model, MODEL_PATH)
    print(f"Saved model -> {MODEL_PATH}")

if __name__ == "__main__":
    main()
