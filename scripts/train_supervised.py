# scripts/train_supervised.py
# -----------------------------------------------------------------------------
# IoTGuard Pipeline — Supervised training (binary or multiclass)
#
# Purpose
#   - Fit a LightGBM model on aggregated feature windows using either binary
#     labels (0/1) or string class labels (e.g., benign, ddos_http, recon).
#
# Inputs
#   - data/iotguard_training.csv: columns = FEATURES + label
#
# Outputs
#   - models/lightgbm.joblib : trained model
#   - models/classes.json    : class order and benign index (multiclass only)
#
# Operational notes
#   - Keeps the feature list in configs/model.yaml authoritative.
#   - If no dataset exists, generates a small synthetic binary dataset to make
#     the script runnable for demos.
# -----------------------------------------------------------------------------
import os, io, json, numpy as np, pandas as pd, joblib, yaml
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
        # label can be 0/1 or strings (benign/ddos_http/etc). Keep strings for multiclass.
        if df["label"].dtype == object:
            df["label"] = df["label"].astype(str).str.strip().str.lower()
        else:
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

    classes_info = None
    # Determine binary vs multiclass and encode labels if needed
    if y.dtype == object:
        y_raw = y.astype(str).str.strip().str.lower()
        class_names = sorted(y_raw.unique())
        class_to_id = {c: i for i, c in enumerate(class_names)}
        benign_index = class_to_id.get("benign")
        y_enc = y_raw.map(class_to_id).astype(int)
        ytr = ytr.astype(str).str.strip().str.lower().map(class_to_id).astype(int)
        yte = yte.astype(str).str.strip().str.lower().map(class_to_id).astype(int)
        num_classes = len(class_names)
        objective = "multiclass" if num_classes > 2 else "binary"
        params = {**CFG["lgbm"]}
        if objective == "multiclass":
            params["objective"] = objective
            params["num_class"] = num_classes
        model = LGBMClassifier(**params)
        model.fit(Xtr, ytr)
        classes_info = {"classes": class_names, "benign_index": benign_index}
    else:
        # Binary numeric labels 0/1
        model = LGBMClassifier(**CFG["lgbm"])
        model.fit(Xtr, ytr)

    ypred = model.predict(Xte)
    print("Evaluation report:")
    print(classification_report(yte, ypred, digits=4))

    joblib.dump(model, MODEL_PATH)
    print(f"Saved model -> {MODEL_PATH}")
    if classes_info is not None:
        with open("models/classes.json", "w", encoding="utf-8") as f:
            json.dump(classes_info, f, ensure_ascii=False)
        print("Saved class mapping -> models/classes.json")

if __name__ == "__main__":
    main()
