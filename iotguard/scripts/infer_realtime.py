import io, os, json, time
from datetime import datetime, timezone
from pathlib import Path
import joblib, pandas as pd, yaml

CFG = yaml.safe_load(io.open("configs/model.yaml", "r", encoding="utf-8-sig"))
MODEL_PATH = CFG["paths"]["model"]
AUDIT_PATH = CFG["paths"]["audit"]
CSV_PATH   = CFG["paths"]["csv"]
FEATS      = CFG["features"]
THRESH     = float(CFG["decision"]["threshold"])
GRACE      = int(CFG["decision"].get("grace_windows", 2))

os.makedirs(Path(AUDIT_PATH).parent, exist_ok=True)

print("🟢 Inference starting…")
print("📦 Loading model:", MODEL_PATH)
model = joblib.load(MODEL_PATH)
print("✅ Model loaded")

hit_streak = {}

def now_iso(): return datetime.now(timezone.utc).isoformat()
def log_audit(d: dict):
    with open(AUDIT_PATH, "a", encoding="utf-8") as f: f.write(json.dumps(d, ensure_ascii=False) + "\n")

def score_row(row_dict: dict) -> float:
    xdf = pd.DataFrame([row_dict], columns=FEATS)
    for f in FEATS:
        xdf[f] = pd.to_numeric(xdf[f], errors="coerce")
    if xdf.isna().any().any():
        raise ValueError("Row has NaN after coercion; missing or non-numeric features.")
    if hasattr(model, "predict_proba"):
        return float(model.predict_proba(xdf)[0, 1])
    return float(model.predict(xdf)[0])

def decide(ip: str, p: float):
    lbl = "ATTACK" if p >= THRESH else "benign"
    hit_streak[ip] = hit_streak.get(ip, 0) + 1 if lbl == "ATTACK" else 0
    action = "block" if (lbl == "ATTACK" and hit_streak[ip] >= GRACE) else "none"
    return lbl, action, hit_streak[ip]

# Demo: watch CSV for new rows
last_len = 0
print(f"🧪 Demo mode: watching {CSV_PATH} for new rows… (Ctrl+C to stop)")
while True:
    try:
        if os.path.exists(CSV_PATH):
            df = pd.read_csv(CSV_PATH)
            if len(df) > last_len:
                batch = df.iloc[last_len:]
                for idx, r in batch.iterrows():
                    row = {f: r[f] for f in FEATS if f in r}
                    try:
                        p = score_row(row)
                    except Exception as e:
                        print(f"{idx}: ⚠️ bad row ({e})"); continue
                    ip = f"10.0.0.{(idx % 250) + 1}"
                    lbl, action, streak = decide(ip, p)
                    print(f"{idx}: ip={ip} score={p:.3f} ({lbl}), streak={streak} → {action}")
                    log_audit({
                        "ts": now_iso(), "row": int(idx), "ip": ip,
                        "score": round(p, 6), "label": lbl, "streak": streak,
                        "action": action, "reason": f"threshold {THRESH}, grace {GRACE}"
                    })
                last_len = len(df)
        time.sleep(0.3)
    except KeyboardInterrupt:
        print("\n👋 Stopped."); break
    except Exception as e:
        print(f"⚠️ infer error: {e}"); time.sleep(0.5)
