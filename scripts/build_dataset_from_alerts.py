import io, json, glob, sys
from pathlib import Path
import pandas as pd, yaml
# -----------------------------------------------------------------------------
# Utility — Build labeled CSV from live alerts + features
#
# Purpose
#   - Join the current features.csv with decision_loop alerts to produce a
#     simple binary-labeled dataset for quick retraining.
#
# Notes
#   - Labels 1 when any alert for a CSV row index has state==ATTACK; else 0.
#   - Good for bootstrapping models from your own environment’s behavior.
# -----------------------------------------------------------------------------

DATA_DIR = Path("data")
FEATURES_CSV = DATA_DIR / "features.csv"
OUT_CSV = DATA_DIR / "iotguard_training.csv"

def load_features_list() -> list[str]:
    cfg_path = Path("configs/model.yaml")
    try:
        cfg = yaml.safe_load(io.open(cfg_path, "r", encoding="utf-8-sig")) or {}
        feats = list(cfg.get("features") or [])
        return feats
    except Exception:
        # fallback to default columns used in the project
        return [
            "flows","bytes_total","pkts_total",
            "uniq_src","uniq_dst","syn_ratio","mean_bytes_flow",
        ]

def load_alert_labels() -> dict[int, int]:
    """Aggregate labels per CSV index from alerts logs.
    Label 1 if any event for that index had state=="ATTACK", else 0.
    """
    labels: dict[int, int] = {}
    # include rotated logs as well
    paths = [str(DATA_DIR / "alerts.jsonl")] + glob.glob(str(DATA_DIR / "alerts-*.jsonl"))
    for p in paths:
        path = Path(p)
        if not path.exists():
            continue
        try:
            for line in io.open(path, "r", encoding="utf-8"):
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                idx = ev.get("index")
                if idx is None:
                    continue
                is_attack = 1 if str(ev.get("state", "")).upper() == "ATTACK" else 0
                prev = labels.get(int(idx), 0)
                # once attack, keep it as positive
                labels[int(idx)] = 1 if (prev == 1 or is_attack == 1) else 0
        except Exception:
            continue
    return labels

def main():
    if not FEATURES_CSV.exists():
        print(f"features.csv not found at {FEATURES_CSV}")
        sys.exit(1)

    features = load_features_list()
    df = pd.read_csv(FEATURES_CSV)
    missing = [c for c in features if c not in df.columns]
    if missing:
        print(f"Missing feature columns in features.csv: {missing}")
        sys.exit(1)

    labels = load_alert_labels()
    if not labels:
        print("No labels found in alerts logs; generate some events first.")
        sys.exit(1)

    rows = []
    matched = 0
    for idx, y in labels.items():
        if idx in df.index:
            row = df.loc[idx, features]
            rec = {c: row[c] for c in features}
            rec["label"] = int(y)
            rows.append(rec)
            matched += 1

    if not rows:
        print("Labels found, but no matching indices in current features.csv")
        sys.exit(1)

    out_df = pd.DataFrame(rows, columns=features + ["label"]).dropna()
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(OUT_CSV, index=False)
    print(f"Built dataset -> {OUT_CSV}  rows={len(out_df)}  matched_indices={matched}  total_labels={len(labels)}")

if __name__ == "__main__":
    main()


