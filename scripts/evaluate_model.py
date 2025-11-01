# scripts/evaluate_model.py
import os, glob, json, argparse
from pathlib import Path
import numpy as np
import pandas as pd
from joblib import load
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_curve, auc, precision_recall_curve, average_precision_score
)
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt

# ----------------- Project defaults -----------------
DATA_DIR   = Path("data")
MODEL_PATH = Path("models/lightgbm.joblib")
REPORT_DIR = Path("logs/eval")
FEATURES   = ["flows","bytes_total","pkts_total","uniq_src","uniq_dst","syn_ratio","mean_bytes_flow"]

def _coerce_numeric(df, cols):
    for c in cols:
        df[c] = pd.to_numeric(df[c].astype(str).str.strip(), errors="coerce")
    return df.dropna(subset=cols)

def _infer_label(df, fallback=None):
    """
    Try to find a label column automatically.
    - Supports: 'label' (0/1), 'attack' (True/False or string), 'y'
    """
    candidates = ["label", "attack", "y", "target", "class"]
    for c in candidates:
        if c in df.columns:
            y = df[c]
            # normalize to 0/1
            if y.dtype == bool:
                return y.astype(int)
            if y.dtype.kind in "biu":
                return y.astype(int)
            # string -> 0/1
            return y.astype(str).str.lower().isin(["1","true","attack","malicious","ddos"]).astype(int)

    if fallback is not None:
        return pd.Series(np.full(len(df), fallback, dtype=int), index=df.index)

    raise RuntimeError("Could not infer label column. Please add a 'label' column (0/1).")

def _load_training_table():
    """
    Flexible loader:
    - If data/iotguard_training.csv exists -> use it.
    - Else, merge any *sim.csv (e.g., benign_sim.csv, ddos_sim.csv), inferring label from filename.
    """
    main = DATA_DIR / "iotguard_training.csv"
    if main.exists():
        df = pd.read_csv(main)
        df = _coerce_numeric(df, FEATURES)
        y  = _infer_label(df)
        return df[FEATURES].copy(), y

    # fallback: merge *_sim.csv
    parts = []
    for path in glob.glob(str(DATA_DIR / "*sim.csv")):
        tmp = pd.read_csv(path)
        tmp = _coerce_numeric(tmp, FEATURES)
        fname = Path(path).name.lower()
        # filename-based label inference
        if "benign" in fname:
            y = _infer_label(tmp, fallback=0)
        else:
            # treat others (ddos_sim.csv, ddos_http, etc.) as attack=1
            y = _infer_label(tmp, fallback=1)
        tmp["__label__"] = y
        parts.append(tmp)

    if not parts:
        raise FileNotFoundError("No training CSV found. Provide data/iotguard_training.csv "
                                "or *_sim.csv files with FEATURES and labels.")
    df = pd.concat(parts, ignore_index=True)
    y = df.pop("__label__").astype(int)
    return df[FEATURES].copy(), y

def _save_txt(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

def _plot_confusion(cm, out_png: Path, labels=("benign","attack")):
    fig = plt.figure(figsize=(4,3))
    ax = fig.add_subplot(111)
    im = ax.imshow(cm, interpolation="nearest")
    ax.set_title("Confusion Matrix")
    ax.set_xticks([0,1]); ax.set_xticklabels(labels)
    ax.set_yticks([0,1]); ax.set_yticklabels(labels)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, cm[i, j], ha="center", va="center")
    ax.set_xlabel("Predicted"); ax.set_ylabel("True")
    fig.tight_layout()
    out_png.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_png, dpi=160, bbox_inches="tight")
    plt.close(fig)

def _plot_roc(y_true, y_score, out_png: Path):
    fpr, tpr, _ = roc_curve(y_true, y_score)
    roc_auc = auc(fpr, tpr)
    fig = plt.figure(figsize=(4,3))
    ax = fig.add_subplot(111)
    ax.plot(fpr, tpr, lw=2, label=f"AUC={roc_auc:.3f}")
    ax.plot([0,1],[0,1], lw=1, linestyle="--")
    ax.set_xlabel("FPR"); ax.set_ylabel("TPR"); ax.set_title("ROC")
    ax.legend(loc="lower right")
    fig.tight_layout()
    out_png.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_png, dpi=160, bbox_inches="tight")
    plt.close(fig)
    return roc_auc

def _plot_pr(y_true, y_score, out_png: Path):
    prec, rec, _ = precision_recall_curve(y_true, y_score)
    ap = average_precision_score(y_true, y_score)
    fig = plt.figure(figsize=(4,3))
    ax = fig.add_subplot(111)
    ax.plot(rec, prec, lw=2, label=f"AP={ap:.3f}")
    ax.set_xlabel("Recall"); ax.set_ylabel("Precision"); ax.set_title("PR curve")
    ax.legend(loc="lower left")
    fig.tight_layout()
    out_png.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_png, dpi=160, bbox_inches="tight")
    plt.close(fig)
    return ap

def _plot_feature_importance(model, columns, out_png: Path, top=20):
    # LightGBM + scikit interface: feature_importances_ is available
    if not hasattr(model, "feature_importances_"):
        return
    vals = model.feature_importances_
    order = np.argsort(vals)[::-1][:top]
    fig = plt.figure(figsize=(5, max(2, 0.35*len(order))))
    ax = fig.add_subplot(111)
    ax.barh(range(len(order)), vals[order][::-1])
    ax.set_yticks(range(len(order)))
    ax.set_yticklabels(np.array(columns)[order][::-1])
    ax.set_title("Feature Importance (gain)")
    fig.tight_layout()
    out_png.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_png, dpi=160, bbox_inches="tight")
    plt.close(fig)

def main():
    parser = argparse.ArgumentParser(description="Evaluate IoTGuard model on labeled data.")
    parser.add_argument("--model", default=str(MODEL_PATH))
    parser.add_argument("--report_dir", default=str(REPORT_DIR))
    parser.add_argument("--test_size", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    report_dir = Path(args.report_dir); report_dir.mkdir(parents=True, exist_ok=True)

    print("🔹 Loading training data…")
    X, y = _load_training_table()

    print(f"  Samples: {len(X)} | Features: {X.shape[1]} | Positives: {int(y.sum())} ({y.mean():.1%})")
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=args.test_size, stratify=y, random_state=args.seed)

    print("🔹 Loading model…")
    model = load(args.model)

    print("🔹 Inference on test split…")
    # If predict_proba not available, fall back to decision_function or predict
    if hasattr(model, "predict_proba"):
        scores = model.predict_proba(Xte)[:,1]
    elif hasattr(model, "decision_function"):
        raw = model.decision_function(Xte)
        scores = (raw - raw.min()) / (raw.max() - raw.min() + 1e-9)
    else:
        scores = model.predict(Xte).astype(float)

    yhat = (scores >= 0.5).astype(int)

    # ------- Metrics -------
    cm = confusion_matrix(yte, yhat)
    cls_rep = classification_report(yte, yhat, target_names=["benign","attack"], digits=3)

    roc_png = report_dir / "roc.png"
    pr_png  = report_dir / "pr.png"
    cm_png  = report_dir / "confusion_matrix.png"
    fi_png  = report_dir / "feature_importance.png"

    roc_auc = _plot_roc(yte, scores, roc_png)
    ap      = _plot_pr(yte, scores, pr_png)
    _plot_confusion(cm, cm_png)
    _plot_feature_importance(model, FEATURES, fi_png)

    # Save text report + JSON
    _save_txt(report_dir / "classification_report.txt", cls_rep)
    meta = {
        "n_samples": int(len(X)),
        "test_size": float(args.test_size),
        "positives_rate": float(y.mean()),
        "roc_auc": float(roc_auc),
        "avg_precision": float(ap),
        "confusion_matrix": cm.tolist(),
        "features": FEATURES,
        "model_path": str(args.model)
    }
    (report_dir / "summary.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print("\n✅ Evaluation complete. Artifacts:")
    print(f"  {report_dir / 'classification_report.txt'}")
    print(f"  {report_dir / 'roc.png'}")
    print(f"  {report_dir / 'pr.png'}")
    print(f"  {report_dir / 'confusion_matrix.png'}")
    if fi_png.exists():
        print(f"  {fi_png}")
    print(f"  {report_dir / 'summary.json'}")

if __name__ == "__main__":
    main()
