## IoTGuard Architecture

This document summarizes the end‑to‑end flow of IoTGuard.

### High‑level pipeline

1. **Traffic capture**
   - Suricata monitors a network interface or PCAP files.
   - Writes JSON events to `data/suricata/eve.json`.

2. **Feature extraction (`suricata_to_features.py`)**
   - Tails `eve.json` and aggregates `flow` events into fixed windows (default 10s).
   - Computes the 13 numeric features defined in `configs/model.yaml`.
   - Appends one row per window to `data/features.csv`.
   - Writes meta context to `data/window_meta.json`:
     - `top_src_ip`, `device_type` (from `configs/devices.yaml`),
     - simple HTTP/DNS/TLS counts.
   - Emits `data/features_health.json` as a heartbeat.

3. **Model scoring & decisions (`decision_loop.py`)**
   - Tails `data/features.csv`, only scores new rows.
   - Loads LightGBM model + `model_meta.json` (and `classes.json` for multiclass).
   - Applies:
     - global threshold (from config + optional adaptive thresholding),
     - sliding window of hits,
     - cooldown and instant‑block logic,
     - per‑IP anomaly flag on `bytes_total`.
   - Selects an IP from `window_meta.json` and enriches with:
     - SHAP reason (`explainer.py`),
     - threat intel (`threat_intel.py`).
   - Writes one JSON line per window to `data/alerts.jsonl` and
     internal logs to `logs/audit.jsonl`.

4. **Dashboard / API (`api_dashboard.py`)**
   - Serves a small web UI on port 5001.
   - Reads `alerts.jsonl` to show recent events, filters, and metrics.
   - Exposes JSON APIs for alerts, health status, and configuration updates.
   - Authentication and live‑config safety are controlled via config + env vars.

5. **Training & evaluation**
   - `create_train_test_split.py` builds `data/iotguard_training_clean.csv`.
   - `train_supervised.py` trains a binary LightGBM model.
   - `train_multiclass.py` (optional) trains a multiclass LightGBM model and
     writes `models/classes.json` for attack‑type predictions.
   - `test_holdout.py` evaluates the model on holdout data and writes reports
     into `results/`.

### Key files

- `configs/model.yaml`, `configs/model_lab.yaml`, `configs/model_prod.yaml` –
  shared config for model + decision logic.
- `configs/devices.yaml` – optional mapping of `src_ip` → `device_type`.
- `models/lightgbm.joblib`, `models/model_meta.json`, `models/classes.json` –
  trained model and metadata.
- `data/features.csv`, `data/window_meta.json`, `data/alerts.jsonl` –
  main runtime data exchange points.





