## Scripts Overview

This folder contains all the Python entry points and helpers for IoTGuard.
Use this as a quick map of “what’s with what” without needing to open every file.

---

## Runtime pipeline (what you run in production/demos)

- **`suricata_to_features.py`**  
  Tails Suricata `eve.json` and builds 10s feature windows into `data/features.csv` +
  `data/window_meta.json`. This is the bridge from raw IDS events to model-ready features.

- **`decision_loop.py`**  
  Main scoring + policy engine. Tails `data/features.csv`, loads `models/lightgbm.joblib` +
  `configs/model.yaml`, scores each window, decides ATTACK/benign, triggers `blocker.py`
  (unless `dry_run`), and writes `data/alerts.jsonl`.

- **`api_dashboard.py`**  
  Flask API + web UI. Reads `data/alerts.jsonl` and `configs/model.yaml`, exposes JSON APIs
  and a live dashboard at `/` for monitoring and adjusting thresholds.

- **`console_dashboard.py`**  
  Terminal-based view of recent alerts. Useful when a browser is not available.

- **`blocker.py` / `unblock.py`**  
  Cross-platform firewall integration. `blocker.py` adds rules (Windows `netsh`, Linux nftables/iptables),
  `unblock.py` clears rules applied by IoTGuard.

---

## Training & evaluation

- **`create_train_test_split.py`**  
  Builds `data/iotguard_training_clean.csv` from raw/converted CSVs, enforcing the final
  13-feature schema and a leakage-safe split.

- **`train_supervised.py`**  
  Trains the LightGBM model on `iotguard_training_clean.csv`. Reads feature list + `lgbm`
  params from `configs/model.yaml`, performs threshold tuning, and writes
  `models/lightgbm.joblib` + `models/model_meta.json`.

- **`test_holdout.py`**  
  Evaluates the trained model on unseen IoT holdout datasets under `data/test_holdout/`,
  printing per-file detection/false-positive rates and global metrics (ROC-AUC, recall, FPR).

- **`analyze_feature_importance.py`**  
  Loads the model and prints a ranked list of feature importances to help you understand
  which features matter.

---

## Data conversion and generation

- **`convert_pcap_datasets.py`**  
  Converts raw `*.pcap.csv` exports (many columns) into the standard IoTGuard feature schema,
  writing `*_converted.csv` into `data/converted_attacks/`.

- **`feature_extractor.py`**  
  Standalone synthetic feature generator that writes realistic IoT-like windows into
  `data/features.csv` (for pipeline testing without Suricata).

- **`generate_synthetic_test.py`**  
  Creates synthetic labeled datasets in the 13-feature schema for stress-testing the model.

- **`stream_csvs.py`**  
  Streams existing CSVs (benign + attack) into `data/features.csv` at a configurable rate,
  emulating live traffic from static datasets.

- **`simulate_stream.py`**  
  Generates an endless stream of alternating benign/attack-like windows directly into
  `data/features.csv` for quick demos.

- **`replay_eve.py`**  
  Replays stored eve-style JSON into the feature pipeline, producing `data/features.csv`
  without running Suricata live.

---

## Explainability, intel, and utilities

- **`explainer.py`**  
  SHAP-based real-time explainer. Given a feature row and the model, returns a compact
  “why” string describing which features pushed the score up.

- **`threat_intel.py`**  
  Lightweight GeoIP/reputation stub used by the decision loop to enrich alerts with
  country, flag, and threat tags.

- **`check_pcap_files.py`**  
  Sanity checks PCAP-derived CSVs (counts, basic stats) before conversion or training.

- **`utils_common.py`**  
  Shared helper functions used by multiple scripts.

---

When in doubt, start from:

- **Training**: `create_train_test_split.py` → `train_supervised.py` → `test_holdout.py`  
- **Runtime**: `suricata_to_features.py` → `decision_loop.py` → `api_dashboard.py`  
- **Synthetic/demo**: `feature_extractor.py` or `simulate_stream.py` instead of Suricata.


