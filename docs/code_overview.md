## IoTGuard Code Overview

This document explains each important script in the project in **plain language**, so you can use it directly in your report or presentation.

---

## `train_supervised.py`

**Role**: Trains the main LightGBM intrusion detection model.

**Key steps**:
- Loads the **clean training CSV** (`data/iotguard_training_clean.csv`) created by `create_train_test_split.py`.
- Uses the 13 final features:
  - `flows, bytes_total, pkts_total, syn_ratio, mean_bytes_flow, ack_ratio, fin_ratio, rst_ratio, http_ratio, tcp_ratio, protocol_diversity, std_bytes, iat_mean`.
- Splits the data into **train/validation** subsets.
- Trains a **LightGBM binary classifier** and monitors:
  - `ROC-AUC` (how well it separates benign vs attack),
  - `PR-AUC` (precision–recall for imbalanced data),
  - Confusion matrix and classification report at the best threshold.
- Performs **threshold tuning**:
  - Finds a threshold that balances recall and false positives.
- Saves:
  - `models/lightgbm.joblib`: the trained model.
  - `models/model_meta.json`: feature list, threshold, label mapping, and path to the training CSV.

This script is only needed when **retraining**; the runtime pipeline just loads the saved model.

---

## `create_train_test_split.py`

**Role**: Builds a **clean, leakage-free training dataset** from all your raw IoT CSVs.

**What it does**:
- Gathers converted IoT PCAP CSVs and simulation CSVs.
- **Splits by file**, not by row:
  - Entire files are assigned to **train** or **holdout/test**, so no flow from the same PCAP appears in both sets.
- **Deduplicates** rows:
  - Removes exact duplicates to avoid the model memorizing repeated flows.
- Enforces the final **13-feature schema**:
  - Drops any legacy/extra columns and ensures consistent column order.
- Explicitly **skips low-quality or mismatched datasets** (like `ciciot_benign_15f.csv`) that caused unrealistic perfect scores.
- Writes:
  - `data/iotguard_training_clean.csv` – final supervised training file, used by `train_supervised.py`.

This script is critical for avoiding **data leakage** and for getting realistic evaluation metrics.

---

## `test_holdout.py`

**Role**: Evaluates the trained model on **holdout IoT datasets** that were never seen during training.

**What it does**:
- Loads `models/lightgbm.joblib` and `model_meta.json`.
- Iterates over files in `data/test_holdout/`:
  - IoT DDoS PCAP-derived CSVs,
  - recon/port-scan, SQL injection, Mirai attacks,
  - benign IoT traffic.
- For each file:
  - Builds features using the same 13-feature schema.
  - Computes per-file detection stats (detection rate or false-positive rate).
- Aggregates results:
  - Global confusion matrix.
  - Overall recall, precision, false-positive rate.
  - ROC-AUC on the combined holdout set.

This script demonstrates that the model generalizes across different IoT attack types and benign conditions.

---

## `generate_synthetic_test.py`

**Role**: Creates synthetic **unseen** IoT-like data for robustness testing.

**What it does**:
- Generates rows for all 13 features with **plausible ranges**:
  - Separate distributions for benign vs attack traffic.
  - Includes “tricky” cases like low-rate attacks and high-load benign traffic.
- Writes a CSV with a configurable number of rows (e.g. 5000) and a label column.

This is used to check if the model can handle scenarios not present in the original datasets.

---

## `convert_pcap_datasets.py`

**Role**: Converts raw `.pcap.csv` files (with ~80 raw features) into the **13-feature IoTGuard schema**.

**What it does**:
- Reads PCAP-derived CSVs.
- Maps raw columns (like forward/backward bytes and packets) into:
  - `bytes_total, pkts_total, syn_ratio, ack_ratio, fin_ratio, rst_ratio, http_ratio, tcp_ratio, protocol_diversity, std_bytes, iat_mean`.
- Derives a binary label (attack/benign) from the filename (e.g. `DDoS-SYN_Flood.pcap_converted.csv` is attack).
- Ensures consistent column order and writes `*_converted.csv` files used by:
  - `create_train_test_split.py`
  - `test_holdout.py`

This script standardizes heterogeneous PCAP exports into a single, model-ready format.

---

## `analyze_feature_importance.py`

**Role**: Explains which features matter most for the trained model.

**What it does**:
- Loads `models/lightgbm.joblib`.
- Computes feature importances from the LightGBM model.
- Prints a ranked list of features by importance score.

This script was used to discover that **`uniq_src` and `uniq_dst` contributed nothing**, which led to their removal from the final feature set.

---

## `suricata_to_features.py`

**Role**: Turns Suricata’s **`eve.json` events into 10-second aggregated feature windows** in `data/features.csv`.

**Input**:
- `data/suricata/eve.json` produced by Suricata (live or from replayed PCAP).

**What it does**:
- Tails `eve.json` safely across log rotations.
- For each `flow` event:
  - Extracts timestamp, source/destination IPs, bytes and packets in each direction, flow `state`, and protocol fields (`proto`, `app_proto`).
- Groups events into **fixed-size time windows** (default 10 seconds).
- For each window:
  - Computes:
    - `flows` (number of flows),
    - `bytes_total`, `pkts_total`,
    - `syn_ratio`, `ack_ratio`, `fin_ratio`, `rst_ratio`,
    - `http_ratio`, `tcp_ratio`, `protocol_diversity`,
    - `std_bytes`, `iat_mean`.
  - Writes a single row to `data/features.csv` with exactly these 13 features.
  - Stores **meta data** in `data/window_meta.json`:
    - `top_src_ip` (the IP most active in that window),
    - light DPI context (`http_flows`, `dns_flows`, `tls_flows`, and distinct `app_protos`).

This script is the bridge between **packet-level events (Suricata)** and **flow-level ML features (IoTGuard)**.

---

## `replay_eve.py`

**Role**: Offline testing tool that replays existing eve-style JSON into the features pipeline.

**What it does**:
- Reads a JSON file with Suricata-like events.
- Throttles and feeds them into the same aggregation logic as `suricata_to_features.py`.
- Produces `data/features.csv` for use by the decision loop, without running Suricata live.

Useful for repeatable experiments and demos when you already have captured data.

---

## `feature_extractor.py`

**Role**: Standalone synthetic feature generator for quick experiments.

**What it does**:
- Randomly generates rows that mimic IoT traffic (benign and attack-like).
- Computes all 13 features, including a correct `std_bytes` calculation.
- Writes to `data/features.csv` so you can exercise the decision loop and dashboard **without Suricata or real PCAPs**.

This is mainly for debugging and local development.

---

## `simulate_stream.py`

**Role**: Simulates a continuous stream of IoT feature rows into `data/features.csv`.

**What it does**:
- Alternates between benign-like and attack-like rows, with realistic ranges.
- Appends new rows every few hundred milliseconds.

This lets you see how the decision loop and dashboard behave under a “live feed” that approximates IoT traffic.

---

## `stream_csvs.py`

**Role**: Streams existing CSV files (real datasets) into `data/features.csv` as if they were live.

**Usage**:
- You pass multiple CSVs (e.g. benign and several different attack types).
- The script:
  - Reads each file,
  - Sends rows at a specified **rate** (rows per second),
  - Loops over all files for a number of **cycles**.

This is how you created “live” mixed attack/benign scenarios for evaluation and demos, using your real IoT datasets.

---

## `decision_loop.py`

**Role**: The **brain** of IoTGuard – it makes real-time decisions based on model scores and policies.

**Inputs**:
- `data/features.csv`: continuous feature windows from Suricata (or simulators).
- `models/lightgbm.joblib`: trained ML model.
- `models/model_meta.json`: feature list and default threshold.
- `configs/model.yaml`: hot‑reloaded decision parameters (threshold, grace, window, cooldown, adaptive).
- `data/window_meta.json`: per-window meta (`top_src_ip`, HTTP/DNS/TLS flows, etc.).

**Key logic**:
- Tails `data/features.csv` and keeps an internal **offset** so it only scores new rows.
- Ensures all 13 required features are present and numeric.
- For each new row:
  - Computes `p = P(attack)` using `MODEL.predict_proba`.
  - Optionally applies an **adaptive threshold** based on a moving window of recent scores.
  - Marks the row as `ATTACK` or `benign`.
  - Uses `RealTimeExplainer` (SHAP) to compute a **human-readable reason** (which features pushed the score up).
  - Maintains a sliding window of recent ATTACK flags to implement:
    - **Grace**: require N hits before blocking.
    - **Cooldown**: minimum time between blocks.
    - **Instant block**: immediately block if score is very high.
  - Reads `top_src_ip` (and meta) from `window_meta.json` to decide **which IP to block**.
  - Optionally calls `blocker.py` (respecting `dry_run`) to apply firewall rules.
  - Enriches events with **ThreatIntel** (country, flag, reputation tag).
  - Writes a compact event to `data/alerts.jsonl`:
    - `ts, index, score, state, hits_in_window, action, pred_class, reason, effective_threshold, threat`.

This script connects the ML model, adaptive policies, and firewall in a robust, streaming loop.

---

## `explainer.py`

**Role**: Provides **real-time SHAP explanations** for each ATTACK decision.

**What it does**:
- Wraps `shap.TreeExplainer` for the LightGBM model.
- For a single feature row, computes SHAP values and selects the **top positive contributions** to the attack score.
- Returns short strings like:
  - `"syn_ratio (+0.45), bytes_total (+0.21)"`.

These explanations are printed in the console and stored in `alerts.jsonl` so the dashboard can display **“Reason (XAI)”** for each event.

---

## `threat_intel.py`

**Role**: Adds **context** (GeoIP + reputation) to blocked IPs.

**What it does (demo version)**:
- Maintains a small in‑memory “reputation” database of known bad IPs (e.g., Mirai nodes).
- Simulates GeoIP by deterministically mapping IPs to a small set of countries and flags.
- Given an IP, returns:
  - `country`, `flag`, and optional `threat` tag.

The decision loop attaches this info to events, and the dashboard renders it in the **Threat Intel** column.

---

## `api_dashboard.py`

**Role**: Web API + modern dashboard UI for monitoring IoTGuard in real time.

**APIs**:
- `/api/events`: recent events from `alerts.jsonl`.
- `/api/counts`: counts of total events, attacks, blocks in a time window.
- `/api/config` (GET/POST): view/update decision parameters (`threshold`, `grace`, `window`, `cooldown_sec`, `use_adaptive`).
- `/api/model`: returns model class metadata.
- `/api/clear`, `/api/clear_all`: reset logs and loop state.
- `/api/download.csv`: export enriched alerts as CSV for analysis.

**Dashboard (`/`)**:
- Three headline metrics: recent totals, attacks, blocks.
- Controls to tweak **threshold, adaptive mode, grace, window, cooldown**.
- A score chart with:
  - Blue line: model score.
  - Orange dashed line: **adaptive threshold**.
- Per-class chips showing how many times each predicted class appeared.
- A **Recent Events** table with:
  - Time, index, score, state,
  - **Threat Intel** (flag + country + tag),
  - **Reason (XAI)**,
  - Predicted class / attack type,
  - Window hits, action (including severity).

This is the main **user-facing view** of the system.

---

## `blocker.py` and `unblock.py`

**Role**: Apply and remove firewall rules.

**What they do**:
- `blocker.py`: exposes `block_ip(ip)` which:
  - On Windows, uses `netsh` to add a blocking rule.
  - On Linux, uses `nftables`/`iptables` depending on what’s available.
- `unblock.py`: clears rules that IoTGuard has applied so you can reset the environment.

The decision loop calls into `blocker.py` through a small wrapper that respects `dry_run`, making it safe to run in development.

---

## `console_dashboard.py`

**Role**: Lightweight terminal-based view of recent alerts.

**What it does**:
- Tails `alerts.jsonl` and prints a rolling summary in the console.
- Useful when a browser-based UI is not available, or for quick SSH monitoring.

---

## `utils_common.py` and `check_pcap_files.py`

**Role**: Small utilities to keep code organized.

- `utils_common.py`: holds helper functions shared by multiple scripts (e.g., common CSV loading or path helpers).
- `check_pcap_files.py`: sanity-checks PCAP-derived CSVs (e.g., counts, labels, basic statistics) so you can spot obviously broken files before conversion or training.

These are support modules to keep the main scripts cleaner and more focused.



