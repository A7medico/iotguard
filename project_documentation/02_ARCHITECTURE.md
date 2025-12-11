## IoTGuard Architecture

This document summarizes the end-to-end flow of IoTGuard.

---

### System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           IoTGuard System                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐    ┌─────────────────┐    ┌─────────────────┐                │
│  │ Suricata │───▸│ Feature Extract │───▸│  Decision Loop  │                │
│  │ eve.json │    │ (13 features)   │    │  (ML Scoring)   │                │
│  └──────────┘    └─────────────────┘    └────────┬────────┘                │
│                                                   │                         │
│                    ┌──────────────────────────────┼──────────────────────┐  │
│                    │                              │                      │  │
│                    ▼                              ▼                      ▼  │
│  ┌─────────────────────┐    ┌─────────────────────────┐    ┌───────────┐   │
│  │     Ensemble        │    │     Alerting System     │    │  Blocker  │   │
│  │ (LightGBM+IForest)  │    │ (Email/Slack/Telegram)  │    │ (Firewall)│   │
│  └─────────────────────┘    └─────────────────────────┘    └───────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        API Dashboard                                 │   │
│  │  • Real-time visualization   • JWT Authentication                   │   │
│  │  • Prometheus metrics        • Configuration controls               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### High-level Pipeline

1. **Traffic Capture**
   - Suricata monitors a network interface or PCAP files.
   - Writes JSON events to `data/suricata/eve.json`.

2. **Feature Extraction (`suricata_to_features.py`)**
   - Tails `eve.json` and aggregates `flow` events into fixed windows (default 10s).
   - Computes the 13 numeric features defined in `configs/model.yaml`.
   - Appends one row per window to `data/features.csv`.
   - Writes meta context to `data/window_meta.json`:
     - `top_src_ip`, `device_type` (from `configs/devices.yaml` or fingerprinting),
     - simple HTTP/DNS/TLS counts.
   - Emits `data/features_health.json` as a heartbeat.

3. **Device Fingerprinting (`device_fingerprinting.py`)**
   - Automatically classifies devices as IoT or IT based on traffic patterns.
   - Enables selection of specialized models for different device types.
   - Caches classifications for efficiency.

4. **Model Scoring & Decisions (`decision_loop.py`)**
   - Tails `data/features.csv`, only scores new rows.
   - Loads models based on device type:
     - `models/lightgbm.joblib` – supervised model for IoT.
     - `models/lightgbm_it.joblib` – supervised model for IT.
     - `models/iforest.joblib` – unsupervised anomaly detection.
   - **Ensemble Mode**: Combines supervised + unsupervised predictions.
   - Applies:
     - Global threshold (from config + optional adaptive thresholding),
     - Sliding window of hits,
     - Cooldown and instant-block logic,
     - Per-IP anomaly flag on `bytes_total`.
   - Enriches with:
     - SHAP reason (`explainer.py`),
     - Threat intel (`threat_intel.py`).
   - **Alerting**: Sends notifications via email/Slack/Telegram.
   - Writes one JSON line per window to `data/alerts.jsonl`.

5. **Dashboard / API (`api_dashboard.py`)**
   - Serves a web UI on port 5001.
   - **JWT Authentication**: Secure access with token-based auth.
   - **Prometheus Metrics**: `/metrics` endpoint for monitoring.
   - Exposes JSON APIs for alerts, health status, and configuration.
   - Controls for threshold, grace, window, cooldown, adaptive mode.

6. **Blocking (`blocker.py`)**
   - Cross-platform IP blocking:
     - Windows: `netsh advfirewall`
     - Linux: `nftables` (primary) / `iptables` (fallback)
   - Robust IP validation to prevent command injection.
   - Respects `dry_run` mode for safe testing.

7. **Training & Evaluation**
   - `create_train_test_split.py` builds `data/iotguard_training_clean.csv`.
   - `train_supervised.py` trains a binary LightGBM model.
   - `train_unsupervised.py` trains an IsolationForest anomaly detector.
   - `test_holdout.py` evaluates the model on holdout data.
   - `model_versioning.py` tracks versions with rollback support.

---

### Data Flow Diagram

```
┌────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Network       │────▸│  Suricata        │────▸│  eve.json       │
│  Traffic       │     │  (IDS Engine)    │     │  (Flow Events)  │
└────────────────┘     └──────────────────┘     └────────┬────────┘
                                                         │
                                                         ▼
┌────────────────────────────────────────────────────────────────────┐
│                    Feature Extraction                               │
│  suricata_to_features.py / feature_extractor.py / simulate_stream.py│
└───────────────────────────────┬────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
        ┌───────────────────┐   ┌───────────────────┐
        │  features.csv     │   │  window_meta.json │
        │  (13 features)    │   │  (IP, device type)│
        └─────────┬─────────┘   └─────────┬─────────┘
                  │                       │
                  └───────────┬───────────┘
                              ▼
                  ┌───────────────────────┐
                  │    Decision Loop      │
                  │    (ML Scoring)       │
                  └───────────┬───────────┘
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                 ▼
    ┌───────────┐     ┌───────────┐     ┌───────────┐
    │ Supervised│     │Unsupervised│    │  Ensemble │
    │ (LightGBM)│     │(IsoForest) │    │  Combiner │
    └─────┬─────┘     └─────┬─────┘     └─────┬─────┘
          │                 │                 │
          └─────────────────┴─────────────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │   Final Decision  │
                  │   ATTACK/benign   │
                  └─────────┬─────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ alerts.jsonl  │   │    Blocker    │   │   Alerting    │
│ (Event Log)   │   │  (Firewall)   │   │(Notifications)│
└───────────────┘   └───────────────┘   └───────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────┐
│                   API Dashboard                        │
│  • Score charts      • Event table     • Controls     │
│  • JWT auth          • Prometheus      • WebSocket    │
└───────────────────────────────────────────────────────┘
```

---

### Key Files

**Configuration:**
- `configs/model.yaml`, `configs/model_lab.yaml`, `configs/model_prod.yaml` – shared config for model + decision logic.
- `configs/devices.yaml` – optional mapping of `src_ip` → `device_type`.

**Models:**
- `models/lightgbm.joblib`, `models/lightgbm_it.joblib` – trained supervised models.
- `models/iforest.joblib` – trained unsupervised model.
- `models/model_meta.json`, `models/model_meta_it.json` – model metadata.

**Runtime Data:**
- `data/features.csv` – streaming feature windows.
- `data/window_meta.json` – per-window metadata.
- `data/alerts.jsonl` – detection event log.

**Deployment:**
- `deploy/docker-compose.yml` – containerized deployment.
- `deploy/nginx.conf` – reverse proxy configuration.

---

### Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Security Layers                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Input Validation                                            │
│     └─ IP validation in blocker.py prevents command injection  │
│                                                                  │
│  2. Authentication                                              │
│     └─ JWT tokens with configurable expiry                      │
│     └─ Password hashing with SHA-256 + salt                     │
│     └─ Rate limiting to prevent brute force                     │
│                                                                  │
│  3. Authorization                                               │
│     └─ @require_auth decorator for protected routes             │
│     └─ Live config changes blocked in production mode           │
│                                                                  │
│  4. Audit Logging                                               │
│     └─ All decisions logged to alerts.jsonl                     │
│     └─ Security events logged to logs/audit.log                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### Monitoring & Observability

**Prometheus Metrics** (`/metrics` endpoint):
- `iotguard_detections_total` – Total detections by severity
- `iotguard_blocks_total` – IP blocks (success/failure)
- `iotguard_inference_seconds` – Model inference latency
- `iotguard_score_distribution` – Score histogram
- `iotguard_api_requests_total` – API request counts
- `iotguard_model_drift` – Model drift indicator

**Alerting Channels**:
- Email (SMTP)
- Slack (Webhook)
- Telegram (Bot API)

**Logging**:
- Console output with colors
- Rotating file logs (`logs/iotguard.log`)
- JSON format option for log aggregation

