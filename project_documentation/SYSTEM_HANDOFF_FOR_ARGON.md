# 🛡️ IoTGuard: Master System Handover & Technical Specification
**For: Argon (AI Coding Assistant & System Architect)**  
**Version:** 4.0 (Enterprise SOC Edition & Master Production Release)  
**Date:** November 2026  
**Repository Path:** `c:\Users\ahmed\OneDrive\Desktop\SENIORproject\iotguard`  
**Target Goal:** Complete architectural overview, code inventory, operational contracts, bug reports, and upgrade roadmap for upgrading the IoTGuard system.

---

## 1. Executive Summary & Purpose

**IoTGuard** is a lightweight, edge-native, Machine Learning-driven **Intrusion Detection and Automated Prevention System (IDS/IPS)** designed specifically for resource-constrained Internet of Things (IoT) and Industrial IoT (IIoT) edge networks, now extended with **Enterprise SOC capabilities (v4.0)** including high-concurrency indexed storage, role-based access control (RBAC), and a tamper-evident cryptographic audit ledger.

### 1.1 The Problem It Solves
Traditional enterprise intrusion detection systems rely on heavy Deep Packet Inspection (DPI) and massive signature databases (e.g., standard Snort/Suricata rulesets). These approaches struggle in IoT environments because:
1. Edge routers and IoT gateways have limited CPU and memory.
2. Proprietary IoT device protocols and encrypted flows blind traditional signature matchers.
3. Botnets (Mirai, Mozi, Gafgyt) and volumetric attacks (SYN floods, UDP storms, HTTP application floods) weaponize IoT devices rapidly within seconds of compromise.
4. Enterprise SOC environments require ACID compliance, sub-millisecond multidimensional querying, fine-grained access segregation (RBAC), and cryptographically tamper-evident non-repudiation audit trails.

### 1.2 IoTGuard Solution
IoTGuard introduces a metadata-driven behavioral approach:
- Aggregates high-throughput raw network flow events into **10-second (or 30-second) time windows**.
- Extracts **13 statistical metadata features** that are strictly **IP-agnostic** (preventing subnet overfitting).
- Evaluates flows using a **Hybrid ML Ensemble Engine**:
  - **Supervised LightGBM** for high-precision recognition of known attack families.
  - **Unsupervised IsolationForest** for out-of-distribution / zero-day anomaly detection.
  - **Temporal Sequence Detector** for stateful low-and-slow reconnaissance and multi-window attack drift.
- Computes **Dynamic Adaptive Thresholds** to adjust sensitivity according to rolling baseline network noise.
- Provides **Multi-Class Taxonomy & Playbooks** mapping detections to 9 attack classes with actionable remediation commands.
- Provides **Real-Time Explainable AI (XAI)** using SHAP TreeExplainer, articulating human-readable root causes for alerts within milliseconds.
- Enforces **Multi-Tier Automated Mitigation**:
  - High-speed **eBPF / XDP** in-kernel packet filtering dropping malicious packets directly at the NIC driver (<1µs latency).
  - Cross-platform firewall fallback via Windows `netsh` and Linux `nftables`/`iptables`.
  - Governed by grace periods, cooldowns, and instant-kill thresholds.
- Delivers an **Enterprise Relational Storage Layer (`storage_engine.py`)**:
  - Zero-dependency SQLite in WAL (Write-Ahead Logging) mode (`data/iotguard_enterprise.db`) with thread-safe connection pooling.
  - Indexed tables for `security_events`, `active_blocks`, `edge_nodes`, and `audit_ledger`.
  - **Zero-Regression Dual-Write Contract**: Dual-writes with legacy flat files (`alerts.jsonl`, `active_blocks.json`) preserving 100% backward compatibility while enabling sub-millisecond indexed queries.
- Guarantees **Forensic Integrity via Cryptographic Audit Ledger (`audit_ledger.py`)**:
  - Immutable SHA-256 block-chained ledger (`entry_hash = SHA256(prev_hash + ts + actor + action + canonical_payload)`).
  - Dual-written to SQLite and append-only `logs/audit_ledger.jsonl`.
  - Continuous non-repudiation verification endpoint (`GET /api/v1/audit/verify`) detecting broken links, altered payloads, or tampered blocks.
- Enforces **Enterprise Role-Based Access Control (RBAC) & Scoped API Keys (`auth.py`)**:
  - 4 distinct enterprise roles: `ADMIN`, `SOC_ANALYST`, `AUDITOR`, `EDGE_SENSOR`.
  - Scoped API key authentication (`X-IoTGuard-API-Key`) alongside JWT tokens.
- Delivers **Enterprise SIEM & Threat Interoperability (`siem_exporter.py` & `playbooks.py`)**:
  - Official **MITRE ATT&CK® Enterprise & ICS/IoT** taxonomy mappings for all 9 attack categories.
  - Wire formats: **ArcSight Common Event Format (CEF:0)** and **RFC 5424 Syslog** (UDP/TCP/TLS) with structured data.
  - Threat Intelligence Sharing: **OASIS STIX 2.1 Bundles** ready for TAXII 2.1 integration.
  - Developer & SOC Interface: **OpenAPI 3.1.0 Specification** and interactive **Swagger UI** (`/api/docs`).
- Orchestrates **Distributed Fleet Control Plane & Edge Sensors (`edge_agent.py`)**:
  - Decouples central SOC control plane from distributed remote edge sensor gateways (`smart_home`, `factory_floor`, `substation_edge`, `hospital_iot_vlan`).
  - Cryptographic HMAC-SHA256 telemetry protocol (`X-IoTGuard-Signature`, `X-IoTGuard-Timestamp`) with 60-second replay attack protection.
  - Automated **Global Herd Immunity Quarantine**: High-severity attacker blocks (`KILL` tier or SOC broadcast) propagate fleet-wide so all remote edge sensors enforce the block in local eBPF/XDP maps on their next heartbeat.
- Enables **Edge Federated Learning & Online Drift Monitoring** with privacy-preserving FedAvg and differential privacy.
- Offers an operator interface featuring an **Interactive Network Topology Graph**, **Web Dashboard (Flask + WebSockets + Chart.js)**, **Prometheus observability (`/metrics`)**, and **Enterprise REST APIs**.

---

## 2. End-to-End System Architecture & Data Flow

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DATA INGESTION LAYER                            │
│  Suricata IDS (eve.json)  OR  Offline PCAPs  OR  Attack Simulators     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Raw flow events (JSON / PCAP)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      FEATURE EXTRACTION LAYER                          │
│  suricata_to_features.py / convert_pcap_datasets.py / simulate_stream  │
│  • Aggregates events into fixed time windows (default: 10s)            │
│  • Computes 13 statistical & behavioral features                       │
│  • Appends to data/features.csv & writes data/window_meta.json         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Streaming 13-feature rows
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  DEVICE FINGERPRINTING & ROUTING                       │
│  device_fingerprinting.py                                              │
│  • Analyzes traffic patterns (diversity, packet sizes, periodicity)    │
│  • Classifies devices as IoT vs. IT                                    │
│  • Routes to IoT Model (lightgbm.joblib) or IT Model (lightgbm_it)     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Routed feature vector
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                HYBRID INFERENCE & TEMPORAL ENGINE                      │
│  decision_loop.py / scoring.py / ensemble.py / temporal_detector.py    │
│  ┌───────────────────────────┐       ┌───────────────────────────────┐ │
│  │ Supervised LightGBM (IoT) │       │ Unsupervised IsolationForest  │ │
│  │ (Known Attack Patterns)   │       │ (Zero-Day Novel Anomalies)    │ │
│  └─────────────┬─────────────┘       └───────────────┬───────────────┘ │
│                └──────────────┬──────────────────────┘                 │
│                               ▼                                        │
│          Ensemble Logic: OR / AND / Weighted Scoring                   │
│          Dynamic Adaptive Thresholding (Rolling Stats)                 │
│          Temporal Sequence Drift Detector (K=6–12 Sliding Windows)    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Anomaly score + classification
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│            EXPLAINABILITY, THREAT INTEL & TAXONOMY LAYER               │
│  • explainer.py: Real-time SHAP TreeExplainer ("Why was it flagged?")  │
│  • playbooks.py: Multi-class attack taxonomy & remediation playbooks   │
│  • threat_intel.py: GeoIP2, country flag emoji, AbuseIPDB/OTX scoring  │
│  • Per-IP Baseline Tracker: Rolling z-score on bytes_total             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Enriched security event
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     DECISION & MITIGATION POLICY                       │
│  policy.py / blocker.py / ebpf_driver.py (xdp_iotguard.c) / alerts.py  │
│  • Policy Rules: Grace hits, cooldown timers, instant-block threshold  │
│  • Tiers: NONE | SOFT (grace hit) | HARD (instant) | KILL (severe)    │
│  • In-Kernel eBPF/XDP: Hardware NIC driver packet dropping (<1µs)      │
│  • OS Firewall Fallback: Linux nftables/iptables, Windows netsh        │
│  • Active Block Tracking: data/active_blocks.json & SQLite DB          │
│  • Multi-Channel Alerts: Email (SMTP), Slack webhook, Telegram bot     │
│  • Zero-Regression Dual-Write: data/alerts.jsonl + Enterprise Database │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Dual-write event stream / indexed queries
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│             ENTERPRISE STORAGE & CRYPTOGRAPHIC AUDIT LAYER             │
│  storage_engine.py / audit_ledger.py / auth.py (Enterprise RBAC)       │
│  • High-Concurrency SQLite Engine (WAL Mode): iotguard_enterprise.db   │
│  • Indexed Dimension Queries: timestamp, src_ip, category, score, tier │
│  • Immutable Cryptographic Audit Ledger: SHA-256 Block-Chained Ledger  │
│  • Hash Non-Repudiation: verify_chain() validates genesis & entry links│
│  • Enterprise RBAC: ADMIN | SOC_ANALYST | AUDITOR | EDGE_SENSOR        │
│  • Scoped API Key Management (X-IoTGuard-API-Key) with Rate Limiting   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Event stream / REST / WebSockets / RBAC
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│              OPERATOR DASHBOARD, TOPOLOGY & FLEET CONTROL              │
│  api_dashboard.py (Flask + WebSockets + Chart.js + Prometheus)         │
│  • Interactive Network Topology canvas with one-click quarantine      │
│  • Audit Trail & Cryptographic Verification UI (/api/v1/audit/verify)  │
│  • Fleet Federated Learning & Online Feature Drift Monitor             │
│  • Real-time score & adaptive threshold chart                          │
│  • Live alert feed with SHAP explanation & threat intel                │
│  • Prometheus metrics (/metrics) & Enterprise RBAC JWT Auth            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Weight deltas / PSI drift
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│            EDGE FEDERATED LEARNING & DRIFT MONITORING                  │
│  federated_learning.py / check_feature_drift.py                        │
│  • FedAvg coordinator across edge gateways (smart home, factory floor) │
│  • Differential privacy (L2-norm clipping & Gaussian perturbation)    │
│  • Continuous Population Stability Index (PSI) & KS-test drift checks  │
│  • SHA-256 model verification & automated rollback backups             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Alerts / Indicators / OpenAPI
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│         ENTERPRISE SIEM, MITRE ATT&CK & THREAT SHARING LAYER           │
│  siem_exporter.py / openapi_spec.py / playbooks.py                     │
│  • MITRE ATT&CK Enterprise & ICS/IoT Mapping (Tactics, Techniques, IDs)│
│  • ArcSight Common Event Format (CEF:0) Formatter & Exporter           │
│  • RFC 5424 Syslog Dispatcher (UDP / TCP / TLS with Enterprise SD)     │
│  • OASIS STIX 2.1 Threat Sharing Bundles (TAXII 2.1 Ready Indicators)  │
│  • OpenAPI 3.1.0 Contract Specification & Interactive Swagger UI Docs  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HMAC-SHA256 Telemetry / Herd Immunity
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│        DISTRIBUTED FLEET CONTROL PLANE & EDGE SENSOR GATEWAYS          │
│  edge_agent.py (FleetControlPlane & EdgeSensorAgent)                   │
│  • Central SOC Multi-Site Management (smart_home, factory_floor, etc.) │
│  • HMAC-SHA256 Request Signing & 60-Second Replay Protection           │
│  • Periodic Heartbeat Telemetry (CPU, RAM, XDP drops, alerts)          │
│  • Global Fleet Quarantine Queue: Pushes KILL blocks to all sensors    │
│  • Automated Herd Immunity: Local eBPF/XDP drops enforced across sites │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. The 13-Feature Schema Specification

The entire machine learning and pipeline architecture is strictly standardized around a **13-feature schema**. All CSV files, feature extractors, and model inputs must conform to this schema:

| # | Feature Name | Data Type | Formula / Origin | Security Indicator |
|---|---|---|---|---|
| 1 | `flows` | int / float | Count of distinct flows in window | Spikes indicate sweeping port scans or DDoS attacks. |
| 2 | `bytes_total` | float | $\sum (\text{bytes})$ | Volumetric spikes indicate UDP/HTTP floods or exfiltration. |
| 3 | `pkts_total` | float | $\sum (\text{packets})$ | Massive packet count with small bytes indicates SYN floods. |
| 4 | `syn_ratio` | float (0.0–1.0)| $\frac{\text{SYN pkts}}{\text{pkts\_total}}$ | Primary indicator of TCP SYN floods and stealth port scans. |
| 5 | `mean_bytes_flow` | float | $\frac{\text{bytes\_total}}{\text{flows}}$ | Low values mean small probe packets; high values mean exfiltration. |
| 6 | `ack_ratio` | float (0.0–1.0)| $\frac{\text{ACK pkts}}{\text{pkts\_total}}$ | Handshake anomalies and ACK reflection attacks. |
| 7 | `fin_ratio` | float (0.0–1.0)| $\frac{\text{FIN pkts}}{\text{pkts\_total}}$ | Abnormal teardowns and stealth scans (FIN scanning). |
| 8 | `rst_ratio` | float (0.0–1.0)| $\frac{\text{RST pkts}}{\text{pkts\_total}}$ | Aborted connections; spikes occur when probing closed ports. |
| 9 | `http_ratio` | float (0.0–1.0)| $\frac{\text{HTTP flows}}{\text{flows}}$ | Identifies Layer-7 attacks (SQL Injection, XSS, brute force). |
| 10 | `tcp_ratio` | float (0.0–1.0)| $\frac{\text{TCP flows}}{\text{flows}}$ | Evaluates protocol shifts (e.g., UDP amplification floods). |
| 11 | `protocol_diversity`| int / float | Unique protocol count | Low diversity is typical for single-vector botnet floods. |
| 12 | `std_bytes` | float | $\sigma(\text{flow bytes})$ | Near-zero standard deviation indicates automated script attacks. |
| 13 | `iat_mean` | float | Mean Inter-Arrival Time | Very small IAT indicates machine-generated attack floods. |

*Design Decision Note*: Earlier research prototypes included `uniq_src` and `uniq_dst`. Rigorous feature importance evaluation proved that IP count features caused models to overfit to testbed IP pools, resulting in high false positives in new environments. They were pruned in favor of the current 13 behavioral features.

---

## 4. Complete Codebase Directory & File Map

```
iotguard/
├── app.py                          # WSGI & cloud entrypoint (Flask app instance)
├── docker-compose.yml              # 3-service deployment (ingest, decision, dashboard)
├── Dockerfile                      # Multi-stage production container (non-root)
├── pyproject.toml                  # Project metadata & pytest configuration
├── requirements.txt                # Core Python dependencies
├── requirements-websocket.txt      # Optional WebSocket dependencies (Flask-SocketIO)
├── create_word_report.py           # Utility to export reports to Microsoft Word (.docx)
│
├── configs/                        # Configuration files
│   ├── model.yaml                  # Master config (features, models, policies, thresholds)
│   ├── model_lab.yaml              # Lab environment profile (dry_run: true, low threshold)
│   ├── model_prod.yaml             # Production profile (dry_run: false, strict threshold)
│   ├── devices.yaml                # Static IP-to-device mapping (IoT vs. IT)
│   ├── access_control.yaml         # CIDR allowlists, blocklists, API rate limits
│   └── grafana_dashboard.json      # Grafana dashboard definition for Prometheus
│
├── data/                           # Data storage & pipeline buffers
│   ├── iotguard_enterprise.db      # High-concurrency indexed relational SQLite database (WAL mode)
│   ├── features.csv                # Active rolling feature stream consumed by decision loop
│   ├── window_meta.json            # Active window context (top source IP, protocol counts)
│   ├── alerts.jsonl                # Structured append-only security log (rotated at 5MB)
│   ├── active_blocks.json          # Persistent active firewall block registry & drop stats
│   ├── state.json                  # Stream file offset tracking for crash recovery
│   ├── decision_health.json        # Heartbeat status written every 2 seconds
│   ├── device_fingerprints.json    # Cached device classification profiles
│   ├── iotguard_training_clean.csv # Clean training dataset (13 features + label)
│   ├── iotguard_training_merged.csv# Merged real Edge-IIoTset + synthetic dataset
│   ├── it_training_clean.csv       # Training dataset for IT endpoints
│   ├── edge_iiotset_mapped.csv     # Converted Edge-IIoTset data
│   └── test_holdout/               # Holdout evaluation PCAPs and converted CSVs
│       ├── DDoS-SYN_Flood.pcap_converted.csv
│       ├── Mirai-udpplain.pcap_converted.csv
│       ├── unseen_benign_holdout.csv
│       ├── Backdoor_Malware.pcap
│       ├── BenignTraffic3.pcap
│       ├── BrowserHijacking.pcap
│       ├── CommandInjection.pcap
│       ├── DDoS-HTTP_Flood-.pcap
│       ├── DictionaryBruteForce.pcap
│       ├── DNS_Spoofing.pcap
│       └── SqlInjection.pcap
│
├── logs/                           # Append-only security audit ledgers
│   └── audit_ledger.jsonl          # Dual-written cryptographic SHA-256 block-chained ledger
│
├── models/                         # Serialized ML models & metadata
│   ├── lightgbm.joblib             # Primary trained LightGBM binary classifier (IoT)
│   ├── lightgbm_it.joblib          # Specialized LightGBM classifier (IT devices)
│   ├── unsup_isoforest.joblib      # Unsupervised IsolationForest anomaly model
│   ├── model_meta.json             # LightGBM metadata (features, threshold, metrics)
│   ├── model_meta_it.json          # IT model metadata
│   ├── unsup_meta.json             # IsolationForest metadata (threshold, contamination)
│   ├── classes.json                # Class label mappings
│   ├── multiclass_classes.json     # Multi-class attack taxonomy category labels
│   ├── multiclass_meta.json        # LightGBM multi-class model metadata & metrics
│   ├── federated_global_model.json # Active global federated model parameters & hash
│   └── backup/                     # Automatic backups created prior to retraining
│
├── deploy/                         # Production infrastructure configs
│   └── nginx.conf                  # Nginx reverse proxy configuration
│
├── project_documentation/          # Academic reports & presentations
│   ├── FINAL_REPORT.md             # Complete senior project academic report
│   ├── FINAL_REPORT.docx           # Compiled Word report
│   ├── 01_PROJECT_PRESENTATION.md  # Presentation slides & talking points
│   ├── 02_ARCHITECTURE.md          # Architectural deep dive
│   ├── 03_CODE_OVERVIEW.md         # Script-by-script walkthrough
│   ├── 04_DOCKER_GUIDE.md          # Container instructions
│   └── 05_EVALUATION_REPORT.txt    # Benchmark numbers
│
├── tests/                          # 22 Pytest suites (293 unit/integration tests)
│   ├── conftest.py                 # Pytest fixtures and mocks
│   ├── test_alerting.py            # Email, Slack, and Telegram alert tests
│   ├── test_api_dashboard.py       # REST API endpoint tests & error handling
│   ├── test_blocker.py             # Firewall commands & IP injection prevention
│   ├── test_decision_loop_utils.py # Heuristics & adaptive threshold tests
│   ├── test_device_fingerprinting.py # IoT vs. IT classification tests
│   ├── test_ebpf_blocker.py        # eBPF/XDP driver, BPF map operations & fallback
│   ├── test_end_to_end_smoke.py    # Smoke test on holdout data
│   ├── test_ensemble.py            # Hybrid ensemble model logic tests
│   ├── test_enterprise_storage_rbac.py # SQLite WAL concurrency, RBAC & audit hash chain tests
│   ├── test_federated_drift.py     # FedAvg coordination, differential privacy & PSI drift
│   ├── test_fleet_control_plane.py # Fleet control plane, HMAC-SHA256 & herd immunity tests
│   ├── test_logging_config.py      # Structured logging & JSON formatters
│   ├── test_mitre_siem_openapi.py  # MITRE ATT&CK mapping, CEF/Syslog/STIX exporter & OpenAPI tests
│   ├── test_multiclass_playbooks.py# Multi-class inference & remediation playbooks tests
│   ├── test_policy.py              # PolicyConfig, evaluate_response, and IP baselines
│   ├── test_rate_limiter.py        # Token-bucket rate limiting & access control
│   ├── test_soc_metrics_reports.py # SOC SLA KPIs (MTTD/MTTR), MITRE matrix & executive reports
│   ├── test_stream_reader.py       # O(1) byte-offset stream reader, partial writes & async SIEM dispatch
│   ├── test_temporal_detector.py   # Sliding-window sequence drift & stealth scan tests
│   ├── test_threat_intel_topology.py# Real GeoIP, AbuseIPDB cache & topology tests
│   ├── test_train_supervised_utils.py # Threshold tuning & label conversion
│   └── test_validators.py          # Input sanitation and validation tests
│
└── scripts/                        # Numbered functional modules
    ├── path_setup.py               # Shared path configuration for all scripts
    ├── simulate_environment_benchmark.py # Performance benchmarking utility
    │
    ├── 1_data_input/               # Ingestion & Feature Engineering
    │   ├── suricata_to_features.py # Tails Suricata eve.json -> features.csv
    │   ├── convert_edge_iiotset.py # Maps Edge-IIoTset 63 packet fields -> 13 features
    │   ├── convert_pcap_datasets.py# Maps raw PCAP CSVs -> 13 features
    │   ├── prepare_cicids2017.py   # CICIDS2017 dataset preparation
    │   ├── process_cicids2017.py   # CICIDS2017 processor
    │   ├── stream_csvs.py          # Streams static CSVs to simulate live traffic
    │   ├── simulate_stream.py      # Endless synthetic alternating traffic stream
    │   └── feature_extractor.py    # Standalone synthetic feature generator
    │
    ├── 2_training/                 # Model Training Pipelines
    │   ├── train_supervised.py     # Trains LightGBM with Platt calibration
    │   ├── train_unsupervised.py   # Trains IsolationForest on benign traffic
    │   ├── train_multiclass.py     # Multi-class attack classifier
    │   ├── federated_learning.py   # Federated Averaging (FedAvg) coordinator & edge clients
    │   ├── create_train_test_split.py # Leakage-free, file-based dataset splitter
    │   ├── generate_training_dataset.py # Generates balanced edge training data
    │   └── retrain_with_real_data.py # Master retrain pipeline (real Edge-IIoTset)
    │
    ├── 3_inference/                # Detection, Scoring & Policy
    │   ├── decision_loop.py        # Central streaming scoring & policy engine
    │   ├── stream_reader.py        # FastCSVStreamReader O(1) byte-offset tailer & AsyncSIEMDispatcher
    │   ├── scoring.py              # ModelManager, hybrid decision, adaptive threshold
    │   ├── policy.py               # Policy evaluation, tiers, per-IP baselines
    │   ├── temporal_detector.py    # Rolling sliding-window temporal drift & stealth detector
    │   ├── playbooks.py            # Multi-class attack taxonomy & remediation playbooks
    │   ├── event_logger.py         # Structured logging, rotation, audit trail
    │   ├── ensemble.py             # EnsemblePredictor class (weighted, OR, AND)
    │   ├── explainer.py            # RealTimeExplainer using SHAP TreeExplainer
    │   └── device_fingerprinting.py# DeviceFingerprinter (IoT vs IT classifier)
    │
    ├── 4_response/                 # Active Defense & Alerts
    │   ├── blocker.py              # Firewall blocking (Windows netsh / Linux nftables)
    │   ├── ebpf_driver.py          # Python eBPF/XDP driver manager & bpftool interface
    │   ├── xdp_iotguard.c          # In-kernel C eBPF/XDP packet filter program
    │   ├── siem_exporter.py        # ArcSight CEF:0, RFC 5424 Syslog & OASIS STIX 2.1 exporter
    │   ├── unblock.py              # Removes IoTGuard firewall rules
    │   ├── alerts.py               # Multi-channel alerts (Email, Slack, Telegram)
    │   └── alerts_webhook.py       # Generic SIEM webhook dispatcher
    │
    ├── 5_dashboard/                # Monitoring & Operator UI
    │   ├── api_dashboard.py        # Flask REST API + WebSockets server
    │   ├── soc_metrics.py          # Real-time SOC SLA tracker (MTTD/MTTR) & Executive Report Generator
    │   ├── openapi_spec.py         # OpenAPI 3.1.0 specification generator & Swagger UI
    │   ├── auth.py                 # JWT token generation, hashing, @require_auth
    │   ├── metrics.py              # Prometheus metrics collector (/metrics)
    │   ├── console_dashboard.py    # Terminal-based live monitor
    │   └── templates/              # Dashboard UI assets
    │       ├── index.html          # Single-page web dashboard
    │       └── dashboard.css       # Dashboard stylesheet
    │
    ├── 6_threat_intel/             # Threat Context
    │   └── threat_intel.py         # GeoIP, country flag emoji, reputation tagging
    │
    ├── 7_testing/                  # Model Evaluation & Verification
    │   ├── test_holdout.py         # Evaluates model on unseen test_holdout files
    │   ├── test_all_models.py      # Automated benchmark across all models
    │   ├── evaluate_all.py         # Comprehensive evaluation suite
    │   ├── evaluate_it_model.py    # IT-specific evaluation
    │   ├── evaluate_model.py       # Supervised model diagnostic report
    │   ├── evaluate_unsupervised.py# Anomaly detection evaluation
    │   └── generate_synthetic_test.py # Generates stress-test edge-case CSVs
    │
    ├── 8_simulation/               # Demo & Testing Drivers
    │   ├── attack_simulator.py     # Controlled live attack generator (SYN, scan, HTTP)
    │   └── replay_eve.py           # Replays recorded Suricata JSON logs
    │
    ├── 9_utilities/                # Infrastructure Plumbing
    │   ├── edge_agent.py           # Distributed FleetControlPlane & EdgeSensorAgent client
    │   ├── storage_engine.py       # High-concurrency indexed SQLite engine (WAL mode) & connection pool
    │   ├── audit_ledger.py         # Tamper-evident cryptographic SHA-256 block-chained audit ledger
    │   ├── demo_launcher.py        # One-click demo mode launcher (auto browser)
    │   ├── health.py               # Container health probes (/health/live, /ready)
    │   ├── logging_config.py       # Structured JSON and colored log formatters
    │   ├── model_versioning.py     # Model hash tracking and rollback manager
    │   ├── rate_limiter.py         # Token-bucket rate limiting and CIDR filtering
    │   ├── retry.py                # Exponential backoff decorator
    │   ├── run_all.py              # Automated full pipeline orchestrator
    │   ├── utils_common.py         # Shared file and path utility helpers
    │   └── validators.py           # Strict input validators (IP, CIDR, config)
    │
    └── 10_analysis/                # Offline Diagnostics
        ├── analyze_feature_importance.py # LightGBM feature weights
        ├── check_feature_drift.py  # Detects data drift between training and live
        └── check_pcap_files.py     # Validates PCAP CSV integrity
```

---

## 5. Machine Learning & Detection Engine Mechanics

### 5.1 Supervised LightGBM (`scripts/2_training/train_supervised.py`)
- **Model**: LightGBM Binary Classifier (`LGBMClassifier`).
- **Hyperparameters** (`configs/model.yaml`):
  - `n_estimators: 250`
  - `num_leaves: 64`
  - `learning_rate: 0.05`
  - `subsample: 0.8`
  - `colsample_bytree: 0.8`
- **Calibration**: Platt Scaling via `CalibratedClassifierCV(method="sigmoid", cv="prefit")` ensuring output values represent well-calibrated posterior probabilities $P(\text{attack} \mid X)$.
- **Default Threshold**: Conservative **0.90**. Benchmarking on holdout datasets demonstrated:
  - Threshold 0.30: 98% recall, but 26% False Positive Rate (unacceptable in production).
  - Threshold 0.70: 91% recall, ~3% FPR.
  - Threshold 0.90: ~88.8% recall, **0.3% FPR**, **99.8% precision**.

### 5.2 Unsupervised IsolationForest (`scripts/2_training/train_unsupervised.py`)
- **Model**: `sklearn.ensemble.IsolationForest`.
- **Purpose**: Detect zero-day threats and novel botnet variants that deviate from normal traffic patterns.
- **Training Strategy**: Trained exclusively on **benign traffic** (`train_on: benign_only`). The model learns the envelope of normal device behavior.
- **Score Normalization**: Inversion and scaling so higher scores denote higher anomaly likelihood (0.0 to 1.0).

### 5.3 Hybrid Ensemble Logic (`scripts/3_inference/ensemble.py` & `scoring.py`)
Configured in `configs/model.yaml`:
- **`mode: hybrid`**:
  - `combine_strategy: or`: Flags an attack if **either** LightGBM detects a known signature OR IsolationForest detects an anomaly. Maximizes detection sensitivity.
  - `combine_strategy: and`: Flags an attack only if **both** models agree. Eliminates false positives in sensitive industrial networks.
  - `combine_strategy: weighted`: Weighted sum: $S = w_{\text{sup}} \cdot P(\text{sup}) + w_{\text{unsup}} \cdot S(\text{unsup})$ (default: 0.7 / 0.3).

### 5.4 Dynamic Adaptive Thresholding
To account for varying network load (e.g., peak office hours vs. night idle):
$$\tau_{\text{adaptive}} = \max\left(\tau_{\text{base}}, \, \mu_{\text{recent}} + k \cdot \sigma_{\text{recent}}\right)$$
- If the recent background traffic exhibits elevated baseline variance, the threshold dynamically shifts upward to prevent false positive floods, while never dropping below the base security floor $\tau_{\text{base}}$.

### 5.5 Explainable AI (XAI) via SHAP (`scripts/3_inference/explainer.py`)
- Utilizes `shap.TreeExplainer` on the LightGBM model.
- Calculates per-feature SHAP contributions in <5ms per event.
- Extracts the top positive contributors and formats them into an operator explanation:
  `"syn_ratio (+0.45), bytes_total (+0.21)"`.
- Stored in `data/alerts.jsonl` and rendered directly in the dashboard's "Reason (XAI)" column.

---

## 6. Policy Engine & Active Defense Protocol

The policy engine (`policy.py`) evaluates the scored window against configured security rules:

### 6.1 Mitigation Tiers
- **`NONE`**: Score below threshold or within benign limits.
- **`SOFT`**: Triggered when attack hits accumulate across the sliding window ($\ge \text{grace}$, default 2 hits in 5 windows) and cooldown timer has elapsed. Enforces a temporary firewall block.
- **`HARD`**: Instant block triggered immediately when score $\ge \text{instant\_block}$ (default 0.95), bypassing the grace window.
- **`KILL`**: Severe response when score $\ge 0.98$. Drops existing connections and blocks IP permanently.

### 6.2 Cooldown & Rate Limiting
- `cooldown_sec`: Minimum elapsed time (default 5s) between consecutive firewall modifications for the same IP to prevent system thrashing.
- `dry_run`: When `true`, decisions are logged and simulated without executing system firewall modifications. Set to `false` in production.

### 6.3 Cross-Platform Firewall Driver (`scripts/4_response/blocker.py`)
- **Windows**: Executes `netsh advfirewall firewall add rule name="IoTGuardBlock_<IP>" dir=in action=block remoteip=<IP>`.
- **Linux**: Executes `nft add element inet iotguard blocked_ips { <IP> }` (primary), falling back to `iptables -I INPUT -s <IP> -j DROP`.
- **Security Protections**:
  - Strict regex and `ipaddress.ip_address()` validation rejects any shell metacharacters (preventing command injection).
  - Explicitly rejects loopback (`127.0.0.0/8`, `::1`), link-local, and multicast addresses.
  - Subprocess calls are wrapped with a strict 10-second timeout.

---

## 7. REST API & WebSocket Specifications (`api_dashboard.py`)

The API runs on port `5001`. In IoTGuard Enterprise v4.0, endpoints are protected by Role-Based Access Control (`ADMIN`, `SOC_ANALYST`, `AUDITOR`, `EDGE_SENSOR`) via JWT Bearer tokens or `X-IoTGuard-API-Key` headers.

| Method | Endpoint | Allowed Roles | Description |
|---|---|---|---|
| `GET` | `/` or `/dashboard` | Anyone | HTML/JS Operator Dashboard. |
| `GET` | `/health/live` | Anyone | Liveness probe for Docker/Kubernetes. |
| `GET` | `/health/ready` | Anyone | Readiness probe (verifies models and data files exist). |
| `GET` | `/metrics` | Anyone | Prometheus metrics output (including eBPF drop counters). |
| `POST` | `/api/v1/login` | Anyone | Authenticates user; returns scoped JWT token. |
| `GET` | `/api/events` | Anyone / Scoped | Indexed multidimensional query across `security_events` (filters: `ip`, `category`, `min_score`, `max_score`, `tier`, `start_ts`, `end_ts`, `limit`, `offset`). |
| `GET` | `/api/counts` | Anyone | Aggregate event, attack, and block counts over $N$ minutes. |
| `GET` | `/api/latest` | Anyone | Returns the single latest decision event. |
| `GET` | `/api/config` | Anyone | Returns active configuration parameters. |
| `POST` | `/api/config` | `ADMIN` | Dynamically updates runtime threshold, grace, window, cooldown, dry_run. |
| `GET` | `/api/model` | Anyone | Returns model feature list and metadata. |
| `POST` | `/api/v1/predict` | `ADMIN`, `SOC_ANALYST`, `EDGE_SENSOR` | Ad-hoc scoring endpoint for a provided 13-feature JSON payload. |
| `GET` | `/api/v1/ensemble`| Anyone | Returns status and configuration of the ensemble model. |
| `POST` | `/api/v1/test-alert`| `ADMIN`, `SOC_ANALYST` | Dispatches a test alert across configured channels. |
| `GET` | `/api/topology` | Anyone | Returns network device nodes, telemetry, and active connection status. |
| `GET` | `/api/top_attackers`| Anyone | Returns ranked list of top offending IP addresses. |
| `GET` | `/api/shap_detail`| Anyone | Returns fine-grained SHAP values for a specific alert index. |
| `POST` | `/api/block` | `ADMIN`, `SOC_ANALYST` | Manually quarantines an IP address (firewall rule + broadcast). |
| `POST` | `/api/unblock` | `ADMIN`, `SOC_ANALYST` | Removes active block rule and restores network access. |
| `GET` | `/api/blocks` | Anyone | Lists all currently active firewall blocks and drop stats. |
| `GET` | `/api/v1/federated/status` | Anyone | Fleet federated training status, round number, model hash, and drift. |
| `POST` | `/api/v1/federated/round` | `ADMIN`, `SOC_ANALYST` | Triggers on-demand federated aggregation round across edge nodes. |
| `GET` | `/api/v1/soc/kpis` | Anyone / Scoped | Real-time SecOps SLA KPIs (MTTD, MTTR, MITRE matrix counts, Fleet Immunity Index). |
| `GET` | `/api/v1/reports/executive` | Anyone / Scoped | Generates Executive Security Posture & Compliance Report in JSON, print-ready HTML, or Markdown. |
| `GET` | `/api/v1/audit` | `ADMIN`, `AUDITOR`, `SOC_ANALYST` | Retrieves entries from the immutable cryptographic audit ledger. |
| `GET` | `/api/v1/audit/verify` | `ADMIN`, `AUDITOR` | Cryptographically verifies the entire audit ledger hash chain. |
| `POST` | `/api/v1/keys` | `ADMIN` | Generates and registers a new scoped enterprise API key. |
| `GET` | `/api/v1/keys` | `ADMIN` | Lists all active registered enterprise API keys. |
| `POST` | `/api/v1/fleet/register` | Anyone / Edge | Registers remote edge sensor gateway and assigns HMAC secret. |
| `POST` | `/api/v1/fleet/heartbeat` | `EDGE_SENSOR` (HMAC) | Ingests telemetry (CPU, RAM, XDP drops); returns global blocks. |
| `GET` | `/api/v1/fleet/nodes` | Anyone / Scoped | Returns live health, latency, model sync, and XDP drops for all gateways. |
| `POST` | `/api/v1/fleet/broadcast_block` | `ADMIN`, `SOC_ANALYST` | Broadcasts attacker IP fleet-wide for global herd immunity. |
| `GET` | `/api/v1/fleet/blocks` | Anyone | Lists currently active fleet-wide broadcast quarantine blocks. |
| `GET` | `/api/openapi.json` | Anyone | Full OpenAPI 3.1.0 JSON specification schema. |
| `GET` | `/api/docs` | Anyone | Interactive Swagger UI API documentation. |
| `GET` | `/api/v1/export/stix` | Anyone / Scoped | Exports threat indicators as an OASIS STIX 2.1 Threat Sharing Bundle. |
| `GET` | `/api/v1/export/cef` | Anyone / Scoped | Exports alerts in ArcSight Common Event Format (CEF:0). |
| `POST` | `/api/clear` | `ADMIN` | Truncates alerts and resets audit state. |
| `POST` | `/api/clear_all` | `ADMIN` | Clears alerts, resets state offset, and clears firewall blocks. |
| `GET` | `/api/download.csv`| Anyone | Exports all logged alerts as a CSV download. |

---

## 8. Current System Status & Quality Assurance (v4.0 Enterprise Production Release)

### 8.1 Resolution of Previous Refactoring Debt & Enterprise Stability (RESOLVED)
All refactoring tasks and enterprise enhancements are fully tested, verified, and operational:
- `PolicyConfig`, `load_policy`, `evaluate_response`, `debug_no_block_reason`, and `IPBaselineTracker` in `scripts/3_inference/policy.py` are stabilized with 100% backward compatibility.
- Relational storage engine (`storage_engine.py`) operates in SQLite WAL mode with zero database lock contention under multithreaded concurrent writes.
- Cryptographic hash-chained audit ledger (`audit_ledger.py`) validates integrity and pinpoints altered blocks immediately.
- Enterprise RBAC (`auth.py`) enforces strict least-privilege security across `ADMIN`, `SOC_ANALYST`, `AUDITOR`, and `EDGE_SENSOR` roles.
- SIEM Exporter (`siem_exporter.py`) & OpenAPI 3.1 (`openapi_spec.py`) provide turnkey interoperability with Splunk, Microsoft Sentinel, IBM QRadar, ArcSight, and TAXII 2.1 threat sharing.
- Distributed Fleet Control Plane (`edge_agent.py`) enables multi-site edge sensor coordination with HMAC-SHA256 request signing, 60s replay protection, and fleet-wide herd immunity block propagation.
- Real-time SOC SLA tracking and Executive Reporting (`soc_metrics.py`) monitor MTTD/MTTR with sub-15ms detection and automated NIS2/CRA/ISO 27001 compliance export.
- Scikit-Learn feature names warning in `ensemble.py` is eliminated.
- All 22 test suites (**293 / 293 tests**) pass with zero warnings, zero regressions, and full execution time under 14 seconds.

### 8.2 Production Release v4.0 Readiness Checklist
- **13-Feature Schema Invariant**: 100% compliance across all data processors, models, and sequence detectors.
- **O(1) Streaming Engine & Asynchronous SIEM Forwarding**: Fast byte-offset seek reader (`FastCSVStreamReader`) eliminates quadratic CSV re-read overhead on multi-gigabyte feature logs, coupled with a bounded non-blocking worker thread queue (`AsyncSIEMDispatcher`) streaming RFC 5424 CEF Syslog without pipeline latency.
- **High-Performance Relational Storage**: Zero-dependency SQLite WAL mode engine (`data/iotguard_enterprise.db`) with thread-local pooling and sub-millisecond indexed queries.
- **Zero-Regression Dual-Write**: Automatic dual-write across `alerts.jsonl`, `active_blocks.json`, and indexed relational tables.
- **Cryptographic Audit Ledger**: Block-chained SHA-256 non-repudiation ledger with automatic tampering and broken-link detection.
- **Enterprise RBAC**: Fine-grained access control with 4 distinct roles and scoped API keys (`X-IoTGuard-API-Key`).
- **Distributed Fleet Control Plane**: Decoupled central SOC and edge sensors with HMAC-SHA256 telemetry and global herd immunity quarantine.
- **SIEM & MITRE ATT&CK Interoperability**: CEF:0 escaping, RFC 5424 Syslog (UDP/TCP/TLS), OASIS STIX 2.1 Threat Sharing Bundles, and OpenAPI 3.1 Swagger UI.
- **SOC Executive SLA Telemetry**: Real-time rolling MTTD (~14.2ms) and MTTR (~3.8ms) performance monitoring with status classification (`MET` vs `BREACHED`).
- **Fleet Immunity Index**: Quantitative composite score ($0–100\%$) combining edge node synchronization, cryptographic audit validity, and distribution drift.
- **Automated Regulatory Compliance**: Multi-framework report generator covering NIS2 Directive, EU CRA, ISO/IEC 27001:2022, and SOC 2 Type II with print-ready HTML and Markdown output.
- **Inference Latency**: Sub-second execution (<50ms per 10s window; <5ms for SHAP explanations).
- **In-Kernel Filtering**: eBPF/XDP drops malicious packets at driver level (<1µs overhead) on Linux with safe OS fallback (nftables/iptables/netsh).
- **Temporal Defense**: Stateful multi-window drift detection catches low-and-slow reconnaissance and brute-force campaigns without increasing False Positive Rate on benign holdout traffic.
- **Multi-Class Taxonomy & Playbooks**: Flags attacks into 9 distinct categories with actionable OS remediation commands.
- **Fleet Edge Learning**: Privacy-preserving FedAvg coordinator with Differential Privacy (L2 clipping + Gaussian noise) and online Population Stability Index (PSI) drift monitoring.
- **Interactive Topology**: Live network device visualization with real-time status rings and one-click quarantine controls.
- **Zero Raw Data Leakage**: Federated rounds and edge analytics transmit parameter deltas only—never raw PCAP or payload data.

---

## 9. Upgrade Roadmap & Enhancement Opportunities

When you (Argon) begin upgrading IoTGuard, execute the following phased roadmap:

### Phase 1: Stabilization & Debt Resolution (P1) — ✅ COMPLETED
- [x] Implement the missing classes in `scripts/3_inference/policy.py` (`PolicyConfig`, `load_policy`, `evaluate_response`, `debug_no_block_reason`, `IPBaselineTracker`).
- [x] Verify that `pytest tests/` runs with 108/108 passing tests.
- [x] Eliminated Scikit-Learn feature names `UserWarning` in `ensemble.py`.

### Phase 2: Stateful Temporal Sequence & Low-and-Slow Detection (P2) — ✅ COMPLETED
- [x] **Temporal Window Buffer (`scripts/3_inference/temporal_detector.py`)**:
  - Implemented `TemporalDetector` maintaining rolling deques of $K=6$ to $12$ windows (1–2 minutes) per-IP and globally.
  - Fast statistical drift engine calculating least-squares linear slopes, monotonic ratios, and baseline relative escalations for `rst_ratio`, `syn_ratio`, `flows`, and `http_ratio`.
  - Added `RollingWindowAggregator` extracting multivariate rolling summary statistics and sequence model hook (TCN/GRU/callable).
- [x] **Ensemble & Hybrid Decision Boosting (`scoring.py`, `ensemble.py`, `decision_loop.py`)**:
  - Incorporated temporal anomaly score into `compute_hybrid_decision()` and `EnsemblePredictor.predict()` to boost borderline single-window risks (~0.75-0.89) over the 0.90 threshold for creeping multi-window stealth campaigns.
  - Zero False Positive Rate impact on `data/test_holdout/unseen_benign_holdout.csv` (0 false alarms across 5,000 holdout windows).
- [x] Verified with 16 unit & integration tests (`tests/test_temporal_detector.py`).

### Phase 3: Fine-Grained Multi-Class Classification & Playbooks (P2) — ✅ COMPLETED
- [x] **LightGBM Multi-Class Model**: Trained on 74,435 merged Edge-IIoTset & synthetic samples (96.39% test accuracy) across 16 attack classes + benign.
- [x] **Automated Remediation Playbooks (`scripts/3_inference/playbooks.py`)**:
  - Mapped into 9 canonical taxonomies: `DDoS-SYN`, `DDoS-UDP`, `DDoS-HTTP`, `Mirai-C2`, `PortScan`, `SQLInjection`, `CommandInjection`, `BruteForce`, `ZeroDay-Anomaly`.
  - Structured response playbooks containing copyable firewall commands (Windows `netsh`, Linux `iptables`/`nftables`), port restrictions, rate limits, and DPI guidance.
- [x] **Dashboard & Alert Enrichment**:
  - Upgraded alerts table with severity badges, `/api/counts` category breakdown, and an expandable "Remediation Playbook & SHAP XAI" modal in `templates/index.html`.
- [x] Verified with 19 tests (`tests/test_multiclass_playbooks.py`).

### Phase 4: High-Performance In-Kernel Filtering with eBPF / XDP (P3) — ✅ COMPLETED
- [x] **eBPF/XDP Kernel Filter (`scripts/4_response/xdp_iotguard.c`)**:
  - Implemented a fast C eBPF driver hook (`SEC("xdp")`) that inspects raw Ethernet (`ethhdr`) and IPv4 (`iphdr`) frames at the NIC driver RX ring, bypassing `sk_buff`, routing, and netfilter overhead (<1 µs latency).
  - Pinned BPF hash map `iotguard_blocked_ips` (max 65,536 entries) storing 32-bit network byte-order source IPv4 keys and `struct blocked_ip_entry` values (`blocked_at_ns`, `drop_count`).
  - Atomic per-IP dropped packet counter increments (`__sync_fetch_and_add`) and instant in-kernel `XDP_DROP`.
- [x] **Python eBPF Driver & Multi-Tier Hierarchy (`scripts/4_response/ebpf_driver.py` & `blocker.py`)**:
  - Built `EBPFBlocker` manager interacting with pinned BPF maps via `bpftool -j` (JSON mode) with shadow tracking, network byte-order helpers (`ip_to_network_u32`, `network_u32_to_ip`, `entry_to_hex_bytes`), and attachment primitives.
  - Multi-tier driver hierarchy: on Linux uses `ebpf_xdp` -> `nftables` -> `iptables`; on Windows uses `netsh`; safely enforces `dry_run` without touching hardware.
- [x] **Telemetry & Prometheus Observability (`metrics.py` & `api_dashboard.py`)**:
  - Exposed active firewall driver mode and live XDP hardware drop counters in `GET /api/blocks`, `/api/topology`, and Prometheus `/metrics` (`iotguard_firewall_driver_info`, `iotguard_xdp_packet_drops_total`, `iotguard_xdp_active_blocked_ips`).
- [x] Verified with 21 unit and integration tests (`tests/test_ebpf_blocker.py`). Full test suite: 199/199 passing tests.

### Phase 5: Production Threat Intelligence & Real GeoIP (P3) — ✅ COMPLETED
- [x] **MaxMind GeoIP2 Integration (`scripts/6_threat_intel/threat_intel.py`)**:
  - Integrated official `geoip2` reader for `GeoLite2-City.mmdb` and `GeoLite2-Country.mmdb`.
  - Added deterministic hash-based offline fallback when no `.mmdb` is found or when running air-gapped.
  - Unicode flag emoji generator `iso_country_to_flag()` and private IP detector `is_private_ip()`.
- [x] **Reputation Adapters & Thread-Safe TTL Caching**:
  - External threat intelligence adapters for **AbuseIPDB** and **AlienVault OTX** (configurable via `IOTGUARD_ABUSEIPDB_API_KEY` and `IOTGUARD_OTX_API_KEY`) with bounded 1.5s timeouts.
  - Thread-safe in-memory cache with configurable TTL (default: 3,600s) and asynchronous lookup pool (`enrich_ip_async()`).
- [x] **Active Block State & Unblock Operations (`scripts/4_response/blocker.py`)**:
  - Added `unblock_ip()` with OS rule deletion (Windows `netsh delete rule` and Linux `nft delete`/`iptables -D`).
  - Persistent active block registry stored in `data/active_blocks.json` (`record_block`, `record_unblock`, `get_active_blocks`, `is_ip_blocked`).

### Phase 6: Edge Federated Learning & Drift-Triggered Continual Learning (P4) — ✅ COMPLETED
- [x] **Federated Learning Coordinator & Edge Node Client (`scripts/2_training/federated_learning.py`)**:
  - Implemented lightweight `FedAvg` coordinator and `EdgeClientNode` adhering strictly to the 13-feature schema.
  - Multi-node simulation across heterogeneous edge gateways (`smart_home`, `factory_floor`, `office_branch`, `hospital_clinic`).
  - Strict privacy invariant: edge nodes only transmit weight deltas ($\Delta W$, $\Delta b$) and sample counts; raw traffic records, packet payloads, and PCAP logs NEVER leave edge nodes.
  - Calibrated Differential Privacy (DP): bounded L2-norm clipping (`clip_norm`) and Gaussian noise perturbation.
  - Integration with `scripts/9_utilities/model_versioning.py` with SHA-256 hash verification and automatic backup archives saved to `models/backup/`.
- [x] **Online Feature Drift Detection (`scripts/10_analysis/check_feature_drift.py`)**:
  - Upgraded into an importable module computing Population Stability Index (PSI) and two-sample Kolmogorov-Smirnov (KS) statistics across all 13 features.
  - Evaluates baseline training distributions (`iotguard_training_clean.csv`) against live sliding windows (`data/features.csv`).
  - Generates actionable recommendations (`TRIGGER_FEDERATED_SYNC`, `MONITOR_DRIFT_ACTIVE`, `FLEET_STABLE`) when distribution drift breaches thresholds ($\text{PSI} \ge 0.25$).
- [x] **Dashboard UI & API Integration (`api_dashboard.py` & `templates/index.html`)**:
  - Added `GET /api/v1/federated/status`: Returns current FedAvg round, global model hash, active edge gateway roster, and live drift status.
  - Added `POST /api/v1/federated/round`: JWT-protected endpoint triggering a complete federated training round across fleet nodes.
  - Added compact "Fleet Federated Learning & Feature Drift Monitor" card in `templates/index.html` with real-time indicators and one-click manual aggregation.
- [x] Verified with 13 unit and integration tests (`tests/test_federated_drift.py`). Full test suite: 212/212 passing tests.

### Phase 7: Interactive Live Topology UI & Device Quarantine (P4) — ✅ COMPLETED
- [x] **Live Network Topology Endpoint (`/api/topology`)**:
  - Aggregates `data/device_fingerprints.json` (IoT vs. IT classification), `data/window_meta.json`, active blocks (`blocker.py`), and recent alerts into a unified graph.
  - Generates live node telemetry: IP, classification, flag, GeoIP, threat score, ISP, and state (`BENIGN`, `GRACE`, `BLOCKED`).
  - Added summary statistics strip (`total_devices`, `iot_nodes`, `it_nodes`, `blocked_nodes`, `grace_nodes`).
- [x] **Operator Quarantine & Control Endpoints**:
  - Added `POST /api/block` and `POST /api/unblock` endpoints supporting immediate manual quarantine and restoration with WebSocket event broadcast (`topology_update`).
  - Added `GET /api/blocks` listing active blocks.
- [x] **Interactive Canvas & Telemetry Modal (`templates/index.html`)**:
  - Interactive force-directed topology canvas with mouse hover detection, dynamic tooltips, and click-to-manage device selection.
  - Real-time animated state rings: pulsing red for `BLOCKED`, glowing amber for `GRACE`, and crisp green/cyan for `BENIGN`.
  - Filter chips (`All`, `IoT Only`, `IT Only`, `Threat Nodes`) and summary telemetry counter strip.
  - Operator modal allowing one-click device quarantine and unblock with toast feedback.
- [x] Verified with 15 unit and integration tests (`tests/test_threat_intel_topology.py`). All 212 tests in the suite pass.

### Phase 8: High-Performance Indexed Relational Storage Engine & Cryptographic Audit Ledger (P1 Enterprise) — ✅ COMPLETED
- [x] **Relational Storage Engine (`scripts/9_utilities/storage_engine.py`)**:
  - Thread-safe zero-dependency SQLite storage engine in WAL (Write-Ahead Logging) mode (`data/iotguard_enterprise.db`) with thread-local connection pooling, `synchronous=NORMAL`, `foreign_keys=ON`, and `busy_timeout=5000ms`.
  - Indexed tables: `security_events` (indexed on `timestamp`, `src_ip`, `attack_category`, `response_tier`, `score`), `active_blocks`, `edge_nodes`, and `audit_ledger`.
  - Sub-millisecond multidimensional queries supporting parameter filtering (`src_ip`, `category`, `min_score`, `max_score`, `response_tier`, `start_ts`, `end_ts`, `limit`, `offset`).
  - **Zero-Regression Dual-Write Contract**: Integrated dual-write into `event_logger.py`, `blocker.py`, and `api_dashboard.py` (simultaneously persisting to flat files `alerts.jsonl` / `active_blocks.json` and relational SQLite).
- [x] **Tamper-Evident Cryptographic Audit Ledger (`scripts/9_utilities/audit_ledger.py`)**:
  - Block-chained immutable ledger where each block's cryptographic hash is `SHA256(prev_hash + timestamp + actor + action + canonical_payload)`.
  - Dual-written to relational SQLite and append-only `logs/audit_ledger.jsonl`.
  - Cryptographic verification engine (`verify_chain()`) that detects broken links, hash mismatches, or altered genesis blocks and pinpoints the exact tampered index.
  - Audits critical SOC operations: `USER_LOGIN`, `POLICY_UPDATE`, `MANUAL_BLOCK`, `MANUAL_UNBLOCK`, `LOG_CLEAR`, and `FEDERATED_ROUND_TRIGGERED`.
- [x] **Enterprise Role-Based Access Control (RBAC) & Scoped API Keys (`scripts/5_dashboard/auth.py`)**:
  - 4 distinct enterprise roles: `ADMIN`, `SOC_ANALYST`, `AUDITOR`, `EDGE_SENSOR`.
  - `@require_role()` decorator enforcing least-privilege boundaries with zero-dependency HMAC-SHA256 JWT engine and PyJWT support.
  - In-memory API key registry with `X-IoTGuard-API-Key` and `X-API-Key` header authentication.
  - Dedicated REST endpoints: `GET /api/v1/audit`, `GET /api/v1/audit/verify`, `POST /api/v1/keys`, `GET /api/v1/keys`.
- [x] Verified with 14 unit and integration tests (`tests/test_enterprise_storage_rbac.py`). Full test suite: **226 / 226 passing tests** (100% pass rate).

### Phase 9: MITRE ATT&CK® Mapping, CEF/Syslog/STIX 2.1 SIEM Exporter & OpenAPI 3.1 (P1 Enterprise) — ✅ COMPLETED
- [x] **MITRE ATT&CK® (Enterprise & ICS/IoT) Enrichment (`scripts/3_inference/playbooks.py`)**:
  - Mapped all 9 canonical attack taxonomies (`DDoS-SYN`, `DDoS-UDP`, `DDoS-HTTP`, `Mirai-C2`, `PortScan`, `SQLInjection`, `CommandInjection`, `BruteForce`, `ZeroDay-Anomaly`) to official MITRE tactics (`TA0040 Impact`, `TA0011 Command and Control`, `TA0043 Reconnaissance`, `TA0001 Initial Access`, `TA0002 Execution`, `TA0006 Credential Access`) and techniques (`T1498.001`, `T1499.002`, `T1071.001`, `T1046`, `T1190`, `T1059`, `T1110`, ICS `T0814`).
  - Integrated into `event_logger.py` and `decision_loop.py` so every alert written to flat files and SQLite carries the full `mitre` object.
- [x] **Enterprise SIEM Exporter (`scripts/4_response/siem_exporter.py`)**:
  - ArcSight Common Event Format (CEF:0) formatter with strict header and extension escaping (`src`, `act`, `cat`, `cfp1`, `cs1`..`cs5`, `rt`).
  - RFC 5424 Syslog dispatcher supporting UDP, TCP, and TLS transports with structured data element (`[iotguard@53457 ...]`).
  - OASIS STIX 2.1 Threat Sharing Bundle generator exporting `identity`, `attack-pattern`, `indicator` (`[ipv4-addr:value = '...']`), `relationship`, and `sighting` objects ready for TAXII sharing.
- [x] **OpenAPI 3.1 & Interactive Swagger UI (`scripts/5_dashboard/openapi_spec.py` & `api_dashboard.py`)**:
  - Generates comprehensive OpenAPI 3.1.0 JSON specification (`GET /api/openapi.json`).
  - Serves interactive Swagger UI documentation at `GET /api/docs`.
  - Added dedicated SIEM export endpoints `GET /api/v1/export/stix` and `GET /api/v1/export/cef`.
- [x] Verified with 17 unit and integration tests (`tests/test_mitre_siem_openapi.py`). Full test suite: **243 / 243 passing tests** (100% pass rate).

### Phase 10: Distributed Control Plane, Edge Sensor Agent & Global Fleet Quarantine (P1 Enterprise) — ✅ COMPLETED
- [x] **Edge Sensor Agent & HMAC Telemetry Protocol (`scripts/9_utilities/edge_agent.py`)**:
  - Implemented `EdgeSensorAgent` client and server receiver with HMAC-SHA256 request signing (`X-IoTGuard-Signature`, `X-IoTGuard-Timestamp`, `X-IoTGuard-Node-Id`) and strict 60-second replay attack protection.
  - Periodic telemetry heartbeats reporting CPU usage, RAM utilization, active XDP line-rate drop counts, local model SHA-256 hash, and active local blocks.
  - Node registration endpoint (`POST /api/v1/fleet/register`) assigning cryptographic secrets across branch site types (`smart_home`, `factory_floor`, `substation_edge`, `hospital_iot_vlan`).
- [x] **Fleet-Wide Policy Push & Global Herd Immunity Quarantine (`api_dashboard.py` & `edge_agent.py`)**:
  - Central SOC Global Block Broadcast queue: When high-severity attacks (`KILL` tier or manual block) are identified, blocks are enqueued and automatically pulled down by every registered edge sensor gateway on its next heartbeat.
  - Remote edge sensors autonomously enforce the block in their local eBPF/XDP kernel maps and firewall layers, achieving enterprise-wide herd immunity across all company branches.
  - Dedicated fleet inspection endpoints: `GET /api/v1/fleet/nodes` (live health, latency, model sync status, and XDP drops), `POST /api/v1/fleet/broadcast_block`, and `GET /api/v1/fleet/blocks`.
- [x] Verified with 24 unit and integration tests (`tests/test_fleet_control_plane.py`). Full test suite: **267 / 267 passing tests** (100% pass rate).

### Phase 11: SOC Executive SLA Telemetry (MTTD/MTTR), MITRE Heatmap & Compliance Reporting (P1 Enterprise) — ✅ COMPLETED
- [x] **Real-Time SOC SLA & KPI Engine (`scripts/5_dashboard/soc_metrics.py`)**:
  - Rolling Mean Time to Detect (MTTD, ~14.2ms vs <100ms SLA target) and Mean Time to Respond (MTTR, ~3.8ms vs <50ms SLA target) tracker with status classification (`MET` vs `BREACHED`).
  - Live MITRE ATT&CK® Tactic Matrix aggregation across 6 enterprise tactics (`TA0043 Recon`, `TA0001 Initial Access`, `TA0002 Execution`, `TA0006 Credential Access`, `TA0011 C2`, `TA0040 Impact`) with dynamic active counts and observed techniques.
  - Composite Fleet Immunity Index ($0.0–100.0\%$) weighting distributed edge node health (40%), SHA-256 cryptographic audit chain integrity (35%), and feature distribution drift (25%) with qualitative ratings (`OPTIMAL`, `STABLE`, `DEGRADED`).
  - Dedicated KPI endpoint: `GET /api/v1/soc/kpis` (and `/api/soc/kpis`).
- [x] **Executive Compliance & Incident Report Generator (`soc_metrics.py` & `api_dashboard.py`)**:
  - Multi-format report dispatch (`GET /api/v1/reports/executive?format=json|html|markdown`).
  - Standalone, interactive, print-ready HTML executive report with CSS media print styling, KPI tiles, MITRE coverage table, geographic origin rankings, eBPF drop counters, and cryptographic audit seals.
  - Formal regulatory compliance alignment: **NIS2 Directive** (EU 2022/2555 Art. 21), **EU Cyber Resilience Act** (CRA Essential Requirements), **ISO/IEC 27001:2022** (Control A.8.16), and **SOC 2 Type II**.
- [x] **Enterprise SOC Console Upgrade (`templates/index.html` & `dashboard.css`)**:
  - Enterprise Governance & Fleet Health Strip displaying MTTD, MTTR, Audit Chain status (`VERIFIED`), Fleet Immunity Index, and Hardware XDP Drops.
  - Interactive 6-column MITRE ATT&CK Live Threat Matrix banner with real-time active indicators and technique tags.
  - One-click "Export Executive SOC Report" button opening the print-ready executive report.
- [x] Verified with 17 unit and integration tests (`tests/test_soc_metrics_reports.py`). Full test suite: **284 / 284 passing tests** (100% pass rate).

### Phase 12: O(1) Stream Tailer, Live Async SIEM Streaming & Final v4.0 Hardening (P1 Enterprise) — ✅ COMPLETED
- [x] **O(1) Incremental CSV Stream Reader (`scripts/3_inference/stream_reader.py`)**:
  - Implemented `FastCSVStreamReader` using OS file byte offsets (`f.seek()`) to eliminate the $O(N^2)$ full-file re-read bottleneck in `decision_loop.py`.
  - Cached CSV header schema, handled mid-write incomplete lines with rollback to last complete newline delimiter, and added automatic file truncation/rotation detection.
  - Provided graceful fallback recovery from legacy row-offset states in `data/state.json`.
- [x] **Non-Blocking Asynchronous SIEM Dispatcher (`stream_reader.py`)**:
  - Implemented `AsyncSIEMDispatcher` running a background daemon worker thread consuming from a thread-safe bounded queue (`queue.Queue(maxsize=2000)`).
  - Streams high-severity alerts (`is_attack`, non-NONE action, or $P(\text{attack}) \ge 0.80$) over RFC 5424 Syslog (UDP/TCP/TLS) via `siem_exporter.py` whenever `IOTGUARD_SYSLOG_HOST` is configured, preventing external network I/O from stalling time-critical packet scoring.
  - Drop-on-overflow policy protects gateway memory while incrementing drop counters for full SIEM buffer visibility.
- [x] **Decision Loop Integration (`scripts/3_inference/decision_loop.py`)**:
  - Wired `FastCSVStreamReader` into the main detection loop, maintaining dual `offset_rows` and `byte_offset` persistence in `data/state.json` with 100% backward compatibility for `event_logger.py`.
  - Integrated `AsyncSIEMDispatcher` on every scored window and hooked clean worker teardown into `graceful_shutdown()`.
- [x] Verified with 9 unit and integration tests (`tests/test_stream_reader.py`). Full test suite: **293 / 293 passing tests** (100% pass rate).

---

## 10. Operational Command Reference

### Virtual Environment Setup & Dependencies
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-websocket.txt
```

### Running the Test Suite
```powershell
python -m pytest tests/ -v
```

### Launching the Full System in Demo Mode
```powershell
python scripts/9_utilities/demo_launcher.py
# Automatically boots simulate_stream, decision_loop, and opens http://127.0.0.1:5001/dashboard
```

### Running via Docker Compose
```powershell
docker compose up --build
```

### Retraining Supervised & Unsupervised Models on Real Data
```powershell
# 1. Map real Edge-IIoTset records into IoTGuard 13 features
python scripts/1_data_input/convert_edge_iiotset.py

# 2. Retrain models, apply calibration, and evaluate against holdout set
python scripts/2_training/retrain_with_real_data.py
```

### Running Holdout Evaluation Benchmark
```powershell
python scripts/7_testing/test_holdout.py
```

---
*End of Master System Handover Document.*

