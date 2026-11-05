## IoTGuard System Architecture & Pipeline Specification (v4.0 Enterprise)

This document provides the technical specification of the end-to-end architecture, data pipeline, storage engine, cryptographic audit ledger, and security boundaries in IoTGuard Enterprise v4.0.

---

### 1. High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      IoTGuard Enterprise v4.0 Core Engine                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐    ┌─────────────────┐    ┌─────────────────────────────┐     │
│  │ Suricata │───▸│ Feature Extract │───▸│      Decision Loop          │     │
│  │ eve.json │    │  (13 features)  │    │ (Streaming Scoring Pipeline)│     │
│  └──────────┘    └─────────────────┘    └──────────────┬──────────────┘     │
│                                                        │                    │
│         ┌───────────────────────┬──────────────────────┼─────────────┐      │
│         │                       │                      │             │      │
│         ▼                       ▼                      ▼             ▼      │
│  ┌──────────────┐     ┌──────────────────┐    ┌──────────────┐ ┌──────────┐ │
│  │   Ensemble   │     │ Temporal Detector│    │  Playbooks   │ │ Threat   │ │
│  │(LGBM+IForest)│     │(Low & Slow Drift)│    │(Multi-Class) │ │ Intel    │ │
│  └──────────────┘     └──────────────────┘    └──────────────┘ └──────────┘ │
│         │                       │                      │             │      │
│         └───────────────────────┴──────────────────────┼─────────────┘      │
│                                                        │                    │
│                                                        ▼                    │
│                             ┌───────────────────────────────────────┐       │
│                             │       Decision & Response Policy      │       │
│                             │     (Tiers: NONE, SOFT, HARD, KILL)   │       │
│                             └──────────────────┬────────────────────┘       │
│                                                │                            │
│                    ┌───────────────────────────┴────────────────┐           │
│                    ▼                                            ▼           │
│  ┌────────────────────────────────────┐       ┌──────────────────────────┐  │
│  │ Active Defense (eBPF / XDP Blocker)│       │  Alerting System         │  │
│  │ • In-kernel NIC RX drop (<1µs)     │       │  • Email (SMTP)          │  │
│  │ • Fallback: nftables, netsh        │       │  • Slack Webhooks        │  │
│  │ • Dual-Write: active_blocks.json+DB│       │  • Telegram Bot API      │  │
│  └──────────────────┬─────────────────┘       └─────────────┬────────────┘  │
│                     │                                       │               │
│                     └───────────────────┬───────────────────┘               │
│                                         ▼                                   │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │             Enterprise Storage & Cryptographic Audit Layer            │  │
│  │  • SQLite WAL Engine: data/iotguard_enterprise.db with indexed tables │  │
│  │  • Zero-Regression Dual-Write Contract: alerts.jsonl + active_blocks │  │
│  │  • Hash-Chained Audit Ledger: SHA-256 block chain (logs/audit_ledger) │  │
│  │  • Enterprise RBAC: ADMIN | SOC_ANALYST | AUDITOR | EDGE_SENSOR       │  │
│  │  • Scoped API Key Engine: X-IoTGuard-API-Key with Rate Limiting       │  │
│  └──────────────────────────────────────┬────────────────────────────────┘  │
│                                         │                                   │
│                                         ▼                                   │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                   Web Dashboard, Topology & Telemetry                 │  │
│  │  • Real-time Charts & XAI Drawer   • Interactive Cytoscape Topology   │  │
│  │  • RBAC Auth & Dynamic Policy      • One-Click Device Quarantine      │  │
│  │  • Audit Trail & Verification UI   • Prometheus Metrics (/metrics)    │  │
│  │  • Multidimensional Event Queries  • WebSocket Event Broadcast        │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                      │
│                                      ▼                                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              Fleet Federated Learning & Drift Monitoring              │  │
│  │  • FedAvg Coordinator across distributed edge nodes                   │  │
│  │  • Differential Privacy (L2-norm clipping + Gaussian noise)           │  │
│  │  • Online Feature Drift (PSI & KS-test) on 13 network features        │  │
│  │  • Automated model versioning & backup rollback manager               │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                      │
│                                      ▼                                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │         Enterprise SIEM, MITRE ATT&CK & Threat Sharing Layer          │  │
│  │  • MITRE ATT&CK Mapping (Enterprise & ICS/IoT Tactics & Techniques)   │  │
│  │  • ArcSight Common Event Format (CEF:0) Formatter & Exporter          │  │
│  │  • RFC 5424 Syslog Dispatcher (UDP / TCP / TLS with Structured Data)  │  │
│  │  • OASIS STIX 2.1 Threat Sharing Bundles (TAXII 2.1 Ready Indicators) │  │
│  │  • OpenAPI 3.1.0 Specification & Interactive Swagger UI (/api/docs)   │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                      │
│                                      ▼                                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │        Distributed Fleet Control Plane & Edge Sensor Gateways         │  │
│  │  • Central SOC Multi-Site Management (smart_home, factory_floor, etc.)│  │
│  │  • HMAC-SHA256 Request Signing & 60-Second Replay Protection          │  │
│  │  • Periodic Heartbeat Telemetry (CPU, RAM, XDP drops, alerts)         │  │
│  │  • Global Fleet Quarantine Queue: Pushes KILL blocks to all sensors   │  │
│  │  • Automated Herd Immunity: Local eBPF/XDP drops enforced across sites│  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### 2. High-Level Pipeline Stages

1. **Traffic Capture Layer**
   - Suricata inspects network interfaces in promiscuous mode or replays PCAP streams.
   - Generates flow-level JSON logs in `data/suricata/eve.json`.

2. **Feature Extraction (`suricata_to_features.py`)**
   - Tails `eve.json` and aggregates flow events into fixed windows (default: 10s).
   - Computes 13 IP-agnostic statistical features defined in `configs/model.yaml`:
     `flows, bytes_total, pkts_total, syn_ratio, mean_bytes_flow, ack_ratio, fin_ratio, rst_ratio, http_ratio, tcp_ratio, protocol_diversity, std_bytes, iat_mean`.
   - Appends rows to `data/features.csv` and outputs context to `data/window_meta.json`.

3. **Device Fingerprinting (`device_fingerprinting.py`)**
   - Analyzes traffic variance, protocol entropy, and periodicity to classify endpoints as `IoT` vs `IT`.
   - Routes traffic vectors to specialized supervised models (`lightgbm.joblib` or `lightgbm_it.joblib`).

4. **Hybrid Inference & Temporal Analysis (`scoring.py`, `ensemble.py`, `temporal_detector.py`)**
   - **Supervised LightGBM**: Evaluates probability of known attack signatures with Platt calibration.
   - **Unsupervised IsolationForest**: Computes anomaly scores for novel or zero-day behaviors.
   - **Temporal Detector**: Maintains a rolling buffer of $K=6–12$ windows (1–2 minutes). Computes regression trends and statistical drifts on `rst_ratio`, `syn_ratio`, `flows`, and `http_ratio` to catch stealth low-and-slow campaigns that stay beneath single-window thresholds.
   - **Score Fusion**: Combines scores via configurable strategies (`or`, `and`, `weighted`).

5. **Multi-Class Taxonomy & Playbook Enrichment (`playbooks.py`, `explainer.py`, `threat_intel.py`)**
   - Classifies flagged events into 9 taxonomies: `DDoS-SYN`, `DDoS-UDP`, `DDoS-HTTP`, `Mirai-C2`, `PortScan`, `SQLInjection`, `CommandInjection`, `BruteForce`, `ZeroDay-Anomaly`.
   - Attaches actionable remediation playbooks (CLI commands for Windows `netsh` and Linux `nftables`/`iptables`, port limits, DPI rules).
   - Calculates real-time SHAP feature importance rationales.
   - Resolves GeoIP2 city/country data and queries AbuseIPDB/AlienVault threat intelligence with TTL caching.

6. **Active Defense & Mitigation (`ebpf_driver.py`, `xdp_iotguard.c`, `blocker.py`)**
   - **eBPF/XDP Hook**: Drops malicious IPv4 packets directly at the NIC driver RX ring in <1µs before kernel network stack processing.
   - **OS Fallback**: Seamless fallback to Linux `nftables`/`iptables` and Windows `netsh advfirewall`.
   - **Persistence**: Writes active blocks and drop counters to `data/active_blocks.json`.
   - **Mitigation Tiers**: Evaluates `NONE`, `SOFT` (grace hits), `HARD` (instant block $\ge 0.95$), and `KILL` ($\ge 0.98$).

7. **Edge Federated Learning & Drift Monitoring (`federated_learning.py`, `check_feature_drift.py`)**
   - **Continual Adaptation**: Edge gateways simulate decentralized FedAvg aggregation.
   - **Differential Privacy**: Enforces L2-norm clipping and calibrated Gaussian perturbation to guarantee zero raw-data leakage.
   - **Online Drift Detection**: Evaluates live sliding windows against baseline training distributions using Population Stability Index (PSI) and Kolmogorov-Smirnov (KS) tests. Flags distribution drift ($\text{PSI} \ge 0.25$) and triggers model sync.

8. **Web Dashboard, RBAC & REST API (`api_dashboard.py`, `auth.py`, `templates/index.html`)**
   - Real-time score charts, live alert feed with SHAP drawer, and interactive network topology canvas.
   - Prometheus metrics exposition on `/metrics`.
   - Enterprise RBAC (`ADMIN`, `SOC_ANALYST`, `AUDITOR`, `EDGE_SENSOR`) and scoped API key support (`X-IoTGuard-API-Key`).
   - Cryptographic audit trail endpoints (`/api/v1/audit`, `/api/v1/audit/verify`) with mathematical verification.
   - Dynamic policy controls, manual device quarantine (`/api/block`, `/api/unblock`), and on-demand federated rounds.

9. **Enterprise Relational Storage Engine & Audit Ledger (`storage_engine.py`, `audit_ledger.py`)**
   - **High-Concurrency SQLite WAL Engine**: Zero-dependency ACID persistence (`data/iotguard_enterprise.db`) with connection pooling.
   - **Indexed Multidimensional Queries**: Sub-millisecond filtering on timestamp, source IP, attack category, score, and tier.
   - **Cryptographic Hash Chain**: SHA-256 block-chained entries ensuring tamper-evident non-repudiation and forensic integrity.
   - **Dual-Write Zero-Regression Contract**: Automatically synchronizes relational database and legacy flat files.

10. **Enterprise SIEM, MITRE ATT&CK & Threat Sharing (`siem_exporter.py`, `openapi_spec.py`, `playbooks.py`)**
   - **MITRE ATT&CK® Enterprise & ICS/IoT Mapping**: 100% of attack categories enriched with official tactic and technique identifiers.
   - **ArcSight Common Event Format (CEF:0)**: Compliant CEF serialization (`/api/v1/export/cef`) with header/extension escaping.
   - **RFC 5424 Syslog Dispatcher**: Transmits structured syslog frames (`[iotguard@53457 ...]`) over UDP, TCP, and TLS transports.
   - **OASIS STIX 2.1 Bundles**: Generates TAXII 2.1-compatible threat bundles (`/api/v1/export/stix`) linking indicators to attack patterns.
   - **OpenAPI 3.1.0 Specification & Swagger UI**: Interactive API documentation at `/api/docs` and machine-readable schema at `/api/openapi.json`.

11. **Distributed Fleet Control Plane & Herd Immunity (`edge_agent.py`)**
   - **Central Fleet Coordinator (`FleetControlPlane`)**: Authenticates remote edge sensor gateways, tracks model drift, and manages fleet quarantine queues.
   - **Cryptographic HMAC-SHA256 Protocol**: Request signing with 60-second replay protection window.
   - **Autonomous Herd Immunity**: Central SOC operator blocks or automated `KILL` tier detections propagate to all remote edge sensors on heartbeat, enforcing local eBPF/XDP and firewall packet drops across all company branches.

---

### 3. Key Files & Repository Map

**Configuration:**
- `configs/model.yaml`, `configs/model_lab.yaml`, `configs/model_prod.yaml` – Master configuration (features, policies, thresholds).
- `configs/devices.yaml` – IP-to-device mapping.
- `configs/access_control.yaml` – CIDR allowlists and rate limits.

**Models:**
- `models/lightgbm.joblib` – Primary supervised IoT classifier.
- `models/lightgbm_it.joblib` – IT-specific supervised classifier.
- `models/unsup_isoforest.joblib` – Unsupervised anomaly detector.
- `models/multiclass_classes.json` & `models/multiclass_meta.json` – Multi-class taxonomy and model metadata.
- `models/federated_global_model.json` – Global federated parameter state and SHA-256 hash.

**Runtime Data Buffers & Enterprise Storage:**
- `data/iotguard_enterprise.db` – High-concurrency indexed relational database (WAL mode).
- `data/features.csv` – Active rolling feature stream.
- `data/window_meta.json` – Active window context and top source IPs.
- `data/alerts.jsonl` – Legacy append-only security log (rotated at 5MB).
- `data/active_blocks.json` – Active firewall blocks and drop counters.
- `logs/audit_ledger.jsonl` – Dual-written cryptographic SHA-256 audit ledger.

**Kernel & Drivers:**
- `scripts/4_response/xdp_iotguard.c` – C eBPF/XDP kernel program.
- `scripts/4_response/ebpf_driver.py` – Python eBPF controller and BPF map manager.
- `scripts/4_response/blocker.py` – Multi-tier active response engine.

**Enterprise Plumbing:**
- `scripts/9_utilities/storage_engine.py` – High-concurrency SQLite storage engine & connection pool.
- `scripts/9_utilities/audit_ledger.py` – Tamper-evident cryptographic SHA-256 audit ledger.
- `scripts/5_dashboard/auth.py` – Enterprise RBAC & scoped API key authentication engine.

---

### 4. Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Multi-Tier Security Architecture             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. In-Kernel Packet Filtering                                  │
│     └─ eBPF/XDP driver drops packets at NIC RX ring (<1 µs)     │
│     └─ OS fallback to nftables, iptables, and Windows netsh     │
│                                                                  │
│  2. Strict Input Validation                                     │
│     └─ IP/CIDR validation (validators.py) prevents injection   │
│     └─ Loopback, multicast, and private whitelist preservation   │
│                                                                  │
│  3. Authentication, RBAC & Scoped API Keys                      │
│     └─ Enterprise RBAC: ADMIN | SOC_ANALYST | AUDITOR | EDGE_SENSOR│
│     └─ JWT tokens & X-IoTGuard-API-Key with least-privilege checks │
│     └─ Token-bucket rate limiting (rate_limiter.py)                │
│                                                                  │
│  4. Privacy-Preserving Continual Learning                       │
│     └─ Zero raw payload/traffic export during federated rounds   │
│     └─ Calibrated L2 differential privacy noise perturbation     │
│                                                                  │
│  5. Immutable Cryptographic Audit & Forensics                   │
│     └─ SHA-256 block-chained audit ledger with non-repudiation  │
│     └─ Mathematical verification: verify_chain() detects tampering│
│     └─ Dual-write to SQLite database and logs/audit_ledger.jsonl │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 5. Prometheus Observability Metrics

Exposed via `GET /metrics`:
- `iotguard_detections_total`: Total detections partitioned by severity (`soft`, `hard`, `kill`).
- `iotguard_blocks_total`: Firewall blocking operations (success/failure).
- `iotguard_inference_seconds`: Model inference latency histogram.
- `iotguard_score_distribution`: Distribution of hybrid risk scores.
- `iotguard_firewall_driver_info`: Active mitigation driver (`ebpf_xdp`, `nftables`, `iptables`, `netsh`).
- `iotguard_xdp_packet_drops_total`: Hardware packets dropped directly in XDP kernel hook.
- `iotguard_xdp_active_blocked_ips`: Active entries in pinned BPF map `iotguard_blocked_ips`.
- `iotguard_model_drift`: Real-time Population Stability Index (PSI) drift indicator.
- `iotguard_api_requests_total`: Total API requests partitioned by endpoint and HTTP status.
