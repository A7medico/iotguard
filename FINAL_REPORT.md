# IoTGuard - Final Project Report

## ML-Driven IoT Intrusion Detection System & Automated Edge Response

**Project Repository:** [https://github.com/ahmadaymance/iotguard](https://github.com/ahmadaymance/iotguard)

**Version:** 3.0.0  
**Date:** November 2026

| **Prepared For** | **Prepared By** |
| :--- | :--- |
| **Project Evaluation Committee** | **IoTGuard Team** |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Final System Architecture and Design](#2-final-system-architecture-and-design)
3. [Impact of Engineering Solutions](#3-impact-of-engineering-solutions)
4. [Contemporary Issues](#4-contemporary-issues)
5. [Tools and Technologies](#5-tools-and-technologies)
6. [Library and Internet Resources](#6-library-and-internet-resources)
7. [Test Results](#7-test-results)
8. [Conclusion and Future Work](#8-conclusion-and-future-work)
9. [References](#9-references)

---

## 1. Executive Summary

### 1.1 Project Overview
**IoTGuard** is a lightweight, machine learning-driven Intrusion Detection and Automated Response System (IDS/IPS) specifically engineered to secure the resource-constrained and heterogeneous landscape of Internet of Things (IoT) and Industrial IoT (IIoT) edge networks. As IoT devices proliferate—projected to exceed 29 billion by 2030—they have become the primary target for vast botnets (like Mirai, Mozi, and Gafgyt) due to weak default security, unpatched firmware, and persistent network connectivity.

Traditional enterprise security solutions (relying on heavy signature databases and deep packet inspection) fail in IoT edge environments due to CPU/memory constraints and encryption blinding. IoTGuard addresses this gap by utilizing **behavioral metadata analysis** combined with a **hybrid ensemble machine learning engine**, **stateful temporal drift detection**, and **sub-microsecond eBPF/XDP in-kernel packet filtering**. It provides an autonomous security boundary that monitors, analyzes, explains, and neutralizes threats at the network edge in real time.

### 1.2 Key Achievements & Engineering Milestones
- **🚀 Real-time Low-Latency Detection**: Sub-second end-to-end inference latency (<50ms for 10-second traffic windows; <5ms for SHAP explanations), enabling proactive threat neutralization before lateral propagation.
- **🧠 Hybrid Multi-Model Ensemble**: Fuses **Supervised LightGBM** (high precision on known signatures) with **Unsupervised IsolationForest** (zero-day anomaly detection) via configurable OR, AND, and Weighted combination strategies.
- **📈 Stateful Temporal Sequence Detection**: A dedicated sliding-window temporal analyzer tracks trend drift across $K=6$ to $12$ windows (1–2 minutes of traffic), successfully catching low-and-slow port scans and stealth brute-forcing with **0.0% False Positive Rate** on holdout benign traffic.
- **🎯 Multi-Class Classification & Taxonomy (96.39% Accuracy)**: Trained on 74,435 samples across 16 attack classes, mapping detections to 9 canonical taxonomies (`DDoS-SYN`, `DDoS-UDP`, `DDoS-HTTP`, `Mirai-C2`, `PortScan`, `SQLInjection`, `CommandInjection`, `BruteForce`, `ZeroDay-Anomaly`) with structured remediation playbooks.
- **⚡ In-Kernel Packet Filtering with eBPF / XDP**: Implemented high-speed C eBPF kernel program (`xdp_iotguard.c`) executing at the NIC driver RX ring, dropping malicious IPv4 traffic in **<1 µs** before packets enter kernel networking, with seamless OS fallback (nftables, iptables, netsh).
- **🌐 Privacy-Preserving Edge Federated Learning**: Developed a `FedAvg` coordinator and edge-client module with calibrated Differential Privacy (L2-norm clipping + Gaussian noise) and online Population Stability Index (PSI) drift monitoring—collaborative learning without sharing raw PCAPs or payloads.
- **🗺️ Interactive Live Network Topology UI**: Web dashboard featuring force-directed topology visualization with dynamic status rings (Benign, Grace, Blocked), GeoIP2 enrichment, AbuseIPDB reputation, and JWT-authenticated one-click device quarantine/unblock controls.
- **🏛️ Enterprise Relational Storage & Cryptographic Audit Ledger**: High-concurrency SQLite storage engine in WAL mode (`data/iotguard_enterprise.db`) with connection pooling, dual-write zero-regression contracts, fine-grained Enterprise RBAC (`ADMIN`, `SOC_ANALYST`, `AUDITOR`, `EDGE_SENSOR`), and an immutable SHA-256 block-chained audit ledger with non-repudiation verification.
- **🧪 Comprehensive Automated Verification**: **226 / 226 tests passing (100% pass rate)** across 18 test suites covering all cryptographic, ML, network driver, storage, and security boundaries.

---

## 2. Final System Architecture and Design

The IoTGuard architecture adopts a **decoupled, microservices-inspired design** dividing ingestion, feature extraction, temporal analysis, multi-class inference, active defense, and fleet learning into modular components.

### 2.1 High-Level Component Diagram

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
│  • Active Block Tracking: data/active_blocks.json                      │
│  • Multi-Channel Alerts: Email (SMTP), Slack webhook, Telegram bot     │
│  • Event Persistence: Appends to data/alerts.jsonl                     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Event stream / REST / WebSockets
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│              OPERATOR DASHBOARD, TOPOLOGY & FLEET CONTROL              │
│  api_dashboard.py (Flask + WebSockets + Chart.js + Prometheus)         │
│  • Interactive Network Topology canvas with one-click quarantine      │
│  • Fleet Federated Learning & Online Feature Drift Monitor             │
│  • Real-time score & adaptive threshold chart                          │
│  • Live alert feed with SHAP explanation & threat intel                │
│  • Prometheus metrics (/metrics) & JWT Token Auth (/api/v1/login)      │
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
└────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Detailed Data Flow Pipeline

1. **Traffic Ingestion (Suricata IDS)**: Operates in promiscuous mode on network taps or monitors raw PCAP streams, outputting structured flow-level JSON logs (`eve.json`) without payload storage overhead.
2. **Feature Extraction & Engineering**: `suricata_to_features.py` tails `eve.json`, aggregating flows into 10-second windows and computing 13 IP-agnostic statistical features.
3. **Context-Aware Device Fingerprinting**: `device_fingerprinting.py` determines device personality (`IoT` vs `IT`) based on packet periodicity and protocol entropy, routing traffic to specialized models.
4. **Hybrid Ensemble & Temporal Detection**: 
   - `scoring.py` loads LightGBM and IsolationForest models.
   - `temporal_detector.py` maintains rolling history across $K=6–12$ windows, calculating least-squares regression slopes on `rst_ratio`, `syn_ratio`, `flows`, and `http_ratio` to catch low-and-slow campaigns.
5. **Taxonomy Classification & Playbooks**: When flagged, `playbooks.py` assigns an attack category and embeds structured remediation guidance (OS firewall commands, port restrictions, payload hints).
6. **Active Defense Enforcement**:
   - `ebpf_driver.py` / `xdp_iotguard.c` drops malicious packets at driver level (<1µs).
   - `blocker.py` provides cross-platform userspace fallback (`netsh` on Windows, `nftables`/`iptables` on Linux) with strict validation.
7. **Federated Learning & Drift Detection**:
   - `check_feature_drift.py` continuously computes Population Stability Index (PSI) and Kolmogorov-Smirnov (KS) statistics against training baselines.
   - When drift occurs ($\text{PSI} \ge 0.25$), `federated_learning.py` coordinates privacy-preserving weight aggregation across edge nodes.

### 2.3 The 13 Network Behavioral Features

The system relies strictly on 13 IP-agnostic features, ensuring models never overfit to specific subnets:

| # | Feature Name | Type | Description | Security Relevance |
|---|---|---|---|---|
| 1 | `flows` | Count | Total distinct flows in window. | Spikes indicate sweeping port scans or distributed attacks. |
| 2 | `bytes_total` | Volume | Aggregate bandwidth volume. | Volumetric spikes indicate UDP/HTTP floods or exfiltration. |
| 3 | `pkts_total` | Volume | Total packet count in window. | High packet-to-byte ratio is a classic signature of IoT botnets. |
| 4 | `syn_ratio` | Flag | Ratio of TCP SYN packets. | Approaching 1.0 indicates TCP SYN Floods or stealth scans. |
| 5 | `mean_bytes_flow` | Stat | Average byte volume per flow. | Small values (<60 B) indicate probe packets or C2 heartbeats. |
| 6 | `ack_ratio` | Flag | Ratio of TCP ACK packets. | Low ACK ratios indicate handshake failures or reflection attacks. |
| 7 | `fin_ratio` | Flag | Ratio of TCP FIN packets. | Abnormal teardowns and stealth scans (FIN scanning). |
| 8 | `rst_ratio` | Flag | Ratio of TCP RST packets. | Spikes occur when probing closed ports during reconnaissance. |
| 9 | `http_ratio` | Proto | Proportion of HTTP traffic. | Identifies Layer-7 attacks (SQL Injection, brute force). |
| 10 | `tcp_ratio` | Proto | Ratio of TCP vs UDP traffic. | Evaluates protocol shifts (e.g., UDP amplification floods). |
| 11 | `protocol_diversity` | Meta | Count of unique Service/App protocols. | IoT devices usually have low diversity; shifts imply compromise. |
| 12 | `std_bytes` | Stat | Standard deviation of flow byte sizes. | Low standard deviation indicates automated script attacks. |
| 13 | `iat_mean` | Time | Mean Inter-Arrival Time of packets. | Machine attacks exhibit rigid timing signatures vs human burstiness. |

---

## 3. Impact of Engineering Solutions

### 3.1 Global and Economic Context
- **Edge-Native Economics**: Traditional firewall appliances cost thousands of dollars per unit. IoTGuard runs on commodity ARM/x86 edge hardware (e.g., Raspberry Pi 4, industrial gateways), lowering the security barrier for small enterprises and developing nations.
- **Autonomous Remediation**: By automating detection, classification, and mitigation, IoTGuard reduces incident dwell time from hours to milliseconds and drastically cuts SOC operational overhead.

### 3.2 Environmental Sustainability
- **Ultra-Low Compute Footprint**: Metadata-only analysis requires <10% of the CPU cycles demanded by DPI solutions. eBPF/XDP drops packets before CPU memory allocation, saving server power and extending edge device battery life.
- **Asset Lifespan Extension**: Protecting constrained IoT sensors from volumetric saturation prevents flash memory wear-out and hardware degradation.

### 3.3 Societal Implications & Trust
- **Privacy-Preserving Defense**: Inspects network metadata, never encrypted user payloads (protecting sensitive voice, video, and medical telemetry).
- **Explainable AI (SHAP)**: Demystifies machine learning classifications into human-readable rationales, fostering operational trust.
- **Federated Confidentiality**: Edge devices collaboratively improve detection without ever exporting raw traffic logs or user records.

---

## 4. Contemporary Issues

### 4.1 "Living off the Land" & Low-and-Slow Reconnaissance
Modern threat actors avoid noisy scans and custom malware binaries, instead leveraging native utilities and spreading probes over minutes. IoTGuard's **stateful temporal detector** and **unsupervised IsolationForest** identify anomalous behavioral drift over sliding windows, neutralizing stealth campaigns that bypass traditional static thresholds.

### 4.2 In-Kernel Performance vs. Volumetric Floods
High-volume botnet floods (Mirai, DNS amplification) exhaust userspace socket buffers and OS kernel network stacks. IoTGuard's **eBPF/XDP driver** drops malicious packets directly at the NIC ring buffer (<1 µs), keeping edge CPU utilization minimal during line-rate saturation attacks.

### 4.3 Regulatory Compliance (GDPR, NIS2, EU Cyber Resilience Act)
IoTGuard satisfies modern cybersecurity regulations:
1. **Mandatory Real-Time Detection**: Continuously monitors edge subnets (NIS2 compliance).
2. **Tamper-Evident Audit Trails**: Rotated `alerts.jsonl` logs provide verifiable forensic timelines.
3. **Data Localization**: Federated model updates preserve strict GDPR compliance by processing data on-premise.

---

## 5. Tools and Technologies

| Component | Technology | Version | Rationale & Justification |
| :--- | :--- | :--- | :--- |
| **Language** | **Python** | **3.13+** | Data science and ML ecosystem with optimized execution speed. |
| **Kernel Filtering** | **eBPF / XDP** | **C (clang/bpf)** | Line-rate packet filtering at the NIC driver hook (<1 µs latency). |
| **Firewall Control** | **nftables / netsh** | **OS Native** | Cross-platform host-level containment with command injection protection. |
| **IDS Ingestion** | **Suricata** | **7.0+** | Multi-threaded flow event capture with native structured JSON output. |
| **Supervised ML** | **LightGBM** | **4.3+** | Gradient boosting with high tabular performance and Platt calibration. |
| **Anomaly Detection**| **IsolationForest** | **1.5+** | Linear time complexity ($O(n)$) anomaly detection for zero-day threats. |
| **Explainable AI** | **SHAP** | **0.44+** | Fast TreeExplainer (<5ms) feature attribution for security operators. |
| **Threat Intel** | **MaxMind GeoIP2** | **4.8+** | Fast offline City/Country IP resolution with fallback and AbuseIPDB caching. |
| **Federated ML** | **FedAvg + DP** | **Native Module**| Privacy-preserving distributed parameter averaging with Gaussian noise. |
| **Observability** | **Prometheus** | **Native format**| Standardized metric exposition (`/metrics`) for enterprise monitoring. |

---

## 6. Library and Internet Resources

### 6.1 Datasets
- **Edge-IIoTset (2022/2023)**: Real-world Industrial IoT dataset with 63 raw network fields mapped into IoTGuard's 13-feature schema.
- **IoT-23 Dataset**: Labeled malware captures (Mirai, Torii, Gafgyt) from Stratosphere Laboratories.
- **CIC-IoT-2023**: Used for validation of large-scale DDoS floods, scans, and Layer-7 exploits.

### 6.2 Key Libraries & Frameworks
- `scikit-learn`: IsolationForest, StandardScaler, and evaluation metrics.
- `lightgbm`: High-performance supervised binary and multi-class classification.
- `shap`: Real-time TreeExplainer feature importance attribution.
- `geoip2`: Official MaxMind binary database reader.
- `requests`: Asynchronous threat intelligence API connectors.
- `scipy`: Kolmogorov-Smirnov statistical two-sample tests.

---

## 7. Test Results

The IoTGuard Enterprise v4.0 platform has been validated through an automated test harness covering all functional tiers.

### 7.1 Testing Verification Matrix (226 / 226 Tests Passed)

| Test Suite | Scope & Module Verified | Cases Passed | Status |
| :--- | :--- | :---: | :---: |
| **`test_enterprise_storage_rbac.py`** | SQLite WAL concurrency, RBAC roles & audit hash chain | **14 / 14** | ✅ PASS |
| **`test_policy.py`** | `PolicyConfig`, mitigation tiers, cooldown timers, IP baseline tracking | **16 / 16** | ✅ PASS |
| **`test_temporal_detector.py`** | Sliding-window sequence drift, stealth trend slopes, rolling aggregator | **16 / 16** | ✅ PASS |
| **`test_multiclass_playbooks.py`** | Multi-class scoring, 9 taxonomies, remediation playbooks & API exposure | **19 / 19** | ✅ PASS |
| **`test_ebpf_blocker.py`** | eBPF/XDP driver, BPF map serialization, drop counters, OS fallback | **21 / 21** | ✅ PASS |
| **`test_threat_intel_topology.py`**| GeoIP2 lookup, AbuseIPDB TTL cache, topology graph, quarantine APIs | **15 / 15** | ✅ PASS |
| **`test_federated_drift.py`** | FedAvg coordinator, differential privacy, zero data leakage, PSI/KS drift | **13 / 13** | ✅ PASS |
| **`test_blocker.py`** | Cross-platform firewall execution & strict command injection prevention | **14 / 14** | ✅ PASS |
| **`test_ensemble.py`** | Hybrid score fusion arithmetic, OR/AND strategies, schema retention | **8 / 8** | ✅ PASS |
| **`test_alerting.py`** | Multi-channel dispatch (Email, Slack, Telegram) & rate limiting | **9 / 9** | ✅ PASS |
| **`test_device_fingerprinting.py`**| IoT vs. IT heuristic classification & traffic profile accumulation | **9 / 9** | ✅ PASS |
| **`test_decision_loop_utils.py`** | Heuristic attack classification & dynamic adaptive thresholds | **5 / 5** | ✅ PASS |
| **`test_train_supervised_utils.py`**| Label binarization correctness & threshold calibration logic | **5 / 5** | ✅ PASS |
| **`test_api_dashboard.py`** | Flask REST APIs, JWT authentication, Prometheus `/metrics` | **12 / 12** | ✅ PASS |
| **`test_validators.py`** | IP/CIDR input sanitization, network address validation | **26 / 26** | ✅ PASS |
| **`test_rate_limiter.py`** | Token-bucket rate limiting & CIDR access control lists | **13 / 13** | ✅ PASS |
| **`test_logging_config.py`** | Structured JSON logging & console formatting | **10 / 10** | ✅ PASS |
| **`test_end_to_end_smoke.py`** | Full-pipeline streaming detection smoke test on unseen holdout | **1 / 1** | ✅ PASS |
| **TOTAL** | **Comprehensive System Health (18 Suites)** | **226 / 226** | **100%** |

### 7.2 Model Performance Report

#### **1. Binary IoT Model (LightGBM on 651,944 Holdout Samples)**
- **Accuracy**: **88.86%**
- **ROC-AUC**: **0.9765**
- **Recall (Attack)**: **97.0%**
- **Precision (Attack)**: **88.0%**

#### **2. Binary IT Model (LightGBM on 5,661 Samples)**
- **Accuracy**: **99.47%**
- **ROC-AUC**: **0.9972**
- **Recall (Attack)**: **98.0%**

#### **3. Multi-Class Attack Classifier (74,435 Merged Real/Synthetic Samples)**
- **Accuracy**: **96.39%**
- **Classes Classified (16 + Benign)**: DDoS-UDP, DDoS-SYN, DDoS-HTTP, Mirai-UDP, Mirai-ACK, Mirai-Scan, Recon-HostDiscovery, Recon-OSScan, Recon-PortScan, Web-SqlInjection, Web-XSS, Web-CommandInjection, BruteForce, Backdoor, Ransomware, MITM, Benign.
- **Top Macro F1-Score**: **0.96**

#### **4. Stateful Temporal Sequence Drift Detection**
- **Stealth Low-and-Slow Attack Recall**: **100.0%** (Detected within 6–8 consecutive windows).
- **False Positive Rate on Benign Holdout (5,000 windows)**: **0.00%**.

#### **5. In-Kernel eBPF/XDP Filtering Benchmark**
- **Packet Drop Latency**: **<1 µs** (directly at the NIC driver RX hook).
- **Userspace Overhead**: **0.0% CPU** consumption during volumetric drops.

---

## 8. Conclusion and Future Work

### 8.1 Conclusion
The IoTGuard Enterprise v4.0 release represents a comprehensive realization of enterprise-grade security engineering tailored specifically for the IoT edge and enterprise SOC environments. By fusing lightweight behavioral metadata extraction, hybrid and multi-class machine learning, stateful temporal drift detection, line-rate eBPF/XDP kernel filtering, high-concurrency indexed storage, enterprise RBAC, and tamper-evident cryptographic hash-chaining, IoTGuard provides autonomous, resilient protection against both known botnets and emergent zero-day threats. 

Crucially, **all enterprise milestones—including High-Concurrency Indexed Storage (WAL mode), Forensic Cryptographic Audit Ledger, Enterprise RBAC, Federated Learning, Stateful Sequence Analysis, and In-Kernel eBPF Filtering—have been completely implemented, verified with 226 automated tests, and integrated into production readiness**.

### 8.2 Future Horizon Research
1. **P4 Programmable Hardware Data Planes**: Extending eBPF/XDP packet inspection to programmable edge hardware switches (P4 language) for multi-gigabit line-rate filtering.
2. **Cross-Fleet Zero-Trust Identity Federation**: Implementing cryptographic verifiable credentials (DIDs) for automated node enrollment across distributed enterprise IoT fleets.
3. **Hardware-Accelerated Differential Privacy**: Exploring edge TPM/TEE (Trusted Execution Environments) to cryptographically attest local model updates during federated aggregation rounds.

---

## 9. References

1. **Ke, G., et al.** (2017). *"LightGBM: A Highly Efficient Gradient Boosting Decision Tree."* Advances in Neural Information Processing Systems (NIPS), 30.
2. **Liu, F. T., Ting, K. M., & Zhou, Z. H.** (2008). *"Isolation forest."* 2008 Eighth IEEE International Conference on Data Mining.
3. **Lundberg, S. M., & Lee, S. I.** (2017). *"A unified approach to interpreting model predictions."* Advances in Neural Information Processing Systems (NIPS), 30.
4. **McMahan, B., et al.** (2017). *"Communication-Efficient Learning of Deep Networks from Decentralized Data."* AISTATS.
5. **Høiland-Jørgensen, T., et al.** (2018). *"The eXpress Data Path: Fast Programmable Packet Processing in the Linux Kernel."* ACM CoNEXT.
6. **Ferrag, M. A., et al.** (2022). *"Edge-IIoTset: A New Comprehensive Realistic Cyber Security Dataset of IoT and IIoT Applications for Centralized and Federated Learning."* IEEE Access.
7. **Antonakakis, M., et al.** (2017). *"Understanding the Mirai Botnet."* 26th USENIX Security Symposium.
8. **European Commission.** (2024). *"Cyber Resilience Act: Security Rules for Digital Products in the Single Market."*

---
*End of Report*
