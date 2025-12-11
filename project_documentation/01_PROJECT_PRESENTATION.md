# 🛡️ IoTGuard - Project Presentation

## ML-Driven IoT Intrusion Detection System

**A comprehensive security solution for detecting and blocking network attacks in real-time**

---

## 📋 Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Key Features](#3-key-features)
4. [Machine Learning Pipeline](#4-machine-learning-pipeline)
5. [Docker Deployment](#5-docker-deployment)
6. [Code Structure](#6-code-structure)
7. [How It Works](#7-how-it-works)
8. [Testing & Validation](#8-testing--validation)
9. [Demo Walkthrough](#9-demo-walkthrough)
10. [Future Improvements](#10-future-improvements)

---

## 1. Project Overview

### What is IoTGuard?

IoTGuard is a **lightweight, ML-driven Intrusion Detection System (IDS)** specifically designed for IoT networks. It combines:

- **Real-time traffic analysis** using Suricata IDS
- **Machine Learning models** (LightGBM + IsolationForest) for threat detection
- **Automated blocking** via system firewalls
- **Web dashboard** for monitoring and control

### Problem Statement

IoT devices are increasingly targeted by cyberattacks:
- **Mirai botnet** and its variants
- **DDoS attacks** exploiting vulnerable devices
- **Port scanning** and reconnaissance
- **Web-based attacks** (SQL injection, XSS)

Traditional IDS solutions are often too resource-intensive for IoT environments. IoTGuard provides a **lightweight yet effective** solution.

### Solution

```
┌─────────────────────────────────────────────────────────────────┐
│                     IoTGuard Solution                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Network Traffic → Feature Extraction → ML Scoring → Decision   │
│                                                                  │
│    • 13 network features          • LightGBM classifier         │
│    • 10-second windows            • IsolationForest anomaly     │
│    • Protocol analysis            • Ensemble combination        │
│                                                                  │
│               ↓                           ↓                      │
│                                                                  │
│         ATTACK Detected              benign Traffic              │
│              ↓                                                   │
│   • Block IP automatically                                       │
│   • Send alerts (Slack/Email/Telegram)                          │
│   • Log for analysis                                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. System Architecture

### High-Level Architecture

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

### Data Flow

```
Network Traffic
      │
      ▼
┌──────────────┐
│   Suricata   │  ← Packet capture + flow analysis
│   (IDS)      │
└──────┬───────┘
       │ eve.json (flow events)
       ▼
┌──────────────┐
│   Feature    │  ← 10-second window aggregation
│  Extraction  │  ← 13 numeric features computed
└──────┬───────┘
       │ features.csv
       ▼
┌──────────────┐
│  Decision    │  ← ML model scoring
│    Loop      │  ← Policy enforcement
└──────┬───────┘
       │
   ┌───┴───┐
   │       │
   ▼       ▼
┌─────┐ ┌─────┐
│Block│ │Alert│
│ IP  │ │Email│
└─────┘ └─────┘
```

---

## 3. Key Features

### Feature Matrix

| Feature | Description | Technology |
|---------|-------------|------------|
| 🔍 **Real-time Detection** | Continuous monitoring with adaptive thresholds | LightGBM |
| 🧠 **Ensemble Models** | Supervised + Unsupervised models combined | LightGBM + IsolationForest |
| 🔒 **Automatic Blocking** | Cross-platform IP blocking | Windows netsh / Linux nftables |
| 📊 **Web Dashboard** | Real-time visualization | Flask + JavaScript |
| 🔔 **Multi-Channel Alerts** | Instant notifications | Email/Slack/Telegram |
| 🔐 **JWT Authentication** | Secure API access | PyJWT |
| 📈 **Prometheus Metrics** | Production monitoring | Custom metrics |
| 🎯 **Device Fingerprinting** | Automatic IoT/IT classification | Traffic analysis |
| 📝 **Model Versioning** | Track & rollback models | JSON metadata |
| 💡 **Explainable AI** | SHAP-based explanations | shap library |

### The 13 Network Features

```python
FEATURES = [
    "flows",              # Number of network flows in window
    "bytes_total",        # Total bytes transferred
    "pkts_total",         # Total packets transferred
    "syn_ratio",          # SYN flag ratio (connection attempts)
    "mean_bytes_flow",    # Average bytes per flow
    "ack_ratio",          # ACK flag ratio
    "fin_ratio",          # FIN flag ratio (connection closures)
    "rst_ratio",          # RST flag ratio (connection resets)
    "http_ratio",         # HTTP protocol ratio
    "tcp_ratio",          # TCP vs UDP ratio
    "protocol_diversity", # Number of unique protocols
    "std_bytes",          # Standard deviation of bytes
    "iat_mean",           # Mean inter-arrival time
]
```

### Why These Features?

| Feature | Attack Indicator |
|---------|------------------|
| High `syn_ratio` | SYN Flood attack (many connections, few completions) |
| High `rst_ratio` | Port scanning (probing closed ports) |
| Low `mean_bytes_flow` | DDoS (many small packets) |
| High `bytes_total` + low diversity | Volumetric attack |
| High `http_ratio` | Web attack (SQL injection, XSS) |

---

## 4. Machine Learning Pipeline

### Training Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                    TRAINING PIPELINE                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. DATA COLLECTION                                              │
│     • IoT-23 Dataset (Mirai, benign IoT traffic)                │
│     • CIC-IoT Dataset (DDoS, port scans)                        │
│     • Custom simulated attacks                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. FEATURE ENGINEERING                                          │
│     • PCAP → Flow extraction → 13 features                      │
│     • Window aggregation (10 seconds)                           │
│     • Label assignment (benign/attack)                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. MODEL TRAINING                                               │
│                                                                  │
│     ┌─────────────────┐     ┌─────────────────┐                 │
│     │   SUPERVISED    │     │  UNSUPERVISED   │                 │
│     │   (LightGBM)    │     │ (IsolationForest)│                │
│     └────────┬────────┘     └────────┬────────┘                 │
│              │                       │                           │
│              │   Learns from         │   Learns "normal"         │
│              │   labeled attacks     │   traffic patterns        │
│              ▼                       ▼                           │
│     ┌─────────────────────────────────────────┐                 │
│     │           ENSEMBLE COMBINER             │                 │
│     │   Weighted combination of both models   │                 │
│     └─────────────────────────────────────────┘                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. THRESHOLD TUNING                                             │
│     • Precision-Recall curve analysis                           │
│     • F1-score maximization                                     │
│     • Optimal threshold: 0.70 (configurable)                    │
└─────────────────────────────────────────────────────────────────┘
```

### Model Performance

**Supervised Model (LightGBM):**
```
┌────────────────────────────────────────────────────────────────┐
│                    MODEL PERFORMANCE                            │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Metric              │ Value                                   │
│  ────────────────────┼─────────────────────────────────────────│
│  ROC-AUC             │ 0.95+                                   │
│  Precision (Attack)  │ 0.92                                    │
│  Recall (Attack)     │ 0.89                                    │
│  False Positive Rate │ < 5%                                    │
│                                                                 │
│  Confusion Matrix:                                              │
│  ┌────────────┬──────────┬──────────┐                          │
│  │            │ Predicted│ Predicted│                          │
│  │            │  Benign  │  Attack  │                          │
│  ├────────────┼──────────┼──────────┤                          │
│  │ Actual     │          │          │                          │
│  │ Benign     │   TN     │   FP     │                          │
│  ├────────────┼──────────┼──────────┤                          │
│  │ Actual     │          │          │                          │
│  │ Attack     │   FN     │   TP     │                          │
│  └────────────┴──────────┴──────────┘                          │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

### Ensemble Strategy

```
┌─────────────────────────────────────────────────────────────────┐
│                    ENSEMBLE PREDICTION                           │
└─────────────────────────────────────────────────────────────────┘

     Supervised Model              Unsupervised Model
     (LightGBM)                    (IsolationForest)
          │                              │
          │ P(attack)                    │ Anomaly Score
          │                              │
          ▼                              ▼
     ┌─────────┐                    ┌─────────┐
     │  0.85   │                    │  0.72   │
     └────┬────┘                    └────┬────┘
          │                              │
          └──────────────┬───────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Combination Logic  │
              │                     │
              │  Mode: "weighted"   │
              │  Weight: 0.7 / 0.3  │
              │                     │
              │  Final = 0.7*0.85   │
              │        + 0.3*0.72   │
              │        = 0.81       │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Threshold: 0.70    │
              │  0.81 > 0.70 → 🚨   │
              │  ATTACK DETECTED    │
              └─────────────────────┘

WHY ENSEMBLE?
┌─────────────────────────────────────────────────────────────────┐
│  Supervised (LightGBM)     │  Catches KNOWN attack patterns    │
│                            │  (learned from training data)     │
├────────────────────────────┼────────────────────────────────────┤
│  Unsupervised (IsoForest)  │  Catches NOVEL/ZERO-DAY attacks   │
│                            │  (anomalies from normal baseline) │
├────────────────────────────┼────────────────────────────────────┤
│  ENSEMBLE                  │  BEST OF BOTH WORLDS              │
│                            │  Maximum detection coverage       │
└────────────────────────────┴────────────────────────────────────┘
```

---

## 5. Docker Deployment

### Container Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    DOCKER DEPLOYMENT                             │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      Docker Host                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    iotguard-network                        │  │
│  │                                                            │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │              iotguard-app Container                  │  │  │
│  │  │                                                      │  │  │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐          │  │  │
│  │  │  │Dashboard │  │ Decision │  │ Feature  │          │  │  │
│  │  │  │  (Flask) │  │   Loop   │  │Extractor │          │  │  │
│  │  │  └──────────┘  └──────────┘  └──────────┘          │  │  │
│  │  │                                                      │  │  │
│  │  │  Port 5001 ─────────────────────────────────────────┼──┼──┼──▸ Browser
│  │  │                                                      │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │                                                            │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Volumes:                                                        │
│    ./data   ───▸  /app/data   (features, alerts)                │
│    ./logs   ───▸  /app/logs   (application logs)                │
│    ./models ───▸  /app/models (ML models, read-only)            │
│    ./configs───▸  /app/configs (configuration, read-only)       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Dockerfile Explained

```dockerfile
# Base Image
FROM python:3.13-slim

# Metadata
LABEL org.opencontainers.image.title="IoTGuard"
LABEL org.opencontainers.image.version="1.0.0"

WORKDIR /app

# Dependencies (cached layer)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY . ./

# Environment
ENV IOTGUARD_CONFIG=configs/model.yaml
ENV IOTGUARD_LOG_LEVEL=INFO

# Networking
EXPOSE 5001

# Health check for orchestration
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/health/live')"

# Start command
CMD ["python", "scripts/api_dashboard.py"]
```

### Docker Commands

```bash
# Build the image
docker build -t iotguard:latest .

# Run standalone container
docker run -d \
  --name iotguard \
  -p 5001:5001 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  iotguard:latest

# Using Docker Compose (recommended)
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Docker Compose Services

```yaml
version: "3.9"

services:
  iotguard-app:
    build: .
    container_name: iotguard-app
    environment:
      - IOTGUARD_CONFIG=configs/model.yaml
      - IOTGUARD_LOG_LEVEL=INFO
      - IOTGUARD_ALERTING_ENABLED=false
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./models:/app/models:ro
      - ./configs:/app/configs:ro
    ports:
      - "5001:5001"
    healthcheck:
      test: ["CMD", "python", "-c", "..."]
      interval: 30s
    restart: unless-stopped

networks:
  iotguard-net:
    driver: bridge
```

---

## 6. Code Structure

### Project Layout

```
iotguard/
│
├── 📁 scripts/                    # Main Python modules
│   ├── 🧠 decision_loop.py        # Core ML scoring engine
│   ├── 🌐 api_dashboard.py        # Flask REST API + Web UI
│   ├── 📚 train_supervised.py     # LightGBM training
│   ├── 📚 train_unsupervised.py   # IsolationForest training
│   ├── 🔗 ensemble.py             # Ensemble predictions
│   ├── 🔒 blocker.py              # IP blocking (Windows/Linux)
│   ├── 🔔 alerting.py             # Multi-channel notifications
│   ├── 🔐 auth.py                 # JWT authentication
│   ├── 📊 metrics.py              # Prometheus metrics
│   ├── 💡 explainer.py            # SHAP explanations
│   ├── 🌍 threat_intel.py         # Threat intelligence
│   ├── 📡 suricata_to_features.py # Production feature extraction
│   └── 🎮 simulate_stream.py      # Demo traffic generator
│
├── 📁 tests/                      # Unit & integration tests
│   ├── test_blocker.py
│   ├── test_ensemble.py
│   ├── test_alerting.py
│   └── ...
│
├── 📁 configs/                    # Configuration files
│   ├── model.yaml                 # Main configuration
│   ├── model_prod.yaml            # Production settings
│   └── devices.yaml               # Device mappings
│
├── 📁 models/                     # Trained models
│   ├── lightgbm.joblib            # Supervised model
│   ├── iforest.joblib             # Unsupervised model
│   └── model_meta.json            # Model metadata
│
├── 📁 data/                       # Runtime data
│   ├── features.csv               # Feature stream
│   └── alerts.jsonl               # Detection log
│
├── 📁 docs/                       # Documentation
│   ├── architecture.md
│   └── code_overview.md
│
├── 🐳 Dockerfile                  # Container definition
├── 🐳 docker-compose.yml          # Multi-container setup
├── 📋 requirements.txt            # Python dependencies
└── 📖 README.md                   # Project documentation
```

### Key Scripts Explained

| Script | Purpose | Key Functions |
|--------|---------|---------------|
| `decision_loop.py` | ML scoring engine | `score_row()`, `apply_policies()` |
| `ensemble.py` | Model combination | `predict()`, `predict_batch()` |
| `blocker.py` | Firewall control | `block_ip()`, `validate_ip()` |
| `alerting.py` | Notifications | `send_alert()`, `send_slack_alert()` |
| `auth.py` | API security | `create_token()`, `@require_auth` |
| `explainer.py` | XAI | `explain_row()` |

---

## 7. How It Works

### Real-Time Detection Flow

```
TIME ─────────────────────────────────────────────────────────────────────▸

     t=0s         t=10s         t=20s         t=30s         t=40s
      │            │             │             │             │
      ▼            ▼             ▼             ▼             ▼
   ┌─────┐      ┌─────┐      ┌─────┐      ┌─────┐      ┌─────┐
   │WIN 1│      │WIN 2│      │WIN 3│      │WIN 4│      │WIN 5│
   └──┬──┘      └──┬──┘      └──┬──┘      └──┬──┘      └──┬──┘
      │            │             │             │             │
   Features     Features      Features      Features      Features
      │            │             │             │             │
      ▼            ▼             ▼             ▼             ▼
   Score=0.3    Score=0.4     Score=0.8     Score=0.9     Score=0.7
   benign       benign        ATTACK!       ATTACK!       ATTACK!
                                 │             │             │
                                 │   Grace=2   │             │
                                 │   Hit #1    │   Hit #2    │   Hit #3
                                 │             │             │
                                 │             ▼             │
                                 │      ┌──────────┐        │
                                 │      │  BLOCK   │        │
                                 │      │  1.2.3.4 │        │
                                 │      └──────────┘        │
```

### Adaptive Threshold

```
┌─────────────────────────────────────────────────────────────────┐
│                    ADAPTIVE THRESHOLD                            │
└─────────────────────────────────────────────────────────────────┘

Score
  │
1.0│                                    ╭──╮
   │                                   ╱    ╲   Attack Spike
0.8│ ─ ─ ─ ─ ─ ─ ─┬───────────────────╯────────── Threshold
   │              │         ╭───╮
0.6│              │    ╭───╯   ╰───╮
   │   ╭──╮       │   ╱             ╲
0.4│  ╱    ╲   ╭──┴─╮╱
   │ ╱      ╲ ╱     ╲                   Adaptive threshold
0.2│╯        ╳       ╲                  follows the baseline
   │                                    and raises during attacks
0.0│───────────────────────────────────────────────────▸ Time

The threshold automatically adjusts based on:
  • Recent score history
  • Mean + (sensitivity × standard deviation)
  • Minimum floor (e.g., 0.5)
```

---

## 8. Testing & Validation

### Test Suite

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=scripts --cov-report=html
```

### Test Categories

| Test Type | Files | Coverage |
|-----------|-------|----------|
| Unit Tests | `test_blocker.py` | IP validation, security |
| Unit Tests | `test_ensemble.py` | Model predictions |
| Unit Tests | `test_alerting.py` | Notification system |
| Integration | `test_end_to_end_smoke.py` | Full pipeline |

### Security Tests

```python
# test_blocker.py - Command injection prevention

def test_command_injection_semicolon():
    """Command injection should be rejected"""
    valid, msg = validate_ip("192.168.1.1; rm -rf /")
    assert valid is False
    assert "dangerous" in msg.lower()

def test_loopback_blocked():
    """Cannot block localhost (safety)"""
    valid, msg = validate_ip("127.0.0.1")
    assert valid is False
```

---

## 9. Demo Walkthrough

### Quick Start (3 Terminals)

**Terminal 1: Start Feature Stream**
```bash
python scripts/simulate_stream.py
```

**Terminal 2: Start Decision Loop**
```bash
python scripts/decision_loop.py
```

**Terminal 3: Start Dashboard**
```bash
python scripts/api_dashboard.py
```

**Open Browser:** http://127.0.0.1:5001

### Docker Demo

```bash
# Single command launch
docker-compose up -d

# Open browser
open http://localhost:5001

# Watch logs
docker-compose logs -f iotguard-app
```

### Dashboard Features

```
┌─────────────────────────────────────────────────────────────────┐
│                    IoTGuard Dashboard                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Events    │  │   Attacks   │  │   Blocks    │             │
│  │    1,234    │  │     89      │  │     12      │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    Score Chart                              │ │
│  │  1.0│      ╭──╮                                             │ │
│  │     │     ╱    ╲    ← Score line (blue)                     │ │
│  │  0.7│─ ─ ╯──────── ─ ← Threshold (orange dashed)           │ │
│  │     │                                                       │ │
│  │  0.0│──────────────────────────────────▸                    │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Time   │ Score │ State  │ Reason (XAI)    │ Action        │ │
│  │─────────┼───────┼────────┼─────────────────┼───────────────│ │
│  │ 14:32:01│ 0.92  │ ATTACK │ syn_ratio +0.45 │ BLOCK 🔴      │ │
│  │ 14:31:51│ 0.31  │ benign │ -               │ ALLOW 🟢      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 10. Future Improvements

### Roadmap

| Priority | Feature | Status |
|----------|---------|--------|
| ✅ | Core ML detection | Complete |
| ✅ | Web dashboard | Complete |
| ✅ | Ensemble models | Complete |
| ✅ | Multi-channel alerting | Complete |
| ✅ | Docker deployment | Complete |
| 🔄 | Kubernetes deployment | Planned |
| 🔄 | Model auto-retraining | Planned |
| 🔄 | Grafana integration | Planned |
| 🔄 | Threat feed integration | Planned |

### Potential Enhancements

1. **Deep Learning Models** - LSTM for sequence analysis
2. **Federated Learning** - Privacy-preserving distributed training
3. **Real GeoIP** - MaxMind database integration
4. **SIEM Integration** - Splunk/Elastic compatibility
5. **Mobile App** - iOS/Android monitoring app

---

## Summary

IoTGuard provides a **complete, production-ready IoT security solution**:

✅ **Real-time Detection** - Sub-second ML inference  
✅ **Multi-Model Approach** - Supervised + Unsupervised ensemble  
✅ **Explainable AI** - SHAP-based decision transparency  
✅ **Automatic Response** - IP blocking + notifications  
✅ **Easy Deployment** - Docker + Compose ready  
✅ **Comprehensive Testing** - Unit + integration tests  
✅ **Production Features** - Auth, metrics, logging  

---

**Built with ❤️ for IoT Security**

*IoTGuard v1.0.0*
