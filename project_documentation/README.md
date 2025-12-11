# 📚 IoTGuard Project Documentation

## Overview

This folder contains all project-related documentation for the IoTGuard IoT Intrusion Detection System.

---

## 📁 Contents

| # | File | Description |
|---|------|-------------|
| 1 | [01_PROJECT_PRESENTATION.md](01_PROJECT_PRESENTATION.md) | **Complete Project Presentation** - Full overview of the system including architecture, ML pipeline, features, Docker deployment, and demo instructions |
| 2 | [02_ARCHITECTURE.md](02_ARCHITECTURE.md) | **System Architecture** - High-level pipeline, data flow diagrams, security architecture, and monitoring |
| 3 | [03_CODE_OVERVIEW.md](03_CODE_OVERVIEW.md) | **Code Documentation** - Detailed explanation of every script in the project |
| 4 | [04_DOCKER_GUIDE.md](04_DOCKER_GUIDE.md) | **Docker Deployment Guide** - Commands, environment variables, troubleshooting |
| 5 | [05_EVALUATION_REPORT.txt](05_EVALUATION_REPORT.txt) | **Model Evaluation Results** - Performance metrics, accuracy, confusion matrices |

---

## 🎯 Quick Navigation

### For Presentations
Start with **01_PROJECT_PRESENTATION.md** - it contains everything you need to explain the project.

### For Technical Details
- **02_ARCHITECTURE.md** - System design and data flow
- **03_CODE_OVERVIEW.md** - What each script does

### For Deployment
- **04_DOCKER_GUIDE.md** - How to deploy with Docker

### For Results
- **05_EVALUATION_REPORT.txt** - Model performance metrics

---

## 📊 Project Summary

**IoTGuard** is a lightweight, ML-driven IoT Intrusion Detection System featuring:

- ✅ Real-time network traffic analysis
- ✅ LightGBM + IsolationForest ensemble models
- ✅ 13 engineered network features
- ✅ Automatic IP blocking (Windows/Linux)
- ✅ Web dashboard with real-time visualization
- ✅ Multi-channel alerting (Email/Slack/Telegram)
- ✅ JWT authentication
- ✅ Prometheus metrics
- ✅ Docker deployment ready
- ✅ Comprehensive test suite

---

## 🚀 Quick Start

```bash
# Option 1: Docker (recommended)
docker-compose up -d
open http://localhost:5001

# Option 2: Manual
python scripts/simulate_stream.py  # Terminal 1
python scripts/decision_loop.py    # Terminal 2
python scripts/api_dashboard.py    # Terminal 3
```

---

*IoTGuard v1.0.0*
