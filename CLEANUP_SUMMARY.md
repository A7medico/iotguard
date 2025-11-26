# IoTGuard Cleanup Summary

## Scripts Removed (16 total)

### Outdated/Redundant Evaluation Scripts
- `evaluate_model.py` - Referenced wrong training data (v3)
- `evaluate_and_save.py` - Redundant with `evaluate_on_csv.py`

### Redundant Inference/Scoring Scripts
- `infer_realtime.py` - Redundant with `decision_loop.py`
- `score_csv_tail.py` - Redundant with `decision_loop.py`

### Training Data Builders (Redundant)
- `ingest_and_build.py` - Created v3 training (wrong schema)
- `build_dataset_from_alerts.py`
- `build_split.py`
- `ingest_split.py`
- `merge_labeled_features.py`
- `merge_multiclass.py`
- `rebuild_training_csv.py`
- `add_label.py`

### One-Time Utilities (Already Used)
- `cleanup_and_fix.py` - One-time cleanup script
- `fix_csv.py` - One-time utility
- `eve_to_features_once.py` - One-time conversion

### Empty/Placeholder
- `ip_sidecar.py` - Empty placeholder file

## Core Scripts Kept (18 total)

### Production Pipeline
- `decision_loop.py` - Main production loop (scores traffic, blocks IPs)
- `api_dashboard.py` - Web dashboard and REST API
- `api_status.py` - Simple status endpoint
- `console_dashboard.py` - Terminal dashboard (Rich)
- `suricata_to_features.py` - Feature extraction from Suricata
- `blocker.py` - IP blocking functionality
- `block_ip.ps1` - Windows blocking hook
- `block_ip.sh` - Linux blocking hook
- `unblock.py` - Unblock IPs

### Model Management
- `train_supervised.py` - Train LightGBM model
- `test_model_detection.py` - Test model on datasets
- `evaluate_on_csv.py` - Evaluate model on CSV

### Data Processing
- `convert_ciciot2023.py` - Convert CICIoT2023 datasets
- `feature_extractor.py` - Feature extraction utility
- `utils_common.py` - Common utilities

### Testing/Simulation
- `simulate_stream.py` - Simulate traffic stream
- `stream_csvs.py` - Stream CSV data
- `replay_eve.py` - Replay Suricata events

## Current Project Structure

```
iotguard/
├── configs/
│   ├── model.yaml          # Configuration
│   └── README.md
├── data/
│   ├── ciciot_ddos_http.csv      # Attack dataset
│   ├── ciciot_benign.csv         # Benign dataset
│   ├── ddos_sim.csv              # Attack simulation
│   ├── benign_sim.csv            # Benign simulation
│   ├── DDoS-HTTP_Flood-.pcap.csv # Additional attack data
│   ├── BenignTraffic.pcap.csv    # Additional benign data
│   ├── features.csv              # Live feature stream
│   ├── iotguard_training.csv     # Training data (391K rows)
│   ├── iotguard_training_v2.csv  # Alternative training data
│   ├── alerts.jsonl              # Decision loop alerts
│   └── suricata/                 # Suricata logs
├── models/
│   ├── lightgbm.joblib           # Trained model
│   ├── model_meta.json           # Model metadata
│   └── classes.json              # Class definitions
├── scripts/
│   ├── [18 core scripts listed above]
│   └── __init__.py
└── logs/
    └── audit.jsonl               # Audit log
```

## What Was Accomplished

1. ✅ Removed 16 redundant/outdated scripts
2. ✅ Kept 18 essential core scripts
3. ✅ Cleaned up unnecessary training data builders
4. ✅ Removed one-time utility scripts
5. ✅ Project is now streamlined and focused

## Next Steps

The project is now clean and ready for:
1. Running the production pipeline (`decision_loop.py`)
2. Training new models (`train_supervised.py`)
3. Testing detection (`test_model_detection.py`)
4. Monitoring via dashboard (`api_dashboard.py`)



