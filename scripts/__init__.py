"""
scripts/__init__.py
-----------------------------------------------------------------------------
IoTGuard Scripts Package

This package contains all operational scripts for the IoTGuard IoT Intrusion
Detection System. Scripts are organized by function:

Core Pipeline Components
------------------------
- decision_loop.py     : Main ML scoring engine (supervised + unsupervised)
- api_dashboard.py     : Flask REST API and web dashboard
- suricata_to_features.py : Suricata eve.json → feature extraction
- feature_extractor.py : Simplified feature extraction for demos

Training & Evaluation
---------------------
- train_supervised.py  : LightGBM binary classifier training
- train_unsupervised.py : IsolationForest anomaly detection training
- test_holdout.py      : Holdout set evaluation
- test_all_models.py   : Comprehensive model comparison

Supporting Utilities
--------------------
- blocker.py           : Cross-platform IP blocking (Windows/Linux)
- explainer.py         : SHAP-based model explainability
- threat_intel.py      : Threat intelligence enrichment (demo)
- logging_config.py    : Centralized logging configuration
- utils_common.py      : Shared utility functions

Demo & Simulation
-----------------
- demo_launcher.py     : Demo mode launcher
- simulate_stream.py   : Traffic simulation for testing
- stream_csvs.py       : Replay CSV data as streaming input

Data Processing
---------------
- convert_pcap_datasets.py : PCAP → CSV conversion
- create_train_test_split.py : Dataset splitting utilities

Usage
-----
Scripts can be run directly from the project root:
    python scripts/decision_loop.py
    python scripts/api_dashboard.py
    
Or imported as modules:
    from scripts.blocker import block_ip
    from scripts.explainer import RealTimeExplainer
-----------------------------------------------------------------------------
"""

# Version info for the scripts package
__version__ = "2.0.0"
__author__ = "IoTGuard Team"
