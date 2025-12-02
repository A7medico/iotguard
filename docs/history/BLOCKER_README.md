# IoTGuard - Robust Attack Blocker

IoTGuard is a Machine Learning-based Intrusion Detection System (IDS) for IoT networks.
It uses a rigorous pipeline to detect and block malicious traffic in real-time.

## 1. Model Architecture
- **Algorithm:** LightGBM (Gradient Boosting Decision Trees)
- **Training Data:** 1.55 Million unique flows (deduplicated from 4M+ raw samples).
- **Features (13 Core):**
  - `flows`, `bytes_total`, `pkts_total`, `mean_bytes_flow`, `std_bytes`, `iat_mean`
  - `syn_ratio`, `ack_ratio`, `fin_ratio`, `rst_ratio`
  - `tcp_ratio`, `http_ratio`, `protocol_diversity`
- **Threshold:** 0.75 (Tuned for <2% False Positive Rate on Real Benign Traffic).

## 2. Performance
The model was verified on a strict **Holdout Test Set** (files never seen during training):

| Traffic Type | Detection Rate | False Positives |
| :--- | :--- | :--- |
| **DDoS Flood (SYN/ACK/UDP)** | **100%** | - |
| **Mirai Botnet** | **100%** | - |
| **Benign (Simulated)** | - | **0.8%** |
| **Benign (Real PCAP)** | - | **2.1%** |

## 3. Pipeline Components
1.  **`suricata_to_features.py`**: Real-time feature extractor. Tails `eve.json` and computes rolling window statistics (10s windows).
2.  **`decision_loop.py`**: Loads the model (`models/lightgbm.joblib`), scores features, and triggers blocking if Score > 0.75.
3.  **`blocker.py`**: Executes firewall rules (Windows Firewall / iptables) to block malicious IPs.
4.  **`api_dashboard.py`**: Visualizes alerts and provides manual controls.

## 4. How to Run
1.  **Start Suricata** (monitoring the network interface).
2.  **Start the Pipeline:**
    ```bash
    # Terminal 1: Feature Extractor
    python scripts/suricata_to_features.py

    # Terminal 2: Decision Loop
    python scripts/decision_loop.py

    # Terminal 3: Dashboard
    python scripts/api_dashboard.py
    ```
3.  **Simulate Traffic (Optional):**
    ```bash
    python scripts/simulate_stream.py --type ddos
    ```

## 5. Maintenance
- **Retraining:** If new attacks appear, add PCAPs to `data/` and run:
  1. `python scripts/convert_pcap_datasets.py`
  2. `python scripts/create_train_test_split.py`
  3. `python scripts/train_supervised.py --csv data/iotguard_training_clean.csv`


