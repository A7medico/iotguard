"""
IoTGuard End-to-End Environment Simulation & Stress Benchmark
=============================================================================
Simulates realistic IoT enterprise traffic with diverse device profiles,
background benign telemetry, and injected multi-stage cyber attacks.
Measures latency, accuracy, XAI generation, and mitigation actions.
=============================================================================
"""

import time
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
import sys

# Ensure scripts directory is on path
_scripts_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(_scripts_dir))
from path_setup import configure_paths
configure_paths()

from explainer import RealTimeExplainer
from decision_loop import classify_attack_heuristic, compute_adaptive_threshold

def run_environment_simulation():
    # 1. Load Models & Metadata
    iot_model_path = Path("models/lightgbm.joblib")
    it_model_path = Path("models/lightgbm_it.joblib")
    unsup_model_path = Path("models/unsup_isoforest.joblib")
    meta_path = Path("models/model_meta.json")
    
    if not iot_model_path.exists() or not meta_path.exists():
        print("[ERROR] Model or metadata file missing.")
        return
        
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    iot_model = joblib.load(iot_model_path)
    it_model = joblib.load(it_model_path) if it_model_path.exists() else iot_model
    unsup_model = joblib.load(unsup_model_path) if unsup_model_path.exists() else None
    
    features = meta.get("features")
    explainer = RealTimeExplainer(iot_model, features)
    
    # 2. Define Network Topology
    DEVICES = {
        "192.168.10.101": {"name": "Smart Thermostat", "type": "IoT", "subnet": "IoT-VLAN"},
        "192.168.10.102": {"name": "Security Camera #1", "type": "IoT", "subnet": "IoT-VLAN"},
        "192.168.10.103": {"name": "Security Camera #2", "type": "IoT", "subnet": "IoT-VLAN"},
        "192.168.10.104": {"name": "Smart Door Lock", "type": "IoT", "subnet": "IoT-VLAN"},
        "192.168.20.15":  {"name": "Admin Workstation", "type": "IT",  "subnet": "Corp-LAN"},
        "192.168.20.25":  {"name": "Database Server",   "type": "IT",  "subnet": "Corp-LAN"},
        "192.168.10.199": {"name": "Compromised Gateway", "type": "IoT", "subnet": "IoT-VLAN"},
        "10.0.0.88":      {"name": "External Attacker",  "type": "WAN", "subnet": "Internet"},
    }
    
    # 3. Traffic Generators per Profile
    def generate_flow(device_ip, mode):
        if mode == "benign_periodic":
            # Low throughput IoT heartbeat (Thermostats, Smart Locks)
            flows = np.random.randint(2, 6)
            pkts = flows * np.random.randint(3, 8)
            bytes_total = pkts * np.random.randint(50, 90)
            syn_ratio = np.random.uniform(0.05, 0.15)
            mean_bytes = bytes_total / flows
            ack_ratio = np.random.uniform(0.40, 0.60)
            fin_ratio = np.random.uniform(0.10, 0.20)
            rst_ratio = 0.0
            http_ratio = np.random.uniform(0.10, 0.40)
            tcp_ratio = 1.0
            proto_div = 1
            std_bytes = np.random.uniform(10, 30)
            iat_mean = np.random.uniform(0.15, 0.45)
            is_attack = False
            
        elif mode == "benign_video":
            # Continuous streaming video (IP Cameras)
            flows = np.random.randint(8, 20)
            pkts = flows * np.random.randint(40, 100)
            bytes_total = pkts * np.random.randint(600, 1200)
            syn_ratio = np.random.uniform(0.02, 0.06)
            mean_bytes = bytes_total / flows
            ack_ratio = np.random.uniform(0.48, 0.55)
            fin_ratio = np.random.uniform(0.01, 0.04)
            rst_ratio = 0.0
            http_ratio = 0.0
            tcp_ratio = np.random.uniform(0.75, 0.95)
            proto_div = 2
            std_bytes = np.random.uniform(80, 200)
            iat_mean = np.random.uniform(0.005, 0.02)
            is_attack = False

        elif mode == "benign_corp":
            # Corporate LAN interactive traffic (Browsing, DB queries)
            flows = np.random.randint(15, 35)
            pkts = flows * np.random.randint(10, 25)
            bytes_total = pkts * np.random.randint(150, 450)
            syn_ratio = np.random.uniform(0.10, 0.20)
            mean_bytes = bytes_total / flows
            ack_ratio = np.random.uniform(0.38, 0.48)
            fin_ratio = np.random.uniform(0.08, 0.16)
            rst_ratio = np.random.uniform(0.01, 0.03)
            http_ratio = np.random.uniform(0.30, 0.60)
            tcp_ratio = np.random.uniform(0.90, 0.98)
            proto_div = 3
            std_bytes = np.random.uniform(40, 120)
            iat_mean = np.random.uniform(0.02, 0.08)
            is_attack = False

        elif mode == "attack_syn_flood":
            # Volumetric SYN flood DoS
            flows = np.random.randint(80, 160)
            pkts = flows * np.random.randint(3, 6)
            bytes_total = pkts * 60
            syn_ratio = np.random.uniform(0.88, 0.99)
            mean_bytes = bytes_total / flows
            ack_ratio = 0.0
            fin_ratio = 0.0
            rst_ratio = 0.0
            http_ratio = 0.0
            tcp_ratio = 1.0
            proto_div = 1
            std_bytes = np.random.uniform(0, 3)
            iat_mean = np.random.uniform(0.0001, 0.0008)
            is_attack = True

        elif mode == "attack_mirai_udp":
            # Mirai IoT Botnet UDP Flood
            flows = np.random.randint(100, 250)
            pkts = flows * np.random.randint(15, 40)
            bytes_total = pkts * np.random.randint(400, 750)
            syn_ratio = 0.0
            mean_bytes = bytes_total / flows
            ack_ratio = 0.0
            fin_ratio = 0.0
            rst_ratio = 0.0
            http_ratio = 0.0
            tcp_ratio = 0.0
            proto_div = 1
            std_bytes = np.random.uniform(0, 5)
            iat_mean = np.random.uniform(0.00005, 0.0004)
            is_attack = True

        elif mode == "attack_portscan":
            # Rapid Reconnaissance Port Scan
            flows = np.random.randint(60, 140)
            pkts = flows * 2
            bytes_total = pkts * 44
            syn_ratio = np.random.uniform(0.80, 0.98)
            mean_bytes = bytes_total / flows
            ack_ratio = 0.0
            fin_ratio = 0.0
            rst_ratio = np.random.uniform(0.25, 0.55)
            http_ratio = 0.0
            tcp_ratio = 1.0
            proto_div = 1
            std_bytes = np.random.uniform(0, 2)
            iat_mean = np.random.uniform(0.001, 0.008)
            is_attack = True

        elif mode == "attack_http_exploit":
            # Layer-7 Web Exploit / Brute Force
            flows = np.random.randint(40, 80)
            pkts = flows * np.random.randint(12, 30)
            bytes_total = pkts * np.random.randint(250, 500)
            syn_ratio = np.random.uniform(0.20, 0.35)
            mean_bytes = bytes_total / flows
            ack_ratio = np.random.uniform(0.40, 0.50)
            fin_ratio = np.random.uniform(0.15, 0.30)
            rst_ratio = np.random.uniform(0.02, 0.06)
            http_ratio = np.random.uniform(0.85, 1.0)
            tcp_ratio = 1.0
            proto_div = 1
            std_bytes = np.random.uniform(30, 80)
            iat_mean = np.random.uniform(0.001, 0.006)
            is_attack = True

        vec = [flows, bytes_total, pkts, syn_ratio, mean_bytes, ack_ratio,
               fin_ratio, rst_ratio, http_ratio, tcp_ratio, proto_div,
               std_bytes, iat_mean]
        return np.array(vec, dtype=np.float32), is_attack

    # 4. Create 50 Sequential Scenario Windows
    scenarios = [
        # Normal operations baseline (T=0s to T=70s)
        ("192.168.10.101", "benign_periodic"),
        ("192.168.10.102", "benign_video"),
        ("192.168.10.103", "benign_video"),
        ("192.168.10.104", "benign_periodic"),
        ("192.168.20.15",  "benign_corp"),
        ("192.168.20.25",  "benign_corp"),
        ("192.168.10.102", "benign_video"),

        # Attack Stage 1: Port Scan from External Attacker (T=80s to T=100s)
        ("10.0.0.88", "attack_portscan"),
        ("10.0.0.88", "attack_portscan"),
        ("10.0.0.88", "attack_portscan"),

        # Interleaved normal traffic
        ("192.168.10.101", "benign_periodic"),
        ("192.168.20.15",  "benign_corp"),

        # Attack Stage 2: Volumetric SYN Flood against DB Server (T=130s to T=160s)
        ("10.0.0.88", "attack_syn_flood"),
        ("10.0.0.88", "attack_syn_flood"),
        ("10.0.0.88", "attack_syn_flood"),
        ("10.0.0.88", "attack_syn_flood"),

        # Normal traffic
        ("192.168.10.103", "benign_video"),
        ("192.168.10.104", "benign_periodic"),

        # Attack Stage 3: Compromised IoT Gateway launching Mirai UDP flood (T=190s to T=220s)
        ("192.168.10.199", "attack_mirai_udp"),
        ("192.168.10.199", "attack_mirai_udp"),
        ("192.168.10.199", "attack_mirai_udp"),

        # Normal traffic
        ("192.168.20.25",  "benign_corp"),
        ("192.168.10.101", "benign_periodic"),

        # Attack Stage 4: HTTP Layer-7 Application Brute Force (T=250s to T=280s)
        ("10.0.0.88", "attack_http_exploit"),
        ("10.0.0.88", "attack_http_exploit"),
        ("10.0.0.88", "attack_http_exploit"),

        # Post-mitigation recovery baseline (T=290s to T=340s)
        ("192.168.10.101", "benign_periodic"),
        ("192.168.10.102", "benign_video"),
        ("192.168.10.103", "benign_video"),
        ("192.168.20.15",  "benign_corp"),
        ("192.168.10.104", "benign_periodic"),
    ]

    print("=" * 80)
    print("  [+] STARTING LIVE IOT ENVIRONMENT STRESS TEST (31 Time Windows)")
    print("=" * 80)
    print(f"{'Time':<7} | {'Source Device':<28} | {'Scenario':<20} | {'Score':<7} | {'Action':<11} | {'Latency':<7}")
    print("-" * 80)

    # 5. Execute Simulation Pipeline
    latencies = []
    y_true = []
    y_pred = []
    incident_log = []
    
    recent_hits = {}
    score_history = []
    
    for i, (ip, scenario) in enumerate(scenarios):
        vec, is_attack_truth = generate_flow(ip, scenario)
        row_df = pd.DataFrame([vec], columns=features)
        dev_info = DEVICES.get(ip, {"name": ip, "type": "IoT"})
        
        # Route to appropriate model (IoT vs IT device profile)
        active_model = it_model if dev_info["type"] == "IT" else iot_model
        
        # Measure inference latency
        t0 = time.perf_counter()
        score = float(active_model.predict_proba(row_df)[0][1])
        t1 = time.perf_counter()
        
        latency_ms = (t1 - t0) * 1000
        latencies.append(latency_ms)
        score_history.append(score)
        
        # Adaptive Thresholding calculation
        dynamic_thr = compute_adaptive_threshold(
            score_history, base_threshold=0.75, sensitivity=2.0, min_threshold=0.50
        )
        
        # Decision Policy Logic
        is_attack_pred = score >= dynamic_thr
        y_true.append(1 if is_attack_truth else 0)
        y_pred.append(1 if is_attack_pred else 0)
        
        # Action Determination (Blocker policy)
        hits = recent_hits.get(ip, 0)
        if score >= 0.95:
            action = "BLOCK-KILL"
            recent_hits[ip] = hits + 1
        elif score >= dynamic_thr:
            hits += 1
            recent_hits[ip] = hits
            if hits >= 2:
                action = "BLOCK-HARD"
            else:
                action = "ALERT-SOFT"
        else:
            recent_hits[ip] = max(0, hits - 1)
            action = "ALLOW"
        dev_label = f"{ip} ({dev_info['name'][:10]})"
        
        # Format output row
        print(f"T+{i*10:03d}s  | {dev_label:<28} | {scenario:<20} | {score:5.1%} | {action:<11} | {latency_ms:5.2f}ms")
        
        # Capture XAI on security events
        if is_attack_pred:
            shap_reason = explainer.explain_row(row_df, top_n=2)
            threat_type = classify_attack_heuristic(row_df.iloc[0])
            incident_log.append({
                "time": f"T+{i*10:03d}s",
                "ip": ip,
                "device": dev_info["name"],
                "attack": scenario,
                "threat_cat": threat_type,
                "score": score,
                "action": action,
                "shap": shap_reason
            })
            
    print("-" * 80)
    
    # 6. Summary Metrics
    lat = np.array(latencies)
    y_t = np.array(y_true)
    y_p = np.array(y_pred)
    
    tp = np.sum((y_t == 1) & (y_p == 1))
    fp = np.sum((y_t == 0) & (y_p == 1))
    fn = np.sum((y_t == 1) & (y_p == 0))
    tn = np.sum((y_t == 0) & (y_p == 0))
    
    prec = tp / (tp + fp + 1e-9)
    rec = tp / (tp + fn + 1e-9)
    f1 = 2 * (prec * rec) / (prec + rec + 1e-9)
    
    print("\n" + "=" * 80)
    print("  [+] SIMULATION SUMMARY & OPERATIONAL METRICS")
    print("=" * 80)
    print(f"  • Total Evaluated Windows:     {len(scenarios)}")
    print(f"  • Benign Windows (Legitimate):  {np.sum(y_t == 0)} evaluated  -->  {tn} Passed ({tn/np.sum(y_t == 0)*100:.1f}%)")
    print(f"  • Attack Windows (Malicious):   {np.sum(y_t == 1)} injected   -->  {tp} Detected ({tp/np.sum(y_t == 1)*100:.1f}%)")
    print(f"  • False Alarms (False Pos):    {fp} ({fp/np.sum(y_t == 0)*100:.1f}%)")
    print(f"  • Missed Attacks (False Neg):   {fn} ({fn/np.sum(y_t == 1)*100:.1f}%)")
    print(f"  • Precision / Recall / F1:     {prec*100:.1f}% / {rec*100:.1f}% / {f1:.4f}")
    print()
    print("  [+] INFERENCE & DECISION LATENCY")
    print(f"  • Median (P50) Latency:        {np.median(lat):.2f} ms")
    print(f"  • 95th Percentile (P95):       {np.percentile(lat, 95):.2f} ms")
    print(f"  • 99th Percentile (P99):       {np.percentile(lat, 99):.2f} ms")
    print(f"  • Peak Latency:                {np.max(lat):.2f} ms")

    print("\n" + "=" * 80)
    print("  [+] DETECTED SECURITY INCIDENTS & SHAP XAI AUDIT TRAIL")
    print("=" * 80)
    for inc in incident_log:
        print(f"  [{inc['time']}] {inc['ip']} ({inc['device']})")
        print(f"      Category:   {inc['threat_cat']} (Scenario: {inc['attack']})")
        print(f"      Threat:     Score {inc['score']:.1%}  -->  Enforcement: {inc['action']}")
        print(f"      SHAP XAI:   {inc['shap']}")
        print()

if __name__ == "__main__":
    run_environment_simulation()
