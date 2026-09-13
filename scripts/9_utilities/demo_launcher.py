#!/usr/bin/env python3
"""
scripts/demo_launcher.py
-----------------------------------------------------------------------------
IoTGuard Utility - Demo Mode Launcher

Purpose
    Provide a convenient entry point for running IoTGuard in demo mode.
    This script simplifies testing and demonstrations by:
    - Setting up the correct environment configuration
    - Starting all three pipeline components automatically:
        1. simulate_stream.py (feature generator)
        2. decision_loop.py (ML scoring engine)
        3. api_dashboard.py (web dashboard)
    - Auto-opening the dashboard in the default browser
    - Displaying helpful instructions for users

Usage
    python scripts/demo_launcher.py
    
    Then open http://127.0.0.1:5001/dashboard in your browser (auto-opened).

What It Does
    1. Sets IOTGUARD_CONFIG environment variable to configs/model.yaml
    2. Ensures data directory and features.csv exist
    3. Launches simulate_stream.py as a background subprocess
    4. Launches decision_loop.py as a background subprocess
    5. Launches api_dashboard.py as the main subprocess
    6. Auto-opens the dashboard in the default browser
    7. Handles graceful shutdown of all components on Ctrl+C

Integration with IoTGuard
    This launcher is designed for quick demos. For production deployment,
    use proper process managers (systemd, supervisord) or containerization
    (Docker, Kubernetes) instead of this script.

Related Components
    - scripts/api_dashboard.py: The Flask server this script launches
    - scripts/simulate_stream.py: Generates synthetic feature stream
    - scripts/decision_loop.py: ML scoring and enforcement engine
-----------------------------------------------------------------------------
"""

import subprocess
import sys
import time
import os
import webbrowser
import signal
from pathlib import Path
from typing import Optional, List


def print_banner():
    """Display a welcome banner with project information."""
    print()
    print("=" * 70)
    print()
    print("    ___ ____ _____ ____                     _")
    print("   |_ _/ __ |_   _/ ___|_   _  __ _ _ __ __| |")
    print("    | | |  | || || |  _| | | |/ _` | '__/ _` |")
    print("    | | |__| || || |_| | |_| | (_| | | | (_| |")
    print("   |___\\____/ |_| \\____|\\__,_|\\__,_|_|  \\__,_|")
    print()
    print("   ML-Driven IoT Intrusion Detection System".center(70))
    print("   Cybersecurity Command Center - Demo Mode".center(70))
    print()
    print("=" * 70)
    print()


def print_instructions():
    """Display post-launch instructions for the user."""
    print()
    print("-" * 70)
    print()
    print("  [*] Dashboard:     http://127.0.0.1:5001/dashboard")
    print("  [*] API Health:    http://127.0.0.1:5001/health")
    print("  [*] Export CSV:    http://127.0.0.1:5001/api/download.csv")
    print()
    print("  Components running:")
    print("    [OK] Feature Stream  (simulate_stream.py)")
    print("    [OK] Decision Loop   (decision_loop.py)")
    print("    [OK] Web Dashboard   (api_dashboard.py)")
    print()
    print("  Use the Attack Lab in the dashboard to simulate attacks!")
    print()
    print("  Press Ctrl+C to stop all components")
    print()
    print("-" * 70)
    print()


def ensure_data_dir(root: Path):
    """Ensure the data directory exists with a features.csv header."""
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    
    features_csv = data_dir / "features.csv"
    header = "flows,bytes_total,pkts_total,syn_ratio,mean_bytes_flow,ack_ratio,fin_ratio,rst_ratio,http_ratio,tcp_ratio,protocol_diversity,std_bytes,iat_mean\n"
    
    if not features_csv.exists() or features_csv.stat().st_size == 0:
        features_csv.write_text(header, encoding="utf-8")
        print("  [*] Created data/features.csv with header")


def main() -> int:
    """
    Main entry point for the demo launcher.
    
    Starts all three pipeline components and opens the dashboard in a browser.
    
    Returns:
        Exit code (0 for success, 1 for error)
    """
    # Determine the project root (parent of scripts directory)
    root = Path(__file__).resolve().parent.parent.parent
    
    print_banner()
    
    # ---------- Environment Setup ----------
    env = os.environ.copy()
    env['IOTGUARD_CONFIG'] = 'configs/model.yaml'
    env['PYTHONIOENCODING'] = 'utf-8'
    
    # ---------- Ensure Data Directory ----------
    ensure_data_dir(root)
    
    # ---------- Component Processes ----------
    processes: List[tuple] = []  # (name, Popen)
    
    try:
        # 1. Start Feature Stream (simulate_stream.py)
        print("  [*] Starting Feature Stream...")
        stream_script = str(root / "scripts" / "1_data_input" / "simulate_stream.py")
        stream_proc = subprocess.Popen(
            [sys.executable, stream_script],
            cwd=root,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        processes.append(("Feature Stream", stream_proc))
        print("  [OK] Feature Stream started (PID: {})".format(stream_proc.pid))
        
        # 2. Start Decision Loop (decision_loop.py)
        print("  [*] Starting Decision Loop...")
        decision_script = str(root / "scripts" / "3_inference" / "decision_loop.py")
        decision_proc = subprocess.Popen(
            [sys.executable, decision_script],
            cwd=root,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        processes.append(("Decision Loop", decision_proc))
        print("  [OK] Decision Loop started (PID: {})".format(decision_proc.pid))
        
        # Give the ML model a moment to load
        time.sleep(2)
        
        # 3. Start Dashboard (api_dashboard.py) - this is the main process
        print("  [*] Starting Web Dashboard...")
        dashboard_script = str(root / "scripts" / "5_dashboard" / "api_dashboard.py")
        dashboard_proc = subprocess.Popen(
            [sys.executable, dashboard_script],
            cwd=root,
            env=env,
        )
        processes.append(("Web Dashboard", dashboard_proc))
        print("  [OK] Web Dashboard started (PID: {})".format(dashboard_proc.pid))
        
        # Wait for Flask to start
        time.sleep(2)
        
        # 4. Auto-open dashboard in browser
        dashboard_url = "http://127.0.0.1:5001/dashboard"
        try:
            webbrowser.open(dashboard_url)
            print("  [*] Opened dashboard in browser")
        except Exception:
            print("  [*] Please open manually: {}".format(dashboard_url))
        
        print_instructions()
        
        # ---------- Wait for Dashboard ----------
        # Block until the dashboard process exits
        dashboard_proc.wait()
        
    except KeyboardInterrupt:
        # ---------- Graceful Shutdown ----------
        print("\n\n  [*] Stopping all IoTGuard components...\n")
        
        for name, proc in reversed(processes):
            try:
                proc.terminate()
                proc.wait(timeout=5)
                print(f"  [-] {name} stopped")
            except Exception:
                proc.kill()
                print(f"  [-] {name} killed")
        
        print("\n  [OK] IoTGuard stopped cleanly\n")
        
    except Exception as e:
        print(f"\n  [ERR] Error: {e}\n")
        
        for name, proc in processes:
            try:
                proc.terminate()
            except Exception:
                pass
        
        return 1
    finally:
        # Ensure all subprocesses are cleaned up
        for name, proc in processes:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
