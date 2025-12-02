#!/usr/bin/env python3
"""
Demo launcher - Runs IoTGuard in demo mode with simulated traffic
This is a simplified version perfect for testing and demonstration
"""
import subprocess
import sys
import time
import os
from pathlib import Path

def main():
    root = Path(__file__).resolve().parent.parent
    
    print("=" * 70)
    print("IoTGuard Demo Launcher".center(70))
    print("=" * 70)
    print()
    
    # Set environment for demo mode
    env = os.environ.copy()
    env['IOTGUARD_CONFIG'] = 'configs/model.yaml'
    
    print("Starting IoTGuard Dashboard...")
    print("  URL: http://127.0.0.1:5001")
    print("  Mode: Demo (using existing data)")
    print()
    print("The dashboard will show:")
    print("  - Real-time detection metrics")
    print("  - Alert history")
    print("  - Configuration controls")
    print("  - Performance statistics")
    print()
    print("-" * 70)
    print()
    
    # Start the dashboard
    dashboard_cmd = [sys.executable, "scripts/api_dashboard.py"]
    
    try:
        print("Launching dashboard (press Ctrl+C to stop)...")
        print()
        dashboard_proc = subprocess.Popen(
            dashboard_cmd, 
            cwd=root,
            env=env
        )
        
        # Give it a moment to start
        time.sleep(2)
        
        print("\n✓ Dashboard started!")
        print("\n" + "=" * 70)
        print("NEXT STEPS:")
        print("=" * 70)
        print("1. Open your browser to: http://127.0.0.1:5001")
        print("2. The dashboard is now running")
        print("3. To send test traffic, open another terminal and run:")
        print("   python scripts/simulate_stream.py")
        print()
        print("Press Ctrl+C here to stop the dashboard")
        print("=" * 70)
        
        # Wait for the dashboard process
        dashboard_proc.wait()
        
    except KeyboardInterrupt:
        print("\n\nStopping IoTGuard...")
        if 'dashboard_proc' in locals():
            dashboard_proc.terminate()
            dashboard_proc.wait()
        print("✓ Stopped cleanly")
    except Exception as e:
        print(f"\nError: {e}")
        if 'dashboard_proc' in locals():
            dashboard_proc.terminate()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
