#!/usr/bin/env python3
"""
scripts/demo_launcher.py
-----------------------------------------------------------------------------
IoTGuard Utility — Demo Mode Launcher

Purpose
    Provide a convenient entry point for running IoTGuard in demo mode.
    This script simplifies testing and demonstrations by:
    - Setting up the correct environment configuration
    - Starting the API dashboard server
    - Displaying helpful instructions for users

Usage
    python scripts/demo_launcher.py
    
    Then open http://127.0.0.1:5001 in your browser.

What It Does
    1. Sets IOTGUARD_CONFIG environment variable to configs/model.yaml
    2. Launches the api_dashboard.py Flask server as a subprocess
    3. Displays connection instructions and next steps
    4. Handles graceful shutdown on Ctrl+C

Integration with IoTGuard
    This launcher is designed for quick demos. For production deployment,
    use proper process managers (systemd, supervisord) or containerization
    (Docker, Kubernetes) instead of this script.

Related Components
    - scripts/api_dashboard.py: The Flask server this script launches
    - scripts/simulate_stream.py: Use to generate test traffic
    - scripts/decision_loop.py: Runs separately for ML scoring
-----------------------------------------------------------------------------
"""

import subprocess
import sys
import time
import os
from pathlib import Path
from typing import Optional


def print_banner():
    """Display a welcome banner with project information."""
    print("=" * 70)
    print("IoTGuard Demo Launcher".center(70))
    print("=" * 70)
    print()


def print_instructions():
    """Display post-launch instructions for the user."""
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


def main() -> int:
    """
    Main entry point for the demo launcher.
    
    This function:
    1. Determines the project root directory
    2. Configures the environment for demo mode
    3. Launches the dashboard as a subprocess
    4. Monitors the subprocess and handles shutdown
    
    Returns:
        Exit code (0 for success, 1 for error)
        
    Process Flow:
        1. Print welcome banner
        2. Set IOTGUARD_CONFIG environment variable
        3. Launch api_dashboard.py subprocess
        4. Wait for subprocess to start (2 seconds)
        5. Print success message and instructions
        6. Wait for subprocess to complete (blocking)
        7. On Ctrl+C: gracefully terminate subprocess
    """
    # Determine the project root (parent of scripts directory)
    root = Path(__file__).resolve().parent.parent
    
    print_banner()
    
    # ---------- Environment Setup ----------
    # Copy current environment and add IoTGuard-specific config
    env = os.environ.copy()
    env['IOTGUARD_CONFIG'] = 'configs/model.yaml'
    
    # ---------- Display Startup Information ----------
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
    
    # ---------- Build Dashboard Command ----------
    # Use the same Python interpreter that's running this script
    dashboard_cmd = [sys.executable, "scripts/api_dashboard.py"]
    
    # Variable to hold subprocess reference for cleanup
    dashboard_proc: Optional[subprocess.Popen] = None
    
    try:
        print("Launching dashboard (press Ctrl+C to stop)...")
        print()
        
        # ---------- Launch Dashboard Subprocess ----------
        # Popen starts the process asynchronously, allowing us to monitor it
        dashboard_proc = subprocess.Popen(
            dashboard_cmd, 
            cwd=root,      # Run from project root
            env=env        # Use configured environment
        )
        
        # Give Flask a moment to start up
        # This ensures the server is ready by the time we print instructions
        time.sleep(2)
        
        print("\n✓ Dashboard started!")
        print_instructions()
        
        # ---------- Wait for Process ----------
        # Block until the dashboard process exits
        # (Either from an error or external signal)
        dashboard_proc.wait()
        
    except KeyboardInterrupt:
        # ---------- Graceful Shutdown ----------
        # User pressed Ctrl+C - clean up the subprocess
        print("\n\nStopping IoTGuard...")
        
        if dashboard_proc is not None:
            # Send SIGTERM to allow graceful shutdown
            dashboard_proc.terminate()
            # Wait for process to actually exit
            dashboard_proc.wait()
        
        print("✓ Stopped cleanly")
        
    except Exception as e:
        # ---------- Error Handling ----------
        print(f"\nError: {e}")
        
        # Clean up subprocess if it was started
        if dashboard_proc is not None:
            dashboard_proc.terminate()
        
        return 1  # Non-zero exit code indicates error
    
    return 0  # Success


if __name__ == "__main__":
    sys.exit(main())
