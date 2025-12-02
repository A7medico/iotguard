"""
scripts/run_all.py
-----------------------------------------------------------------------------
Convenience launcher to bring up the core IoTGuard pipeline with one command:

    python scripts/run_all.py

It starts, in the project root:
  - suricata_to_features.py
  - decision_loop.py
  - api_dashboard.py

Assumes you already activated the virtualenv (so sys.executable is the venv
Python) and that Suricata is configured to write eve.json into data/suricata/.
-----------------------------------------------------------------------------
"""

import subprocess
import sys
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    cmds = [
        [sys.executable, "scripts/suricata_to_features.py"],
        [sys.executable, "scripts/decision_loop.py"],
        [sys.executable, "scripts/api_dashboard.py"],
    ]

    procs = []
    for cmd in cmds:
        print(f"[*] Starting: {' '.join(cmd)}")
        procs.append(
            subprocess.Popen(cmd, cwd=root)
        )

    print("\nAll core services started.")
    print("  - Features:   scripts/suricata_to_features.py")
    print("  - Decision:   scripts/decision_loop.py")
    print("  - Dashboard:  scripts/api_dashboard.py  (http://127.0.0.1:5001/)")
    print("\nUse Ctrl+C in each service’s terminal to stop them cleanly.")


if __name__ == "__main__":
    main()


