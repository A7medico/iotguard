"""
app.py - IoTGuard Application Entrypoint
Exposes the Flask 'app' instance for Vercel, WSGI servers, and local execution.
"""
import sys
from pathlib import Path

# Add scripts directory and its subdirectories to sys.path
_scripts_dir = Path(__file__).resolve().parent / "scripts"
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

from path_setup import configure_paths
configure_paths()

import importlib
_dashboard = importlib.import_module("scripts.5_dashboard.api_dashboard")
app = _dashboard.app

if __name__ == "__main__":
    import os
    host = os.environ.get("IOTGUARD_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT") or os.environ.get("IOTGUARD_PORT") or "5001")
    app.run(host=host, port=port, debug=False)

