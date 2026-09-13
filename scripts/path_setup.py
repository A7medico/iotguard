"""
scripts/path_setup.py
-----------------------------------------------------------------------------
IoTGuard - Centralized Path Configuration

Purpose
    Provide a single, shared function for setting up Python import paths
    across all IoTGuard entry-point scripts.  Instead of each script
    manually inserting 4-6 paths into sys.path, they can call:

        from path_setup import configure_paths
        configure_paths()

    This eliminates duplication and ensures consistent import resolution.

Usage
    # At the top of any entry-point script (before local imports):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from path_setup import configure_paths
    configure_paths()
-----------------------------------------------------------------------------
"""

import sys
from pathlib import Path

# The scripts directory is the parent of all numbered subdirectories.
_SCRIPTS_DIR = Path(__file__).resolve().parent

# Subdirectories that contain importable modules.
_SUBDIRS = [
    "1_data_input",
    "2_training",
    "3_inference",
    "4_response",
    "5_dashboard",
    "6_threat_intel",
    "7_testing",
    "8_simulation",
    "9_utilities",
    "10_analysis",
]

_configured = False


def configure_paths() -> None:
    """Add the scripts directory and its subdirectories to sys.path.

    This is idempotent — calling it multiple times has no effect after the
    first invocation.
    """
    global _configured
    if _configured:
        return

    paths_to_add = [str(_SCRIPTS_DIR)]
    for sub in _SUBDIRS:
        p = _SCRIPTS_DIR / sub
        if p.is_dir():
            paths_to_add.append(str(p))

    # Prepend in reverse so the order is preserved (scripts dir first).
    for p in reversed(paths_to_add):
        if p not in sys.path:
            sys.path.insert(0, p)

    _configured = True
