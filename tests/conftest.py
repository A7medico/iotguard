"""
tests/conftest.py
Pytest configuration and fixtures for IoTGuard tests.
"""

import sys
from pathlib import Path

# Add project root to Python path so tests can import scripts.*
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Also add scripts directory for direct imports
scripts_dir = project_root / "scripts"
sys.path.insert(0, str(scripts_dir))


