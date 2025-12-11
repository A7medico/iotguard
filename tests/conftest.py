"""
tests/conftest.py
-----------------------------------------------------------------------------
IoTGuard Test Configuration — Pytest Fixtures and Configuration

Purpose
    Configure the pytest test environment for IoTGuard:
    - Set up Python path to allow importing from scripts/
    - Define shared fixtures used across test modules
    - Configure test discovery and collection

Usage
    This file is automatically loaded by pytest before running tests.
    Fixtures defined here are available to all test modules.

Path Setup
    The project has the following structure:
        iotguard/
        ├── scripts/        # Main Python modules
        ├── tests/          # Test files (this directory)
        ├── configs/        # Configuration files
        └── models/         # Trained model files
    
    We add both project root and scripts/ to sys.path so tests can:
    - Import scripts as modules: `from scripts.blocker import block_ip`
    - Import directly: `from blocker import block_ip`

Fixtures
    Add shared fixtures here as needed, for example:
    
    @pytest.fixture
    def sample_features():
        '''Return a sample feature DataFrame for testing.'''
        return pd.DataFrame({...})

Running Tests
    From project root:
        pytest tests/ -v
        
    With coverage:
        pytest tests/ --cov=scripts --cov-report=html
-----------------------------------------------------------------------------
"""

import sys
from pathlib import Path


# ---------- Path Configuration ----------
# Determine project root (parent of tests directory)
project_root = Path(__file__).parent.parent

# Add project root to Python path for `from scripts.xxx import yyy`
sys.path.insert(0, str(project_root))

# Also add scripts directory for direct imports like `from blocker import block_ip`
scripts_dir = project_root / "scripts"
sys.path.insert(0, str(scripts_dir))


# ---------- Pytest Configuration ----------
# Pytest-specific configuration can be added here if needed
# For example:
#   pytest_plugins = ["pytest_asyncio"]


# ---------- Shared Fixtures ----------
# Add fixtures that should be available to all tests here.
# Example:
#
# import pytest
# import pandas as pd
#
# @pytest.fixture
# def sample_model_config():
#     '''Return sample model configuration for testing.'''
#     return {
#         "threshold": 0.7,
#         "grace": 2,
#         "window": 5,
#     }
