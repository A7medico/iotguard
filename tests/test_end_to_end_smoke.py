"""
tests/test_end_to_end_smoke.py
-----------------------------------------------------------------------------
IoTGuard Tests — End-to-End Smoke Tests

Purpose
    Verify that the complete IoTGuard pipeline works end-to-end by running
    actual scripts and checking they complete without errors.

Test Philosophy
    Smoke tests are shallow integration tests that verify:
    - Scripts can be loaded and executed
    - Dependencies are correctly installed
    - Model files can be loaded
    - Basic scoring pipeline works
    
    They do NOT test:
    - Correctness of predictions
    - Performance metrics
    - Edge cases

Why Smoke Tests Matter
    - Catch import errors and missing dependencies early
    - Verify model files are present and loadable
    - Ensure feature schema alignment between training and inference
    - Quick CI/CD gate before running more expensive tests

Running
    pytest tests/test_end_to_end_smoke.py -v
    
    Note: These tests require trained models in models/ directory.
-----------------------------------------------------------------------------
"""

import subprocess
import sys
from pathlib import Path


class TestEndToEndSmoke:
    """Smoke tests for complete pipeline execution."""
    
    def test_test_holdout_runs_successfully(self):
        """
        Smoke test: Verify the holdout evaluation script runs without errors.
        
        This test exercises the complete inference pipeline:
        1. Load trained LightGBM model from models/
        2. Load feature schema from model_meta.json
        3. Read and process holdout test data
        4. Run predictions on test samples
        5. Compute and report metrics
        
        A successful run indicates:
        - Model file is present and loadable
        - Feature schema matches between training and inference
        - All dependencies (numpy, pandas, sklearn, lightgbm) work correctly
        
        Timeout:
            60 seconds should be sufficient for holdout evaluation.
            If this times out, the test data may be too large.
        """
        # Determine project root
        root = Path(__file__).resolve().parent.parent
        script = root / "scripts" / "test_holdout.py"
        
        # Run the holdout script using the same Python interpreter as pytest
        result = subprocess.run(
            [sys.executable, str(script)],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
        )
        
        # Verify successful exit
        assert result.returncode == 0, (
            f"test_holdout.py failed with exit code {result.returncode}:\n"
            f"{result.stdout}"
        )


# Additional smoke tests can be added here:
#
# def test_api_dashboard_starts():
#     '''Verify the API dashboard can start without errors.'''
#     # Start the dashboard, wait briefly, then terminate
#     pass
#
# def test_decision_loop_imports():
#     '''Verify decision_loop.py can be imported.'''
#     from scripts import decision_loop
#     assert decision_loop.FEATURES is not None
