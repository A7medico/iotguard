import subprocess
import sys
from pathlib import Path


def test_test_holdout_runs_smoke():
    """
    Smoke test: ensure the holdout evaluation script runs without crashing.
    This exercises model loading, feature schema, and scoring end-to-end.
    """
    root = Path(__file__).resolve().parent.parent
    script = root / "scripts" / "test_holdout.py"
    # Run with the same Python used for pytest
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"test_holdout.py failed:\n{result.stdout}"





