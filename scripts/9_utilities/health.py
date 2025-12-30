"""
scripts/9_utilities/health.py
-----------------------------------------------------------------------------
IoTGuard — System Health Check Utilities

Purpose:
    Centralized health checks for all IoTGuard components:
    - Model availability
    - Configuration validity
    - File permissions
    - Component connectivity

Usage:
    from health import HealthChecker, run_health_checks

    checker = HealthChecker()
    results = checker.run_all()

    # Individual checks
    model_ok = checker.check_models()
    config_ok = checker.check_config()
-----------------------------------------------------------------------------
"""
import os
import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# =============================================================================
# HEALTH CHECK RESULT
# =============================================================================

@dataclass
class HealthCheckResult:
    """Result of a single health check."""
    name: str
    status: str  # "ok", "warning", "error"
    message: str
    details: Dict[str, Any] = field(default_factory=dict)

    def is_ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "details": self.details,
        }


# =============================================================================
# HEALTH CHECKER
# =============================================================================

class HealthChecker:
    """
    Comprehensive health checker for IoTGuard components.

    Checks:
        - Model files exist and are readable
        - Configuration files are valid
        - Required directories exist and are writable
        - Python dependencies are available

    Usage:
        checker = HealthChecker()
        results = checker.run_all()

        if not all(r.is_ok() for r in results):
            print("System health issues detected!")
    """

    def __init__(self, base_dir: Optional[Path] = None):
        """
        Initialize health checker.

        Args:
            base_dir: Project base directory (auto-detected if None)
        """
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            # Auto-detect based on common project structure
            self.base_dir = Path.cwd()

        self.models_dir = self.base_dir / "models"
        self.configs_dir = self.base_dir / "configs"
        self.data_dir = self.base_dir / "data"
        self.logs_dir = self.base_dir / "logs"

    def check_models(self) -> HealthCheckResult:
        """Check if ML models are available and loadable."""
        required_models = [
            ("lightgbm.joblib", "Supervised model (LightGBM)"),
            ("iforest.joblib", "Unsupervised model (IsolationForest)"),
        ]

        found = []
        missing = []

        for filename, description in required_models:
            path = self.models_dir / filename
            if path.exists():
                try:
                    # Check file is readable
                    size = path.stat().st_size
                    found.append({
                        "file": filename,
                        "description": description,
                        "size_bytes": size,
                    })
                except Exception as e:
                    missing.append({"file": filename, "error": str(e)})
            else:
                missing.append({"file": filename, "error": "File not found"})

        if len(found) == len(required_models):
            return HealthCheckResult(
                name="models",
                status="ok",
                message="All ML models available",
                details={"found": found}
            )
        elif found:
            return HealthCheckResult(
                name="models",
                status="warning",
                message=f"Some models missing ({len(missing)}/{len(required_models)})",
                details={"found": found, "missing": missing}
            )
        else:
            return HealthCheckResult(
                name="models",
                status="error",
                message="No ML models found",
                details={"missing": missing}
            )

    def check_config(self) -> HealthCheckResult:
        """Check if configuration files are valid."""
        required_configs = [
            "model.yaml",
            "devices.yaml",
        ]

        optional_configs = [
            "access_control.yaml",
        ]

        issues = []
        valid = []

        for filename in required_configs:
            path = self.configs_dir / filename
            if not path.exists():
                issues.append({"file": filename, "error": "File not found"})
                continue

            if YAML_AVAILABLE:
                try:
                    with path.open("r", encoding="utf-8") as f:
                        cfg = yaml.safe_load(f)
                    valid.append({"file": filename, "keys": list(cfg.keys()) if cfg else []})
                except yaml.YAMLError as e:
                    issues.append({"file": filename, "error": f"Invalid YAML: {e}"})
                except Exception as e:
                    issues.append({"file": filename, "error": str(e)})
            else:
                valid.append({"file": filename, "note": "YAML not available for validation"})

        # Check optional configs (no error if missing)
        for filename in optional_configs:
            path = self.configs_dir / filename
            if path.exists():
                valid.append({"file": filename, "optional": True})

        if not issues:
            return HealthCheckResult(
                name="config",
                status="ok",
                message="All configuration files valid",
                details={"valid": valid}
            )
        else:
            return HealthCheckResult(
                name="config",
                status="error",
                message=f"Configuration issues: {len(issues)}",
                details={"valid": valid, "issues": issues}
            )

    def check_directories(self) -> HealthCheckResult:
        """Check if required directories exist and are writable."""
        required_dirs = [
            ("data", self.data_dir, True),  # (name, path, must_be_writable)
            ("logs", self.logs_dir, True),
            ("models", self.models_dir, False),
            ("configs", self.configs_dir, False),
        ]

        issues = []
        valid = []

        for name, path, must_write in required_dirs:
            if not path.exists():
                # Try to create it
                try:
                    path.mkdir(parents=True, exist_ok=True)
                    valid.append({"name": name, "path": str(path), "created": True})
                except Exception as e:
                    issues.append({"name": name, "path": str(path), "error": f"Cannot create: {e}"})
                continue

            if must_write:
                # Check writable
                test_file = path / ".write_test"
                try:
                    test_file.write_text("test", encoding="utf-8")
                    test_file.unlink()
                    valid.append({"name": name, "path": str(path), "writable": True})
                except Exception as e:
                    issues.append({"name": name, "path": str(path), "error": f"Not writable: {e}"})
            else:
                valid.append({"name": name, "path": str(path), "exists": True})

        if not issues:
            return HealthCheckResult(
                name="directories",
                status="ok",
                message="All directories accessible",
                details={"valid": valid}
            )
        else:
            return HealthCheckResult(
                name="directories",
                status="error",
                message=f"Directory issues: {len(issues)}",
                details={"valid": valid, "issues": issues}
            )

    def check_dependencies(self) -> HealthCheckResult:
        """Check if required Python packages are available."""
        required = [
            ("numpy", "NumPy"),
            ("pandas", "Pandas"),
            ("flask", "Flask"),
            ("yaml", "PyYAML"),
        ]

        optional = [
            ("sklearn", "scikit-learn"),
            ("lightgbm", "LightGBM"),
            ("joblib", "Joblib"),
            ("flask_socketio", "Flask-SocketIO"),
        ]

        available = []
        missing_required = []
        missing_optional = []

        for module, name in required:
            try:
                __import__(module)
                available.append({"module": module, "name": name, "required": True})
            except ImportError:
                missing_required.append({"module": module, "name": name})

        for module, name in optional:
            try:
                __import__(module)
                available.append({"module": module, "name": name, "required": False})
            except ImportError:
                missing_optional.append({"module": module, "name": name})

        if missing_required:
            return HealthCheckResult(
                name="dependencies",
                status="error",
                message=f"Missing required packages: {len(missing_required)}",
                details={
                    "available": available,
                    "missing_required": missing_required,
                    "missing_optional": missing_optional,
                }
            )
        elif missing_optional:
            return HealthCheckResult(
                name="dependencies",
                status="warning",
                message=f"Optional packages unavailable: {len(missing_optional)}",
                details={
                    "available": available,
                    "missing_optional": missing_optional,
                }
            )
        else:
            return HealthCheckResult(
                name="dependencies",
                status="ok",
                message="All dependencies available",
                details={"available": available}
            )

    def check_pipeline_health(self) -> HealthCheckResult:
        """Check health of running pipeline components."""
        health_files = [
            ("decision_loop", self.data_dir / "decision_health.json", 60),
            ("features", self.data_dir / "features_health.json", 60),
        ]

        components = []
        stale = []

        now = time.time()

        for name, path, max_age_seconds in health_files:
            if not path.exists():
                components.append({"name": name, "status": "unknown", "note": "No health file"})
                continue

            try:
                health = json.loads(path.read_text(encoding="utf-8"))
                last_ts = health.get("ts", 0) or health.get("last_ts", 0)
                age = now - last_ts

                if age <= max_age_seconds:
                    components.append({
                        "name": name,
                        "status": "running",
                        "age_seconds": round(age, 1),
                    })
                else:
                    components.append({
                        "name": name,
                        "status": "stale",
                        "age_seconds": round(age, 1),
                    })
                    stale.append(name)
            except Exception as e:
                components.append({"name": name, "status": "error", "error": str(e)})

        if not stale and all(c["status"] in ("running", "unknown") for c in components):
            return HealthCheckResult(
                name="pipeline",
                status="ok",
                message="Pipeline components healthy",
                details={"components": components}
            )
        elif stale:
            return HealthCheckResult(
                name="pipeline",
                status="warning",
                message=f"Stale components: {stale}",
                details={"components": components}
            )
        else:
            return HealthCheckResult(
                name="pipeline",
                status="warning",
                message="Some components not reporting",
                details={"components": components}
            )

    def run_all(self) -> List[HealthCheckResult]:
        """Run all health checks and return results."""
        return [
            self.check_dependencies(),
            self.check_directories(),
            self.check_config(),
            self.check_models(),
            self.check_pipeline_health(),
        ]

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of all health checks."""
        results = self.run_all()

        status_counts = {"ok": 0, "warning": 0, "error": 0}
        for r in results:
            status_counts[r.status] = status_counts.get(r.status, 0) + 1

        overall = "ok"
        if status_counts["error"] > 0:
            overall = "error"
        elif status_counts["warning"] > 0:
            overall = "warning"

        return {
            "overall_status": overall,
            "timestamp": time.time(),
            "counts": status_counts,
            "checks": [r.to_dict() for r in results],
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def run_health_checks(base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """
    Run all health checks and return summary.

    Args:
        base_dir: Project base directory

    Returns:
        Dictionary with overall status and check results
    """
    checker = HealthChecker(base_dir)
    return checker.get_summary()


def is_system_healthy(base_dir: Optional[Path] = None) -> bool:
    """
    Quick check if system is healthy.

    Args:
        base_dir: Project base directory

    Returns:
        True if no errors detected
    """
    summary = run_health_checks(base_dir)
    return summary["overall_status"] != "error"


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IoTGuard Health Check")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    summary = run_health_checks()

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"\n{'='*50}")
        print(f"IoTGuard Health Check")
        print(f"{'='*50}\n")

        for check in summary["checks"]:
            icon = {"ok": "✅", "warning": "⚠️", "error": "❌"}.get(check["status"], "?")
            print(f"{icon} {check['name']}: {check['message']}")

        print(f"\n{'='*50}")
        overall_icon = {"ok": "✅", "warning": "⚠️", "error": "❌"}.get(summary["overall_status"], "?")
        print(f"Overall: {overall_icon} {summary['overall_status'].upper()}")
        print(f"{'='*50}\n")
