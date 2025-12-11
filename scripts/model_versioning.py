"""
scripts/model_versioning.py
=============================================================================
IoTGuard — Model Version Management

PURPOSE:
    Track model versions, performance metrics, and enable rollback to
    previous versions if a new model underperforms.

FEATURES:
    - Automatic version bumping on model save
    - Performance tracking (accuracy, ROC-AUC, FPR)
    - Model comparison reporting
    - Rollback to previous versions

USAGE:
    from model_versioning import ModelVersionManager
    
    # Initialize
    manager = ModelVersionManager("models")
    
    # Save new model version
    manager.save_version("lightgbm.joblib", metrics={"accuracy": 0.93, "fpr": 0.04})
    
    # List versions
    versions = manager.list_versions("lightgbm.joblib")
    
    # Rollback
    manager.rollback("lightgbm.joblib", version="1.0.2")
=============================================================================
"""

import os
import json
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger("iotguard.versioning")


class ModelVersionManager:
    """
    Manage model versions with performance tracking and rollback.
    
    VERSION FORMAT:
        major.minor.patch (e.g., 1.2.3)
        - Major: Breaking changes (different features)
        - Minor: Significant improvements
        - Patch: Bug fixes or minor tuning
    """
    
    def __init__(self, models_dir: str = "models"):
        """
        Initialize the version manager.
        
        Args:
            models_dir: Directory containing model files
        """
        self.models_dir = Path(models_dir)
        self.versions_dir = self.models_dir / ".versions"
        self.versions_dir.mkdir(parents=True, exist_ok=True)
        
        # Version history file
        self.history_file = self.versions_dir / "history.json"
        self.history = self._load_history()
    
    def _load_history(self) -> Dict[str, List[Dict]]:
        """Load version history from JSON file."""
        if self.history_file.exists():
            try:
                return json.loads(self.history_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}
    
    def _save_history(self) -> None:
        """Save version history to JSON file."""
        self.history_file.write_text(
            json.dumps(self.history, indent=2),
            encoding="utf-8"
        )
    
    def _get_next_version(self, model_name: str, bump: str = "patch") -> str:
        """
        Get the next version number.
        
        Args:
            model_name: Name of the model file
            bump: Version component to bump (major, minor, patch)
        
        Returns:
            Next version string (e.g., "1.0.3")
        """
        versions = self.history.get(model_name, [])
        
        if not versions:
            return "1.0.0"
        
        # Get latest version
        latest = versions[-1]["version"]
        parts = [int(x) for x in latest.split(".")]
        
        if bump == "major":
            parts[0] += 1
            parts[1] = 0
            parts[2] = 0
        elif bump == "minor":
            parts[1] += 1
            parts[2] = 0
        else:  # patch
            parts[2] += 1
        
        return ".".join(str(x) for x in parts)
    
    def save_version(
        self,
        model_name: str,
        metrics: Optional[Dict[str, float]] = None,
        description: str = "",
        bump: str = "patch"
    ) -> str:
        """
        Save the current model as a new version.
        
        Args:
            model_name: Name of the model file (e.g., "lightgbm.joblib")
            metrics: Performance metrics (accuracy, roc_auc, fpr, etc.)
            description: Description of changes in this version
            bump: Version component to bump
        
        Returns:
            New version string
        """
        model_path = self.models_dir / model_name
        
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        # Get next version
        version = self._get_next_version(model_name, bump)
        
        # Create version backup directory
        version_dir = self.versions_dir / model_name.replace(".", "_")
        version_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy model to version directory
        backup_path = version_dir / f"v{version}{model_path.suffix}"
        shutil.copy2(model_path, backup_path)
        
        # Also backup metadata if exists
        meta_name = model_name.replace(".joblib", "_meta.json").replace("lightgbm", "model")
        if model_name == "lightgbm.joblib":
            meta_name = "model_meta.json"
        elif model_name == "lightgbm_it.joblib":
            meta_name = "model_meta_it.json"
        
        meta_path = self.models_dir / meta_name
        if meta_path.exists():
            meta_backup = version_dir / f"v{version}_meta.json"
            shutil.copy2(meta_path, meta_backup)
        
        # Record version info
        version_info = {
            "version": version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "description": description,
            "metrics": metrics or {},
            "backup_path": str(backup_path),
        }
        
        if model_name not in self.history:
            self.history[model_name] = []
        self.history[model_name].append(version_info)
        
        self._save_history()
        
        logger.info(f"Saved {model_name} version {version}")
        return version
    
    def list_versions(self, model_name: str) -> List[Dict]:
        """
        List all versions of a model.
        
        Args:
            model_name: Name of the model file
        
        Returns:
            List of version info dictionaries
        """
        return self.history.get(model_name, [])
    
    def get_latest_version(self, model_name: str) -> Optional[Dict]:
        """Get info about the latest version."""
        versions = self.list_versions(model_name)
        return versions[-1] if versions else None
    
    def compare_versions(
        self,
        model_name: str,
        v1: str,
        v2: str
    ) -> Dict[str, Any]:
        """
        Compare metrics between two versions.
        
        Args:
            model_name: Name of the model
            v1: First version string
            v2: Second version string
        
        Returns:
            Comparison dict with differences
        """
        versions = {v["version"]: v for v in self.list_versions(model_name)}
        
        if v1 not in versions or v2 not in versions:
            return {"error": "Version not found"}
        
        m1 = versions[v1].get("metrics", {})
        m2 = versions[v2].get("metrics", {})
        
        all_keys = set(m1.keys()) | set(m2.keys())
        
        comparison = {}
        for key in all_keys:
            val1 = m1.get(key, None)
            val2 = m2.get(key, None)
            
            if val1 is not None and val2 is not None:
                diff = val2 - val1
                comparison[key] = {
                    v1: val1,
                    v2: val2,
                    "diff": diff,
                    "improved": diff > 0 if key != "fpr" else diff < 0
                }
        
        return comparison
    
    def rollback(self, model_name: str, version: str) -> bool:
        """
        Rollback model to a previous version.
        
        Args:
            model_name: Name of the model file
            version: Version string to rollback to
        
        Returns:
            True if rollback successful
        """
        versions = {v["version"]: v for v in self.list_versions(model_name)}
        
        if version not in versions:
            logger.error(f"Version {version} not found")
            return False
        
        backup_path = Path(versions[version]["backup_path"])
        
        if not backup_path.exists():
            logger.error(f"Backup file not found: {backup_path}")
            return False
        
        model_path = self.models_dir / model_name
        
        # Save current as latest (so we can undo rollback)
        self.save_version(
            model_name,
            description=f"Pre-rollback backup (rolling back to {version})"
        )
        
        # Copy backup to active model
        shutil.copy2(backup_path, model_path)
        
        # Also restore metadata if exists
        meta_backup = backup_path.parent / f"v{version}_meta.json"
        if meta_backup.exists():
            if model_name == "lightgbm.joblib":
                meta_name = "model_meta.json"
            elif model_name == "lightgbm_it.joblib":
                meta_name = "model_meta_it.json"
            else:
                meta_name = model_name.replace(".joblib", "_meta.json")
            
            meta_path = self.models_dir / meta_name
            shutil.copy2(meta_backup, meta_path)
        
        logger.info(f"Rolled back {model_name} to version {version}")
        return True
    
    def get_report(self) -> str:
        """Generate a text report of all model versions."""
        lines = ["=" * 60, "IoTGuard Model Version Report", "=" * 60, ""]
        
        for model_name, versions in self.history.items():
            lines.append(f"📦 {model_name}")
            lines.append("-" * 40)
            
            for v in reversed(versions[-5:]):  # Last 5 versions
                ts = v["timestamp"][:19].replace("T", " ")
                metrics = v.get("metrics", {})
                
                metrics_str = ", ".join(
                    f"{k}={float(val):.2%}" if k in ("accuracy", "fpr", "tpr") 
                    else f"{k}={val:.4f}"
                    for k, val in metrics.items()
                )
                
                lines.append(f"  v{v['version']} ({ts})")
                if metrics_str:
                    lines.append(f"    Metrics: {metrics_str}")
                if v.get("description"):
                    lines.append(f"    Note: {v['description']}")
            
            lines.append("")
        
        return "\n".join(lines)


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="IoTGuard Model Version Manager")
    parser.add_argument("command", choices=["list", "save", "rollback", "report"])
    parser.add_argument("--model", default="lightgbm.joblib")
    parser.add_argument("--version", help="Version for rollback")
    parser.add_argument("--description", default="", help="Description for new version")
    
    args = parser.parse_args()
    
    manager = ModelVersionManager("models")
    
    if args.command == "list":
        print(f"\nVersions of {args.model}:")
        for v in manager.list_versions(args.model):
            print(f"  v{v['version']} - {v['timestamp'][:10]}")
    
    elif args.command == "save":
        version = manager.save_version(args.model, description=args.description)
        print(f"Saved version {version}")
    
    elif args.command == "rollback":
        if not args.version:
            print("Error: --version required for rollback")
        else:
            if manager.rollback(args.model, args.version):
                print(f"Rolled back to version {args.version}")
            else:
                print("Rollback failed")
    
    elif args.command == "report":
        print(manager.get_report())
