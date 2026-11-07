"""
scripts/9_utilities/audit_ledger.py
-----------------------------------------------------------------------------
IoTGuard Enterprise v4.0 — Cryptographic Hash-Chained Audit Ledger

Responsibilities:
    - Maintain an immutable, tamper-evident cryptographic blockchain-style ledger
    - Every administrative event is chained:
        entry_hash = SHA256(prev_hash + timestamp + actor + action + canonical_payload_json)
    - Detect any retroactive database edits, deletions, or unauthorized modifications
    - Verify full ledger integrity on demand and pinpoint exact tampered block indices
    - Dual-write to relational storage engine and append-only audit JSONL file
-----------------------------------------------------------------------------
"""

import os
import sys
import json
import time
import hashlib
import threading
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

_scripts_dir = Path(__file__).resolve().parent.parent
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))
from path_setup import configure_paths
configure_paths()

try:
    from storage_engine import get_storage_engine, BaseStorageEngine
except ImportError:
    get_storage_engine = None
    BaseStorageEngine = None

logger = logging.getLogger("iotguard.audit_ledger")

GENESIS_PREV_HASH = "0" * 64
AUDIT_LOG_FILE = Path("logs/audit_ledger.jsonl")
_ledger_lock = threading.Lock()


def canonical_json_str(data: Any) -> str:
    """Format data into canonical deterministic JSON representation."""
    if data is None:
        return ""
    if isinstance(data, (dict, list)):
        return json.dumps(data, sort_keys=True, separators=(",", ":"))
    return str(data)


def compute_entry_hash(
    prev_hash: str,
    timestamp: float,
    actor: str,
    action: str,
    payload_str: Any,
) -> str:
    """
    Compute cryptographic SHA-256 hash of an audit block:
    SHA-256(prev_hash + timestamp + actor + action + canonical_payload)
    """
    if not isinstance(payload_str, str):
        payload_str = canonical_json_str(payload_str)
    raw = f"{prev_hash}|{timestamp:.6f}|{actor}|{action}|{payload_str}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class AuditLedger:
    """Manages the cryptographic hash-chained audit ledger."""

    def __init__(
        self,
        storage=None,
        log_path: Union[str, Path] = AUDIT_LOG_FILE,
        storage_engine=None,
        jsonl_path: Optional[Union[str, Path]] = None,
    ):
        self._storage = storage_engine if storage_engine is not None else storage
        target_path = jsonl_path if jsonl_path is not None else log_path
        self.log_path = Path(target_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_storage(self):
        if self._storage is not None:
            return self._storage
        if get_storage_engine is not None:
            return get_storage_engine()
        return None

    def record_action(
        self,
        actor: str,
        action: str,
        role: str = "ADMIN",
        payload: Any = None,
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Record an administrative or operational event into the cryptographic ledger.
        """
        with _ledger_lock:
            ts = float(timestamp if timestamp is not None else time.time())
            payload_str = canonical_json_str(payload)
            storage = self._get_storage()

            # Retrieve previous hash
            prev_hash = GENESIS_PREV_HASH
            if storage is not None:
                latest = storage.get_latest_audit_entry()
                if latest and latest.get("entry_hash"):
                    prev_hash = latest["entry_hash"]

            entry_hash = compute_entry_hash(prev_hash, ts, actor, action, payload_str)

            entry = {
                "timestamp": ts,
                "actor": str(actor),
                "role": str(role),
                "action": str(action),
                "payload": payload_str,
                "prev_hash": prev_hash,
                "entry_hash": entry_hash,
            }

            # 1. Store in relational database
            if storage is not None:
                try:
                    entry_id = storage.insert_audit_entry(
                        timestamp=ts,
                        actor=actor,
                        role=role,
                        action=action,
                        payload=payload_str,
                        prev_hash=prev_hash,
                        entry_hash=entry_hash,
                    )
                    entry["id"] = entry_id
                    entry["index"] = (entry_id - 1) if entry_id is not None else 0
                except Exception as e:
                    logger.error(f"Failed to persist audit entry to DB: {e}")

            # 2. Dual-write to append-only flat file
            try:
                with self.log_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception as e:
                logger.warning(f"Failed to append to audit ledger file: {e}")

            return entry

    def verify_chain(self, storage=None) -> Tuple[bool, str, Optional[int]]:
        """
        Verify the integrity of the audit hash chain.
        Returns:
            (is_valid: bool, status: str, tampered_block_index: Optional[int])
        """
        with _ledger_lock:
            s = storage or self._get_storage()
            entries: List[Dict[str, Any]] = []

            if s is not None:
                entries = s.get_audit_entries(limit=10000, offset=0)

            # Fallback to log file if DB is empty
            if not entries and self.log_path.exists():
                try:
                    with self.log_path.open("r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                entries.append(json.loads(line))
                except Exception:
                    pass

            if not entries:
                return True, "EMPTY_LEDGER", None

            for i, block in enumerate(entries):
                expected_prev = GENESIS_PREV_HASH if i == 0 else entries[i - 1]["entry_hash"]
                actual_prev = block.get("prev_hash")

                if actual_prev != expected_prev:
                    return False, f"CHAIN_BROKEN_AT_BLOCK_{i}", i

                # Verify entry hash
                recomputed = compute_entry_hash(
                    prev_hash=block["prev_hash"],
                    timestamp=float(block["timestamp"]),
                    actor=str(block["actor"]),
                    action=str(block["action"]),
                    payload_str=str(block.get("payload", "")),
                )

                if recomputed != block.get("entry_hash"):
                    return False, f"HASH_MISMATCH_AT_BLOCK_{i}", i

            return True, "INTEGRITY_VERIFIED", None

    def get_trail(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve audit entries."""
        s = self._get_storage()
        if s is not None:
            return s.get_audit_entries(limit=limit, offset=offset)

        # Fallback to file
        entries = []
        if self.log_path.exists():
            try:
                with self.log_path.open("r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            entries.append(json.loads(line))
            except Exception:
                pass
        return entries[offset : offset + limit]


# ── Global Singleton & Convenience Functions ─────────────────────────────────

_default_ledger: Optional[AuditLedger] = None


def get_audit_ledger() -> AuditLedger:
    global _default_ledger
    if _default_ledger is None:
        _default_ledger = AuditLedger()
    return _default_ledger


def record_audit_event(
    actor: str,
    action: str,
    role: str = "ADMIN",
    payload: Any = None,
    timestamp: Optional[float] = None,
) -> Dict[str, Any]:
    """Convenience helper to record an audit action."""
    return get_audit_ledger().record_action(
        actor=actor, action=action, role=role, payload=payload, timestamp=timestamp
    )


def verify_audit_ledger() -> Tuple[bool, str, Optional[int]]:
    """Convenience helper to verify the ledger integrity."""
    return get_audit_ledger().verify_chain()
