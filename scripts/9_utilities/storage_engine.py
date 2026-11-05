"""
scripts/9_utilities/storage_engine.py
-----------------------------------------------------------------------------
IoTGuard Enterprise v4.0 — High-Performance Relational Storage Engine

Responsibilities:
    - Thread-safe, zero-dependency relational persistence layer using SQLite in WAL mode
    - Extensible abstract base interface (BaseStorageEngine) ready for PostgreSQL/TimescaleDB
    - High-concurrency indexed tables for security_events, active_blocks, edge_nodes, and audit_ledger
    - Sub-millisecond multidimensional queries with composite indexing
    - Dual-write contract integration with legacy JSONL/JSON formats
-----------------------------------------------------------------------------
"""

import os
import json
import time
import sqlite3
import threading
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("iotguard.storage_engine")

DEFAULT_DB_PATH = Path("data/iotguard_enterprise.db")


# ── Abstract Storage Interface ───────────────────────────────────────────────

class BaseStorageEngine(ABC):
    """Abstract interface for enterprise time-series & relational persistence."""

    @abstractmethod
    def insert_event(self, evt: Dict[str, Any]) -> int:
        """Insert a single security event."""
        pass

    @abstractmethod
    def count_events(self) -> int:
        """Count total security events in the repository."""
        pass

    @abstractmethod
    def query_events(
        self,
        src_ip: Optional[str] = None,
        category: Optional[str] = None,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        response_tier: Optional[str] = None,
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Query security events with multidimensional indexed filters."""
        pass

    @abstractmethod
    def record_block(
        self,
        ip: str,
        severity: str = "hard",
        reason: str = "",
        driver: str = "auto",
        drop_count: int = 0,
    ) -> None:
        """Upsert an actively blocked IP."""
        pass

    @abstractmethod
    def record_unblock(self, ip: str) -> None:
        """Deactivate or remove a blocked IP."""
        pass

    @abstractmethod
    def get_active_blocks(self) -> Dict[str, Dict[str, Any]]:
        """Retrieve all currently active firewall blocks."""
        pass

    @abstractmethod
    def upsert_edge_node(
        self,
        node_id: str,
        ip: str = "",
        status: str = "online",
        current_round: int = 0,
        samples: int = 0,
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Upsert edge node status and round telemetry."""
        pass

    @abstractmethod
    def get_edge_nodes(self) -> List[Dict[str, Any]]:
        """List all registered edge nodes."""
        pass

    @abstractmethod
    def insert_audit_entry(
        self,
        timestamp: float,
        actor: str,
        role: str,
        action: str,
        payload: str,
        prev_hash: str,
        entry_hash: str,
    ) -> int:
        """Insert an immutable cryptographic audit record."""
        pass

    @abstractmethod
    def get_audit_entries(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve historical audit records in chronological order."""
        pass

    @abstractmethod
    def get_latest_audit_entry(self) -> Optional[Dict[str, Any]]:
        """Retrieve the most recent audit block in the chain."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close connections and release locks."""
        pass


# ── SQLite High-Concurrency Implementation (WAL Mode) ────────────────────────

class SQLiteStorageEngine(BaseStorageEngine):
    """
    Thread-safe SQLite engine configured with Write-Ahead Logging (WAL) mode
    and connection pooling via thread-local state.
    """

    def __init__(self, db_path: Union[str, Path] = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Get or initialize a thread-local SQLite connection with WAL PRAGMAs."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=10.0,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            # Configure high-concurrency PRAGMAs
            cursor = conn.cursor()
            if str(self.db_path) != ":memory:":
                cursor.execute("PRAGMA journal_mode = WAL;")
            cursor.execute("PRAGMA synchronous = NORMAL;")
            cursor.execute("PRAGMA foreign_keys = ON;")
            cursor.execute("PRAGMA busy_timeout = 5000;")
            cursor.close()
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        """Initialize relational schema with composite indexes."""
        with self._lock:
            conn = self._get_connection()
            with conn:
                conn.executescript(
                    """
                    -- Security Events (Alerts & Telemetry)
                    CREATE TABLE IF NOT EXISTS security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_index INTEGER,
                        timestamp REAL NOT NULL,
                        score REAL NOT NULL,
                        state TEXT NOT NULL,
                        hits_in_window INTEGER DEFAULT 0,
                        action TEXT NOT NULL,
                        src_ip TEXT,
                        attack_category TEXT,
                        pred_class TEXT,
                        response_tier TEXT,
                        confidence REAL,
                        effective_threshold REAL,
                        device_type TEXT,
                        detection_source TEXT,
                        reason TEXT,
                        payload_json TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp DESC);
                    CREATE INDEX IF NOT EXISTS idx_events_src_ip ON security_events(src_ip);
                    CREATE INDEX IF NOT EXISTS idx_events_category ON security_events(attack_category);
                    CREATE INDEX IF NOT EXISTS idx_events_tier ON security_events(response_tier);
                    CREATE INDEX IF NOT EXISTS idx_events_score ON security_events(score DESC);
                    CREATE INDEX IF NOT EXISTS idx_events_composite ON security_events(src_ip, attack_category, timestamp DESC);

                    -- Active Firewall Blocks
                    CREATE TABLE IF NOT EXISTS active_blocks (
                        ip TEXT PRIMARY KEY,
                        blocked_at REAL NOT NULL,
                        severity TEXT DEFAULT 'hard',
                        reason TEXT,
                        driver TEXT DEFAULT 'auto',
                        active INTEGER DEFAULT 1,
                        drop_count INTEGER DEFAULT 0,
                        updated_at REAL NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_blocks_active ON active_blocks(active);

                    -- Edge Node Fleet Roster
                    CREATE TABLE IF NOT EXISTS edge_nodes (
                        node_id TEXT PRIMARY KEY,
                        last_seen REAL NOT NULL,
                        ip TEXT,
                        status TEXT DEFAULT 'online',
                        current_round INTEGER DEFAULT 0,
                        samples INTEGER DEFAULT 0,
                        meta_json TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON edge_nodes(last_seen DESC);

                    -- Cryptographic Hash-Chained Audit Ledger
                    CREATE TABLE IF NOT EXISTS audit_ledger (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        actor TEXT NOT NULL,
                        role TEXT NOT NULL,
                        action TEXT NOT NULL,
                        payload TEXT,
                        prev_hash TEXT NOT NULL,
                        entry_hash TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_ledger(timestamp DESC);
                    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_ledger(action);
                    """
                )

    # ── Security Events API ──────────────────────────────────────────────────

    def insert_event(self, evt: Dict[str, Any]) -> int:
        """Insert a security event and index its key operational dimensions."""
        conn = self._get_connection()
        ts = float(evt.get("ts", evt.get("timestamp", time.time())))
        idx = evt.get("index")
        score = float(evt.get("score", 0.0))
        state = str(evt.get("state", "UNKNOWN"))
        hits = int(evt.get("hits_in_window", evt.get("hits", 0)))
        action = str(evt.get("action", "NONE"))
        src_ip = evt.get("src_ip")
        category = evt.get("attack_category")
        pred_class = evt.get("pred_class")
        tier = evt.get("response_tier", evt.get("state"))
        conf = float(evt["confidence"]) if evt.get("confidence") is not None else None
        eff_thr = float(evt["effective_threshold"]) if evt.get("effective_threshold") is not None else None
        dev_type = evt.get("device_type", evt.get("model_used"))
        det_src = evt.get("detection_source")
        reason = evt.get("reason")
        payload = json.dumps(evt)

        with conn:
            cursor = conn.execute(
                """
                INSERT INTO security_events (
                    event_index, timestamp, score, state, hits_in_window,
                    action, src_ip, attack_category, pred_class, response_tier,
                    confidence, effective_threshold, device_type, detection_source,
                    reason, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    idx, ts, score, state, hits, action, src_ip, category,
                    pred_class, tier, conf, eff_thr, dev_type, det_src, reason, payload
                ),
            )
            return cursor.lastrowid

    def query_events(
        self,
        src_ip: Optional[str] = None,
        category: Optional[str] = None,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        response_tier: Optional[str] = None,
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Execute indexed sub-millisecond query across security events."""
        conn = self._get_connection()
        query = "SELECT * FROM security_events WHERE 1=1"
        params: List[Any] = []

        if src_ip:
            query += " AND src_ip = ?"
            params.append(src_ip)
        if category:
            query += " AND attack_category = ?"
            params.append(category)
        if min_score is not None:
            query += " AND score >= ?"
            params.append(float(min_score))
        if max_score is not None:
            query += " AND score <= ?"
            params.append(float(max_score))
        if response_tier:
            query += " AND (response_tier = ? OR action = ?)"
            params.extend([response_tier, response_tier])
        if start_ts is not None:
            query += " AND timestamp >= ?"
            params.append(float(start_ts))
        if end_ts is not None:
            query += " AND timestamp <= ?"
            params.append(float(end_ts))

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([int(limit), int(offset)])

        cursor = conn.execute(query, params)
        rows = cursor.fetchall()
        results: List[Dict[str, Any]] = []

        for row in rows:
            # Reconstruct original event dictionary from payload_json if present
            payload_str = row["payload_json"]
            if payload_str:
                try:
                    evt = json.loads(payload_str)
                    evt["db_id"] = row["id"]
                    results.append(evt)
                    continue
                except Exception:
                    pass

            # Fallback to column mapping
            results.append({
                "db_id": row["id"],
                "index": row["event_index"],
                "ts": row["timestamp"],
                "score": row["score"],
                "state": row["state"],
                "hits_in_window": row["hits_in_window"],
                "action": row["action"],
                "src_ip": row["src_ip"],
                "attack_category": row["attack_category"],
                "pred_class": row["pred_class"],
                "response_tier": row["response_tier"],
                "confidence": row["confidence"],
                "effective_threshold": row["effective_threshold"],
                "device_type": row["device_type"],
                "detection_source": row["detection_source"],
                "reason": row["reason"],
            })

        return results

    def count_events(self) -> int:
        """Count total security events in the repository."""
        conn = self._get_connection()
        cursor = conn.execute("SELECT COUNT(*) FROM security_events")
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    # ── Active Blocks API ────────────────────────────────────────────────────

    def record_block(
        self,
        ip: str,
        severity: Union[str, float, int] = "hard",
        reason: str = "",
        driver: str = "auto",
        drop_count: int = 0,
        *args,
        **kwargs,
    ) -> None:
        """Upsert active block record with flexible parameters."""
        conn = self._get_connection()
        now = time.time()
        
        # Handle timestamp passed as 2nd positional argument
        if isinstance(severity, (int, float)):
            blocked_at = float(severity)
            severity_str = str(kwargs.get("severity", "hard")).lower()
        else:
            blocked_at = float(kwargs.get("blocked_at", now))
            severity_str = str(severity).lower()

        reason_str = str(kwargs.get("reason", reason))
        driver_str = str(kwargs.get("driver", kwargs.get("backend", driver)))
        drop_cnt = int(kwargs.get("drop_count", drop_count))

        with conn:
            conn.execute(
                """
                INSERT INTO active_blocks (ip, blocked_at, severity, reason, driver, active, drop_count, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    blocked_at = excluded.blocked_at,
                    severity = excluded.severity,
                    reason = excluded.reason,
                    driver = excluded.driver,
                    active = 1,
                    drop_count = active_blocks.drop_count + excluded.drop_count,
                    updated_at = excluded.updated_at
                """,
                (ip, blocked_at, severity_str, reason_str, driver_str, drop_cnt, now),
            )

    def record_unblock(self, ip: str, *args, **kwargs) -> None:
        """Mark block as inactive."""
        conn = self._get_connection()
        now = time.time()
        with conn:
            conn.execute(
                "UPDATE active_blocks SET active = 0, updated_at = ? WHERE ip = ?",
                (now, ip),
            )

    def get_active_blocks(self, active_only: bool = True) -> Dict[str, Dict[str, Any]]:
        """Return dict of active (or all) blocks."""
        conn = self._get_connection()
        if active_only:
            cursor = conn.execute(
                "SELECT * FROM active_blocks WHERE active = 1 ORDER BY blocked_at DESC"
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM active_blocks ORDER BY blocked_at DESC"
            )
        rows = cursor.fetchall()
        blocks = {}
        for r in rows:
            is_active = bool(r["active"])
            blocks[r["ip"]] = {
                "ip": r["ip"],
                "blocked_at": r["blocked_at"],
                "severity": r["severity"],
                "reason": r["reason"],
                "driver": r["driver"],
                "drop_count": r["drop_count"],
                "active": is_active,
                "status": "active" if is_active else "unblocked",
                "updated_at": r["updated_at"],
            }
        return blocks

    # ── Edge Nodes Fleet API ─────────────────────────────────────────────────

    def upsert_edge_node(
        self,
        node_id: str,
        ip: str = "",
        status: str = "online",
        current_round: int = 0,
        samples: int = 0,
        meta: Optional[Dict[str, Any]] = None,
        last_seen: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> None:
        """Upsert edge node status and metrics."""
        conn = self._get_connection()
        now = float(last_seen if last_seen is not None else time.time())
        meta_dict = metadata if metadata is not None else (meta or {})
        meta_str = json.dumps(meta_dict)
        with conn:
            conn.execute(
                """
                INSERT INTO edge_nodes (node_id, last_seen, ip, status, current_round, samples, meta_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    ip = CASE WHEN excluded.ip != '' THEN excluded.ip ELSE edge_nodes.ip END,
                    status = excluded.status,
                    current_round = excluded.current_round,
                    samples = excluded.samples,
                    meta_json = excluded.meta_json
                """,
                (node_id, now, ip, status, current_round, samples, meta_str),
            )

    def get_edge_nodes(self) -> List[Dict[str, Any]]:
        """Retrieve registered edge gateways."""
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM edge_nodes ORDER BY last_seen DESC")
        rows = cursor.fetchall()
        nodes = []
        for r in rows:
            meta = {}
            if r["meta_json"]:
                try:
                    meta = json.loads(r["meta_json"])
                except Exception:
                    pass
            nodes.append({
                "node_id": r["node_id"],
                "last_seen": r["last_seen"],
                "ip": r["ip"],
                "status": r["status"],
                "current_round": r["current_round"],
                "samples": r["samples"],
                "meta": meta,
                "metadata": meta,
            })
        return nodes

    # ── Cryptographic Audit Ledger API ───────────────────────────────────────

    def insert_audit_entry(
        self,
        timestamp: float,
        actor: str,
        role: str,
        action: str,
        payload: str,
        prev_hash: str,
        entry_hash: str,
    ) -> int:
        """Insert cryptographic audit ledger entry."""
        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_ledger (timestamp, actor, role, action, payload, prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp, actor, role, action, payload, prev_hash, entry_hash),
            )
            return cursor.lastrowid

    def get_audit_entries(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve audit entries in forward chronological order."""
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT * FROM audit_ledger ORDER BY id ASC LIMIT ? OFFSET ?",
            (int(limit), int(offset)),
        )
        rows = cursor.fetchall()
        entries = []
        for r in rows:
            entries.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "actor": r["actor"],
                "role": r["role"],
                "action": r["action"],
                "payload": r["payload"],
                "prev_hash": r["prev_hash"],
                "entry_hash": r["entry_hash"],
            })
        return entries

    def get_latest_audit_entry(self) -> Optional[Dict[str, Any]]:
        """Return the most recent audit entry in the ledger."""
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM audit_ledger ORDER BY id DESC LIMIT 1")
        r = cursor.fetchone()
        if not r:
            return None
        return {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "actor": r["actor"],
            "role": r["role"],
            "action": r["action"],
            "payload": r["payload"],
            "prev_hash": r["prev_hash"],
            "entry_hash": r["entry_hash"],
        }

    def close(self) -> None:
        """Close connection for the current thread."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None


# ── Global Singleton Accessor ────────────────────────────────────────────────

_storage_instance: Optional[SQLiteStorageEngine] = None
_instance_lock = threading.Lock()


def get_storage_engine(db_path: Optional[Union[str, Path]] = None) -> SQLiteStorageEngine:
    """Retrieve or initialize thread-safe global storage engine instance."""
    global _storage_instance
    if _storage_instance is None or db_path is not None:
        with _instance_lock:
            if _storage_instance is None or db_path is not None:
                target_path = db_path or os.getenv("IOTGUARD_DB_PATH", str(DEFAULT_DB_PATH))
                _storage_instance = SQLiteStorageEngine(target_path)
    return _storage_instance
