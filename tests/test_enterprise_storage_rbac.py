"""Tests for Enterprise Phase 8: High-Performance Indexed Storage Engine,
Enterprise RBAC, and Tamper-Evident Cryptographic Audit Ledger.
"""

import json
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path
import pytest

from storage_engine import SQLiteStorageEngine, get_storage_engine
from audit_ledger import (
    AuditLedger,
    compute_entry_hash,
    GENESIS_PREV_HASH,
    record_audit_event,
    verify_audit_ledger,
    get_audit_ledger,
)
from auth import (
    ROLE_ADMIN,
    ROLE_SOC_ANALYST,
    ROLE_AUDITOR,
    ROLE_EDGE_SENSOR,
    create_token,
    validate_token,
    register_api_key,
    validate_api_key,
    revoke_api_key,
    list_api_keys,
)
import auth as auth_mod
import api_dashboard as api_mod
from event_logger import EventLogger
from blocker import record_block, record_unblock


@pytest.fixture
def temp_env():
    """Create isolated temporary directory for db and log files."""
    tmp_dir = tempfile.mkdtemp(prefix="iotguard_test_")
    db_path = Path(tmp_dir) / "test_iotguard.db"
    jsonl_path = Path(tmp_dir) / "test_audit.jsonl"
    alerts_path = Path(tmp_dir) / "test_alerts.jsonl"
    blocks_path = Path(tmp_dir) / "test_blocks.json"

    yield {
        "dir": tmp_dir,
        "db_path": db_path,
        "jsonl_path": jsonl_path,
        "alerts_path": alerts_path,
        "blocks_path": blocks_path,
    }

    shutil.rmtree(tmp_dir, ignore_errors=True)


# =====================================================================
# 1. STORAGE ENGINE TESTS
# =====================================================================

def test_storage_engine_initialization_and_wal(temp_env):
    """Verify SQLite WAL mode, foreign keys, and table creation."""
    engine = SQLiteStorageEngine(db_path=temp_env["db_path"])
    conn = engine._get_connection()
    cursor = conn.cursor()

    # Check journal mode is WAL
    cursor.execute("PRAGMA journal_mode;")
    mode = cursor.fetchone()[0]
    assert mode.upper() == "WAL"

    # Check tables exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row[0] for row in cursor.fetchall()}
    assert {"security_events", "active_blocks", "edge_nodes", "audit_ledger"}.issubset(tables)
    engine.close()


def test_storage_engine_concurrent_writes(temp_env):
    """Test high-concurrency multithreaded writes without database locking errors."""
    engine = SQLiteStorageEngine(db_path=temp_env["db_path"])
    num_threads = 8
    events_per_thread = 25
    errors = []

    def worker(thread_id):
        try:
            for i in range(events_per_thread):
                evt = {
                    "timestamp": time.time(),
                    "src_ip": f"192.168.1.{thread_id + 1}",
                    "score": 0.5 + (i * 0.01),
                    "attack_category": "DDoS-SYN" if i % 2 == 0 else "PortScan",
                    "response_tier": "RATE_LIMIT" if i % 2 == 0 else "HARD_BLOCK",
                    "features": {"flows": 100 + i},
                    "playbook": {"name": "test_pb"},
                }
                engine.insert_event(evt)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(tid,)) for tid in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Concurrent write errors: {errors}"
    total = engine.count_events()
    assert total == num_threads * events_per_thread
    engine.close()


def test_storage_engine_multidimensional_queries(temp_env):
    """Test indexed queries across IP, category, score range, tier, and time range."""
    engine = SQLiteStorageEngine(db_path=temp_env["db_path"])
    base_ts = 1700000000.0

    # Insert seeded events
    engine.insert_event({
        "timestamp": base_ts + 10,
        "src_ip": "10.0.0.1",
        "score": 0.95,
        "attack_category": "DDoS-SYN",
        "response_tier": "HARD_BLOCK",
    })
    engine.insert_event({
        "timestamp": base_ts + 20,
        "src_ip": "10.0.0.2",
        "score": 0.65,
        "attack_category": "PortScan",
        "response_tier": "RATE_LIMIT",
    })
    engine.insert_event({
        "timestamp": base_ts + 30,
        "src_ip": "10.0.0.1",
        "score": 0.40,
        "attack_category": "Benign",
        "response_tier": "MONITOR",
    })

    # Query by IP
    res_ip = engine.query_events(src_ip="10.0.0.1")
    assert len(res_ip) == 2

    # Query by Category
    res_cat = engine.query_events(category="PortScan")
    assert len(res_cat) == 1
    assert res_cat[0]["src_ip"] == "10.0.0.2"

    # Query by Score Range
    res_score = engine.query_events(min_score=0.60, max_score=0.90)
    assert len(res_score) == 1
    assert res_score[0]["src_ip"] == "10.0.0.2"

    # Query by Response Tier
    res_tier = engine.query_events(response_tier="HARD_BLOCK")
    assert len(res_tier) == 1
    assert res_tier[0]["src_ip"] == "10.0.0.1"

    # Query by Time Range
    res_time = engine.query_events(start_ts=base_ts + 15, end_ts=base_ts + 35)
    assert len(res_time) == 2

    # Query with Pagination
    res_page = engine.query_events(limit=2, offset=0)
    assert len(res_page) == 2

    engine.close()


def test_storage_engine_active_blocks_and_edge_nodes(temp_env):
    """Test recording and updating active blocks and edge node heartbeats."""
    engine = SQLiteStorageEngine(db_path=temp_env["db_path"])

    # Record block
    now = time.time()
    engine.record_block("192.168.1.100", now, duration=300, reason="DDoS", dry_run=False, backend="nftables")
    active = engine.get_active_blocks(active_only=True)
    assert "192.168.1.100" in active
    assert active["192.168.1.100"]["status"] == "active"

    # Record unblock
    engine.record_unblock("192.168.1.100", unblock_time=now + 50, reason="manual_test")
    active_after = engine.get_active_blocks(active_only=True)
    assert "192.168.1.100" not in active_after

    all_blocks = engine.get_active_blocks(active_only=False)
    assert "192.168.1.100" in all_blocks
    assert all_blocks["192.168.1.100"]["status"] == "unblocked"

    # Edge node upsert
    engine.upsert_edge_node("node-alpha", ip="10.1.1.5", status="ONLINE", last_seen=now, metadata={"version": "4.0"})
    nodes = engine.get_edge_nodes()
    assert len(nodes) == 1
    assert nodes[0]["node_id"] == "node-alpha"
    assert nodes[0]["metadata"]["version"] == "4.0"

    engine.close()


# =====================================================================
# 2. CRYPTOGRAPHIC AUDIT LEDGER TESTS
# =====================================================================

def test_audit_ledger_genesis_and_chaining(temp_env):
    """Test that audit events form a valid cryptographic SHA-256 hash chain."""
    engine = SQLiteStorageEngine(db_path=temp_env["db_path"])
    ledger = AuditLedger(storage_engine=engine, jsonl_path=temp_env["jsonl_path"])

    # First entry (Genesis)
    e0 = ledger.record_action(actor="admin", action="POLICY_UPDATE", payload={"threshold": 0.85})
    assert e0["index"] == 0
    assert e0["prev_hash"] == GENESIS_PREV_HASH
    assert e0["entry_hash"] == compute_entry_hash(GENESIS_PREV_HASH, e0["timestamp"], "admin", "POLICY_UPDATE", {"threshold": 0.85})

    # Second entry
    e1 = ledger.record_action(actor="soc_analyst", action="MANUAL_BLOCK", payload={"ip": "10.0.0.50"})
    assert e1["index"] == 1
    assert e1["prev_hash"] == e0["entry_hash"]

    # Third entry
    e2 = ledger.record_action(actor="admin", action="USER_LOGIN", payload={"ip": "127.0.0.1"})
    assert e2["index"] == 2
    assert e2["prev_hash"] == e1["entry_hash"]

    # Verify integrity
    verified, reason, idx = ledger.verify_chain()
    assert verified is True
    assert reason == "INTEGRITY_VERIFIED"
    assert idx is None

    # Check JSONL output also matches
    with open(temp_env["jsonl_path"], "r", encoding="utf-8") as f:
        lines = [json.loads(line) for line in f]
    assert len(lines) == 3
    assert lines[0]["entry_hash"] == e0["entry_hash"]
    assert lines[1]["entry_hash"] == e1["entry_hash"]
    assert lines[2]["entry_hash"] == e2["entry_hash"]

    engine.close()


def test_audit_ledger_tamper_detection(temp_env):
    """Verify that tampering with an entry in the ledger breaks hash verification."""
    engine = SQLiteStorageEngine(db_path=temp_env["db_path"])
    ledger = AuditLedger(storage_engine=engine, jsonl_path=temp_env["jsonl_path"])

    ledger.record_action(actor="admin", action="LOGIN", payload={"status": "ok"})
    ledger.record_action(actor="analyst", action="BLOCK", payload={"ip": "1.2.3.4"})
    ledger.record_action(actor="admin", action="CONFIG", payload={"rate": 100})

    # Un-tampered verify
    ok, _, _ = ledger.verify_chain()
    assert ok is True

    # Maliciously modify index 1 payload in the database
    conn = engine._get_connection()
    with conn:
        conn.execute("UPDATE audit_ledger SET payload = ? WHERE id = 2", (json.dumps({"ip": "5.6.7.8"}),))

    # Verify must detect the tampering at index 1
    ok, reason, bad_idx = ledger.verify_chain()
    assert ok is False
    assert "HASH_MISMATCH" in reason
    assert bad_idx == 1

    engine.close()


def test_audit_ledger_broken_link_tamper(temp_env):
    """Verify that altering prev_hash triggers LINK_BROKEN."""
    engine = SQLiteStorageEngine(db_path=temp_env["db_path"])
    ledger = AuditLedger(storage_engine=engine, jsonl_path=temp_env["jsonl_path"])

    ledger.record_action(actor="admin", action="ACT1", payload={})
    ledger.record_action(actor="admin", action="ACT2", payload={})

    conn = engine._get_connection()
    with conn:
        conn.execute("UPDATE audit_ledger SET prev_hash = ? WHERE id = 2", ("f" * 64,))

    ok, reason, bad_idx = ledger.verify_chain()
    assert ok is False
    assert "CHAIN_BROKEN" in reason or "LINK_BROKEN" in reason
    assert bad_idx == 1

    engine.close()


# =====================================================================
# 3. ENTERPRISE RBAC & API KEY TESTS
# =====================================================================

def test_api_key_lifecycle():
    """Test generating, registering, validating, and revoking API keys."""
    key = register_api_key(
        name="edge-node-1",
        role=ROLE_EDGE_SENSOR,
        created_by="admin",
        rate_limit=500,
    )
    assert key.startswith("iotguard_")

    info = validate_api_key(key)
    assert info is not None
    assert info["role"] == ROLE_EDGE_SENSOR
    assert info["name"] == "edge-node-1"

    keys_list = list_api_keys()
    assert any(k["name"] == "edge-node-1" for k in keys_list)

    # Revoke key
    revoked = revoke_api_key(key)
    assert revoked is True
    assert validate_api_key(key) is None


def test_token_creation_with_roles():
    """Test JWT creation and role embedding."""
    token = create_token("alice", role=ROLE_SOC_ANALYST)
    valid, claims, _ = validate_token(token)
    assert valid is True
    assert claims is not None
    assert claims["sub"] == "alice"
    assert claims["role"] == ROLE_SOC_ANALYST

    # Backward compatibility: role defaults to ADMIN if omitted
    token_def = create_token("bob")
    valid_def, claims_def, _ = validate_token(token_def)
    assert valid_def is True
    assert claims_def is not None
    assert claims_def["role"] == ROLE_ADMIN


# =====================================================================
# 4. DASHBOARD RBAC & ENDPOINT ACCESS CONTROL TESTS
# =====================================================================

@pytest.fixture
def auth_client():
    """Create Flask test client with auth enforcement configured."""
    api_mod.app.config["TESTING"] = True
    orig_pass = auth_mod.AUTH_PASS
    auth_mod.AUTH_PASS = "Secr3tTestPass!"

    client = api_mod.app.test_client()
    yield client

    auth_mod.AUTH_PASS = orig_pass


def test_rbac_admin_full_access(auth_client):
    """Test that ADMIN has access to admin endpoints and audit logs."""
    admin_token = create_token("admin_user", role=ROLE_ADMIN)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Access /api/config
    resp = auth_client.post("/api/config", headers=headers, json={"dry_run": True})
    assert resp.status_code == 200

    # Access /api/v1/audit
    resp_audit = auth_client.get("/api/v1/audit", headers=headers)
    assert resp_audit.status_code == 200
    data = json.loads(resp_audit.data)
    assert "entries" in data

    # Access /api/v1/audit/verify
    resp_verify = auth_client.get("/api/v1/audit/verify", headers=headers)
    assert resp_verify.status_code == 200
    vdata = json.loads(resp_verify.data)
    assert vdata["status"] == "INTEGRITY_VERIFIED"


def test_rbac_soc_analyst_permissions(auth_client):
    """Test SOC_ANALYST can block/unblock, but CANNOT access /api/config or /api/clear."""
    soc_token = create_token("analyst_bob", role=ROLE_SOC_ANALYST)
    headers = {"Authorization": f"Bearer {soc_token}"}

    # Block IP allowed for SOC_ANALYST
    resp_block = auth_client.post(
        "/api/block",
        headers=headers,
        json={"ip": "198.51.100.22", "duration": 120, "reason": "pytest_analyst"},
    )
    assert resp_block.status_code == 200

    # View audit allowed
    resp_audit = auth_client.get("/api/v1/audit", headers=headers)
    assert resp_audit.status_code == 200

    # Setting config FORBIDDEN (403)
    resp_cfg = auth_client.post(
        "/api/config",
        headers=headers,
        json={"dry_run": True},
    )
    assert resp_cfg.status_code == 403

    # Clearing logs FORBIDDEN (403)
    resp_clr = auth_client.post("/api/clear", headers=headers)
    assert resp_clr.status_code == 403


def test_rbac_auditor_permissions(auth_client):
    """Test AUDITOR can view audit trail and verify integrity, but cannot block or configure."""
    auditor_token = create_token("auditor_eve", role=ROLE_AUDITOR)
    headers = {"Authorization": f"Bearer {auditor_token}"}

    # View audit allowed
    resp_audit = auth_client.get("/api/v1/audit", headers=headers)
    assert resp_audit.status_code == 200

    # Verify audit allowed
    resp_verify = auth_client.get("/api/v1/audit/verify", headers=headers)
    assert resp_verify.status_code == 200

    # Block FORBIDDEN (403)
    resp_block = auth_client.post(
        "/api/block",
        headers=headers,
        json={"ip": "198.51.100.23", "duration": 120},
    )
    assert resp_block.status_code == 403

    # Config FORBIDDEN (403)
    resp_cfg = auth_client.post("/api/config", headers=headers, json={"dry_run": True})
    assert resp_cfg.status_code == 403


def test_api_key_header_authentication(auth_client):
    """Test authentication via X-IoTGuard-API-Key header."""
    soc_key = register_api_key("soc-automation", role=ROLE_SOC_ANALYST, created_by="admin")
    headers = {"X-IoTGuard-API-Key": soc_key}

    # Query /api/events with API Key
    resp = auth_client.get("/api/events", headers=headers)
    assert resp.status_code == 200

    # Block IP with API Key
    resp_block = auth_client.post(
        "/api/block",
        headers=headers,
        json={"ip": "198.51.100.45", "duration": 60, "reason": "api_key_test"},
    )
    assert resp_block.status_code == 200


def test_dual_write_persistence_integration(temp_env):
    """Verify dual-write to both legacy files and relational storage engine."""
    # Test logging event dual write
    ev_logger = EventLogger(alert_path=str(temp_env["alerts_path"]))
    ev_logger.log_event(
        idx=42,
        score=0.99,
        state_text="HARD_BLOCK",
        hits=1,
        action="BLOCK",
        src_ip="198.51.100.99",
        attack_category="CommandInjection",
        reason="Test Dual Write",
    )

    # Check alerts.jsonl has event
    assert temp_env["alerts_path"].exists()

    # Check database has event
    engine = get_storage_engine()
    results = engine.query_events(src_ip="198.51.100.99")
    assert len(results) >= 1
    assert results[0]["attack_category"] == "CommandInjection"

    # Test record block dual write
    record_block("198.51.100.99", time.time(), duration=600, reason="DualWriteTest", dry_run=True, backend="test")
    active_in_db = engine.get_active_blocks(active_only=True)
    assert "198.51.100.99" in active_in_db

    record_unblock("198.51.100.99", reason="DualWriteTestUnblock")
    active_after = engine.get_active_blocks(active_only=True)
    assert "198.51.100.99" not in active_after
