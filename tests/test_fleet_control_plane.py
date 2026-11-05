"""
tests/test_fleet_control_plane.py
-----------------------------------------------------------------------------
IoTGuard Enterprise v4.0 — Fleet Control Plane & Edge Sensor Verification

Tests:
  1. HMAC-SHA256 request signing and verification.
  2. Replay-attack prevention (60-second window boundary checks).
  3. Edge node registration, secret generation, and metadata persistence.
  4. Heartbeat telemetry ingestion (CPU, RAM, XDP drops, alerts).
  5. Model synchronization status detection (synced vs outdated).
  6. Fleet-wide block broadcast & herd immunity quarantine propagation.
  7. EdgeSensorAgent client integration and automated local block enforcement.
  8. REST API endpoints (/api/v1/fleet/register, /api/v1/fleet/heartbeat,
     /api/v1/fleet/nodes, /api/v1/fleet/broadcast_block).
-----------------------------------------------------------------------------
"""

import time
import json
import pytest
from pathlib import Path

from edge_agent import (
    compute_hmac_signature,
    verify_hmac_request,
    FleetControlPlane,
    get_fleet_control_plane,
    EdgeSensorAgent,
    get_central_model_hash,
)
from api_dashboard import app
from auth import create_token as generate_token, ROLE_ADMIN, ROLE_SOC_ANALYST


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def fleet_plane():
    """Return a fresh, isolated FleetControlPlane instance."""
    cp = FleetControlPlane()
    cp.clear_fleet()
    cp.set_central_model_hash("central_hash_abc123")
    return cp


@pytest.fixture
def client():
    """Flask test client for API integration tests."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def admin_headers():
    """Return JWT Bearer authorization headers for ADMIN role."""
    token = generate_token(username="admin_soc", role=ROLE_ADMIN)
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# =============================================================================
# 1. HMAC SIGNING & VERIFICATION TESTS
# =============================================================================

def test_compute_and_verify_hmac_signature_success():
    """Verify standard HMAC-SHA256 signature generation and validation."""
    secret = "test_shared_secret_12345"
    now = time.time()
    payload = {"event": "ping", "node_id": "sensor-01"}

    sig = compute_hmac_signature(secret, now, payload)
    assert isinstance(sig, str)
    assert len(sig) == 64  # SHA-256 hex digest length

    is_valid, reason = verify_hmac_request(secret, sig, now, payload)
    assert is_valid is True
    assert reason == "OK"


def test_tampered_payload_fails_hmac_verification():
    """Verify that tampering with any field in the body invalidates the signature."""
    secret = "test_shared_secret_12345"
    now = time.time()
    original_payload = {"cpu_pct": 25.0, "active_xdp_drops": 100}
    sig = compute_hmac_signature(secret, now, original_payload)

    # Tampered payload
    tampered_payload = {"cpu_pct": 25.0, "active_xdp_drops": 9999}
    is_valid, reason = verify_hmac_request(secret, sig, now, tampered_payload)
    assert is_valid is False
    assert "mismatch" in reason.lower()


def test_tampered_secret_fails_hmac_verification():
    """Verify that using an incorrect secret fails validation."""
    secret = "correct_secret"
    wrong_secret = "wrong_secret"
    now = time.time()
    payload = "hello_world"

    sig = compute_hmac_signature(secret, now, payload)
    is_valid, reason = verify_hmac_request(wrong_secret, sig, now, payload)
    assert is_valid is False
    assert "mismatch" in reason.lower()


# =============================================================================
# 2. REPLAY-ATTACK PREVENTION TESTS
# =============================================================================

def test_replay_attack_rejected_timestamp_in_past():
    """Verify that requests with timestamps older than 60s are rejected."""
    secret = "replay_test_secret"
    past_timestamp = time.time() - 75.0  # 75s in the past (exceeds 60s window)
    payload = {"telemetry": "sample"}

    sig = compute_hmac_signature(secret, past_timestamp, payload)
    is_valid, reason = verify_hmac_request(secret, sig, past_timestamp, payload, max_skew_sec=60.0)

    assert is_valid is False
    assert "replay attack" in reason.lower()


def test_replay_attack_rejected_timestamp_in_future():
    """Verify that requests with timestamps skewed into the future are rejected."""
    secret = "replay_test_secret"
    future_timestamp = time.time() + 90.0  # 90s in the future
    payload = {"telemetry": "sample"}

    sig = compute_hmac_signature(secret, future_timestamp, payload)
    is_valid, reason = verify_hmac_request(secret, sig, future_timestamp, payload, max_skew_sec=60.0)

    assert is_valid is False
    assert "replay attack" in reason.lower()


def test_timestamp_within_window_accepted():
    """Verify that requests within the 60s window pass replay protection."""
    secret = "replay_test_secret"
    recent_timestamp = time.time() - 15.0  # 15s in the past (valid)
    payload = {"telemetry": "sample"}

    sig = compute_hmac_signature(secret, recent_timestamp, payload)
    is_valid, reason = verify_hmac_request(secret, sig, recent_timestamp, payload, max_skew_sec=60.0)

    assert is_valid is True
    assert reason == "OK"


# =============================================================================
# 3. FLEET CONTROL PLANE REGISTRATION & STATE
# =============================================================================

def test_control_plane_register_node(fleet_plane):
    """Verify node registration assigns secret and initializes telemetry state."""
    res = fleet_plane.register_node(
        node_id="substation_edge_01",
        site_type="substation_edge",
        hostname="substation-gw-1",
        ip="10.200.1.5",
        capabilities=["ebpf_xdp", "nftables"],
        model_hash="central_hash_abc123"
    )

    assert res["ok"] is True
    assert res["node_id"] == "substation_edge_01"
    assert "secret" in res
    assert len(res["secret"]) >= 32

    node = fleet_plane.get_node("substation_edge_01")
    assert node is not None
    assert node["site_type"] == "substation_edge"
    assert node["status"] == "online"
    assert node["model_sync_status"] == "synced"


def test_control_plane_empty_node_id_rejected(fleet_plane):
    """Verify that registering with empty node_id raises ValueError."""
    with pytest.raises(ValueError):
        fleet_plane.register_node(node_id="")


def test_control_plane_unknown_node_heartbeat_raises_keyerror(fleet_plane):
    """Verify recording heartbeat for an unregistered node raises KeyError."""
    with pytest.raises(KeyError):
        fleet_plane.record_heartbeat("ghost_node_999", {"cpu_pct": 10.0})


# =============================================================================
# 4. HEARTBEAT & TELEMETRY INGESTION TESTS
# =============================================================================

def test_heartbeat_telemetry_updates_metrics(fleet_plane):
    """Verify telemetry updates CPU, RAM, XDP drops, and latency."""
    fleet_plane.register_node("hospital_iot_vlan", site_type="hospital_iot_vlan")

    now = time.time()
    telemetry = {
        "timestamp": now - 0.05,  # 50ms latency simulation
        "cpu_pct": 28.5,
        "ram_pct": 52.1,
        "active_xdp_drops": 4520,
        "active_blocks_count": 7,
        "local_model_hash": "central_hash_abc123",
    }

    ack = fleet_plane.record_heartbeat("hospital_iot_vlan", telemetry)
    assert ack["ok"] is True
    assert ack["status"] == "acknowledged"
    assert ack["model_sync_status"] == "synced"

    node = fleet_plane.get_node("hospital_iot_vlan")
    assert node["cpu_pct"] == 28.5
    assert node["ram_pct"] == 52.1
    assert node["active_xdp_drops"] == 4520
    assert node["active_blocks_count"] == 7
    assert node["latency_ms"] > 0


def test_model_sync_status_detection(fleet_plane):
    """Verify that outdated model hashes are flagged as 'outdated'."""
    fleet_plane.register_node("factory_floor_02", model_hash="outdated_hash_999")

    telemetry = {
        "timestamp": time.time(),
        "local_model_hash": "outdated_hash_999",
    }
    ack = fleet_plane.record_heartbeat("factory_floor_02", telemetry)

    assert ack["model_sync_status"] == "outdated"
    assert ack["central_model_hash"] == "central_hash_abc123"

    # Now simulate node updating its model to the central hash
    telemetry["local_model_hash"] = "central_hash_abc123"
    ack2 = fleet_plane.record_heartbeat("factory_floor_02", telemetry)
    assert ack2["model_sync_status"] == "synced"


# =============================================================================
# 5. FLEET-WIDE BLOCK PROPAGATION & HERD IMMUNITY
# =============================================================================

def test_fleet_wide_block_broadcast_and_queue(fleet_plane):
    """Verify broadcasting an IP creates an entry that reaches edge nodes on heartbeat."""
    fleet_plane.register_node("smart_home_gateway", site_type="smart_home")

    # Broadcast high-severity threat from central SOC
    block_entry = fleet_plane.broadcast_global_block(
        ip="198.51.100.77",
        reason="Mirai Botnet C2 Flood",
        severity="KILL",
        source="central_soc_operator"
    )

    assert block_entry["ip"] == "198.51.100.77"
    assert block_entry["severity"] == "KILL"

    # Edge node sends heartbeat
    ack = fleet_plane.record_heartbeat("smart_home_gateway", {"cpu_pct": 12.0})

    # Edge node should receive the pending global block
    assert len(ack["global_blocks"]) == 1
    assert ack["global_blocks"][0]["ip"] == "198.51.100.77"
    assert ack["global_blocks"][0]["severity"] == "KILL"

    # Next heartbeat should not repeat the block (already synced)
    ack_subsequent = fleet_plane.record_heartbeat("smart_home_gateway", {"cpu_pct": 12.5})
    assert len(ack_subsequent["global_blocks"]) == 0


def test_herd_immunity_across_multiple_branch_nodes(fleet_plane):
    """Verify that multiple remote edge sensors all receive the broadcasted quarantine."""
    node_ids = ["branch_chicago", "branch_london", "branch_tokyo"]
    for nid in node_ids:
        fleet_plane.register_node(nid, site_type="branch_office")

    fleet_plane.broadcast_global_block(
        ip="203.0.113.88",
        reason="Zero-Day DDoS Flood",
        severity="KILL"
    )

    # All nodes must pull the block on their next heartbeat
    for nid in node_ids:
        ack = fleet_plane.record_heartbeat(nid, {"cpu_pct": 15.0})
        ips = [b["ip"] for b in ack["global_blocks"]]
        assert "203.0.113.88" in ips


# =============================================================================
# 6. EDGE SENSOR AGENT CLIENT TESTS
# =============================================================================

def test_edge_sensor_agent_initialization_and_signing():
    """Verify EdgeSensorAgent generates properly signed request headers."""
    agent = EdgeSensorAgent(
        node_id="sensor_node_01",
        site_type="smart_home",
        secret="agent_secret_key_443",
        dry_run=True,
    )

    body = {"test": 123}
    headers = agent.get_auth_headers(body)

    assert headers["X-IoTGuard-Node-Id"] == "sensor_node_01"
    assert "X-IoTGuard-Signature" in headers
    assert "X-IoTGuard-Timestamp" in headers
    assert len(headers["X-IoTGuard-Signature"]) == 64


def test_edge_sensor_agent_enforces_blocks_locally():
    """Verify agent enforce_global_blocks updates its local active defense state."""
    agent = EdgeSensorAgent(node_id="sensor_01", dry_run=True)

    blocks = [
        {"ip": "198.51.100.11", "severity": "KILL", "reason": "C2 Botnet", "block_id": "b1"},
        {"ip": "198.51.100.22", "severity": "HARD", "reason": "SYN Flood", "block_id": "b2"},
    ]

    count = agent.enforce_global_blocks(blocks)
    assert count == 2
    assert "198.51.100.11" in agent.enforced_blocks
    assert "198.51.100.22" in agent.enforced_blocks
    assert agent.enforced_blocks["198.51.100.11"]["severity"] == "kill"

    # Enforcing again ignores already active blocks
    assert agent.enforce_global_blocks(blocks) == 0


# =============================================================================
# 7. REST API ENDPOINTS INTEGRATION TESTS
# =============================================================================

def test_api_fleet_register_endpoint(client):
    """Test POST /api/v1/fleet/register registers a node via HTTP."""
    payload = {
        "node_id": "remote_edge_alpha",
        "site_type": "factory_floor",
        "hostname": "alpha-gateway",
        "capabilities": ["ebpf_xdp"],
    }

    resp = client.post("/api/v1/fleet/register", json=payload)
    assert resp.status_code == 201

    data = resp.get_json()
    assert data["ok"] is True
    assert data["node_id"] == "remote_edge_alpha"
    assert "secret" in data
    assert len(data["secret"]) >= 32


def test_api_fleet_register_missing_node_id_rejected(client):
    """Test POST /api/v1/fleet/register without node_id returns 400."""
    resp = client.post("/api/v1/fleet/register", json={"site_type": "smart_home"})
    assert resp.status_code == 400
    data = resp.get_json()
    assert "node_id" in data.get("error", "").lower()


def test_api_fleet_heartbeat_authenticated_flow(client):
    """Test end-to-end registration -> signed heartbeat flow over REST API."""
    # 1. Register node
    reg_resp = client.post(
        "/api/v1/fleet/register",
        json={"node_id": "sensor_beta_01", "site_type": "substation_edge"}
    )
    secret = reg_resp.get_json()["secret"]

    # 2. Build signed heartbeat payload
    telemetry = {
        "node_id": "sensor_beta_01",
        "timestamp": time.time(),
        "cpu_pct": 21.4,
        "ram_pct": 43.8,
        "active_xdp_drops": 128,
        "active_blocks_count": 2,
    }
    raw_body = json.dumps(telemetry, sort_keys=True, separators=(",", ":"))
    sig = compute_hmac_signature(secret, telemetry["timestamp"], raw_body)

    headers = {
        "X-IoTGuard-Node-Id": "sensor_beta_01",
        "X-IoTGuard-Signature": sig,
        "X-IoTGuard-Timestamp": str(telemetry["timestamp"]),
        "Content-Type": "application/json",
    }

    hb_resp = client.post("/api/v1/fleet/heartbeat", data=raw_body, headers=headers)
    assert hb_resp.status_code == 200

    data = hb_resp.get_json()
    assert data["ok"] is True
    assert data["status"] == "acknowledged"


def test_api_fleet_heartbeat_missing_headers_returns_401(client):
    """Test POST /api/v1/fleet/heartbeat with missing HMAC headers returns 401."""
    resp = client.post("/api/v1/fleet/heartbeat", json={"cpu_pct": 20.0})
    assert resp.status_code == 401
    assert "Missing HMAC" in resp.get_json().get("error", "")


def test_api_fleet_heartbeat_invalid_signature_returns_401(client):
    """Test POST /api/v1/fleet/heartbeat with invalid signature returns 401."""
    # Register node
    client.post("/api/v1/fleet/register", json={"node_id": "sensor_gamma_01"})

    headers = {
        "X-IoTGuard-Node-Id": "sensor_gamma_01",
        "X-IoTGuard-Signature": "invalid_hex_signature_0000000000000000000000000000000000000000",
        "X-IoTGuard-Timestamp": str(time.time()),
        "Content-Type": "application/json",
    }
    resp = client.post("/api/v1/fleet/heartbeat", data="{}", headers=headers)
    assert resp.status_code == 401
    assert "mismatch" in resp.get_json().get("error", "").lower()


def test_api_fleet_heartbeat_replay_drift_returns_401(client):
    """Test POST /api/v1/fleet/heartbeat with clock drift > 60s returns 401."""
    reg_resp = client.post("/api/v1/fleet/register", json={"node_id": "sensor_delta_01"})
    secret = reg_resp.get_json()["secret"]

    drifted_ts = time.time() - 120.0  # 2 minutes ago
    raw_body = "{}"
    sig = compute_hmac_signature(secret, drifted_ts, raw_body)

    headers = {
        "X-IoTGuard-Node-Id": "sensor_delta_01",
        "X-IoTGuard-Signature": sig,
        "X-IoTGuard-Timestamp": str(drifted_ts),
        "Content-Type": "application/json",
    }
    resp = client.post("/api/v1/fleet/heartbeat", data=raw_body, headers=headers)
    assert resp.status_code == 401
    assert "replay attack" in resp.get_json().get("error", "").lower()


def test_api_fleet_nodes_endpoint(client):
    """Test GET /api/v1/fleet/nodes returns live status across all edge gateways."""
    # Register two nodes
    client.post("/api/v1/fleet/register", json={"node_id": "gw_office_01", "site_type": "office"})
    client.post("/api/v1/fleet/register", json={"node_id": "gw_factory_01", "site_type": "factory_floor"})

    resp = client.get("/api/v1/fleet/nodes")
    assert resp.status_code == 200

    data = resp.get_json()
    assert data["ok"] is True
    assert data["total_nodes"] >= 2

    node_ids = [n["node_id"] for n in data["nodes"]]
    assert "gw_office_01" in node_ids
    assert "gw_factory_01" in node_ids


def test_api_fleet_broadcast_block_admin_only(client, admin_headers):
    """Test POST /api/v1/fleet/broadcast_block pushes global quarantine."""
    payload = {
        "ip": "198.51.100.123",
        "severity": "KILL",
        "reason": "Mirai botnet sweeping port scan",
        "dry_run": True,
    }

    # Request with insufficient role (e.g. AUDITOR) is rejected with 403 Forbidden
    auditor_token = generate_token(username="auditor_user", role="AUDITOR")
    auditor_headers = {"Authorization": f"Bearer {auditor_token}", "Content-Type": "application/json"}
    unauth_resp = client.post("/api/v1/fleet/broadcast_block", json=payload, headers=auditor_headers)
    assert unauth_resp.status_code == 403

    # Request with invalid token is rejected with 401
    bad_token_headers = {"Authorization": "Bearer invalid_jwt_token", "Content-Type": "application/json"}
    bad_resp = client.post("/api/v1/fleet/broadcast_block", json=payload, headers=bad_token_headers)
    assert bad_resp.status_code == 401

    # Request with ADMIN auth succeeds
    auth_resp = client.post("/api/v1/fleet/broadcast_block", json=payload, headers=admin_headers)
    assert auth_resp.status_code == 200

    data = auth_resp.get_json()
    assert data["ok"] is True
    assert data["ip"] == "198.51.100.123"
    assert "Global herd immunity" in data.get("message", "")


def test_manual_kill_block_triggers_fleet_broadcast(client, admin_headers):
    """
    Verify that quarantining an IP with severity='KILL' via POST /api/block
    automatically enqueues a global block for herd immunity across the fleet.
    """
    cp = get_fleet_control_plane()
    initial_blocks_count = len(cp.get_global_blocks())

    payload = {
        "ip": "203.0.113.199",
        "severity": "KILL",
        "reason": "Hostile volumetric attack",
        "dry_run": True,
    }

    resp = client.post("/api/block", json=payload, headers=admin_headers)
    assert resp.status_code == 200

    data = resp.get_json()
    assert data["ok"] is True
    assert data.get("fleet_broadcast") is True

    # Check that control plane has recorded the global block
    updated_blocks = cp.get_global_blocks()
    assert len(updated_blocks) == initial_blocks_count + 1
    assert any(b["ip"] == "203.0.113.199" for b in updated_blocks)
