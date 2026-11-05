"""
tests/test_threat_intel_topology.py
-----------------------------------------------------------------------------
Comprehensive Unit Tests for Threat Intelligence, GeoIP & Network Topology UI
(Phases 5 & 7 Upgrade Verification)
-----------------------------------------------------------------------------
"""

import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

# Ensure repository root and script directories are on sys.path
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "4_response"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "5_dashboard"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "6_threat_intel"))

from threat_intel import ThreatIntel, iso_country_to_flag
import blocker
from blocker import (
    validate_ip,
    block_ip,
    unblock_ip,
    record_block,
    record_unblock,
    get_active_blocks,
    is_ip_blocked,
)


@pytest.fixture
def isolated_blocks_file(tmp_path, monkeypatch):
    """Isolate active blocks storage to a clean temporary file."""
    test_file = tmp_path / "test_active_blocks.json"
    monkeypatch.setattr(blocker, "ACTIVE_BLOCKS_FILE", test_file)
    return test_file


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    """Create a test client for the dashboard Flask application."""
    test_blocks = tmp_path / "test_active_blocks_api.json"
    monkeypatch.setattr(blocker, "ACTIVE_BLOCKS_FILE", test_blocks)

    from api_dashboard import app
    app.config["TESTING"] = True
    app.config["DEBUG"] = False

    with app.test_client() as client:
        yield client


# ============================================================================
# 1. Threat Intelligence & GeoIP Resolver Tests
# ============================================================================

class TestThreatIntel:
    """Unit tests for the ThreatIntel engine, GeoIP fallback, and caching."""

    def test_iso_country_to_flag(self):
        """Verify ISO 3166-1 alpha-2 conversion to Unicode flag emoji."""
        assert iso_country_to_flag("US") == "🇺🇸"
        assert iso_country_to_flag("GB") == "🇬🇧"
        assert iso_country_to_flag("DE") == "🇩🇪"
        assert iso_country_to_flag("EG") == "🇪🇬"
        assert iso_country_to_flag("JP") == "🇯🇵"
        # Edge cases and invalids
        assert iso_country_to_flag(None) == "🏳️"
        assert iso_country_to_flag("") == "🏳️"
        assert iso_country_to_flag("XYZ") == "🏳️"
        assert iso_country_to_flag("A") == "🏳️"

    def test_is_private_ip(self):
        """Verify RFC 1918, loopback, and link-local address classification."""
        ti = ThreatIntel()
        assert ti.is_private_ip("192.168.1.1") is True
        assert ti.is_private_ip("10.0.0.1") is True
        assert ti.is_private_ip("172.16.0.10") is True
        assert ti.is_private_ip("127.0.0.1") is True
        assert ti.is_private_ip("169.254.1.1") is True
        assert ti.is_private_ip("::1") is True

        # Public IPs
        assert ti.is_private_ip("8.8.8.8") is False
        assert ti.is_private_ip("1.1.1.1") is False
        assert ti.is_private_ip("104.244.42.1") is False

        # Invalid strings
        assert ti.is_private_ip("not-an-ip") is False
        assert ti.is_private_ip("") is False
        assert ti.is_private_ip(None) is False

    def test_enrich_private_ip(self):
        """Private IPs should be categorized as LAN without external queries."""
        ti = ThreatIntel()
        data = ti.enrich_ip("192.168.1.45")

        assert data["ip"] == "192.168.1.45"
        assert data["is_private"] is True
        assert data["country"] == "LAN"
        assert data["country_name"] == "Private Network"
        assert data["city"] == "Internal Gateway"
        assert data["flag"] == "🏠"
        assert data["abuse_score"] == 0

    def test_enrich_public_ip_offline_fallback(self):
        """Public IP lookup should resolve deterministically when offline/no mmdb."""
        ti = ThreatIntel(geoip_db_path=None)
        data = ti.enrich_ip("8.8.8.8")

        assert data["ip"] == "8.8.8.8"
        assert data["is_private"] is False
        assert isinstance(data["country"], str)
        assert isinstance(data["flag"], str)
        assert "abuse_score" in data
        assert "isp" in data
        assert "asn" in data

    def test_reputation_database_and_custom_ioc(self):
        """Pre-loaded and runtime IOCs should be detected."""
        ti = ThreatIntel()

        # Built-in IOC
        assert ti.is_known_threat("192.168.1.105") is True
        assert ti.enrich_ip("192.168.1.105")["threat"] == "Mirai Botnet Node"

        # Dynamically added IOC
        assert ti.is_known_threat("198.51.100.77") is False
        ti.add_reputation("198.51.100.77", "Advanced Persistent Threat - C2")
        assert ti.is_known_threat("198.51.100.77") is True
        assert ti.enrich_ip("198.51.100.77")["threat"] == "Advanced Persistent Threat - C2"

    def test_thread_safe_caching_and_invalidation(self):
        """Enriched IPs must be cached in memory and cleared on request."""
        ti = ThreatIntel(cache_ttl=3600)
        assert len(ti._cache) == 0

        res1 = ti.enrich_ip("1.1.1.1")
        assert "1.1.1.1" in ti._cache

        # Subsequent call returns cached object
        res2 = ti.enrich_ip("1.1.1.1")
        assert res1 == res2

        # Cache invalidation
        ti.clear_cache()
        assert len(ti._cache) == 0

    def test_async_enrichment(self):
        """Asynchronous enrichment should invoke callback in background."""
        ti = ThreatIntel()
        captured = {}

        def on_complete(result):
            captured.update(result)

        ti.enrich_ip_async("9.9.9.9", callback=on_complete)
        time.sleep(0.15)  # Allow background worker to complete

        assert captured.get("ip") == "9.9.9.9"
        assert captured.get("is_private") is False


# ============================================================================
# 2. Blocker Active Blocks & Unblock Tests
# ============================================================================

class TestBlockerTrackingAndUnblock:
    """Unit tests for active block tracking and OS rule removal."""

    def test_active_block_lifecycle(self, isolated_blocks_file):
        """Record block, verify persistence, check status, and record unblock."""
        assert is_ip_blocked("192.168.1.80") is False

        record_block("192.168.1.80", severity="hard", reason="SYN Flood", dry_run=True)
        assert is_ip_blocked("192.168.1.80") is True

        blocks = get_active_blocks()
        assert len(blocks) == 1
        assert blocks[0]["ip"] == "192.168.1.80"
        assert blocks[0]["severity"] == "hard"
        assert blocks[0]["reason"] == "SYN Flood"
        assert blocks[0]["dry_run"] is True

        record_unblock("192.168.1.80")
        assert is_ip_blocked("192.168.1.80") is False
        assert len(get_active_blocks()) == 0

    def test_unblock_ip_dry_run(self, isolated_blocks_file):
        """Unblocking in dry-run mode returns success without touching OS."""
        record_block("192.168.1.90", severity="kill", dry_run=True)
        assert is_ip_blocked("192.168.1.90") is True

        ok, msg = unblock_ip("192.168.1.90", dry_run=True)
        assert ok is True
        assert "dry-run-unblocked-192.168.1.90" in msg
        assert is_ip_blocked("192.168.1.90") is False

    def test_unblock_ip_validation_error(self, isolated_blocks_file):
        """Unblocking invalid or empty IPs fails validation."""
        ok, msg = unblock_ip(None)
        assert ok is False
        assert "no ip provided" in msg.lower()

        ok, msg = unblock_ip("bad;ip;address")
        assert ok is False
        assert "validation failed" in msg.lower()


# ============================================================================
# 3. Dashboard Topology & Block Control Endpoints
# ============================================================================

class TestTopologyAndBlockApi:
    """Tests for /api/topology, /api/block, /api/unblock, and /api/blocks."""

    def test_api_topology_contract(self, app_client):
        """GET /api/topology returns full graph schema and summary counts."""
        resp = app_client.get("/api/topology")
        assert resp.status_code == 200

        data = resp.get_json()
        assert data.get("ok") is True

        # Graph node/edge schemas
        assert "nodes" in data and isinstance(data["nodes"], list)
        assert "edges" in data and isinstance(data["edges"], list)
        assert "devices" in data and isinstance(data["devices"], list)
        assert "connections" in data and isinstance(data["connections"], list)

        # Summary telemetry strip
        assert "summary" in data
        summary = data["summary"]
        assert "total_devices" in summary
        assert "iot_nodes" in summary
        assert "it_nodes" in summary
        assert "blocked_nodes" in summary
        assert "grace_nodes" in summary
        assert summary["total_devices"] >= 4  # Core nodes always present

        # Node attributes verification
        first_node = data["nodes"][0]
        for field in ("id", "label", "type", "ip", "state", "flag"):
            assert field in first_node, f"Missing field {field} in topology node"

    def test_api_block_and_unblock_workflow(self, app_client):
        """POST /api/block quarantines IP and POST /api/unblock restores it."""
        target_ip = "192.168.1.188"

        # 1. Manual Quarantine
        block_resp = app_client.post(
            "/api/block",
            json={
                "ip": target_ip,
                "severity": "hard",
                "reason": "Suspicious PortScan Activity",
                "dry_run": True,
            },
        )
        assert block_resp.status_code == 200
        block_data = block_resp.get_json()
        assert block_data["ok"] is True
        assert block_data["ip"] == target_ip
        assert block_data["severity"] == "hard"

        # 2. Verify in active blocks endpoint
        list_resp = app_client.get("/api/blocks")
        assert list_resp.status_code == 200
        active_list = list_resp.get_json()["blocks"]
        assert any(b["ip"] == target_ip for b in active_list)

        # 3. Topology should reflect state BLOCKED for this node
        topo_resp = app_client.get("/api/topology")
        topo_nodes = topo_resp.get_json()["nodes"]
        node_entry = next((n for n in topo_nodes if n.get("ip") == target_ip), None)
        assert node_entry is not None
        assert node_entry["state"] == "BLOCKED"

        # 4. Manual Unblock
        unblock_resp = app_client.post(
            "/api/unblock",
            json={"ip": target_ip, "dry_run": True},
        )
        assert unblock_resp.status_code == 200
        unblock_data = unblock_resp.get_json()
        assert unblock_data["ok"] is True
        assert unblock_data["ip"] == target_ip

        # 5. Verify removal
        list_resp2 = app_client.get("/api/blocks")
        active_list2 = list_resp2.get_json()["blocks"]
        assert not any(b["ip"] == target_ip for b in active_list2)

    def test_api_block_missing_ip_rejected(self, app_client):
        """POST /api/block with empty payload returns 400."""
        resp = app_client.post("/api/block", json={})
        assert resp.status_code == 400
        assert resp.get_json()["ok"] is False

    def test_api_unblock_missing_ip_rejected(self, app_client):
        """POST /api/unblock with empty payload returns 400."""
        resp = app_client.post("/api/unblock", json={})
        assert resp.status_code == 400
        assert resp.get_json()["ok"] is False

    def test_api_block_invalid_ip_rejected(self, app_client):
        """POST /api/block with invalid/injected IP returns 400."""
        resp = app_client.post("/api/block", json={"ip": "10.0.0.1; rm -rf /"})
        assert resp.status_code == 400
        assert resp.get_json()["ok"] is False
