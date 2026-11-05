"""
tests/test_mitre_siem_openapi.py
-----------------------------------------------------------------------------
Unit and integration tests for Enterprise Phase 9:
    1. MITRE ATT&CK® Enterprise & ICS/IoT Enrichment
    2. ArcSight Common Event Format (CEF:0) Formatter
    3. RFC 5424 Syslog Dispatcher (UDP / TCP / TLS)
    4. OASIS STIX 2.1 Threat Sharing Bundle Generator
    5. OpenAPI 3.1.0 Specification & Swagger UI Documentation
    6. SIEM Export API Endpoints (/api/v1/export/stix, /api/v1/export/cef, /api/openapi.json, /api/docs)
-----------------------------------------------------------------------------
"""

import json
import socket
import tempfile
import time
from pathlib import Path
import pytest

from playbooks import (
    TAXONOMIES,
    MITRE_ATTACK_MAP,
    DEFAULT_MITRE,
    get_mitre_attack,
    get_remediation_playbook,
    normalize_taxonomy,
)
from siem_exporter import (
    format_cef_event,
    format_rfc5424_syslog,
    send_syslog,
    generate_stix_bundle,
    IOTGUARD_IDENTITY_ID,
)
from openapi_spec import get_openapi_spec, get_swagger_ui_html
import api_dashboard as api_mod
from event_logger import EventLogger


# =============================================================================
# 1. MITRE ATT&CK® ENRICHMENT TESTS
# =============================================================================

def test_mitre_all_taxonomies_mapped():
    """Verify all 9 canonical attack taxonomies have official MITRE ATT&CK mappings."""
    assert len(TAXONOMIES) == 9
    for taxonomy in TAXONOMIES:
        assert taxonomy in MITRE_ATTACK_MAP, f"Missing MITRE mapping for {taxonomy}"
        mapping = MITRE_ATTACK_MAP[taxonomy]
        assert "tactic_id" in mapping and mapping["tactic_id"].startswith("TA")
        assert "tactic_name" in mapping and len(mapping["tactic_name"]) > 0
        assert "technique_id" in mapping and mapping["technique_id"].startswith("T")
        assert "technique_name" in mapping and len(mapping["technique_name"]) > 0
        assert "url" in mapping and mapping["url"].startswith("https://attack.mitre.org/")
        assert "framework" in mapping


def test_mitre_specific_techniques():
    """Test technique and tactic precision for key attack classes."""
    # DDoS-SYN
    syn = get_mitre_attack("DDoS-SYN")
    assert syn["tactic_id"] == "TA0040"
    assert syn["tactic_name"] == "Impact"
    assert syn["technique_id"] == "T1498.001"
    assert "Direct Network Flood" in syn["technique_name"]

    # Mirai-C2
    mirai = get_mitre_attack("Mirai-C2")
    assert mirai["tactic_id"] == "TA0011"
    assert mirai["tactic_name"] == "Command and Control"
    assert mirai["technique_id"] == "T1071.001"
    assert "Web Protocols" in mirai["technique_name"]
    assert mirai.get("ics_technique_id") == "T0814"

    # PortScan
    scan = get_mitre_attack("PortScan")
    assert scan["tactic_id"] == "TA0043"
    assert scan["tactic_name"] == "Reconnaissance"
    assert scan["technique_id"] == "T1046"
    assert "Network Service Discovery" in scan["technique_name"]

    # SQLInjection
    sqli = get_mitre_attack("SQLInjection")
    assert sqli["tactic_id"] == "TA0001"
    assert sqli["tactic_name"] == "Initial Access"
    assert sqli["technique_id"] == "T1190"

    # BruteForce
    brute = get_mitre_attack("BruteForce")
    assert brute["tactic_id"] == "TA0006"
    assert brute["tactic_name"] == "Credential Access"
    assert brute["technique_id"] == "T1110"

    # ZeroDay-Anomaly (ICS/IoT Impact)
    zday = get_mitre_attack("ZeroDay-Anomaly")
    assert zday["technique_id"] == "T0814"
    assert "Denial of View/Control" in zday["technique_name"]


def test_mitre_raw_label_resolution():
    """Test that informal/raw heuristic labels resolve to correct MITRE metadata."""
    assert get_mitre_attack("syn_flood")["technique_id"] == "T1498.001"
    assert get_mitre_attack("recon: port scan (rst)")["technique_id"] == "T1046"
    assert get_mitre_attack("mirai")["technique_id"] == "T1071.001"
    assert get_mitre_attack("dictionarybruteforce")["technique_id"] == "T1110"
    assert get_mitre_attack("novel anomaly")["technique_id"] == "T0814"


def test_playbook_includes_mitre():
    """Verify get_remediation_playbook attaches MITRE metadata to returned playbook."""
    pb = get_remediation_playbook("DDoS-SYN", src_ip="192.168.1.50")
    assert "mitre" in pb
    assert pb["mitre"]["technique_id"] == "T1498.001"
    assert "192.168.1.50" in pb["firewall_rule"]


def test_event_logger_mitre_attachment():
    """Verify EventLogger.log_event automatically enriches logged alert with MITRE metadata."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        alert_file = Path(tmp_dir) / "alerts.jsonl"
        ev_logger = EventLogger(alert_path=str(alert_file))
        evt = ev_logger.log_event(
            idx=101,
            score=0.96,
            state_text="HARD_BLOCK",
            hits=2,
            action="BLOCK",
            attack_category="PortScan",
            src_ip="10.0.0.99",
        )

        assert "mitre" in evt
        assert evt["mitre"]["technique_id"] == "T1046"
        assert evt["mitre"]["tactic_name"] == "Reconnaissance"

        # Check serialized JSON on disk
        with open(alert_file, "r", encoding="utf-8") as f:
            disk_evt = json.loads(f.readline())
        assert disk_evt["mitre"]["technique_id"] == "T1046"


# =============================================================================
# 2. ARCSIGHT COMMON EVENT FORMAT (CEF) FORMATTER TESTS
# =============================================================================

def test_cef_formatter_structure_and_header():
    """Verify CEF string compliance with ArcSight format and escaping rules."""
    event = {
        "ts": 1700000000.0,
        "score": 0.95,
        "state": "HARD_BLOCK",
        "action": "BLOCK",
        "attack_category": "DDoS-SYN",
        "src_ip": "198.51.100.10",
        "hits_in_window": 5,
        "confidence": 0.985,
        "device_type": "iot",
        "reason": "High SYN ratio (0.95) with small packets",
        "mitre": {
            "tactic_id": "TA0040",
            "tactic_name": "Impact",
            "technique_id": "T1498.001",
            "technique_name": "Direct Network Flood",
        },
    }

    cef_line = format_cef_event(event)

    # 1. Header Validation
    assert cef_line.startswith("CEF:0|IoTGuard|EdgeIPS|4.0|DDoS-SYN|")
    parts = cef_line.split("|")
    assert len(parts) >= 8
    assert parts[0] == "CEF:0"
    assert parts[1] == "IoTGuard"
    assert parts[2] == "EdgeIPS"
    assert parts[3] == "4.0"
    assert parts[4] == "DDoS-SYN"
    assert parts[6] == "8"  # Severity 8 for HARD_BLOCK

    # 2. Extension Key-Value Pairs
    extension = parts[7]
    assert "src=198.51.100.10" in extension
    assert "act=BLOCK" in extension
    assert "cat=DDoS-SYN" in extension
    assert "cnt=5" in extension
    assert "cfp1=0.9500" in extension
    assert "cfp1Label=AnomalyScore" in extension
    assert "cs1=TA0040 - Impact" in extension
    assert "cs1Label=MitreTactic" in extension
    assert "cs2=T1498.001 - Direct Network Flood" in extension
    assert "cs2Label=MitreTechnique" in extension
    assert "cs3=iot" in extension
    assert "cs3Label=DeviceType" in extension
    assert "rt=1700000000000" in extension


def test_cef_escaping_rules():
    """Verify pipe and equals escaping in CEF headers and extensions."""
    tricky_event = {
        "score": 0.99,
        "action": "KILL",
        "state": "KILL",
        "attack_category": "Custom|Pipe|Attack",
        "reason": "Test reason with key=val and backslash \\ and pipe | chars",
        "src_ip": "1.2.3.4",
    }
    cef_line = format_cef_event(tricky_event)
    # Event Class ID should have escaped pipe or replaced
    assert "Custom\\|Pipe\\|Attack" in cef_line or "Custom_Pipe_Attack" in cef_line
    # Extension should escape equals sign
    assert "key\\=val" in cef_line


# =============================================================================
# 3. RFC 5424 SYSLOG DISPATCHER TESTS
# =============================================================================

def test_rfc5424_syslog_formatting():
    """Verify syslog message adheres to RFC 5424 header structure."""
    event = {
        "ts": 1700000000.0,
        "score": 0.92,
        "action": "BLOCK",
        "attack_category": "Mirai-C2",
        "src_ip": "192.168.1.188",
    }

    syslog_msg = format_rfc5424_syslog(event, hostname="edge-gateway-1", app_name="iotguard")

    # Priority check: Facility local0 (16) * 8 + Severity Critical (2) = 130
    assert syslog_msg.startswith("<130>1 ")
    assert " edge-gateway-1 iotguard " in syslog_msg
    assert " Mirai_C2 " in syslog_msg
    assert '[iotguard@53457 src_ip="192.168.1.188" score="0.92" category="Mirai-C2" action="BLOCK"]' in syslog_msg
    assert "CEF:0|IoTGuard|EdgeIPS|4.0|Mirai-C2|" in syslog_msg


def test_send_syslog_udp_localhost():
    """Test transmitting a syslog event over UDP localhost socket."""
    # Set up mock UDP receiver on localhost
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.bind(("127.0.0.1", 0))
    port = recv_sock.getsockname()[1]
    recv_sock.settimeout(2.0)

    test_evt = {
        "ts": time.time(),
        "score": 0.88,
        "action": "RATE_LIMIT",
        "attack_category": "PortScan",
        "src_ip": "10.0.0.55",
    }

    ok, status = send_syslog(test_evt, host="127.0.0.1", port=port, protocol="udp")
    assert ok is True
    assert status == "SENT_UDP"

    data, _ = recv_sock.recvfrom(4096)
    recv_sock.close()
    assert b"PortScan" in data
    assert b"10.0.0.55" in data


def test_send_syslog_graceful_offline_handling():
    """Verify syslog sender reports connection errors cleanly without crashing."""
    # Connecting to unused TCP port with 0.2s timeout
    test_evt = {"score": 0.5, "src_ip": "1.1.1.1"}
    ok, status = send_syslog(test_evt, host="127.0.0.1", port=59999, protocol="tcp", timeout=0.2)
    assert ok is False
    assert len(status) > 0


# =============================================================================
# 4. OASIS STIX 2.1 THREAT SHARING BUNDLE TESTS
# =============================================================================

def test_generate_stix_bundle_structure():
    """Verify STIX 2.1 bundle complies with OASIS spec and contains required SDOs."""
    events = [
        {
            "src_ip": "198.51.100.22",
            "attack_category": "DDoS-SYN",
            "score": 0.97,
            "hits": 15,
            "ts": 1700000000.0,
            "mitre": {
                "technique_id": "T1498.001",
                "technique_name": "Direct Network Flood",
                "tactic_name": "Impact",
                "url": "https://attack.mitre.org/techniques/T1498/001/",
            },
        }
    ]
    active_blocks = {
        "198.51.100.33": {
            "ip": "198.51.100.33",
            "reason": "Mirai-C2",
            "blocked_at": 1700000050.0,
            "drop_count": 100,
        }
    }

    bundle = generate_stix_bundle(events=events, active_blocks=active_blocks)

    # 1. Bundle Root Attributes
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    objects = bundle["objects"]
    assert len(objects) >= 5

    # 2. Identity Object
    identities = [o for o in objects if o["type"] == "identity"]
    assert len(identities) == 1
    assert identities[0]["id"] == IOTGUARD_IDENTITY_ID
    assert identities[0]["name"] == "IoTGuard Edge IPS"

    # 3. Indicator Objects
    indicators = [o for o in objects if o["type"] == "indicator"]
    assert len(indicators) == 2
    patterns = {ind["pattern"] for ind in indicators}
    assert "[ipv4-addr:value = '198.51.100.22']" in patterns
    assert "[ipv4-addr:value = '198.51.100.33']" in patterns
    for ind in indicators:
        assert ind["spec_version"] == "2.1"
        assert ind["pattern_type"] == "stix"
        assert "malicious-activity" in ind["indicator_types"]

    # 4. Attack Pattern Objects
    attack_patterns = [o for o in objects if o["type"] == "attack-pattern"]
    assert len(attack_patterns) >= 1
    ap_names = {ap["name"] for ap in attack_patterns}
    assert "Direct Network Flood" in ap_names or any("Flood" in n for n in ap_names)

    # 5. Relationship Objects
    relationships = [o for o in objects if o["type"] == "relationship"]
    assert len(relationships) >= 2
    for rel in relationships:
        assert rel["relationship_type"] == "indicates"
        assert rel["source_ref"].startswith("indicator--")
        assert rel["target_ref"].startswith("attack-pattern--")

    # 6. Sighting Objects
    sightings = [o for o in objects if o["type"] == "sighting"]
    assert len(sightings) >= 2
    for sight in sightings:
        assert sight["sighting_of_ref"].startswith("indicator--")
        assert IOTGUARD_IDENTITY_ID in sight["where_sighted_refs"]


# =============================================================================
# 5. OPENAPI 3.1 SPECIFICATION & SWAGGER UI TESTS
# =============================================================================

def test_openapi_spec_structure():
    """Verify OpenAPI 3.1 schema completeness, paths, and security schemes."""
    spec = get_openapi_spec()

    assert spec["openapi"] == "3.1.0"
    assert spec["info"]["title"] == "IoTGuard Enterprise REST API"
    assert spec["info"]["version"] == "4.0.0"

    # Required paths
    paths = spec["paths"]
    assert "/api/events" in paths
    assert "/api/latest" in paths
    assert "/api/counts" in paths
    assert "/api/topology" in paths
    assert "/api/block" in paths
    assert "/api/unblock" in paths
    assert "/api/blocks" in paths
    assert "/api/v1/audit" in paths
    assert "/api/v1/audit/verify" in paths
    assert "/api/v1/keys" in paths
    assert "/api/v1/export/stix" in paths
    assert "/api/v1/federated/status" in paths
    assert "/api/v1/federated/round" in paths
    assert "/health/live" in paths
    assert "/health/ready" in paths
    assert "/metrics" in paths

    # Security Schemes
    schemes = spec["components"]["securitySchemes"]
    assert "BearerAuth" in schemes
    assert schemes["BearerAuth"]["scheme"] == "bearer"
    assert "ApiKeyAuth" in schemes
    assert schemes["ApiKeyAuth"]["name"] == "X-IoTGuard-API-Key"


def test_swagger_ui_html_rendering():
    """Verify Swagger UI HTML contains bundle scripts and openapi url link."""
    html = get_swagger_ui_html(openapi_url="/api/openapi.json", title="IoTGuard Test Docs")
    assert "<!DOCTYPE html>" in html
    assert "IoTGuard Test Docs" in html
    assert "swagger-ui-bundle.js" in html
    assert "/api/openapi.json" in html


# =============================================================================
# 6. DASHBOARD SIEM & OPENAPI ENDPOINTS INTEGRATION
# =============================================================================

@pytest.fixture
def client():
    """Flask test client fixture."""
    api_mod.app.config["TESTING"] = True
    return api_mod.app.test_client()


def test_endpoint_openapi_json(client):
    """GET /api/openapi.json returns valid OpenAPI 3.1 JSON schema."""
    resp = client.get("/api/openapi.json")
    assert resp.status_code == 200
    assert resp.content_type == "application/json"
    data = json.loads(resp.data)
    assert data["openapi"] == "3.1.0"
    assert "paths" in data


def test_endpoint_swagger_docs_ui(client):
    """GET /api/docs returns Swagger UI interactive documentation page."""
    resp = client.get("/api/docs")
    assert resp.status_code == 200
    assert "text/html" in resp.content_type
    assert b"swagger-ui" in resp.data


def test_endpoint_export_stix_bundle(client):
    """GET /api/v1/export/stix exports OASIS STIX 2.1 JSON bundle."""
    resp = client.get("/api/v1/export/stix")
    assert resp.status_code == 200
    assert resp.content_type == "application/json"
    data = json.loads(resp.data)
    assert data["type"] == "bundle"
    assert "objects" in data
    assert any(o["type"] == "identity" for o in data["objects"])


def test_endpoint_export_cef(client):
    """GET /api/v1/export/cef exports CEF stream."""
    resp = client.get("/api/v1/export/cef?limit=10")
    assert resp.status_code == 200
    assert "text/plain" in resp.content_type

