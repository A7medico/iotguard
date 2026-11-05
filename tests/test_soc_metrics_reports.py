"""
tests/test_soc_metrics_reports.py
-----------------------------------------------------------------------------
IoTGuard Enterprise v4.0 — Phase 11 SOC Metrics & Executive Reports Verification

Tests:
  1. SOCMetricsTracker MTTD & MTTR sample recording, rolling averages, and baselines.
  2. SLA adherence computation and target thresholds (MTTD <= 100ms, MTTR <= 50ms).
  3. MITRE ATT&CK® matrix aggregation across recent security events & tactics.
  4. Composite Fleet Immunity Index calculation (edge nodes + audit ledger + drift).
  5. Executive Compliance & Incident Report generation (JSON schema validation).
  6. Executive Report HTML generation (interactive, print-ready, CSS styling).
  7. Executive Report Markdown generation (structured tables & cryptographic seal).
  8. Regulatory compliance mappings (NIS2, EU CRA, ISO/IEC 27001).
  9. REST API GET /api/v1/soc/kpis endpoint responses and contracts.
 10. REST API GET /api/v1/reports/executive multi-format dispatch (json, html, markdown).
-----------------------------------------------------------------------------
"""

import time
import json
import pytest
from pathlib import Path

from soc_metrics import (
    SOCMetricsTracker,
    get_soc_metrics_tracker,
    generate_executive_report,
)
from api_dashboard import app
from auth import create_token as generate_token, ROLE_ADMIN, ROLE_SOC_ANALYST, ROLE_AUDITOR


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def fresh_soc_tracker():
    """Return an isolated SOCMetricsTracker instance."""
    tracker = SOCMetricsTracker(max_samples=50)
    tracker.mttd_samples.clear()
    tracker.mttr_samples.clear()
    return tracker


@pytest.fixture
def client():
    """Flask test client for API integration testing."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def admin_headers():
    """Return JWT Bearer authorization headers for ADMIN role."""
    token = generate_token(username="soc_lead", role=ROLE_ADMIN)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def auditor_headers():
    """Return JWT Bearer authorization headers for AUDITOR role."""
    token = generate_token(username="external_auditor", role=ROLE_AUDITOR)
    return {"Authorization": f"Bearer {token}"}


# =============================================================================
# 1. SOC METRICS TRACKER UNIT TESTS
# =============================================================================

class TestSOCMetricsTracker:
    def test_mttd_mttr_default_baselines(self, fresh_soc_tracker):
        """When no latency samples are recorded, baselines should be returned."""
        assert fresh_soc_tracker.get_mttd() == fresh_soc_tracker.default_mttd_ms
        assert fresh_soc_tracker.get_mttr() == fresh_soc_tracker.default_mttr_ms
        assert fresh_soc_tracker.get_mttd() < 50.0
        assert fresh_soc_tracker.get_mttr() < 10.0

    def test_record_mttd_rolling_average(self, fresh_soc_tracker):
        """MTTD samples are averaged over the rolling sample window."""
        fresh_soc_tracker.record_mttd(10.0)
        fresh_soc_tracker.record_mttd(20.0)
        fresh_soc_tracker.record_mttd(30.0)
        assert fresh_soc_tracker.get_mttd() == 20.0

        # Non-positive values should be ignored
        fresh_soc_tracker.record_mttd(-5.0)
        fresh_soc_tracker.record_mttd(0.0)
        assert fresh_soc_tracker.get_mttd() == 20.0

    def test_record_mttr_rolling_average(self, fresh_soc_tracker):
        """MTTR samples are averaged over the rolling sample window."""
        fresh_soc_tracker.record_mttr(2.5)
        fresh_soc_tracker.record_mttr(3.5)
        fresh_soc_tracker.record_mttr(6.0)
        assert fresh_soc_tracker.get_mttr() == 4.0

    def test_mttd_mttr_max_samples_deque(self):
        """Sample buffer maintains the configured max capacity without memory leak."""
        tracker = SOCMetricsTracker(max_samples=5)
        for i in range(1, 11):
            tracker.record_mttd(float(i))
        assert len(tracker.mttd_samples) == 5
        # The last 5 samples are 6.0, 7.0, 8.0, 9.0, 10.0 -> average = 8.0
        assert tracker.get_mttd() == 8.0

    def test_mitre_matrix_aggregation(self, fresh_soc_tracker, monkeypatch):
        """Recent alerts map into MITRE ATT&CK tactics correctly."""
        dummy_alerts = [
            {
                "attack_category": "DDoS-SYN",
                "mitre": {
                    "tactic_id": "TA0040",
                    "tactic_name": "Impact",
                    "technique_id": "T1498.001",
                    "technique_name": "Direct Network Flood",
                },
                "ts": 1729001000.0,
            },
            {
                "attack_category": "PortScan",
                "mitre": {
                    "tactic_id": "TA0043",
                    "tactic_name": "Reconnaissance",
                    "technique_id": "T1046",
                    "technique_name": "Network Service Discovery",
                },
                "ts": 1729001005.0,
            },
            {
                "attack_category": "Mirai-C2",
                "mitre": {
                    "tactic_id": "TA0011",
                    "tactic_name": "Command and Control",
                    "technique_id": "T1071.001",
                    "technique_name": "Web Protocols",
                },
                "ts": 1729001010.0,
            },
            {
                "attack_category": "DDoS-UDP",
                "mitre": {
                    "tactic_id": "TA0040",
                    "tactic_name": "Impact",
                    "technique_id": "T1498.001",
                    "technique_name": "Direct Network Flood",
                },
                "ts": 1729001015.0,
            },
        ]
        monkeypatch.setattr(fresh_soc_tracker, "_fetch_recent_alerts", lambda limit=150: dummy_alerts)

        matrix = fresh_soc_tracker.get_mitre_matrix()
        assert matrix["total_mapped_threats"] == 4
        assert matrix["active_tactics_count"] == 3
        assert matrix["tactics_count"] == 6

        tactics = matrix["tactics"]
        assert tactics["TA0040"]["count"] == 2
        assert tactics["TA0040"]["active"] is True
        assert "T1498.001 Direct Network Flood" in tactics["TA0040"]["techniques"]

        assert tactics["TA0043"]["count"] == 1
        assert tactics["TA0043"]["active"] is True

        assert tactics["TA0011"]["count"] == 1
        assert tactics["TA0011"]["active"] is True

        # Unseen tactics should have count 0
        assert tactics["TA0001"]["count"] == 0
        assert tactics["TA0001"]["active"] is False
        assert tactics["TA0002"]["count"] == 0
        assert tactics["TA0006"]["count"] == 0

    def test_fleet_immunity_index_optimal(self, fresh_soc_tracker, monkeypatch):
        """Fleet Immunity Index reaches OPTIMAL when nodes, audit, and drift are sound."""
        # Simulated 4 online synced edge nodes
        dummy_nodes = [
            {"node_id": "edge-1", "status": "ONLINE", "model_synced": True},
            {"node_id": "edge-2", "status": "ONLINE", "model_synced": True},
            {"node_id": "edge-3", "status": "ONLINE", "model_synced": True},
            {"node_id": "edge-4", "status": "ONLINE", "model_synced": True},
        ]
        monkeypatch.setattr("soc_metrics.get_fleet_nodes", lambda: dummy_nodes)
        monkeypatch.setattr("soc_metrics.verify_audit_ledger", lambda: (True, "Ledger integrity verified", 10))

        immunity = fresh_soc_tracker.get_fleet_immunity_index()
        assert immunity["index_pct"] >= 90.0
        assert immunity["rating"] == "OPTIMAL"
        assert immunity["components"]["audit_chain_valid"] is True
        assert immunity["components"]["edge_nodes_healthy"] == 4

    def test_fleet_immunity_index_degraded_on_audit_failure(self, fresh_soc_tracker, monkeypatch):
        """Fleet Immunity drops to DEGRADED when audit chain tampering is detected."""
        dummy_nodes = [
            {"node_id": "edge-1", "status": "ONLINE", "model_synced": True},
            {"node_id": "edge-2", "status": "OFFLINE", "model_synced": False},
        ]
        monkeypatch.setattr("soc_metrics.get_fleet_nodes", lambda: dummy_nodes)
        monkeypatch.setattr("soc_metrics.verify_audit_ledger", lambda: (False, "Hash mismatch detected", 5))

        immunity = fresh_soc_tracker.get_fleet_immunity_index()
        assert immunity["index_pct"] < 75.0
        assert immunity["rating"] == "DEGRADED"
        assert immunity["components"]["audit_chain_valid"] is False

    def test_get_soc_kpis_contract(self, fresh_soc_tracker):
        """get_soc_kpis returns all required SecOps attributes."""
        fresh_soc_tracker.record_mttd(12.5)
        fresh_soc_tracker.record_mttr(3.2)
        kpis = fresh_soc_tracker.get_soc_kpis()

        assert kpis["ok"] is True
        assert kpis["mttd_ms"] == 12.5
        assert kpis["mttr_ms"] == 3.2
        assert kpis["mttd_sla_status"] == "MET"
        assert kpis["mttr_sla_status"] == "MET"
        assert kpis["sla_adherence_pct"] == 100.0
        assert "fleet_immunity_index" in kpis
        assert "mitre_matrix" in kpis
        assert "audit_chain_status" in kpis
        assert isinstance(kpis["timestamp"], float)


# =============================================================================
# 2. EXECUTIVE COMPLIANCE REPORT GENERATOR TESTS
# =============================================================================

class TestExecutiveReportGenerator:
    def test_generate_executive_report_json(self):
        """JSON executive report matches SOC governance schema."""
        report = generate_executive_report(fmt="json")
        assert isinstance(report, dict)
        assert report["report_meta"]["report_title"] == "IoTGuard Enterprise SOC Executive Security Posture & Compliance Report"
        assert report["report_meta"]["format"] == "json"

        # Executive summary
        summary = report["executive_summary"]
        assert "total_flows_inspected" in summary
        assert "total_attacks_neutralized" in summary
        assert "fleet_immunity_index" in summary

        # SLA telemetry
        sla = report["sla_telemetry"]
        assert "mttd_ms" in sla
        assert "mttr_ms" in sla
        assert sla["mttd_target_ms"] == 100.0
        assert sla["mttr_target_ms"] == 50.0

        # MITRE ATT&CK coverage
        mitre = report["mitre_attack_coverage"]
        assert "tactics" in mitre
        assert "TA0043" in mitre["tactics"]
        assert "TA0040" in mitre["tactics"]

        # Regulatory compliance frameworks
        comp = report["regulatory_compliance"]
        assert "NIS2_DIRECTIVE" in comp
        assert "EU_CYBER_RESILIENCE_ACT" in comp
        assert "ISO_IEC_27001_2022" in comp
        assert comp["NIS2_DIRECTIVE"]["status"] == "COMPLIANT"

        # Audit ledger seal
        audit = report["cryptographic_audit_seal"]
        assert audit["mechanism"] == "SHA-256 Merkle Chaining"
        assert "chain_status" in audit

    def test_generate_executive_report_html(self):
        """HTML executive report is a styled, standalone, print-ready document."""
        html = generate_executive_report(fmt="html")
        assert isinstance(html, str)
        assert html.startswith("<!DOCTYPE html>")
        assert "<title>IoTGuard Enterprise SOC Executive Security Posture Report" in html
        assert "@media print" in html
        assert "MITRE ATT&CK® Threat Coverage" in html
        assert "Cryptographic Audit" in html
        assert "NIS2" in html
        assert "EU Cyber Resilience Act" in html
        assert "window.print()" in html

    def test_generate_executive_report_markdown(self):
        """Markdown executive report contains structured headers, tables, and seals."""
        md = generate_executive_report(fmt="markdown")
        assert isinstance(md, str)
        assert "IoTGuard Enterprise v4.0 — Executive Security Posture & Compliance Report" in md
        assert "## 1. Executive Summary & Fleet Posture" in md
        assert "## 2. SecOps SLA Performance Telemetry" in md
        assert "## 3. MITRE ATT&CK® Threat Tactic Matrix" in md
        assert "## 6. Regulatory Compliance & Governance Alignment" in md
        assert "## 7. Cryptographic Audit Ledger Verification Seal" in md
        assert "NIS2 Directive (EU 2022/2555)" in md


# =============================================================================
# 3. REST API ENDPOINT INTEGRATION TESTS
# =============================================================================

class TestSOCEndpointsAPI:
    def test_api_soc_kpis_endpoint(self, client):
        """GET /api/v1/soc/kpis returns 200 OK with valid SecOps KPIs."""
        res = client.get("/api/v1/soc/kpis")
        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
        assert "mttd_ms" in data
        assert "mttr_ms" in data
        assert "fleet_immunity_index" in data
        assert "mitre_matrix" in data
        assert "audit_chain_status" in data

    def test_api_soc_kpis_backward_compatibility_route(self, client):
        """GET /api/soc/kpis aliases to /api/v1/soc/kpis."""
        res = client.get("/api/soc/kpis")
        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True

    def test_api_reports_executive_json(self, client, admin_headers):
        """GET /api/v1/reports/executive?format=json returns valid JSON document."""
        res = client.get("/api/v1/reports/executive?format=json", headers=admin_headers)
        assert res.status_code == 200
        assert "application/json" in res.content_type
        data = res.get_json()
        assert data["ok"] is True
        assert data["format"] == "json"
        assert "report" in data
        assert data["report"]["report_meta"]["report_title"] is not None

    def test_api_reports_executive_html(self, client, admin_headers):
        """GET /api/v1/reports/executive?format=html returns standalone printable HTML."""
        res = client.get("/api/v1/reports/executive?format=html", headers=admin_headers)
        assert res.status_code == 200
        assert "text/html" in res.content_type
        html_str = res.data.decode("utf-8")
        assert "<!DOCTYPE html>" in html_str
        assert "IoTGuard Enterprise SOC Executive Security Posture Report" in html_str
        assert "Print / Save" in html_str

    def test_api_reports_executive_markdown(self, client, admin_headers):
        """GET /api/v1/reports/executive?format=markdown returns markdown document."""
        res = client.get("/api/v1/reports/executive?format=markdown", headers=admin_headers)
        assert res.status_code == 200
        md_str = res.data.decode("utf-8")
        assert "IoTGuard Enterprise v4.0" in md_str
        assert "SecOps SLA Performance Telemetry" in md_str

    def test_api_reports_executive_auditor_access(self, client, auditor_headers):
        """Auditors can access executive reports for compliance reviews."""
        res = client.get("/api/v1/reports/executive?format=json", headers=auditor_headers)
        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
