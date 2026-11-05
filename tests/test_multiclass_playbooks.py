"""
tests/test_multiclass_playbooks.py
-----------------------------------------------------------------------------
Unit tests for Multi-Class Attack Taxonomy, Playbook Integration & Dashboard APIs
-----------------------------------------------------------------------------
"""

import json
import pytest
import pandas as pd
import numpy as np

from playbooks import (
    TAXONOMIES,
    REMEDIATION_PLAYBOOKS,
    normalize_taxonomy,
    get_remediation_playbook,
)
from scoring import (
    ModelManager,
    classify_multiclass,
    infer_attack_taxonomy,
)
from event_logger import EventLogger
from api_dashboard import app


class TestTaxonomyNormalization:
    def test_all_canonical_taxonomies_present(self):
        expected = [
            "DDoS-SYN", "DDoS-UDP", "DDoS-HTTP", "Mirai-C2", "PortScan",
            "SQLInjection", "CommandInjection", "BruteForce", "ZeroDay-Anomaly"
        ]
        for item in expected:
            assert item in TAXONOMIES

    def test_normalize_syn_attacks(self):
        assert normalize_taxonomy("syn_flood") == "DDoS-SYN"
        assert normalize_taxonomy("ddos_syn") == "DDoS-SYN"
        assert normalize_taxonomy("DDoS: SYN Flood") == "DDoS-SYN"

    def test_normalize_udp_attacks(self):
        assert normalize_taxonomy("udp_flood") == "DDoS-UDP"
        assert normalize_taxonomy("ddos_udp") == "DDoS-UDP"
        assert normalize_taxonomy("DDoS: Volumetric (Mirai/UDP)") == "DDoS-UDP"

    def test_normalize_http_and_web_attacks(self):
        assert normalize_taxonomy("ddos_http") == "DDoS-HTTP"
        assert normalize_taxonomy("http_exploit") == "DDoS-HTTP"
        assert normalize_taxonomy("Web Attack (HTTP)") == "DDoS-HTTP"

    def test_normalize_botnets_and_c2(self):
        assert normalize_taxonomy("backdoor") == "Mirai-C2"
        assert normalize_taxonomy("ransomware") == "Mirai-C2"
        assert normalize_taxonomy("mirai") == "Mirai-C2"
        assert normalize_taxonomy("data_exfil") == "Mirai-C2"

    def test_normalize_scans(self):
        assert normalize_taxonomy("port_scan") == "PortScan"
        assert normalize_taxonomy("vulnerability_scan") == "PortScan"
        assert normalize_taxonomy("os_fingerprint") == "PortScan"

    def test_normalize_injections(self):
        assert normalize_taxonomy("sql_injection") == "SQLInjection"
        assert normalize_taxonomy("command_injection") == "CommandInjection"
        assert normalize_taxonomy("upload_attack") == "CommandInjection"

    def test_normalize_bruteforce(self):
        assert normalize_taxonomy("bruteforce") == "BruteForce"

    def test_unsupervised_detection_forces_zeroday(self):
        assert normalize_taxonomy("syn_flood", detection_source="unsupervised") == "ZeroDay-Anomaly"
        assert normalize_taxonomy(None, detection_source="unsupervised") == "ZeroDay-Anomaly"

    def test_benign_normalized(self):
        assert normalize_taxonomy("benign") == "Benign"
        assert normalize_taxonomy("normal") == "Benign"


class TestRemediationPlaybooks:
    def test_playbook_schema_integrity(self):
        required_keys = [
            "title", "category", "severity", "recommended_action",
            "port_restrictions", "firewall_rule", "rate_limit_policy",
            "payload_inspection_hint"
        ]
        for canon in TAXONOMIES:
            pb = get_remediation_playbook(canon)
            for k in required_keys:
                assert k in pb, f"Missing {k} in playbook for {canon}"
            assert pb["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_firewall_rule_ip_formatting(self):
        pb = get_remediation_playbook("DDoS-SYN", src_ip="192.168.1.100")
        assert "192.168.1.100" in pb["firewall_rule"]
        assert "{src_ip}" not in pb["firewall_rule"]


class TestMultiClassInference:
    def test_infer_attack_taxonomy_unsupervised(self):
        row = pd.Series({"syn_ratio": 0.1})
        x_df = pd.DataFrame([[0.1]])
        cat, conf = infer_attack_taxonomy(row, x_df, detection_source="unsupervised")
        assert cat == "ZeroDay-Anomaly"
        assert conf >= 0.85

    def test_infer_attack_taxonomy_heuristic_fallback(self):
        # SYN flood heuristic
        row = pd.Series({
            "syn_ratio": 0.9,
            "rst_ratio": 0.0,
            "http_ratio": 0.0,
            "bytes_total": 500_000,
            "pkts_total": 10_000,
            "mean_bytes_flow": 50.0,
            "flows": 50,
        })
        x_df = pd.DataFrame([row])
        cat, conf = infer_attack_taxonomy(row, x_df, detection_source="supervised", multiclass_model=None)
        assert cat == "DDoS-SYN"
        assert conf > 0.7

    def test_model_manager_loads_multiclass_if_available(self):
        mgr = ModelManager()
        if mgr.multiclass_available:
            assert mgr.multiclass_model is not None
            assert len(mgr.multiclass_classes) > 0


class TestEventLoggerEnrichment:
    def test_log_event_with_playbook(self, tmp_path):
        log_file = tmp_path / "alerts.jsonl"
        logger = EventLogger(alert_path=str(log_file))

        pb = get_remediation_playbook("Mirai-C2", src_ip="10.0.0.99")
        evt = logger.log_event(
            idx=1,
            score=0.96,
            state_text="ATTACK",
            hits=2,
            action="BLOCK-HARD",
            pred_class="Mirai-C2",
            attack_category="Mirai-C2",
            confidence=0.94,
            remediation_playbook=pb,
            src_ip="10.0.0.99",
        )

        assert evt["attack_category"] == "Mirai-C2"
        assert evt["confidence"] == 0.94
        assert evt["remediation_playbook"]["severity"] == "CRITICAL"
        assert "10.0.0.99" in evt["remediation_playbook"]["firewall_rule"]

        # Verify disk persistence
        lines = log_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        persisted = json.loads(lines[0])
        assert persisted["attack_category"] == "Mirai-C2"
        assert persisted["remediation_playbook"]["category"] == "Mirai-C2"


class TestDashboardAPIEndpoints:
    @pytest.fixture
    def client(self):
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client

    def test_api_playbooks_endpoint(self, client):
        res = client.get("/api/playbooks")
        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
        assert "taxonomies" in data
        assert "playbooks" in data
        assert "DDoS-SYN" in data["playbooks"]

    def test_api_playbook_detail_endpoint(self, client):
        res = client.get("/api/playbook/SQLInjection?src_ip=192.168.1.45")
        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
        assert data["category"] == "SQLInjection"
        assert data["playbook"]["severity"] == "HIGH"
        assert "192.168.1.45" in data["playbook"]["firewall_rule"]

    def test_api_model_contains_taxonomies(self, client):
        res = client.get("/api/model")
        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
        assert "taxonomies" in data["model"]
        assert "DDoS-SYN" in data["model"]["taxonomies"]

