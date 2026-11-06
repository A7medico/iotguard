"""
tests/test_forensics_timemachine.py
-----------------------------------------------------------------------------
IoTGuard Tests — Interactive Attack Replay Time-Machine & Auto-Forensics System

Validates:
    - Forensic Incident Snapshot Generator (scripts/4_response/forensic_snapshot.py)
    - Exact 13-feature trigger vector + preceding K=8 sliding windows
    - SHAP feature attributions and Zero-Day tail-probability contributors
    - MITRE ATT&CK tactic/technique mapping & multi-OS firewall remediation rules
    - Threat Intelligence context (GeoIP, ASN, AbuseIPDB score)
    - Cryptographic SHA-256 evidence integrity signature chained to Audit Ledger
    - Tamper-evident verification of evidence bundles
    - REST API Endpoints:
        * GET /api/v1/forensics/<event_index>
        * GET /api/forensics/<event_index> (backward-compatibility alias)
        * GET /api/v1/forensics/<event_index>?download=true
        * GET /api/v1/forensics
        * POST /api/v1/forensics/<event_index>/verify
-----------------------------------------------------------------------------
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import forensic_snapshot
from forensic_snapshot import (
    ForensicEvidenceBundle,
    generate_forensic_snapshot,
    get_forensic_snapshot,
    list_forensic_snapshots,
    verify_bundle_integrity,
    load_window_features,
    compute_shap_attributions,
    compute_zero_day_tail_contributors,
    SCHEMA_13_FEATURES,
    DEFAULT_K_WINDOWS,
)


@pytest.fixture
def mock_event():
    """Mock alert event matching decision loop output."""
    return {
        "index": 42,
        "score": 0.942,
        "state": "ATTACK",
        "action": "BLOCK-HARD",
        "attack_category": "DDoS-SYN",
        "pred_class": "DDoS-SYN",
        "src_ip": "185.220.101.5",
        "reason": "syn_ratio (+0.48), flows (+0.25), bytes_total (+0.18)",
        "hits_in_window": 5,
        "threat": {
            "ip": "185.220.101.5",
            "country": "DE",
            "country_name": "Germany",
            "flag": "🇩🇪",
            "city": "Frankfurt",
            "threat": "Tor Exit Node",
            "isp": "Tor Transit LLC",
            "asn": "AS60729",
            "abuse_confidence_score": 98,
            "abuse_score": 98,
            "is_malicious": True,
        },
    }


@pytest.fixture
def mock_trigger_features():
    """Exact 13-feature vector for an attack window."""
    return {
        "flows": 145.0,
        "bytes_total": 84200.0,
        "pkts_total": 420.0,
        "syn_ratio": 0.89,
        "mean_bytes_flow": 580.0,
        "ack_ratio": 0.05,
        "fin_ratio": 0.02,
        "rst_ratio": 0.04,
        "http_ratio": 0.01,
        "tcp_ratio": 0.99,
        "protocol_diversity": 1.0,
        "std_bytes": 12.4,
        "iat_mean": 0.00035,
    }


@pytest.fixture
def temp_forensics_dir(tmp_path, monkeypatch):
    """Isolate forensics output directory for test hermeticity."""
    forensics_dir = tmp_path / "forensics"
    forensics_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(forensic_snapshot, "FORENSICS_DIR", forensics_dir)
    return forensics_dir


# ============================================================================
# 1. Forensic Snapshot Generator & Schema Tests
# ============================================================================

class TestForensicSnapshotGenerator:
    """Unit tests for the forensic evidence bundle generator."""

    def test_bundle_complete_schema(self, mock_event, mock_trigger_features, temp_forensics_dir):
        """Bundle must include all required forensic metadata, features, and attributions."""
        bundle = generate_forensic_snapshot(
            event_index=42,
            trigger_row=mock_trigger_features,
            event_meta=mock_event,
            k_windows=8,
            record_audit=True,
            save_to_disk=True,
        )

        assert isinstance(bundle, ForensicEvidenceBundle)
        data = bundle.to_dict()

        # Core Identity
        assert data["ok"] is True
        assert data["event_index"] == 42
        assert "bundle_id" in data
        assert "generated_at" in data
        assert "iso_timestamp" in data

        # Sliding Windows Contract
        assert data["k_windows"] == 8
        assert len(data["preceding_windows"]) == 8
        assert "trigger_window" in data
        assert "replay_timeline" in data
        assert len(data["replay_timeline"]) == 9  # 8 preceding + 1 trigger

        # Attributions & Context
        assert "shap_attributions" in data
        assert "zero_day_analysis" in data
        assert "mitre_attack" in data
        assert "remediation_playbook" in data
        assert "threat_intel" in data
        assert "evidence_integrity" in data

    def test_exact_13_features_present_in_all_windows(self, mock_event, mock_trigger_features):
        """Every window in trigger and preceding must contain the exact 13 schema features."""
        bundle = generate_forensic_snapshot(
            event_index=10,
            trigger_row=mock_trigger_features,
            event_meta=mock_event,
            save_to_disk=False,
        )

        # Trigger window features
        for feat in SCHEMA_13_FEATURES:
            assert feat in bundle.trigger_window, f"Missing {feat} in trigger_window"
            assert isinstance(bundle.trigger_window[feat], (int, float))

        # Preceding windows features
        for window in bundle.preceding_windows:
            feats = window["features"]
            assert len(feats) == 13
            for feat in SCHEMA_13_FEATURES:
                assert feat in feats, f"Missing {feat} in preceding window"

    def test_shap_feature_attributions(self, mock_trigger_features):
        """SHAP feature attributions must rank feature contributions across 13 schema features."""
        shap_res = compute_shap_attributions(mock_trigger_features, reason_str="syn_ratio (+0.48), flows (+0.25)")

        assert "feature_contributions" in shap_res
        assert "ranked_contributors" in shap_res
        assert len(shap_res["ranked_contributors"]) == 13
        assert all("feature" in c and "contribution" in c for c in shap_res["ranked_contributors"])
        assert "syn_ratio" in shap_res["feature_contributions"]
        assert "summary" in shap_res

    def test_zero_day_tail_probability_contributors(self, mock_trigger_features):
        """Zero-Day analysis must detect extreme statistical tail deviations."""
        zd = compute_zero_day_tail_contributors(mock_trigger_features)

        assert "tail_probability" in zd
        assert 0.0 <= zd["tail_probability"] <= 1.0
        assert "max_z_score" in zd
        assert "tail_contributors" in zd
        assert len(zd["tail_contributors"]) > 0

        # syn_ratio = 0.89 vs baseline μ=0.08 must show elevated/critical tail
        syn_tail = [c for c in zd["tail_contributors"] if c["feature"] == "syn_ratio"]
        assert len(syn_tail) == 1
        assert syn_tail[0]["z_score"] >= 3.0
        assert syn_tail[0]["severity"] in ("CRITICAL_TAIL", "HIGH_TAIL")

    def test_mitre_and_playbook_enrichment(self, mock_event, mock_trigger_features):
        """Evidence bundle must link official MITRE ATT&CK and recommended firewall rules."""
        bundle = generate_forensic_snapshot(
            event_index=42,
            trigger_row=mock_trigger_features,
            event_meta=mock_event,
            save_to_disk=False,
        )

        mitre = bundle.mitre_attack
        assert mitre["technique_id"] == "T1498.001"
        assert mitre["tactic_name"] == "Impact"
        assert "attack.mitre.org" in mitre["url"]

        pb = bundle.remediation_playbook
        assert "firewall_rule" in pb
        assert "185.220.101.5" in pb["firewall_rule"]
        assert "rate_limit_policy" in pb

    def test_threat_intelligence_context(self, mock_event, mock_trigger_features):
        """Threat Intelligence must capture IP, GeoIP, ASN, and abuse scores."""
        bundle = generate_forensic_snapshot(
            event_index=42,
            trigger_row=mock_trigger_features,
            event_meta=mock_event,
            save_to_disk=False,
        )

        ti = bundle.threat_intel
        assert ti["ip"] == "185.220.101.5"
        assert ti["country"] == "DE"
        assert ti["flag"] == "🇩🇪"
        assert ti["asn"] == "AS60729"
        assert ti["abuse_confidence_score"] == 98
        assert ti["is_malicious"] is True

    def test_replay_timeline_chronology(self, mock_event, mock_trigger_features):
        """Replay timeline must track 8 preceding windows plus the trigger window."""
        bundle = generate_forensic_snapshot(
            event_index=15,
            trigger_row=mock_trigger_features,
            event_meta=mock_event,
            save_to_disk=False,
        )

        timeline = bundle.replay_timeline
        assert len(timeline) == 9

        # Last item must be trigger window W0
        assert timeline[-1]["is_trigger"] is True
        assert timeline[-1]["relative_window"] == 0
        assert "W-0" in timeline[-1]["relative_label"]

        # Preceding items must be W-8 to W-1
        for i, item in enumerate(timeline[:-1]):
            assert item["is_trigger"] is False
            assert item["relative_window"] < 0
            assert "key_metrics" in item
            assert "syn_ratio" in item["key_metrics"]
            assert "flows" in item["key_metrics"]
            assert "bytes_total" in item["key_metrics"]

    def test_cryptographic_signature_and_audit_ledger(self, mock_event, mock_trigger_features, temp_forensics_dir):
        """Bundle must compute SHA-256 digest and record in cryptographic audit ledger."""
        bundle = generate_forensic_snapshot(
            event_index=42,
            trigger_row=mock_trigger_features,
            event_meta=mock_event,
            record_audit=True,
            save_to_disk=True,
        )

        data = bundle.to_dict()
        integrity = data["evidence_integrity"]
        assert integrity["algorithm"] == "SHA-256"
        assert len(integrity["sha256_hash"]) == 64
        assert integrity["verified"] is True

        # Verify integrity using the self-verification method
        is_valid, msg = verify_bundle_integrity(data)
        assert is_valid is True
        assert msg == "EVIDENCE_SIGNATURE_VERIFIED"

    def test_tamper_detection(self, mock_event, mock_trigger_features):
        """Modifying any feature or metadata in evidence package must fail verification."""
        bundle = generate_forensic_snapshot(
            event_index=42,
            trigger_row=mock_trigger_features,
            event_meta=mock_event,
            save_to_disk=False,
        )

        data = bundle.to_dict()

        # Maliciously tamper with trigger window features
        tampered_data = json.loads(json.dumps(data))
        tampered_data["trigger_window"]["syn_ratio"] = 0.01  # Alter attack evidence

        is_valid, reason = verify_bundle_integrity(tampered_data)
        assert is_valid is False
        assert "SIGNATURE_MISMATCH" in reason


# ============================================================================
# 2. REST API Endpoints Integration Tests
# ============================================================================

class TestForensicsAPI:
    """Integration tests for /api/v1/forensics endpoints."""

    @pytest.fixture
    def client(self, tmp_path, monkeypatch):
        """Flask test client with isolated forensics and alerts."""
        forensics_dir = tmp_path / "forensics"
        forensics_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(forensic_snapshot, "FORENSICS_DIR", forensics_dir)

        import api_dashboard
        api_dashboard.app.config["TESTING"] = True
        return api_dashboard.app.test_client()

    def test_get_forensic_snapshot_success(self, client):
        """GET /api/v1/forensics/<event_index> returns 200 with full evidence bundle."""
        resp = client.get("/api/v1/forensics/0")
        assert resp.status_code == 200

        data = resp.get_json()
        assert data["ok"] is True
        assert data["event_index"] == 0
        assert "bundle_id" in data
        assert "replay_timeline" in data
        assert len(data["replay_timeline"]) == 9
        assert "shap_attributions" in data
        assert "zero_day_analysis" in data
        assert "evidence_integrity" in data
        assert len(data["evidence_integrity"]["sha256_hash"]) == 64

    def test_get_forensic_snapshot_backward_compat_route(self, client):
        """GET /api/forensics/<event_index> alias must also return 200."""
        resp = client.get("/api/forensics/0")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["event_index"] == 0

    def test_get_forensic_snapshot_download_header(self, client):
        """GET /api/v1/forensics/<event_index>?download=true returns downloadable attachment."""
        resp = client.get("/api/v1/forensics/0?download=true")
        assert resp.status_code == 200
        assert "attachment" in resp.headers.get("Content-Disposition", "")
        assert "forensic_evidence_event_0.json" in resp.headers.get("Content-Disposition", "")

        # Verify body is valid JSON bundle
        body = json.loads(resp.data.decode("utf-8"))
        assert body["ok"] is True
        assert body["event_index"] == 0

    def test_list_forensics_endpoint(self, client):
        """GET /api/v1/forensics returns list of stored forensic snapshots."""
        # First generate snapshot 0
        client.get("/api/v1/forensics/0")

        resp = client.get("/api/v1/forensics")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["count"] >= 1
        assert isinstance(data["snapshots"], list)

    def test_verify_forensic_snapshot_api(self, client):
        """POST /api/v1/forensics/<event_index>/verify verifies cryptographic integrity."""
        # First ensure snapshot 0 exists
        client.get("/api/v1/forensics/0")

        resp = client.post("/api/v1/forensics/0/verify")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["verified"] is True
        assert data["status"] == "EVIDENCE_SIGNATURE_VERIFIED"
        assert "sha256" in data

    def test_verify_non_existent_snapshot_returns_404(self, client, tmp_path, monkeypatch):
        """Verifying non-existent snapshot index returns 404."""
        # Ensure directory is empty
        empty_dir = tmp_path / "empty_forensics"
        empty_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(forensic_snapshot, "FORENSICS_DIR", empty_dir)

        resp = client.post("/api/v1/forensics/999999/verify")
        assert resp.status_code == 404
