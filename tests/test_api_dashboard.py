"""
tests/test_api_dashboard.py
-----------------------------------------------------------------------------
Unit tests for the API dashboard endpoints (api_dashboard.py)
-----------------------------------------------------------------------------
"""
import pytest
import sys
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts" / "5_dashboard"))


@pytest.fixture
def app_client():
    """Create a test client for the Flask app."""
    from api_dashboard import app

    app.config["TESTING"] = True
    app.config["DEBUG"] = False

    with app.test_client() as client:
        yield client


@pytest.fixture
def mock_alerts_file(tmp_path: Path):
    """Create a mock alerts.jsonl file for testing."""
    alerts_file = tmp_path / "alerts.jsonl"
    alerts = [
        {
            "ts": "2025-12-25T12:00:00",
            "index": 1,
            "score": 0.85,
            "state": "ATTACK",
            "hits_in_window": 3,
            "action": "BLOCK",
            "pred_class": "DDoS",
            "reason": "High SYN ratio",
        },
        {
            "ts": "2025-12-25T12:01:00",
            "index": 2,
            "score": 0.25,
            "state": "BENIGN",
            "hits_in_window": 0,
            "action": "NONE",
            "pred_class": "Normal",
            "reason": None,
        },
    ]
    with open(alerts_file, "w") as f:
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")
    return alerts_file


class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_health_live(self, app_client):
        """Liveness probe should return 200 OK."""
        response = app_client.get("/health/live")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["status"] == "ok"

    def test_health_ready(self, app_client):
        """Readiness probe should return status."""
        response = app_client.get("/health/ready")

        # Should be 200 or 503 depending on model availability
        assert response.status_code in [200, 503]

        data = json.loads(response.data)
        assert "status" in data


class TestAPIEndpoints:
    """Test main API endpoints."""

    def test_api_latest(self, app_client):
        """Test /api/latest endpoint."""
        response = app_client.get("/api/latest")
        assert response.status_code == 200

        data = json.loads(response.data)
        # The /api/latest endpoint returns 'ok' and 'latest' keys
        assert "ok" in data
        assert "latest" in data

    def test_api_counts_default(self, app_client):
        """Test /api/counts endpoint with default parameters."""
        response = app_client.get("/api/counts")
        assert response.status_code == 200

        data = json.loads(response.data)
        # Should have count-related keys
        assert isinstance(data, dict)

    def test_api_counts_with_minutes(self, app_client):
        """Test /api/counts endpoint with custom minutes."""
        response = app_client.get("/api/counts?minutes=30")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert isinstance(data, dict)

    def test_api_events_default(self, app_client):
        """Test /api/events endpoint returns events."""
        response = app_client.get("/api/events")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert "events" in data
        assert isinstance(data["events"], list)

    def test_api_model(self, app_client):
        """Test /api/model endpoint."""
        response = app_client.get("/api/model")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert isinstance(data, dict)


class TestPrometheusMetrics:
    """Test Prometheus metrics endpoint."""

    def test_metrics_endpoint(self, app_client):
        """Test /metrics endpoint returns Prometheus format."""
        response = app_client.get("/metrics")
        assert response.status_code == 200

        # Should be text/plain content type for Prometheus
        assert "text/plain" in response.content_type or "text" in response.content_type


class TestAPIv1Endpoints:
    """Test API v1 endpoints."""

    def test_api_v1_metrics(self, app_client):
        """Test /api/v1/metrics endpoint."""
        response = app_client.get("/api/v1/metrics")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert isinstance(data, dict)

    def test_api_v1_ensemble(self, app_client):
        """Test /api/v1/ensemble endpoint."""
        response = app_client.get("/api/v1/ensemble")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert isinstance(data, dict)


class TestErrorHandling:
    """Test error handling."""

    def test_404_not_found(self, app_client):
        """Non-existent endpoint should return 404."""
        response = app_client.get("/api/nonexistent")
        assert response.status_code == 404

    def test_invalid_method(self, app_client):
        """Wrong HTTP method should return 405."""
        # POST to GET-only endpoint
        response = app_client.post("/api/latest")
        assert response.status_code == 405


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
