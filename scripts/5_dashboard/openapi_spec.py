"""
scripts/5_dashboard/openapi_spec.py
-----------------------------------------------------------------------------
IoTGuard Enterprise Component — OpenAPI 3.1 Specification & Swagger UI Generator

Generates a complete, standards-compliant OpenAPI 3.1.0 JSON specification
for the IoTGuard Enterprise REST API and provides an interactive Swagger UI.
-----------------------------------------------------------------------------
"""

import json
from typing import Any, Dict


def get_openapi_spec() -> Dict[str, Any]:
    """Generate OpenAPI 3.1.0 specification for IoTGuard Enterprise v4.0."""
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "IoTGuard Enterprise REST API",
            "version": "4.0.0",
            "description": (
                "High-performance, edge-native Machine Learning Network Intrusion "
                "Detection and Automated Prevention System (IDS/IPS) for IoT/IIoT.\n\n"
                "Features:\n"
                "- 13-feature IP-agnostic behavioral schema\n"
                "- Supervised LightGBM + Unsupervised IsolationForest hybrid ensemble\n"
                "- Sliding-window stateful temporal sequence detection\n"
                "- 9 MITRE ATT&CK® taxonomies and automated remediation playbooks\n"
                "- Sub-microsecond eBPF/XDP in-kernel packet filtering\n"
                "- Write-Ahead Logging (WAL) indexed SQLite storage engine\n"
                "- Cryptographic SHA-256 block-chained audit ledger\n"
                "- Enterprise Role-Based Access Control (ADMIN, SOC_ANALYST, AUDITOR, EDGE_SENSOR)\n"
                "- ArcSight CEF, RFC 5424 Syslog, and OASIS STIX 2.1 exporters"
            ),
            "contact": {
                "name": "IoTGuard Security Engineering",
                "url": "https://github.com/iotguard/iotguard",
            },
            "license": {
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT",
            },
        },
        "servers": [
            {
                "url": "/",
                "description": "Current IoTGuard Edge Gateway / API Instance",
            }
        ],
        "tags": [
            {"name": "Security Events", "description": "Streaming alerts and multidimensional queries"},
            {"name": "Mitigation & Defense", "description": "eBPF/XDP hardware blocking and firewall control"},
            {"name": "Audit & Compliance", "description": "Cryptographic tamper-evident non-repudiation ledger"},
            {"name": "Topology & Threat Intel", "description": "Live device network topology and GeoIP context"},
            {"name": "Fleet & Federated Learning", "description": "Decentralized FedAvg and online feature drift"},
            {"name": "SIEM & Threat Sharing", "description": "STIX 2.1, ArcSight CEF, and Syslog export"},
            {"name": "System & Health", "description": "Prometheus metrics, health probes, and runtime config"},
        ],
        "paths": {
            "/api/events": {
                "get": {
                    "tags": ["Security Events"],
                    "summary": "Query Security Events",
                    "description": "Executes an indexed multidimensional query across security events.",
                    "parameters": [
                        {"name": "ip", "in": "query", "schema": {"type": "string"}, "description": "Filter by source IP"},
                        {"name": "category", "in": "query", "schema": {"type": "string"}, "description": "Filter by attack category"},
                        {"name": "min_score", "in": "query", "schema": {"type": "number"}, "description": "Minimum anomaly score (0.0-1.0)"},
                        {"name": "max_score", "in": "query", "schema": {"type": "number"}, "description": "Maximum anomaly score (0.0-1.0)"},
                        {"name": "tier", "in": "query", "schema": {"type": "string"}, "description": "Filter by mitigation tier (MONITOR, SOFT, HARD, KILL)"},
                        {"name": "start_ts", "in": "query", "schema": {"type": "number"}, "description": "Start Unix timestamp"},
                        {"name": "end_ts", "in": "query", "schema": {"type": "number"}, "description": "End Unix timestamp"},
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100}, "description": "Max results"},
                        {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}, "description": "Pagination offset"},
                    ],
                    "responses": {
                        "200": {
                            "description": "List of matching security events",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/EventsListResponse"}
                                }
                            },
                        }
                    },
                }
            },
            "/api/latest": {
                "get": {
                    "tags": ["Security Events"],
                    "summary": "Latest Decision Event",
                    "description": "Returns the most recent window decision event from the pipeline.",
                    "responses": {
                        "200": {"description": "Latest decision event"}
                    },
                }
            },
            "/api/counts": {
                "get": {
                    "tags": ["Security Events"],
                    "summary": "Aggregate Metrics Summary",
                    "parameters": [
                        {"name": "minutes", "in": "query", "schema": {"type": "integer", "default": 60}}
                    ],
                    "responses": {
                        "200": {"description": "Aggregate event, attack, and block counts"}
                    },
                }
            },
            "/api/topology": {
                "get": {
                    "tags": ["Topology & Threat Intel"],
                    "summary": "Live Network Topology Graph",
                    "description": "Combines device fingerprints, telemetry, and active blocks into a graph.",
                    "responses": {
                        "200": {"description": "Topology nodes, edges, and statistics"}
                    },
                }
            },
            "/api/block": {
                "post": {
                    "tags": ["Mitigation & Defense"],
                    "summary": "Quarantine / Block IP",
                    "security": [{"BearerAuth": []}, {"ApiKeyAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/BlockRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "IP blocked successfully"},
                        "400": {"description": "Invalid IP address"},
                        "403": {"description": "Forbidden (Requires ADMIN or SOC_ANALYST)"},
                    },
                }
            },
            "/api/unblock": {
                "post": {
                    "tags": ["Mitigation & Defense"],
                    "summary": "Restore / Unblock IP",
                    "security": [{"BearerAuth": []}, {"ApiKeyAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/UnblockRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "IP unblocked successfully"},
                        "403": {"description": "Forbidden (Requires ADMIN or SOC_ANALYST)"},
                    },
                }
            },
            "/api/blocks": {
                "get": {
                    "tags": ["Mitigation & Defense"],
                    "summary": "List Active Firewall Blocks",
                    "responses": {
                        "200": {"description": "Active firewall blocks and drop counts"}
                    },
                }
            },
            "/api/v1/audit": {
                "get": {
                    "tags": ["Audit & Compliance"],
                    "summary": "Retrieve Cryptographic Audit Trail",
                    "security": [{"BearerAuth": []}, {"ApiKeyAuth": []}],
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100}},
                        {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}},
                    ],
                    "responses": {
                        "200": {"description": "Chronological audit ledger entries"},
                        "403": {"description": "Forbidden (Requires ADMIN, AUDITOR, or SOC_ANALYST)"},
                    },
                }
            },
            "/api/v1/audit/verify": {
                "get": {
                    "tags": ["Audit & Compliance"],
                    "summary": "Cryptographically Verify Audit Chain",
                    "description": "Recalculates SHA-256 block chain from genesis to head and detects tampering.",
                    "security": [{"BearerAuth": []}, {"ApiKeyAuth": []}],
                    "responses": {
                        "200": {"description": "Chain valid (INTEGRITY_VERIFIED)"},
                        "409": {"description": "Chain altered / hash mismatch detected"},
                        "403": {"description": "Forbidden (Requires ADMIN or AUDITOR)"},
                    },
                }
            },
            "/api/v1/keys": {
                "get": {
                    "tags": ["System & Health"],
                    "summary": "List Registered API Keys",
                    "security": [{"BearerAuth": []}],
                    "responses": {
                        "200": {"description": "List of active API keys"},
                        "403": {"description": "Forbidden (Requires ADMIN)"},
                    },
                },
                "post": {
                    "tags": ["System & Health"],
                    "summary": "Register New API Key",
                    "security": [{"BearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ApiKeyCreateRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "API key registered successfully"},
                        "403": {"description": "Forbidden (Requires ADMIN)"},
                    },
                },
            },
            "/api/v1/export/stix": {
                "get": {
                    "tags": ["SIEM & Threat Sharing"],
                    "summary": "Export OASIS STIX 2.1 Threat Bundle",
                    "description": "Generates a valid STIX 2.1 JSON bundle containing indicator, attack-pattern, relationship, and sighting objects.",
                    "responses": {
                        "200": {
                            "description": "STIX 2.1 JSON bundle",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/STIXBundle"}
                                }
                            },
                        }
                    },
                }
            },
            "/api/v1/federated/status": {
                "get": {
                    "tags": ["Fleet & Federated Learning"],
                    "summary": "Fleet Federated Learning Status",
                    "responses": {
                        "200": {"description": "Current FedAvg round, model hash, and PSI feature drift"}
                    },
                }
            },
            "/api/v1/federated/round": {
                "post": {
                    "tags": ["Fleet & Federated Learning"],
                    "summary": "Trigger On-Demand Federated Round",
                    "security": [{"BearerAuth": []}, {"ApiKeyAuth": []}],
                    "responses": {
                        "200": {"description": "Federated round completed and model updated"},
                        "403": {"description": "Forbidden (Requires ADMIN or SOC_ANALYST)"},
                    },
                }
            },
            "/api/v1/fleet/register": {
                "post": {
                    "tags": ["Fleet & Federated Learning"],
                    "summary": "Register Edge Sensor Gateway",
                    "description": "Registers a new remote edge sensor gateway with the central SOC control plane.",
                    "responses": {
                        "201": {"description": "Sensor registered and secret assigned"},
                        "400": {"description": "Missing node_id"},
                    },
                }
            },
            "/api/v1/fleet/heartbeat": {
                "post": {
                    "tags": ["Fleet & Federated Learning"],
                    "summary": "Edge Sensor Telemetry Heartbeat",
                    "description": "Ingests periodic telemetry and dispatches global herd immunity blocks. Requires HMAC-SHA256 request signing.",
                    "responses": {
                        "200": {"description": "Heartbeat acknowledged and pending global blocks returned"},
                        "401": {"description": "Invalid HMAC signature or replay attack (>60s skew)"},
                        "404": {"description": "Unknown node ID"},
                    },
                }
            },
            "/api/v1/fleet/nodes": {
                "get": {
                    "tags": ["Fleet & Federated Learning"],
                    "summary": "List Fleet Edge Gateways",
                    "description": "Returns live health, latency, model sync status, and XDP drop stats for all edge nodes.",
                    "responses": {
                        "200": {"description": "List of active edge gateways"},
                    },
                }
            },
            "/api/v1/fleet/broadcast_block": {
                "post": {
                    "tags": ["Fleet & Federated Learning"],
                    "summary": "Broadcast Global Herd Immunity Quarantine",
                    "description": "Pushes an attacker IP across all remote edge sensor gateways for immediate local blocking.",
                    "security": [{"BearerAuth": []}, {"ApiKeyAuth": []}],
                    "responses": {
                        "200": {"description": "Global block enqueued across fleet"},
                        "403": {"description": "Forbidden (Requires ADMIN or SOC_ANALYST)"},
                    },
                }
            },
            "/api/v1/soc/kpis": {
                "get": {
                    "tags": ["SOC Executive Telemetry"],
                    "summary": "Get Live SOC SecOps KPIs & SLAs",
                    "description": "Returns real-time MTTD, MTTR, MITRE matrix breakdown, and Fleet Immunity Index.",
                    "responses": {
                        "200": {"description": "Real-time SOC KPIs and SLA performance"},
                    },
                }
            },
            "/api/v1/reports/executive": {
                "get": {
                    "tags": ["SOC Executive Telemetry"],
                    "summary": "Generate Executive Compliance & Posture Report",
                    "description": "Produces an executive audit and posture report in JSON, print-ready HTML, or Markdown.",
                    "parameters": [
                        {
                            "name": "format",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string", "enum": ["json", "html", "markdown"], "default": "json"},
                            "description": "Report output format",
                        }
                    ],
                    "responses": {
                        "200": {"description": "Executive report generated successfully"},
                    },
                }
            },
            "/health/live": {
                "get": {
                    "tags": ["System & Health"],
                    "summary": "Liveness Probe",
                    "responses": {
                        "200": {"description": "Process is alive"}
                    },
                }
            },
            "/health/ready": {
                "get": {
                    "tags": ["System & Health"],
                    "summary": "Readiness Probe",
                    "responses": {
                        "200": {"description": "Subsystems and models are loaded"}
                    },
                }
            },
            "/metrics": {
                "get": {
                    "tags": ["System & Health"],
                    "summary": "Prometheus Metrics",
                    "responses": {
                        "200": {
                            "description": "Prometheus text format metrics",
                            "content": {"text/plain": {}},
                        }
                    },
                }
            },
        },
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "Enter JWT token obtained from POST /api/v1/login",
                },
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-IoTGuard-API-Key",
                    "description": "Enter scoped enterprise API key",
                },
            },
            "schemas": {
                "BlockRequest": {
                    "type": "object",
                    "required": ["ip"],
                    "properties": {
                        "ip": {"type": "string", "example": "198.51.100.42"},
                        "duration": {"type": "integer", "default": 300},
                        "reason": {"type": "string", "default": "Manual SOC Quarantine"},
                    },
                },
                "UnblockRequest": {
                    "type": "object",
                    "required": ["ip"],
                    "properties": {
                        "ip": {"type": "string", "example": "198.51.100.42"},
                    },
                },
                "ApiKeyCreateRequest": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": {"type": "string", "example": "siem-collector"},
                        "role": {
                            "type": "string",
                            "enum": ["ADMIN", "SOC_ANALYST", "AUDITOR", "EDGE_SENSOR"],
                            "default": "SOC_ANALYST",
                        },
                    },
                },
                "STIXBundle": {
                    "type": "object",
                    "required": ["type", "id", "objects"],
                    "properties": {
                        "type": {"type": "string", "example": "bundle"},
                        "id": {"type": "string", "example": "bundle--3b827e8a-d9ec-4b06-a841-b8efd8eb876b"},
                        "objects": {
                            "type": "array",
                            "items": {"type": "object"},
                        },
                    },
                },
                "EventsListResponse": {
                    "type": "object",
                    "properties": {
                        "ok": {"type": "boolean", "example": True},
                        "count": {"type": "integer", "example": 25},
                        "events": {"type": "array", "items": {"type": "object"}},
                    },
                },
            },
        },
    }


def get_swagger_ui_html(openapi_url: str = "/api/openapi.json", title: str = "IoTGuard API Documentation") -> str:
    """Generate self-contained HTML page rendering Swagger UI for OpenAPI 3.1."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
  <style>
    body {{
      margin: 0;
      background: #0f172a;
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }}
    .topbar {{
      background: #090d16 !important;
      border-bottom: 1px solid #1e293b;
      padding: 10px 20px;
    }}
    .swagger-ui .topbar a {{
      color: #38bdf8 !important;
      font-weight: 700;
      font-size: 1.1rem;
      text-decoration: none;
    }}
    .swagger-ui {{
      background: #0f172a;
      color: #e2e8f0;
      padding-bottom: 40px;
    }}
    .swagger-ui .info .title {{
      color: #38bdf8;
    }}
    .swagger-ui .info p, .swagger-ui .info li {{
      color: #94a3b8;
    }}
    .swagger-ui .scheme-container {{
      background: #1e293b;
      box-shadow: none;
      border-radius: 8px;
    }}
    .swagger-ui .opblock {{
      background: #1e293b;
      border-color: #334155;
      border-radius: 8px;
    }}
    .swagger-ui .opblock .opblock-summary {{
      border-color: #334155;
    }}
    .swagger-ui .opblock .opblock-summary-method {{
      border-radius: 4px;
      font-weight: 700;
    }}
    .swagger-ui .opblock .opblock-summary-path {{
      color: #f1f5f9;
    }}
    .swagger-ui .opblock .opblock-summary-description {{
      color: #94a3b8;
    }}
    .swagger-ui table thead tr td, .swagger-ui table thead tr th {{
      color: #cbd5e1;
      border-bottom-color: #334155;
    }}
    .swagger-ui .response-col_status {{
      color: #f1f5f9;
    }}
    .swagger-ui .btn {{
      border-radius: 6px;
    }}
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {{
      window.ui = SwaggerUIBundle({{
        url: "{openapi_url}",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout"
      }});
    }};
  </script>
</body>
</html>
"""

