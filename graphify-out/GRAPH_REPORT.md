# Graph Report - iotguard  (2026-11-06)

## Corpus Check
- 136 files · ~320,457 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 8 file(s) not represented in the graph (top: (none) 4, .css 2, .conf 1)

## Summary
- 3136 nodes · 5108 edges · 203 communities (117 shown, 86 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 512 edges (avg confidence: 0.89)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `a0c67a7c`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- json
- IOTGUARD_CODEBASE.md
- pathlib
- time
- ThreatIntel
- api_dashboard.py
- DeviceFingerprinter
- typing
- get_logger
- with
- post
- AlertManager
- evaluate_feature_drift
- Gauge
- IoTGuard - Final Project Report
- 03_CODE_OVERVIEW.md
- 🛡️ IoTGuard
- IoTGuard - Final Project Report
- retry.py
- FleetControlPlane
- test_fleet_control_plane.py
- PolicyConfig
- 🛡️ IoTGuard: Master System Handover & Technical Specification
- 🛡️ IoTGuard: Master System Handover & Technical Specification
- test_all_models.py
- HealthChecker
- dashboard
- IoTGuard_Final_Report_Detailed_4ce3b14f.md
- argparse
- TemporalDetector
- AuditLedger
- compute_hmac_signature
- policy.py
- infer_attack_taxonomy
- ModelVersionManager
- TestForensicsAPI
- test_enterprise_storage_rbac.py
- TestValidateIP
- EnsemblePredictor
- FederatedCoordinator
- BaseStorageEngine
- ._reload_config
- 🛡️ IoTGuard: Master System Handover & Technical Specification
- AsyncSIEMDispatcher
- EdgeSensorAgent
- federated_averaging
- EventLogger
- TestEnsemblePredictor
- forensic_snapshot.py
- FastCSVStreamReader
- .is_available
- generate_forensic_snapshot
- ModelManager
- ZeroDayAnomalyEngine
- .get_drop_stats
- TestSOCMetricsTracker
- EBPFBlocker
- Any
- AccessControl
- RateLimiter
- TestBlockerDriverHierarchy
- TestRateLimiter
- decision
- decision
- create_token
- 🛡️ IoTGuard: Master System Handover & Technical Specification
- .update
- decorated
- evaluate_all.py
- TestIPValidation
- EdgeClientNode
- SOCMetricsTracker
- suricata_to_features.py
- .simulate_scan
- get_alert_manager
- load_cfg
- SQLiteStorageEngine
- Any
- TestNumericValidation
- TestStringValidation
- TestAPIEndpoints
- FINAL_REPORT_6f6a70ee.md
- FINAL_REPORT_detailed_d40d8187.md
- FINAL_REPORT_ecbfa1fe.md
- 🛡️ IoTGuard - Project Presentation
- convert_pcap_datasets.py
- main
- score_feature_drift
- get_driver_telemetry
- generate_executive_report
- demo_launcher.py
- TestSOCEndpointsAPI
- create_word_report.py
- entry_to_hex_bytes
- main
- get_ensemble
- IPBaselineTracker
- ForensicEvidenceBundle
- TestTopologyAndBlockApi
- decision
- 🐳 IoTGuard Docker Deployment Guide
- Histogram
- Any
- TestTaxonomyNormalization
- auth.py
- rate_limiting
- unsupervised
- PCACovarianceDetector
- IoTGuard System Architecture & Pipeline Specification (v4.0 Enterprise)
- RealTimeExplainer
- get_openapi_spec
- 📚 IoTGuard Project Documentation
- LRUCache
- ECODDetector
- api_demo_inject
- validate_config_value
- validate_feature_vector
- TestToBinaryLabels
- iot
- math
- main
- build_or_load_zero_day_engine
- fresh_soc_tracker
- TestTemporalWindowBuffer
- stream_csvs.py
- 9. Upgrade Roadmap & Enhancement Opportunities
- validate_api_key
- RateLimiter
- check_rate_limit
- TestBlockIP
- TestComputeAdaptiveThreshold
- TestApiAndMetricsTelemetry
- test_policy.py
- TestCIDRValidation
- hybrid
- temporal
- process_cicids2017.py
- repos
- 10. Operational Command Reference
- 9. Upgrade Roadmap & Enhancement Opportunities
- generate_training_dataset.py
- compute_unsupervised_score
- api_get_audit
- 10. Operational Command Reference
- 9. Upgrade Roadmap & Enhancement Opportunities
- fleet_plane
- device_map
- model.yaml
- lgbm
- 5. Machine Learning & Detection Engine Mechanics
- .__init__
- .add_blocked_ip
- scripts/README.md
- mock_alerts_file
- TestAPIv1Endpoints
- TestHealthEndpoints
- TestFederatedApiEndpoints
- TestDashboardAPIEndpoints
- TestPickBestThreshold
- _check_rate_limit
- ensemble
- graceful_shutdown
- 5. Docker Deployment
- Docker Commands Reference
- Troubleshooting
- TestErrorHandling
- app_client
- detector
- app_client
- 1. Project Overview
- 3. Key Features
- 4. Machine Learning Pipeline
- 8. Testing & Validation
- 9. Demo Walkthrough
- get_federated_coordinator
- verify_bundle_integrity
- api_fleet_nodes
- authenticate_user
- register_api_key
- TestPrometheusMetrics
- TestEndToEndSmoke
- _add_rate_limit_headers
- 2. System Architecture
- test_storage_engine_concurrent_writes
- client
- TestRemediationPlaybooks
- temp_csv_dir
- TestDecisionLoopStreamIntegration
- configs/README.md
- models/README.md
- iotguard

## God Nodes (most connected - your core abstractions)
1. `PolicyConfig` - 30 edges
2. `SQLiteStorageEngine` - 27 edges
3. `FastCSVStreamReader` - 26 edges
4. `EBPFBlocker` - 25 edges
5. `AsyncSIEMDispatcher` - 22 edges
6. `TemporalDetector` - 22 edges
7. `generate_forensic_snapshot()` - 22 edges
8. `AlertManager` - 21 edges
9. `ThreatIntel` - 21 edges
10. `EnsemblePredictor` - 20 edges

## Surprising Connections (you probably didn't know these)
- `Phase 6: Edge Federated Learning & Drift-Triggered Continual Learning (P4) — ✅ COMPLETED` --references--> `EdgeClientNode`  [INFERRED]
  graphify-out/converted/SYSTEM_HANDOFF_FOR_ARGON_ae861e23.md → scripts/2_training/federated_learning.py
- `Phase 6: Edge Federated Learning & Drift-Triggered Continual Learning (P4) — ✅ COMPLETED` --references--> `EdgeClientNode`  [INFERRED]
  project_documentation/SYSTEM_HANDOFF_FOR_ARGON.md → scripts/2_training/federated_learning.py
- `7.1 Testing Verification Matrix (226 / 226 Tests Passed)` --references--> `PolicyConfig`  [INFERRED]
  FINAL_REPORT.md → scripts/3_inference/policy.py
- `7.1 Testing Verification Matrix (293 / 293 Tests Passed)` --references--> `PolicyConfig`  [INFERRED]
  project_documentation/FINAL_REPORT.md → scripts/3_inference/policy.py
- `2. High-Level Pipeline Stages` --references--> `FleetControlPlane`  [INFERRED]
  project_documentation/02_ARCHITECTURE.md → scripts/9_utilities/edge_agent.py

## Import Cycles
- None detected.

## Communities (203 total, 86 thin omitted)

### Community 0 - "json"
Cohesion: 0.04
Nodes (31): analyze_model_importance(), map_cicids_to_iotguard(), _load_config(), main(), pick_best_threshold(), step1_convert_edge_iiotset(), step2_merge_datasets(), step3_backup_models() (+23 more)

### Community 1 - "IOTGUARD_CODEBASE.md"
Cohesion: 0.02
Nodes (101): FILE: c:\Users\ahmed\OneDrive\Desktop\SENIORproject\iotguard\app.py, FILE: c:\Users\ahmed\OneDrive\Desktop\SENIORproject\iotguard\configs\access_control.yaml, FILE: c:\Users\ahmed\OneDrive\Desktop\SENIORproject\iotguard\configs\devices.yaml, FILE: c:\Users\ahmed\OneDrive\Desktop\SENIORproject\iotguard\configs\model_lab.yaml, FILE: c:\Users\ahmed\OneDrive\Desktop\SENIORproject\iotguard\configs\model_prod.yaml, FILE: c:\Users\ahmed\OneDrive\Desktop\SENIORproject\iotguard\configs\model.yaml, FILE: c:\Users\ahmed\OneDrive\Desktop\SENIORproject\iotguard\create_word_report.py, FILE: c:\Users\ahmed\OneDrive\Desktop\SENIORproject\iotguard\export_codebase.py (+93 more)

### Community 2 - "pathlib"
Cohesion: 0.04
Nodes (19): block_ip(), block_ip_linux(), block_ip_windows(), get_active_driver(), get_configured_firewall_backend(), have(), is_wsl(), record_block() (+11 more)

### Community 3 - "time"
Cohesion: 0.04
Nodes (34): generate_attack_flow(), generate_benign_device_flow(), main(), _escape_cef_extension(), _escape_cef_header(), format_cef_event(), format_rfc5424_syslog(), generate_stix_bundle() (+26 more)

### Community 4 - "ThreatIntel"
Cohesion: 0.05
Nodes (10): Phase 5: Production Threat Intelligence & Real GeoIP (P3) — ✅ COMPLETED, Phase 5: Production Threat Intelligence & Real GeoIP (P3) — ✅ COMPLETED, Phase 5: Production Threat Intelligence & Real GeoIP (P3) — ✅ COMPLETED, is_ip_blocked(), iso_country_to_flag(), ThreatIntel, _task(), Phase 5: Production Threat Intelligence & Real GeoIP (P3) — ✅ COMPLETED (+2 more)

### Community 5 - "api_dashboard.py"
Cohesion: 0.06
Nodes (28): api_counts(), api_demo_status(), api_docs_ui(), api_download_csv(), api_events(), api_export_cef(), api_export_stix(), api_forensic_snapshot() (+20 more)

### Community 6 - "DeviceFingerprinter"
Cohesion: 0.05
Nodes (4): DeviceFingerprinter, get_fingerprinter(), TestDeviceFingerprinter, TestGetFingerprinter

### Community 7 - "typing"
Cohesion: 0.06
Nodes (4): _load_feature_list(), parse_line(), record_detection(), validate_ip_or_cidr()

### Community 8 - "get_logger"
Cohesion: 0.06
Nodes (10): ColoredFormatter, get_audit_logger(), get_logger(), JSONFormatter, log_event(), TestAuditLogger, TestColoredFormatter, TestGetLogger (+2 more)

### Community 9 - "with"
Cohesion: 0.06
Nodes (41): name, runs-on, steps, PYTHONPATH, jobs, docker, lint, security (+33 more)

### Community 10 - "post"
Cohesion: 0.07
Nodes (20): api_block_ip(), api_clear(), api_clear_all(), api_create_api_key(), api_demo_start(), api_demo_stop(), api_federated_round(), api_fleet_blocks() (+12 more)

### Community 11 - "AlertManager"
Cohesion: 0.07
Nodes (4): AlertManager, TestAlertManagerConfig, TestSendAlert, TestSeverityLevels

### Community 12 - "evaluate_feature_drift"
Cohesion: 0.08
Nodes (7): calculate_ks(), calculate_psi(), evaluate_feature_drift(), FeatureDriftDetector, main(), TestFeatureDriftDetector, TestFeatureDriftMath

### Community 13 - "Gauge"
Cohesion: 0.06
Nodes (8): Counter, Gauge, get_metrics_json(), record_api_request(), record_block(), record_xdp_drops(), update_firewall_telemetry(), update_model_drift()

### Community 14 - "IoTGuard - Final Project Report"
Cohesion: 0.06
Nodes (34): 1.1 Project Overview, 1.2 Key Achievements & Engineering Milestones, **1. Binary IoT Model (LightGBM on 651,944 Holdout Samples)**, 1. Executive Summary, 2.1 High-Level Component Diagram, 2.2 Detailed Data Flow Pipeline, 2.3 The 13 Network Behavioral Features, **2. Binary IT Model (LightGBM on 5,661 Samples)** (+26 more)

### Community 15 - "03_CODE_OVERVIEW.md"
Cohesion: 0.06
Nodes (34): `alerting.py`, `analyze_feature_importance.py`, `api_dashboard.py`, `auth.py`, `blocker.py` and `unblock.py`, `check_feature_drift.py`, `console_dashboard.py`, `convert_pcap_datasets.py` (+26 more)

### Community 16 - "🛡️ IoTGuard"
Cohesion: 0.06
Nodes (34): 1. Create and activate a virtual environment (recommended), 1. Feature Source, 1. Prepare training data, 2. Decision Loop (ML Scoring Engine), 2. Install dependencies, 2. Train LightGBM (Supervised), 3. Dashboard (Web UI), 3. Optional: Suricata integration (+26 more)

### Community 17 - "IoTGuard - Final Project Report"
Cohesion: 0.06
Nodes (33): 1.1 Project Overview, **1. Binary IoT Model (LightGBM on 651,944 Holdout Samples)**, 1. Executive Summary, 2.1 High-Level Component Diagram, 2.2 Detailed Data Flow Pipeline, 2.3 The 13 Network Behavioral Features, **2. Binary IT Model (LightGBM on 5,661 Samples)**, 2. Final System Architecture and Design (+25 more)

### Community 18 - "retry.py"
Cohesion: 0.08
Nodes (8): CircuitBreaker, wrapper(), retry(), decorator(), wrapper(), TimeoutError, with_retry(), with_timeout()

### Community 20 - "test_fleet_control_plane.py"
Cohesion: 0.06
Nodes (15): test_api_fleet_broadcast_block_admin_only(), test_api_fleet_heartbeat_invalid_signature_returns_401(), test_api_fleet_heartbeat_missing_headers_returns_401(), test_api_fleet_nodes_endpoint(), test_api_fleet_register_endpoint(), test_api_fleet_register_missing_node_id_rejected(), test_control_plane_empty_node_id_rejected(), test_control_plane_register_node() (+7 more)

### Community 21 - "PolicyConfig"
Cohesion: 0.15
Nodes (15): 8.1 Resolution of Previous Refactoring Debt & Enterprise Stability (RESOLVED), Phase 1: Stabilization & Debt Resolution (P1) — ✅ COMPLETED, 8.1 Resolution of Previous Refactoring Debt & Enterprise Stability (RESOLVED), Phase 1: Stabilization & Debt Resolution (P1) — ✅ COMPLETED, 8.1 Resolution of Previous Refactoring Debt & Enterprise Stability (RESOLVED), Phase 1: Stabilization & Debt Resolution (P1) — ✅ COMPLETED, debug_no_block_reason(), determine_response() (+7 more)

### Community 22 - "🛡️ IoTGuard: Master System Handover & Technical Specification"
Cohesion: 0.07
Nodes (29): 10. Operational Command Reference, 1.1 The Problem It Solves, 1.2 IoTGuard Solution, 1. Executive Summary & Purpose, 1. Map real Edge-IIoTset records into IoTGuard 13 features, 2. End-to-End System Architecture & Data Flow, 2. Retrain models, apply calibration, and evaluate against holdout set, 3. The 13-Feature Schema Specification (+21 more)

### Community 23 - "🛡️ IoTGuard: Master System Handover & Technical Specification"
Cohesion: 0.07
Nodes (29): 10. Operational Command Reference, 1.1 The Problem It Solves, 1.2 IoTGuard Solution, 1. Executive Summary & Purpose, 1. Map real Edge-IIoTset records into IoTGuard 13 features, 2. End-to-End System Architecture & Data Flow, 2. Retrain models, apply calibration, and evaluate against holdout set, 3. The 13-Feature Schema Specification (+21 more)

### Community 24 - "test_all_models.py"
Cohesion: 0.14
Nodes (15): Colors, compute_metrics(), create_comparison_table(), load_models(), load_test_data(), main(), prepare_features(), print_header() (+7 more)

### Community 25 - "HealthChecker"
Cohesion: 0.11
Nodes (4): HealthChecker, HealthCheckResult, is_system_healthy(), run_health_checks()

### Community 26 - "dashboard"
Cohesion: 0.07
Nodes (26): build, command, container_name, depends_on, environment, ports, restart, volumes (+18 more)

### Community 27 - "IoTGuard_Final_Report_Detailed_4ce3b14f.md"
Cohesion: 0.07
Nodes (26): 1.1 Project Overview, 1.2 Key Achievements & Engineering Milestones, 1. Executive Summary, 2.1 High-Level Component Diagram, 2.2 Detailed Data Flow Pipeline, 2.3 The 13 Network Features (Deep Dive), 2.4 Ensemble Logic Diagram, 2. Final System Architecture and Design (+18 more)

### Community 28 - "argparse"
Cohesion: 0.11
Nodes (10): convert_edge_iiotset(), _detect_protocol(), main(), _safe_numeric(), main(), tail_file(), generate_dataset(), main() (+2 more)

### Community 29 - "TemporalDetector"
Cohesion: 0.13
Nodes (10): Phase 2: Stateful Temporal Sequence & Low-and-Slow Detection (P2) — ✅ COMPLETED, Phase 2: Stateful Temporal Sequence & Low-and-Slow Detection (P2) — ✅ COMPLETED, `temporal_detector.py`, Phase 2: Stateful Temporal Sequence & Low-and-Slow Detection (P2) — ✅ COMPLETED, compute_hybrid_decision(), RollingWindowAggregator, TemporalDetector, Phase 2: Stateful Temporal Sequence & Low-and-Slow Detection (P2) — ✅ COMPLETED (+2 more)

### Community 30 - "AuditLedger"
Cohesion: 0.12
Nodes (8): Phase 8: High-Performance Indexed Relational Storage Engine & Cryptographic Audit Ledger (P1 Enterprise) — ✅ COMPLETED, `audit_ledger.py`, Phase 8: High-Performance Indexed Relational Storage Engine & Cryptographic Audit Ledger (P1 Enterprise) — ✅ COMPLETED, AuditLedger, canonical_json_str(), compute_entry_hash(), test_audit_ledger_broken_link_tamper(), test_audit_ledger_genesis_and_chaining()

### Community 31 - "compute_hmac_signature"
Cohesion: 0.11
Nodes (12): `edge_agent.py`, canonicalize_payload(), compute_hmac_signature(), verify_hmac_request(), test_api_fleet_heartbeat_authenticated_flow(), test_api_fleet_heartbeat_replay_drift_returns_401(), test_compute_and_verify_hmac_signature_success(), test_replay_attack_rejected_timestamp_in_future() (+4 more)

### Community 32 - "policy.py"
Cohesion: 0.11
Nodes (10): block_ip_wrapper(), get_mitre_attack(), get_remediation_playbook(), normalize_taxonomy(), block_ip_wrapper(), blocker_block_ip(), normalize_taxonomy(), update_ip_baseline() (+2 more)

### Community 33 - "infer_attack_taxonomy"
Cohesion: 0.10
Nodes (6): classify_attack_heuristic(), compute_shannon_entropy(), infer_attack_taxonomy(), TestClassifyAttackHeuristic, TestMultiClassInference, TestShannonEntropyNoveltyDetection

### Community 35 - "TestForensicsAPI"
Cohesion: 0.09
Nodes (4): mock_event(), mock_trigger_features(), temp_forensics_dir(), TestForensicsAPI

### Community 36 - "test_enterprise_storage_rbac.py"
Cohesion: 0.11
Nodes (8): main(), auth_client(), temp_env(), test_audit_ledger_tamper_detection(), test_dual_write_persistence_integration(), test_rbac_admin_full_access(), test_storage_engine_active_blocks_and_edge_nodes(), test_event_logger_mitre_attachment()

### Community 39 - "FederatedCoordinator"
Cohesion: 0.12
Nodes (3): FederatedCoordinator, app_client(), TestFederatedCoordinator

### Community 41 - "._reload_config"
Cohesion: 0.12
Nodes (3): _ip_in_networks(), _load_config(), _parse_ip_list()

### Community 42 - "🛡️ IoTGuard: Master System Handover & Technical Specification"
Cohesion: 0.10
Nodes (19): 1.1 The Problem It Solves, 1.2 IoTGuard Solution, 1. Executive Summary & Purpose, 2. End-to-End System Architecture & Data Flow, 3. The 13-Feature Schema Specification, 4. Complete Codebase Directory & File Map, 5.1 Supervised LightGBM (`scripts/2_training/train_supervised.py`), 5.2 Unsupervised IsolationForest (`scripts/2_training/train_unsupervised.py`) (+11 more)

### Community 43 - "AsyncSIEMDispatcher"
Cohesion: 0.12
Nodes (7): 8.2 Production Release v4.0 Readiness Checklist, 8.2 Production Release v4.0 Readiness Checklist, `stream_reader.py`, 1.2 Key Achievements & Engineering Milestones, AsyncSIEMDispatcher, 8.2 Production Release v4.0 Readiness Checklist, TestAsyncSIEMDispatcher

### Community 44 - "EdgeSensorAgent"
Cohesion: 0.14
Nodes (3): Phase 10: Distributed Control Plane, Edge Sensor Agent & Global Fleet Quarantine (P1 Enterprise) — ✅ COMPLETED, EdgeSensorAgent, test_edge_sensor_agent_enforces_blocks_locally()

### Community 45 - "federated_averaging"
Cohesion: 0.14
Nodes (4): clip_and_perturb_deltas(), federated_averaging(), LocalModelUpdate, TestFederatedPrivacyAndMath

### Community 48 - "forensic_snapshot.py"
Cohesion: 0.15
Nodes (9): _build_playbook_and_mitre(), _build_threat_intel_context(), _find_event_by_index(), _get_playbooks_module(), _get_storage_engine(), _get_threat_intel(), load_window_features(), _parse_csv_line() (+1 more)

### Community 49 - "FastCSVStreamReader"
Cohesion: 0.16
Nodes (3): FastCSVStreamReader, TestFastCSVStreamReader, TestO1StreamReaderIncrementalTailing

### Community 56 - ".get_drop_stats"
Cohesion: 0.14
Nodes (3): parse_dump_key(), parse_dump_value(), TestIPv4ByteOrderConversions

### Community 59 - "Any"
Cohesion: 0.15
Nodes (4): canonical_json(), generate_and_save_snapshot(), get_forensic_snapshot(), list_forensic_snapshots()

### Community 60 - "AccessControl"
Cohesion: 0.17
Nodes (3): AccessControl, get_access_control(), TestAccessControl

### Community 64 - "decision"
Cohesion: 0.13
Nodes (14): decision, cooldown_sec, dry_run, grace, instant_block, threshold, window, features (+6 more)

### Community 65 - "decision"
Cohesion: 0.13
Nodes (14): decision, cooldown_sec, dry_run, grace, instant_block, threshold, window, features (+6 more)

### Community 66 - "create_token"
Cohesion: 0.16
Nodes (7): _b64url_encode(), create_token(), refresh_token(), validate_token(), test_rbac_auditor_permissions(), test_rbac_soc_analyst_permissions(), test_token_creation_with_roles()

### Community 67 - "🛡️ IoTGuard: Master System Handover & Technical Specification"
Cohesion: 0.13
Nodes (14): 1.1 The Problem It Solves, 1.2 IoTGuard Solution, 1. Executive Summary & Purpose, 2. End-to-End System Architecture & Data Flow, 3. The 13-Feature Schema Specification, 4. Complete Codebase Directory & File Map, 6.1 Mitigation Tiers, 6.2 Cooldown & Rate Limiting (+6 more)

### Community 69 - "decorated"
Cohesion: 0.16
Nodes (9): get_api_key_from_request(), get_token_from_request(), optional_auth(), decorated(), rate_limit(), require_auth(), decorated(), decorator() (+1 more)

### Community 70 - "evaluate_all.py"
Cohesion: 0.19
Nodes (7): evaluate(), get_iot_test_data(), get_it_test_data(), load_model_and_meta(), main(), prepare_features(), configure_paths()

### Community 73 - "EdgeClientNode"
Cohesion: 0.15
Nodes (9): 9. Upgrade Roadmap & Enhancement Opportunities, Phase 10: Distributed Control Plane, Edge Sensor Agent & Global Fleet Quarantine (P1 Enterprise) — ✅ COMPLETED, Phase 11: SOC Executive SLA Telemetry (MTTD/MTTR), MITRE Heatmap & Compliance Reporting (P1 Enterprise) — ✅ COMPLETED, Phase 3: Fine-Grained Multi-Class Classification & Playbooks (P2) — ✅ COMPLETED, Phase 6: Edge Federated Learning & Drift-Triggered Continual Learning (P4) — ✅ COMPLETED, Phase 7: Interactive Live Topology UI & Device Quarantine (P4) — ✅ COMPLETED, Phase 9: MITRE ATT&CK® Mapping, CEF/Syslog/STIX 2.1 SIEM Exporter & OpenAPI 3.1 (P1 Enterprise) — ✅ COMPLETED, EdgeClientNode (+1 more)

### Community 74 - "SOCMetricsTracker"
Cohesion: 0.14
Nodes (3): `soc_metrics.py`, get_soc_metrics_tracker(), SOCMetricsTracker

### Community 75 - "suricata_to_features.py"
Cohesion: 0.23
Nodes (9): aggregate(), ensure_csv_header(), file_inode(), _handle_shutdown(), load_state(), parse_ts(), run(), save_state() (+1 more)

### Community 77 - "get_alert_manager"
Cohesion: 0.15
Nodes (5): get_alert_manager(), send_threat_alert(), api_v1_alerts_config(), api_v1_test_alert(), TestSendThreatAlert

### Community 78 - "load_cfg"
Cohesion: 0.14
Nodes (7): api_feature_radar(), api_get_config(), api_health(), api_set_config(), load_cfg(), save_cfg(), _validate_config()

### Community 79 - "SQLiteStorageEngine"
Cohesion: 0.16
Nodes (4): get_storage_engine(), SQLiteStorageEngine, test_storage_engine_initialization_and_wal(), test_storage_engine_multidimensional_queries()

### Community 80 - "Any"
Cohesion: 0.16
Nodes (5): validate_int(), validate_ip(), validate_non_negative_int(), validate_path(), validate_positive_int()

### Community 82 - "TestStringValidation"
Cohesion: 0.16
Nodes (3): sanitize_string(), validate_safe_string(), TestStringValidation

### Community 84 - "FINAL_REPORT_6f6a70ee.md"
Cohesion: 0.15
Nodes (12): 1. Executive Summary, 2.1 High-Level Component Flow, 2.2 The 13 Network Behavioral Features Matrix, 2. Final System Architecture and Design, 3. Impact of Engineering Solutions, 4. Contemporary Cybersecurity Issues, 5. Tools, Frameworks & Verified Stack, 6. Test Results & Verification Matrix (+4 more)

### Community 85 - "FINAL_REPORT_detailed_d40d8187.md"
Cohesion: 0.15
Nodes (12): 1. Executive Summary, 2.1 High-Level Component Flow, 2.2 The 13 Network Behavioral Features Matrix, 2. Final System Architecture and Design, 3. Impact of Engineering Solutions, 4. Contemporary Cybersecurity Issues, 5. Tools, Frameworks & Verified Stack, 6. Test Results & Verification Matrix (+4 more)

### Community 86 - "FINAL_REPORT_ecbfa1fe.md"
Cohesion: 0.15
Nodes (12): 1. Executive Summary, 2.1 High-Level Component Flow, 2.2 The 13 Network Behavioral Features Matrix, 2. Final System Architecture and Design, 3. Impact of Engineering Solutions, 4. Contemporary Cybersecurity Issues, 5. Tools, Frameworks & Verified Stack, 6. Test Results & Verification Matrix (+4 more)

### Community 87 - "🛡️ IoTGuard - Project Presentation"
Cohesion: 0.15
Nodes (13): 10. Future Improvements, 6. Code Structure, 7. How It Works, Adaptive Threshold, 🛡️ IoTGuard - Project Presentation, Key Scripts Explained, ML-Driven IoT Intrusion Detection System, Potential Enhancements (+5 more)

### Community 88 - "convert_pcap_datasets.py"
Cohesion: 0.22
Nodes (5): convert_pcap_to_features(), extract_attack_label(), find_column(), main(), normalize_col_name()

### Community 89 - "main"
Cohesion: 0.17
Nodes (5): main(), _normalize_columns(), _pick_features(), _pick_threshold_from_scores(), make_binary_labels()

### Community 90 - "score_feature_drift"
Cohesion: 0.19
Nodes (4): compute_linear_slope(), compute_monotonic_ratio(), score_feature_drift(), TestStatisticalDriftMath

### Community 91 - "get_driver_telemetry"
Cohesion: 0.15
Nodes (6): get_active_blocks(), get_driver_telemetry(), api_get_blocks(), api_topology(), prometheus_metrics(), get_metrics_text()

### Community 92 - "generate_executive_report"
Cohesion: 0.18
Nodes (4): generate_executive_report(), _render_report_html(), _render_report_markdown(), TestExecutiveReportGenerator

### Community 93 - "demo_launcher.py"
Cohesion: 0.21
Nodes (4): ensure_data_dir(), main(), print_banner(), print_instructions()

### Community 95 - "create_word_report.py"
Cohesion: 0.21
Nodes (4): add_code_block(), convert_md_to_docx(), create_final_report_doc(), main()

### Community 96 - "entry_to_hex_bytes"
Cohesion: 0.27
Nodes (7): Phase 4: High-Performance In-Kernel Filtering with eBPF / XDP (P3) — ✅ COMPLETED, Phase 4: High-Performance In-Kernel Filtering with eBPF / XDP (P3) — ✅ COMPLETED, Phase 4: High-Performance In-Kernel Filtering with eBPF / XDP (P3) — ✅ COMPLETED, entry_to_hex_bytes(), ip_to_network_u32(), network_u32_to_ip(), Phase 4: High-Performance In-Kernel Filtering with eBPF / XDP (P3) — ✅ COMPLETED

### Community 97 - "main"
Cohesion: 0.18
Nodes (5): append_row(), compute_features(), ensure_header(), main(), tail_file()

### Community 98 - "get_ensemble"
Cohesion: 0.17
Nodes (5): get_ensemble(), api_v1_ensemble(), api_v1_predict(), health_ready(), TestGetEnsemble

### Community 102 - "decision"
Cohesion: 0.18
Nodes (11): decision, cooldown_sec, dry_run, firewall_backend, grace, instant_block, threshold, use_adaptive (+3 more)

### Community 103 - "🐳 IoTGuard Docker Deployment Guide"
Cohesion: 0.18
Nodes (11): Environment Variables, Example docker-compose.yml, Health Checks, 🐳 IoTGuard Docker Deployment Guide, Ports, Production Deployment, Quick Start, Resource Limits (+3 more)

### Community 104 - "Histogram"
Cohesion: 0.18
Nodes (3): Histogram, record_inference_time(), record_score()

### Community 108 - "rate_limiting"
Cohesion: 0.20
Nodes (9): allowlist, blocklist, rate_limiting, config_limit, default_limit, enabled, exempt_ips, login_limit (+1 more)

### Community 109 - "unsupervised"
Cohesion: 0.20
Nodes (10): unsupervised, contamination, enabled, fallback_quantile, max_samples, meta_path, model_path, n_estimators (+2 more)

### Community 111 - "IoTGuard System Architecture & Pipeline Specification (v4.0 Enterprise)"
Cohesion: 0.20
Nodes (6): 1. High-Level Architecture Diagram, 2. High-Level Pipeline Stages, 3. Key Files & Repository Map, 4. Security Architecture, 5. Prometheus Observability Metrics, IoTGuard System Architecture & Pipeline Specification (v4.0 Enterprise)

### Community 113 - "get_openapi_spec"
Cohesion: 0.20
Nodes (5): `openapi_spec.py`, get_openapi_spec(), get_swagger_ui_html(), test_openapi_spec_structure(), test_swagger_ui_html_rendering()

### Community 114 - "📚 IoTGuard Project Documentation"
Cohesion: 0.20
Nodes (10): 📁 Contents, For Deployment, For Presentations, For Results, For Technical Details, 📚 IoTGuard Project Documentation, Overview, 📊 Project Summary (+2 more)

### Community 117 - "api_demo_inject"
Cohesion: 0.22
Nodes (5): api_demo_inject(), _generate_sim_attack_row(), _generate_sim_benign_row(), _sim_background_loop(), _write_feature_row()

### Community 121 - "iot"
Cohesion: 0.22
Nodes (9): meta, path, threshold, meta, path, threshold, models, iot (+1 more)

### Community 123 - "main"
Cohesion: 0.25
Nodes (6): has_required_cols(), main(), maybe_reload_config(), read_window_meta(), to_numeric(), get_remediation_playbook()

### Community 125 - "fresh_soc_tracker"
Cohesion: 0.22
Nodes (4): admin_headers(), auditor_headers(), client(), fresh_soc_tracker()

### Community 128 - "stream_csvs.py"
Cohesion: 0.39
Nodes (3): ensure_header(), main(), stream_file()

### Community 129 - "9. Upgrade Roadmap & Enhancement Opportunities"
Cohesion: 0.25
Nodes (8): 9. Upgrade Roadmap & Enhancement Opportunities, Phase 10: Distributed Control Plane, Edge Sensor Agent & Global Fleet Quarantine (P1 Enterprise) — ✅ COMPLETED, Phase 11: SOC Executive SLA Telemetry (MTTD/MTTR), MITRE Heatmap & Compliance Reporting (P1 Enterprise) — ✅ COMPLETED, Phase 3: Fine-Grained Multi-Class Classification & Playbooks (P2) — ✅ COMPLETED, Phase 6: Edge Federated Learning & Drift-Triggered Continual Learning (P4) — ✅ COMPLETED, Phase 7: Interactive Live Topology UI & Device Quarantine (P4) — ✅ COMPLETED, Phase 8: High-Performance Indexed Relational Storage Engine & Cryptographic Audit Ledger (P1 Enterprise) — ✅ COMPLETED, Phase 9: MITRE ATT&CK® Mapping, CEF/Syslog/STIX 2.1 SIEM Exporter & OpenAPI 3.1 (P1 Enterprise) — ✅ COMPLETED

### Community 131 - "validate_api_key"
Cohesion: 0.29
Nodes (4): list_api_keys(), revoke_api_key(), validate_api_key(), test_api_key_lifecycle()

### Community 133 - "check_rate_limit"
Cohesion: 0.25
Nodes (3): check_rate_limit(), get_rate_limiter(), TestCheckRateLimit

### Community 139 - "hybrid"
Cohesion: 0.29
Nodes (7): hybrid, combine_strategy, mode, supervised_weight, unsup_only_label, unsup_threshold, unsupervised_weight

### Community 140 - "temporal"
Cohesion: 0.29
Nodes (7): temporal, boost_weight, drift_threshold, enabled, features, min_windows, window_size

### Community 142 - "repos"
Cohesion: 0.29
Nodes (6): args, id, repos, hooks, repo, rev

### Community 143 - "10. Operational Command Reference"
Cohesion: 0.29
Nodes (7): 10. Operational Command Reference, Launching the Full System in Demo Mode, Retraining Supervised & Unsupervised Models on Real Data, Running Holdout Evaluation Benchmark, Running the Test Suite, Running via Docker Compose, Virtual Environment Setup & Dependencies

### Community 144 - "9. Upgrade Roadmap & Enhancement Opportunities"
Cohesion: 0.29
Nodes (7): 9. Upgrade Roadmap & Enhancement Opportunities, Phase 11: SOC Executive SLA Telemetry (MTTD/MTTR), MITRE Heatmap & Compliance Reporting (P1 Enterprise) — ✅ COMPLETED, Phase 12: O(1) Stream Tailer, Live Async SIEM Streaming & Final v4.0 Hardening (P1 Enterprise) — ✅ COMPLETED, Phase 3: Fine-Grained Multi-Class Classification & Playbooks (P2) — ✅ COMPLETED, Phase 6: Edge Federated Learning & Drift-Triggered Continual Learning (P4) — ✅ COMPLETED, Phase 7: Interactive Live Topology UI & Device Quarantine (P4) — ✅ COMPLETED, Phase 9: MITRE ATT&CK® Mapping, CEF/Syslog/STIX 2.1 SIEM Exporter & OpenAPI 3.1 (P1 Enterprise) — ✅ COMPLETED

### Community 145 - "generate_training_dataset.py"
Cohesion: 0.38
Nodes (3): generate_authentic_attack_flows(), generate_authentic_benign_flows(), main()

### Community 146 - "compute_unsupervised_score"
Cohesion: 0.29
Nodes (3): classify_multiclass(), compute_unsupervised_score(), supervised_score()

### Community 147 - "api_get_audit"
Cohesion: 0.29
Nodes (4): api_get_audit(), api_verify_audit(), get_audit_ledger(), verify_audit_ledger()

### Community 148 - "10. Operational Command Reference"
Cohesion: 0.29
Nodes (7): 10. Operational Command Reference, Launching the Full System in Demo Mode, Retraining Supervised & Unsupervised Models on Real Data, Running Holdout Evaluation Benchmark, Running the Test Suite, Running via Docker Compose, Virtual Environment Setup & Dependencies

### Community 149 - "9. Upgrade Roadmap & Enhancement Opportunities"
Cohesion: 0.29
Nodes (7): 9. Upgrade Roadmap & Enhancement Opportunities, Phase 10: Distributed Control Plane, Edge Sensor Agent & Global Fleet Quarantine (P1 Enterprise) — ✅ COMPLETED, Phase 11: SOC Executive SLA Telemetry (MTTD/MTTR), MITRE Heatmap & Compliance Reporting (P1 Enterprise) — ✅ COMPLETED, Phase 3: Fine-Grained Multi-Class Classification & Playbooks (P2) — ✅ COMPLETED, Phase 7: Interactive Live Topology UI & Device Quarantine (P4) — ✅ COMPLETED, Phase 8: High-Performance Indexed Relational Storage Engine & Cryptographic Audit Ledger (P1 Enterprise) — ✅ COMPLETED, Phase 9: MITRE ATT&CK® Mapping, CEF/Syslog/STIX 2.1 SIEM Exporter & OpenAPI 3.1 (P1 Enterprise) — ✅ COMPLETED

### Community 150 - "fleet_plane"
Cohesion: 0.29
Nodes (3): admin_headers(), client(), fleet_plane()

### Community 151 - "device_map"
Cohesion: 0.33
Nodes (5): default_type, device_map, 10.0.0.50, 192.168.1.100, 192.168.1.101

### Community 152 - "model.yaml"
Cohesion: 0.33
Nodes (5): alerts, email_enabled, min_severity, slack_enabled, features

### Community 153 - "lgbm"
Cohesion: 0.33
Nodes (6): lgbm, colsample_bytree, learning_rate, n_estimators, num_leaves, subsample

### Community 154 - "5. Machine Learning & Detection Engine Mechanics"
Cohesion: 0.33
Nodes (6): 5.1 Supervised LightGBM (`scripts/2_training/train_supervised.py`), 5.2 Unsupervised IsolationForest (`scripts/2_training/train_unsupervised.py`), 5.3 Hybrid Ensemble Logic (`scripts/3_inference/ensemble.py` & `scoring.py`), 5.4 Dynamic Adaptive Thresholding, 5.5 Explainable AI (XAI) via SHAP (`scripts/3_inference/explainer.py`), 5. Machine Learning & Detection Engine Mechanics

### Community 157 - "scripts/README.md"
Cohesion: 0.33
Nodes (5): Data conversion and generation, Explainability, intel, and utilities, Runtime pipeline (what you run in production/demos), Scripts Overview, Training & evaluation

### Community 165 - "ensemble"
Cohesion: 0.40
Nodes (5): ensemble, calibrate, strategy, supervised_weight, unsupervised_weight

### Community 166 - "graceful_shutdown"
Cohesion: 0.40
Nodes (4): Phase 12: O(1) Stream Tailer, Live Async SIEM Streaming & Final v4.0 Hardening (P1 Enterprise) — ✅ COMPLETED, Phase 12: O(1) Stream Tailer, Live Async SIEM Streaming & Final v4.0 Hardening (P1 Enterprise) — ✅ COMPLETED, graceful_shutdown(), Phase 12: O(1) Stream Tailer, Live Async SIEM Streaming & Final v4.0 Hardening (P1 Enterprise) — ✅ COMPLETED

### Community 167 - "5. Docker Deployment"
Cohesion: 0.40
Nodes (5): 5. Docker Deployment, Container Architecture, Docker Commands, Docker Compose Services, Dockerfile Explained

### Community 168 - "Docker Commands Reference"
Cohesion: 0.40
Nodes (5): Building, Docker Commands Reference, Docker Compose, Monitoring, Running

### Community 169 - "Troubleshooting"
Cohesion: 0.40
Nodes (5): Cannot access dashboard, Container won't start, Health check failing, Permission issues, Troubleshooting

### Community 174 - "1. Project Overview"
Cohesion: 0.50
Nodes (4): 1. Project Overview, Problem Statement, Solution, What is IoTGuard?

### Community 175 - "3. Key Features"
Cohesion: 0.50
Nodes (4): 3. Key Features, Feature Matrix, The 13 Network Features, Why These Features?

### Community 176 - "4. Machine Learning Pipeline"
Cohesion: 0.50
Nodes (4): 4. Machine Learning Pipeline, Ensemble Strategy, Model Performance, Training Pipeline

### Community 177 - "8. Testing & Validation"
Cohesion: 0.50
Nodes (4): 8. Testing & Validation, Security Tests, Test Categories, Test Suite

### Community 178 - "9. Demo Walkthrough"
Cohesion: 0.50
Nodes (4): 9. Demo Walkthrough, Dashboard Features, Docker Demo, Quick Start (3 Terminals)

### Community 188 - "2. System Architecture"
Cohesion: 0.67
Nodes (3): 2. System Architecture, Data Flow, High-Level Architecture

## Knowledge Gaps
- **1 isolated node(s):** `iotguard`
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1669 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **86 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `PolicyConfig` connect `PolicyConfig` to `policy.py`, `IoTGuard - Final Project Report`, `decision_loop.py`, `IoTGuard - Final Project Report`?**
  _High betweenness centrality (0.053) - this node is a cross-community bridge._
- **What connects `iotguard` to the rest of the system?**
  _1 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `json` be split into smaller, more focused modules?**
  _Cohesion score 0.04090989243519661 - nodes in this community are weakly interconnected._
- **Why does `🛡️ IoTGuard - Project Presentation` connect `🛡️ IoTGuard - Project Presentation` to `5. Docker Deployment`, `1. Project Overview`, `3. Key Features`, `4. Machine Learning Pipeline`, `IoTGuard System Architecture & Pipeline Specification (v4.0 Enterprise)`, `8. Testing & Validation`, `9. Demo Walkthrough`, `2. System Architecture`?**
  _High betweenness centrality (0.036) - this node is a cross-community bridge._
- **Should `IOTGUARD_CODEBASE.md` be split into smaller, more focused modules?**
  _Cohesion score 0.0196078431372549 - nodes in this community are weakly interconnected._
- **Why does `SQLiteStorageEngine` connect `SQLiteStorageEngine` to `pathlib`, `test_enterprise_storage_rbac.py`, `Any`, `BaseStorageEngine`, `.get_latest_audit_entry`, `._get_connection`, `AuditLedger`, `test_storage_engine_concurrent_writes`?**
  _High betweenness centrality (0.036) - this node is a cross-community bridge._
- **Should `pathlib` be split into smaller, more focused modules?**
  _Cohesion score 0.04411461554318697 - nodes in this community are weakly interconnected._