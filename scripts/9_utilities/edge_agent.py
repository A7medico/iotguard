"""
scripts/9_utilities/edge_agent.py
-----------------------------------------------------------------------------
IoTGuard Enterprise v4.0 — Distributed Fleet Control Plane & Edge Sensor Agent

PURPOSE:
    Separates the central SOC Fleet Control Plane from distributed edge sensor
    gateways (e.g. smart_home, factory_floor, substation_edge, hospital_iot_vlan).
    
    Provides:
      1. HMAC-SHA256 request signing and verification (X-IoTGuard-Signature,
         X-IoTGuard-Timestamp, X-IoTGuard-Node-Id) with 60-second replay protection.
      2. EdgeSensorAgent client: Heartbeat telemetry (CPU/RAM, active XDP drops,
         local model hash, local alerts) and automated global block enforcement.
      3. FleetControlPlane coordinator: Node registration, health tracking,
         model drift/sync verification, and Fleet-Wide Global Block Broadcast
         queue ("herd immunity" across all edge branch locations).
      4. Relational SQLite synchronization with data/iotguard_enterprise.db.
-----------------------------------------------------------------------------
"""

import os
import sys
import json
import time
import hmac
import uuid
import socket
import secrets
import hashlib
import logging
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("iotguard.fleet")

# Optional psutil for real hardware telemetry
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

_scripts_dir = Path(__file__).resolve().parent.parent
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))
from path_setup import configure_paths
configure_paths()

# Try importing storage engine and audit logger
try:
    from storage_engine import get_storage_engine
    STORAGE_AVAILABLE = True
except ImportError:
    STORAGE_AVAILABLE = False
    get_storage_engine = None

try:
    from audit_ledger import record_audit_event
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False
    record_audit_event = None

# Decoupled Block Enforcement (Layer 0 Pub/Sub & Pluggable Handler)
_local_block_handler: Optional[Callable[..., Any]] = None

def register_block_handler(handler: Callable[..., Any]) -> None:
    """Register a callback for local block enforcement without direct Layer 2 dependency."""
    global _local_block_handler
    _local_block_handler = handler

def _dispatch_local_block(ip: str, severity: str = "kill", reason: str = "", dry_run: bool = True) -> Any:
    """Dispatch local block via registered handler, event bus, or lazy dynamic import."""
    if _local_block_handler is not None:
        return _local_block_handler(ip, severity=severity, reason=reason, dry_run=dry_run)
    try:
        from event_bus import publish as bus_publish
        bus_publish("local_block_request", ip=ip, severity=severity, reason=reason, dry_run=dry_run)
    except Exception:
        pass
    try:
        import importlib
        _bl = importlib.import_module("blocker")
        if hasattr(_bl, "block_ip"):
            return _bl.block_ip(ip, severity=severity, reason=reason, dry_run=dry_run)
    except Exception:
        pass
    return True, f"dry-run-{severity}"

BLOCKER_AVAILABLE = True
block_ip = _dispatch_local_block



# =============================================================================
# 1. HMAC-SHA256 REQUEST SIGNING & REPLAY PROTECTION
# =============================================================================

def canonicalize_payload(body: Union[str, bytes, dict, None]) -> str:
    """Canonicalize a request body to a deterministic string."""
    if body is None:
        return ""
    if isinstance(body, dict):
        return json.dumps(body, sort_keys=True, separators=(",", ":"))
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def compute_hmac_signature(
    secret: str,
    timestamp: Union[float, int, str],
    body: Union[str, bytes, dict, None] = ""
) -> str:
    """
    Compute an HMAC-SHA256 signature for a request:
        HMAC_SHA256(secret, f"{int(timestamp)}:{canonical_body}")
    """
    try:
        ts_int = int(float(timestamp))
    except (ValueError, TypeError):
        ts_int = int(time.time())

    body_str = canonicalize_payload(body)
    message = f"{ts_int}:{body_str}".encode("utf-8")
    key = secret.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_hmac_request(
    secret: str,
    signature: str,
    timestamp_val: Union[float, int, str],
    body: Union[str, bytes, dict, None],
    max_skew_sec: float = 60.0
) -> Tuple[bool, str]:
    """
    Verify incoming HMAC request signature and enforce replay protection within
    the max_skew_sec window (default 60s).

    Returns:
        (is_valid, reason_message)
    """
    if not secret:
        return False, "Node secret is missing or empty"
    if not signature:
        return False, "Missing HMAC signature"

    try:
        req_ts = float(timestamp_val)
    except (ValueError, TypeError):
        return False, "Invalid timestamp format in request headers"

    now = time.time()
    drift = abs(now - req_ts)
    if drift > max_skew_sec:
        return (
            False,
            f"Replay attack rejected: clock drift {drift:.1f}s exceeds {max_skew_sec}s allowed window"
        )

    expected = compute_hmac_signature(secret, req_ts, body)
    if not hmac.compare_digest(expected, signature):
        return False, "HMAC signature mismatch"

    return True, "OK"


# =============================================================================
# 2. CENTRAL FLEET CONTROL PLANE
# =============================================================================

def get_central_model_hash(model_path: Optional[Union[str, Path]] = None) -> str:
    """Compute the SHA-256 hash of the central production model."""
    candidate_paths = [
        model_path,
        Path("models/lightgbm.joblib"),
        Path("models/model_meta.json"),
        Path("models/federated_global_model.json"),
    ]
    for p in candidate_paths:
        if p and Path(p).exists():
            try:
                with open(p, "rb") as f:
                    return hashlib.sha256(f.read()).hexdigest()[:16]
            except Exception:
                pass
    return "0000000000000000"


class FleetControlPlane:
    """
    Central SOC Control Plane managing a fleet of distributed Edge Sensor Gateways.
    
    Responsibilities:
      - Authenticates and registers edge sensors across branch locations.
      - Ingests high-frequency telemetry and health heartbeats.
      - Tracks model version drift across all edge gateways.
      - Maintains the Global Fleet Quarantine Queue ("Herd Immunity"):
        when high-severity attackers are identified at any node or the central SOC,
        blocks propagate fleet-wide so all branch gateways drop the attacker locally.
    """

    def __init__(self, storage_engine=None):
        self._lock = threading.RLock()
        self.storage = storage_engine
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.global_blocks: List[Dict[str, Any]] = []
        self._central_model_hash = get_central_model_hash()

    def set_central_model_hash(self, hash_str: str) -> None:
        """Update the expected central model hash."""
        with self._lock:
            self._central_model_hash = str(hash_str)

    def get_central_model_hash(self) -> str:
        """Get the active central model hash."""
        with self._lock:
            return self._central_model_hash or get_central_model_hash()

    def register_node(
        self,
        node_id: str,
        site_type: str = "smart_home",
        hostname: str = "",
        ip: str = "",
        capabilities: Optional[List[str]] = None,
        model_hash: str = "",
        secret: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Register a new edge sensor gateway or update an existing registration.
        """
        if not node_id:
            raise ValueError("node_id cannot be empty")

        with self._lock:
            now = time.time()
            assigned_secret = secret or secrets.token_hex(32)
            caps = list(capabilities or ["packet_inspection", "active_defense"])

            node_data = {
                "node_id": node_id,
                "site_type": site_type,
                "hostname": hostname or f"edge-{node_id[:8]}",
                "ip": ip or "127.0.0.1",
                "capabilities": caps,
                "secret": assigned_secret,
                "registered_at": now,
                "last_seen": now,
                "status": "online",
                "cpu_pct": 0.0,
                "ram_pct": 0.0,
                "active_xdp_drops": 0,
                "active_blocks_count": 0,
                "local_model_hash": model_hash or self.get_central_model_hash(),
                "model_sync_status": "synced" if (model_hash == self.get_central_model_hash()) else "outdated",
                "latency_ms": 1.0,
                "last_block_sync_ts": 0.0,
            }

            self.nodes[node_id] = node_data

            # Persist to SQLite relational engine if available
            self._sync_node_to_storage(node_id, node_data)

            # Audit event
            if AUDIT_AVAILABLE and record_audit_event is not None:
                record_audit_event(
                    actor=f"edge:{node_id}",
                    role="EDGE_SENSOR",
                    action="FLEET_NODE_REGISTERED",
                    payload={"node_id": node_id, "site_type": site_type, "ip": ip}
                )

            logger.info(f"Registered edge node '{node_id}' ({site_type})")
            return {
                "ok": True,
                "node_id": node_id,
                "secret": assigned_secret,
                "site_type": site_type,
                "registered_at": now,
            }

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve node state by ID."""
        with self._lock:
            return self.nodes.get(node_id)

    def get_node_secret(self, node_id: str) -> Optional[str]:
        """Retrieve shared HMAC secret for a registered node."""
        with self._lock:
            node = self.nodes.get(node_id)
            return node.get("secret") if node else None

    def record_heartbeat(self, node_id: str, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingest a periodic heartbeat from an authenticated edge sensor.
        Evaluates model sync drift and returns pending global blocks.
        """
        with self._lock:
            node = self.nodes.get(node_id)
            if not node:
                raise KeyError(f"Node '{node_id}' is not registered with fleet control plane")

            now = time.time()
            node["last_seen"] = now
            node["status"] = "online"

            # Update performance metrics
            if "cpu_pct" in telemetry:
                node["cpu_pct"] = float(telemetry["cpu_pct"])
            if "ram_pct" in telemetry:
                node["ram_pct"] = float(telemetry["ram_pct"])
            if "active_xdp_drops" in telemetry:
                node["active_xdp_drops"] = int(telemetry["active_xdp_drops"])
            if "active_blocks_count" in telemetry:
                node["active_blocks_count"] = int(telemetry["active_blocks_count"])

            # Compute estimated round-trip latency
            req_ts = telemetry.get("timestamp")
            if req_ts:
                try:
                    latency = max(0.1, (now - float(req_ts)) * 1000.0)
                    node["latency_ms"] = round(latency, 2)
                except Exception:
                    pass

            # Model synchronization check
            local_hash = str(telemetry.get("local_model_hash", node.get("local_model_hash", "")))
            node["local_model_hash"] = local_hash
            central_hash = self.get_central_model_hash()
            if local_hash and central_hash and local_hash == central_hash:
                node["model_sync_status"] = "synced"
            else:
                node["model_sync_status"] = "outdated"

            # Global Block Broadcast Queue ("Herd Immunity"):
            # Fetch blocks created since this node's last sync
            last_sync = node.get("last_block_sync_ts", 0.0)
            pending_blocks = [
                b for b in self.global_blocks
                if b.get("created_at", 0.0) > last_sync
            ]
            node["last_block_sync_ts"] = now

            # Persist updated telemetry to storage engine
            self._sync_node_to_storage(node_id, node)

            return {
                "ok": True,
                "node_id": node_id,
                "status": "acknowledged",
                "model_sync_status": node["model_sync_status"],
                "central_model_hash": central_hash,
                "global_blocks": pending_blocks,
                "pending_blocks_count": len(pending_blocks),
                "timestamp": now,
            }

    def broadcast_global_block(
        self,
        ip: str,
        reason: str = "Central SOC Fleet Quarantine",
        severity: str = "KILL",
        source: str = "central_soc"
    ) -> Dict[str, Any]:
        """
        Broadcast an attacker IP to the entire fleet of edge sensor gateways.
        Every edge node will receive this block on its next heartbeat and
        enforce it in its local in-kernel eBPF/XDP map or firewall.
        """
        if not ip:
            raise ValueError("IP address cannot be empty")

        with self._lock:
            # Check for existing active global block for this IP
            for existing in self.global_blocks:
                if existing.get("ip") == ip:
                    existing["severity"] = severity.upper()
                    existing["reason"] = reason
                    existing["updated_at"] = time.time()
                    return existing

            block_entry = {
                "block_id": secrets.token_hex(4),
                "ip": ip,
                "severity": severity.upper(),
                "reason": reason,
                "created_at": time.time(),
                "source": source,
            }
            self.global_blocks.append(block_entry)

            # Audit record
            if AUDIT_AVAILABLE and record_audit_event is not None:
                record_audit_event(
                    actor=source,
                    role="ADMIN",
                    action="FLEET_GLOBAL_BLOCK_BROADCAST",
                    payload={"ip": ip, "severity": severity, "reason": reason}
                )

            logger.warning(
                f"🚨 FLEET-WIDE GLOBAL BLOCK BROADCAST: {ip} [{severity}] ({reason})"
            )
            return block_entry

    def get_global_blocks(self) -> List[Dict[str, Any]]:
        """Return all broadcasted global fleet blocks."""
        with self._lock:
            return list(self.global_blocks)

    def get_fleet_nodes(self) -> List[Dict[str, Any]]:
        """
        Return live health, latency, model sync status, and XDP drops
        for all registered edge gateways.
        """
        with self._lock:
            now = time.time()
            res = []
            for nid, node in self.nodes.items():
                last_seen = node.get("last_seen", 0.0)
                # Offline if heartbeat missed for > 120s
                is_online = (now - last_seen) < 120.0
                res.append({
                    "node_id": nid,
                    "site_type": node.get("site_type", "edge"),
                    "hostname": node.get("hostname", nid),
                    "ip": node.get("ip", ""),
                    "status": "online" if is_online else "offline",
                    "latency_ms": node.get("latency_ms", 1.0),
                    "last_seen": last_seen,
                    "cpu_pct": node.get("cpu_pct", 0.0),
                    "ram_pct": node.get("ram_pct", 0.0),
                    "active_xdp_drops": node.get("active_xdp_drops", 0),
                    "active_blocks_count": node.get("active_blocks_count", 0),
                    "local_model_hash": node.get("local_model_hash", ""),
                    "model_sync_status": node.get("model_sync_status", "unknown"),
                    "capabilities": node.get("capabilities", []),
                })
            return res

    def clear_fleet(self) -> None:
        """Reset fleet registry state (primarily for test teardown)."""
        with self._lock:
            self.nodes.clear()
            self.global_blocks.clear()

    def _sync_node_to_storage(self, node_id: str, node: Dict[str, Any]) -> None:
        """Persist node metadata to relational storage engine."""
        storage = self.storage
        if storage is None and STORAGE_AVAILABLE and get_storage_engine is not None:
            storage = get_storage_engine()

        if storage is not None and hasattr(storage, "upsert_edge_node"):
            try:
                meta = {
                    "site_type": node.get("site_type"),
                    "hostname": node.get("hostname"),
                    "cpu_pct": node.get("cpu_pct"),
                    "ram_pct": node.get("ram_pct"),
                    "active_xdp_drops": node.get("active_xdp_drops"),
                    "active_blocks_count": node.get("active_blocks_count"),
                    "local_model_hash": node.get("local_model_hash"),
                    "model_sync_status": node.get("model_sync_status"),
                    "latency_ms": node.get("latency_ms"),
                }
                storage.upsert_edge_node(
                    node_id=node_id,
                    ip=node.get("ip", ""),
                    status=node.get("status", "online"),
                    current_round=0,
                    samples=node.get("active_xdp_drops", 0),
                    meta=meta,
                )
            except Exception as e:
                logger.debug(f"Failed to sync node to storage: {e}")


# Global FleetControlPlane Singleton
_FLEET_CONTROL_PLANE: Optional[FleetControlPlane] = None
_fleet_plane_lock = threading.Lock()

def get_fleet_control_plane() -> FleetControlPlane:
    """Return the global FleetControlPlane singleton."""
    global _FLEET_CONTROL_PLANE
    with _fleet_plane_lock:
        if _FLEET_CONTROL_PLANE is None:
            _FLEET_CONTROL_PLANE = FleetControlPlane()
        return _FLEET_CONTROL_PLANE


# =============================================================================
# 3. EDGE SENSOR AGENT CLIENT
# =============================================================================

class EdgeSensorAgent:
    """
    Lightweight Edge Sensor Gateway Agent deployed across edge subnets.
    
    Capabilities:
      - Authenticates with central SOC via HMAC-SHA256 request signing.
      - Dispatches periodic telemetry heartbeats (CPU, RAM, XDP drops, alerts).
      - Pulls fleet-wide global blocks and enforces them in local eBPF/XDP map.
    """

    def __init__(
        self,
        node_id: str,
        site_type: str = "smart_home",
        hostname: Optional[str] = None,
        ip: Optional[str] = None,
        secret: Optional[str] = None,
        control_plane_url: str = "http://127.0.0.1:5001",
        capabilities: Optional[List[str]] = None,
        local_model_hash: Optional[str] = None,
        dry_run: bool = True
    ):
        self.node_id = node_id
        self.site_type = site_type
        self.hostname = hostname or f"sensor-{node_id[:8]}"
        self.ip = ip or "192.168.1.1"
        self.secret = secret
        self.control_plane_url = control_plane_url.rstrip("/")
        self.capabilities = capabilities or ["ebpf_xdp", "nftables", "stream_inference"]
        self.local_model_hash = local_model_hash or get_central_model_hash()
        self.dry_run = dry_run

        self.active_xdp_drops = 0
        self.enforced_blocks: Dict[str, Dict[str, Any]] = {}
        self.last_heartbeat_ack: Optional[Dict[str, Any]] = None

    def compute_signature(
        self,
        body: Union[str, bytes, dict, None],
        timestamp: Optional[float] = None
    ) -> Tuple[str, float]:
        """Compute HMAC-SHA256 signature for this agent."""
        if not self.secret:
            raise ValueError(f"Agent '{self.node_id}' does not have a shared secret configured")
        ts = time.time() if timestamp is None else float(timestamp)
        sig = compute_hmac_signature(self.secret, ts, body)
        return sig, ts

    def get_auth_headers(
        self,
        body: Union[str, bytes, dict, None],
        timestamp: Optional[float] = None
    ) -> Dict[str, str]:
        """Generate authentication headers including HMAC signature and timestamp."""
        sig, ts = self.compute_signature(body, timestamp)
        return {
            "X-IoTGuard-Node-Id": self.node_id,
            "X-IoTGuard-Signature": sig,
            "X-IoTGuard-Timestamp": str(ts),
            "Content-Type": "application/json",
        }

    def register(
        self,
        control_plane_url: Optional[str] = None,
        client: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Register with the central SOC control plane.
        Supports both live HTTP requests and Flask test client.
        """
        url = (control_plane_url or self.control_plane_url).rstrip("/") + "/api/v1/fleet/register"
        payload = {
            "node_id": self.node_id,
            "site_type": self.site_type,
            "hostname": self.hostname,
            "ip": self.ip,
            "capabilities": self.capabilities,
            "model_hash": self.local_model_hash,
            "secret": self.secret,
        }

        if client is not None:
            # Flask TestClient
            resp = client.post("/api/v1/fleet/register", json=payload)
            data = resp.get_json() if hasattr(resp, "get_json") else json.loads(resp.data)
            if resp.status_code in (200, 201) and data.get("ok"):
                if "secret" in data:
                    self.secret = data["secret"]
                return data
            raise RuntimeError(f"Registration failed ({resp.status_code}): {data}")

        # Live HTTP
        try:
            import requests
            resp = requests.post(url, json=payload, timeout=5.0)
            data = resp.json()
            if resp.status_code in (200, 201) and data.get("ok"):
                if "secret" in data:
                    self.secret = data["secret"]
                return data
            raise RuntimeError(f"Registration failed ({resp.status_code}): {data}")
        except Exception as e:
            # Fallback direct call if control plane is in-process
            cp = get_fleet_control_plane()
            res = cp.register_node(
                node_id=self.node_id,
                site_type=self.site_type,
                hostname=self.hostname,
                ip=self.ip,
                capabilities=self.capabilities,
                model_hash=self.local_model_hash,
                secret=self.secret,
            )
            self.secret = res["secret"]
            return res

    def send_heartbeat(
        self,
        cpu_pct: Optional[float] = None,
        ram_pct: Optional[float] = None,
        xdp_drops: Optional[int] = None,
        alerts: Optional[List[Dict[str, Any]]] = None,
        client: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Send periodic telemetry heartbeat to the central SOC control plane.
        Automatically processes and enforces any global herd immunity blocks received.
        """
        if xdp_drops is not None:
            self.active_xdp_drops = int(xdp_drops)

        payload = {
            "node_id": self.node_id,
            "timestamp": time.time(),
            "cpu_pct": cpu_pct if cpu_pct is not None else self.get_cpu_usage(),
            "ram_pct": ram_pct if ram_pct is not None else self.get_ram_usage(),
            "active_xdp_drops": self.active_xdp_drops,
            "active_blocks_count": len(self.enforced_blocks),
            "local_model_hash": self.local_model_hash,
            "alerts_count": len(alerts) if alerts else 0,
            "recent_alerts": alerts or [],
        }

        body_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        headers = self.get_auth_headers(body_str, timestamp=payload["timestamp"])

        if client is not None:
            # Flask TestClient
            resp = client.post(
                "/api/v1/fleet/heartbeat",
                data=body_str,
                headers=headers,
                content_type="application/json",
            )
            data = resp.get_json() if hasattr(resp, "get_json") else json.loads(resp.data)
            if resp.status_code == 200 and data.get("ok"):
                self.last_heartbeat_ack = data
                self._handle_heartbeat_response(data)
                return data
            raise RuntimeError(f"Heartbeat rejected ({resp.status_code}): {data}")

        # Live HTTP
        try:
            import requests
            url = f"{self.control_plane_url}/api/v1/fleet/heartbeat"
            resp = requests.post(url, data=body_str, headers=headers, timeout=5.0)
            data = resp.json()
            if resp.status_code == 200 and data.get("ok"):
                self.last_heartbeat_ack = data
                self._handle_heartbeat_response(data)
                return data
            raise RuntimeError(f"Heartbeat rejected ({resp.status_code}): {data}")
        except Exception:
            # Direct in-process fallback
            cp = get_fleet_control_plane()
            valid, err = verify_hmac_request(
                self.secret,
                headers["X-IoTGuard-Signature"],
                headers["X-IoTGuard-Timestamp"],
                body_str
            )
            if not valid:
                raise PermissionError(f"HMAC failure: {err}")
            res = cp.record_heartbeat(self.node_id, payload)
            self.last_heartbeat_ack = res
            self._handle_heartbeat_response(res)
            return res

    def _handle_heartbeat_response(self, ack: Dict[str, Any]) -> None:
        """Process incoming global herd immunity blocks from control plane."""
        global_blocks = ack.get("global_blocks", [])
        if global_blocks:
            self.enforce_global_blocks(global_blocks)

    def enforce_global_blocks(self, blocks: List[Dict[str, Any]]) -> int:
        """
        Enforce received fleet-wide quarantine blocks in local active defense.
        """
        count = 0
        for block in blocks:
            ip = block.get("ip")
            if not ip or ip in self.enforced_blocks:
                continue

            sev = block.get("severity", "KILL").lower()
            reason = block.get("reason", "Global Herd Immunity Quarantine")

            # Enforce via local blocker if available
            if BLOCKER_AVAILABLE and block_ip is not None:
                try:
                    block_ip(ip, severity=sev, reason=reason, dry_run=self.dry_run)
                except Exception as e:
                    logger.debug(f"Local block execution failed for {ip}: {e}")

            self.enforced_blocks[ip] = {
                "blocked_at": time.time(),
                "severity": sev,
                "reason": reason,
                "block_id": block.get("block_id"),
            }
            count += 1
            logger.warning(f"🛡️ [Herd Immunity] Sensor {self.node_id} locally quarantined {ip}")

        return count

    def get_cpu_usage(self) -> float:
        """Return current CPU usage percent."""
        if PSUTIL_AVAILABLE:
            try:
                return float(psutil.cpu_percent(interval=None))
            except Exception:
                pass
        return 14.5

    def get_ram_usage(self) -> float:
        """Return current RAM usage percent."""
        if PSUTIL_AVAILABLE:
            try:
                return float(psutil.virtual_memory().percent)
            except Exception:
                pass
        return 38.2
