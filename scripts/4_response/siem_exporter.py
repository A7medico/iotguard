"""
scripts/4_response/siem_exporter.py
-----------------------------------------------------------------------------
IoTGuard Enterprise Component — Enterprise SIEM & Threat Intelligence Exporter

Provides industry-standard export wire formats:
    1. ArcSight Common Event Format (CEF) for Splunk, QRadar, ArcSight, Sentinel
    2. RFC 5424 Syslog Dispatcher (UDP / TCP / TLS) with structured data
    3. OASIS STIX 2.1 Threat Sharing Bundle Generator (indicator, attack-pattern,
       sighting, relationship) for TAXII 2.1 sharing and threat platforms.
-----------------------------------------------------------------------------
"""

import json
import logging
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import NAMESPACE_URL, uuid4, uuid5

logger = logging.getLogger("iotguard.siem_exporter")

# ── Static STIX Identity ID ──────────────────────────────────────────────────
IOTGUARD_IDENTITY_ID = "identity--a864d3e5-8204-4b5c-b17b-9df2c2194911"
STIX_NAMESPACE_SEED = "iotguard.edge.ips"


# =============================================================================
# 1. ARCSIGHT COMMON EVENT FORMAT (CEF) FORMATTER
# =============================================================================

def _escape_cef_header(value: Any) -> str:
    """Escape backslash and pipe characters in CEF header."""
    val_str = str(value if value is not None else "")
    return val_str.replace("\\", "\\\\").replace("|", "\\|")


def _escape_cef_extension(value: Any) -> str:
    """Escape backslash and equals characters in CEF extension values."""
    val_str = str(value if value is not None else "")
    return val_str.replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")


def format_cef_event(event: Dict[str, Any]) -> str:
    """
    Format an IoTGuard security event into ArcSight Common Event Format (CEF:0).

    Standard CEF Format:
        CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension

    Args:
        event: Dictionary representing an IoTGuard decision or security alert.

    Returns:
        Formatted CEF string conforming to HP/MicroFocus ArcSight CEF guidelines.
    """
    version = "0"
    device_vendor = "IoTGuard"
    device_product = "EdgeIPS"
    device_version = "4.0"

    # Extract event attributes
    attack_category = event.get("attack_category") or event.get("pred_class") or "Anomaly"
    action = event.get("action", "MONITOR")
    score = float(event.get("score", 0.0))
    event_class_id = str(attack_category).replace(" ", "_")

    # Name mapping
    playbook = event.get("remediation_playbook") or {}
    name = playbook.get("title") or f"{attack_category} Detection"

    # Map severity to 0-10 scale
    state_str = str(event.get("state", "")).upper()
    if "KILL" in state_str or action == "KILL":
        severity = 10
    elif "HARD" in state_str or action == "BLOCK":
        severity = 8
    elif "SOFT" in state_str or action == "RATE_LIMIT":
        severity = 6
    elif score >= 0.90:
        severity = 8
    elif score >= 0.70:
        severity = 5
    else:
        severity = 3

    # Build Header
    header = (
        f"CEF:{version}|"
        f"{_escape_cef_header(device_vendor)}|"
        f"{_escape_cef_header(device_product)}|"
        f"{_escape_cef_header(device_version)}|"
        f"{_escape_cef_header(event_class_id)}|"
        f"{_escape_cef_header(name)}|"
        f"{severity}"
    )

    # Build Extension Key-Value Pairs
    ext_pairs: List[str] = []

    # Standard IP & traffic extensions
    src_ip = event.get("src_ip")
    if src_ip:
        ext_pairs.append(f"src={_escape_cef_extension(src_ip)}")

    hits = event.get("hits_in_window", event.get("hits", 1))
    ext_pairs.append(f"cnt={int(hits)}")
    ext_pairs.append(f"act={_escape_cef_extension(action)}")
    ext_pairs.append(f"cat={_escape_cef_extension(attack_category)}")

    # Score & Confidence Custom Floats
    ext_pairs.append(f"cfp1={score:.4f}")
    ext_pairs.append(f"cfp1Label={_escape_cef_extension('AnomalyScore')}")

    conf = event.get("confidence")
    if conf is not None:
        ext_pairs.append(f"cfp2={float(conf):.4f}")
        ext_pairs.append(f"cfp2Label={_escape_cef_extension('ClassificationConfidence')}")

    # MITRE ATT&CK Extensions
    mitre = event.get("mitre") or playbook.get("mitre") or {}
    if mitre:
        tactic = f"{mitre.get('tactic_id', '')} - {mitre.get('tactic_name', '')}".strip(" -")
        technique = f"{mitre.get('technique_id', '')} - {mitre.get('technique_name', '')}".strip(" -")
        if tactic:
            ext_pairs.append(f"cs1={_escape_cef_extension(tactic)}")
            ext_pairs.append(f"cs1Label={_escape_cef_extension('MitreTactic')}")
        if technique:
            ext_pairs.append(f"cs2={_escape_cef_extension(technique)}")
            ext_pairs.append(f"cs2Label={_escape_cef_extension('MitreTechnique')}")

    # Device Classification Extension
    dev_type = event.get("device_type") or event.get("model_used")
    if dev_type:
        ext_pairs.append(f"cs3={_escape_cef_extension(dev_type)}")
        ext_pairs.append(f"cs3Label={_escape_cef_extension('DeviceType')}")

    # Threat Intel Context
    threat = event.get("threat") or {}
    if threat:
        country = threat.get("country_code") or threat.get("country")
        if country:
            ext_pairs.append(f"cs4={_escape_cef_extension(country)}")
            ext_pairs.append(f"cs4Label={_escape_cef_extension('GeoCountry')}")
        asn = threat.get("asn")
        if asn:
            ext_pairs.append(f"cs5={_escape_cef_extension(asn)}")
            ext_pairs.append(f"cs5Label={_escape_cef_extension('SourceASN')}")

    # Timestamp in Milliseconds (rt)
    ts = float(event.get("ts", event.get("timestamp", time.time())))
    ext_pairs.append(f"rt={int(ts * 1000)}")

    # Explanation / Reason
    reason = event.get("reason")
    if reason:
        ext_pairs.append(f"msg={_escape_cef_extension(reason)}")

    extension_str = " ".join(ext_pairs)
    return f"{header}|{extension_str}"


# =============================================================================
# 2. RFC 5424 SYSLOG DISPATCHER
# =============================================================================

def format_rfc5424_syslog(
    event: Dict[str, Any],
    hostname: Optional[str] = None,
    app_name: str = "iotguard",
    facility: int = 16,  # local0
    payload_format: str = "cef",
) -> str:
    """
    Format an event into an RFC 5424 compliant syslog frame:
        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG

    Args:
        event: Security event dictionary.
        hostname: Node hostname (defaults to local machine hostname).
        app_name: Application identifier (default 'iotguard').
        facility: Syslog facility code (default 16 for local0).
        payload_format: 'cef' or 'json'.
    """
    # Severity mapping (0=Emergency, 1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Info)
    score = float(event.get("score", 0.0))
    action = str(event.get("action", "")).upper()
    if action in ("KILL", "HARD_BLOCK", "BLOCK") or score >= 0.90:
        syslog_sev = 2  # Critical
    elif score >= 0.80:
        syslog_sev = 3  # Error
    elif score >= 0.60:
        syslog_sev = 4  # Warning
    else:
        syslog_sev = 6  # Informational

    pri = (facility * 8) + syslog_sev
    version = "1"

    ts = float(event.get("ts", event.get("timestamp", time.time())))
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    ts_str = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    host = hostname or socket.gethostname()
    procid = str(os.getpid())
    msgid = str(event.get("attack_category", "ALERT")).replace("-", "_")

    # Structured Data element
    src_ip = event.get("src_ip", "-")
    cat = event.get("attack_category", "-")
    sd = (
        f'[iotguard@53457 src_ip="{src_ip}" '
        f'score="{score:.2f}" '
        f'category="{cat}" '
        f'action="{action}"]'
    )

    if payload_format.lower() == "cef":
        msg = format_cef_event(event)
    else:
        msg = json.dumps(event)

    return f"<{pri}>{version} {ts_str} {host} {app_name} {procid} {msgid} {sd} {msg}"


def send_syslog(
    event: Dict[str, Any],
    host: str = "127.0.0.1",
    port: int = 514,
    protocol: str = "udp",
    payload_format: str = "cef",
    timeout: float = 2.0,
    tls_cert: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Transmit security event via Syslog (UDP, TCP, or TLS).

    Returns:
        (success: bool, status_message: str)
    """
    try:
        raw_msg = format_rfc5424_syslog(event, payload_format=payload_format).encode("utf-8")
        proto_clean = protocol.lower()

        if proto_clean == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(raw_msg, (host, port))
            sock.close()
            return True, "SENT_UDP"

        elif proto_clean == "tcp":
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.sendall(raw_msg + b"\n")
            sock.close()
            return True, "SENT_TCP"

        elif proto_clean == "tls":
            ctx = ssl.create_default_context()
            if tls_cert and os.path.exists(tls_cert):
                ctx.load_verify_locations(tls_cert)
            else:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            raw_sock = socket.create_connection((host, port), timeout=timeout)
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                tls_sock.sendall(raw_msg + b"\n")
            return True, "SENT_TLS"

        else:
            return False, f"UNSUPPORTED_PROTOCOL_{protocol}"

    except Exception as e:
        logger.debug(f"Syslog transmission error ({protocol}://{host}:{port}): {e}")
        return False, str(e)


# =============================================================================
# 3. OASIS STIX 2.1 THREAT SHARING BUNDLE GENERATOR
# =============================================================================

def _iso_utc(ts: Optional[float] = None) -> str:
    """Format Unix timestamp into STIX 2.1 ISO-8601 UTC string."""
    t = ts if ts is not None else time.time()
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def generate_stix_bundle(
    events: Optional[List[Dict[str, Any]]] = None,
    active_blocks: Optional[Dict[str, Any]] = None,
    bundle_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate an OASIS STIX 2.1 JSON bundle representing active threat indicators.

    Includes:
        - `identity`: IoTGuard Edge IPS Identity
        - `attack-pattern`: MITRE ATT&CK techniques with external references
        - `indicator`: IP-based threat indicator (`[ipv4-addr:value = '...']`)
        - `relationship`: `indicates` linking indicator to attack-pattern
        - `sighting`: records of observing the threat at the network edge

    Args:
        events: List of security alert dictionaries.
        active_blocks: Dictionary of actively blocked IP records.
        bundle_id: Optional custom bundle UUID.

    Returns:
        STIX 2.1 compliant bundle dictionary.
    """
    now_str = _iso_utc()
    actual_bundle_id = bundle_id or f"bundle--{uuid4()}"

    objects: List[Dict[str, Any]] = []

    # 1. IoTGuard System Identity
    identity_obj = {
        "type": "identity",
        "spec_version": "2.1",
        "id": IOTGUARD_IDENTITY_ID,
        "created": "2026-11-01T00:00:00.000Z",
        "modified": now_str,
        "name": "IoTGuard Edge IPS",
        "description": "IoTGuard Edge-Native Intrusion Prevention & Response System",
        "identity_class": "system",
        "sectors": ["defense", "technology", "critical-infrastructure"],
    }
    objects.append(identity_obj)

    # Track unique attack patterns and indicators created
    attack_pattern_ids: Dict[str, str] = {}
    indicator_ips: set[str] = set()

    # Collect indicators from active blocks
    targets: List[Dict[str, Any]] = []
    if active_blocks:
        for ip, blk in active_blocks.items():
            targets.append({
                "src_ip": ip,
                "attack_category": blk.get("reason", "Malicious-Traffic"),
                "ts": blk.get("blocked_at", time.time()),
                "hits": blk.get("drop_count", 1),
                "score": 0.99,
                "action": "BLOCK",
            })

    # Collect indicators from alert events
    if events:
        for evt in events:
            src = evt.get("src_ip")
            if src and src not in indicator_ips:
                targets.append(evt)

    for item in targets:
        ip = item.get("src_ip")
        if not ip or ip in indicator_ips or ip in ("127.0.0.1", "0.0.0.0", "localhost"):
            continue
        indicator_ips.add(ip)

        cat = item.get("attack_category") or "ZeroDay-Anomaly"
        score = float(item.get("score", 0.90))
        item_ts = float(item.get("ts", time.time()))
        created_str = _iso_utc(item_ts)

        # Resolve MITRE details
        mitre = item.get("mitre") or {}
        technique_id = mitre.get("technique_id", "T1498.001")
        technique_name = mitre.get("technique_name", f"{cat} Flood/Exploit")
        tactic_name = mitre.get("tactic_name", "Impact")
        url = mitre.get("url", f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/")

        # 2. Attack Pattern Object (Deduplicated per technique)
        if technique_id not in attack_pattern_ids:
            ap_id = f"attack-pattern--{uuid5(NAMESPACE_URL, f'{STIX_NAMESPACE_SEED}.{technique_id}')}"
            attack_pattern_ids[technique_id] = ap_id
            ap_obj = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": "2026-11-01T00:00:00.000Z",
                "modified": now_str,
                "name": technique_name,
                "description": f"MITRE ATT&CK {technique_id} ({tactic_name}) targeting IoT/Edge infrastructure.",
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": tactic_name.lower().replace(" ", "-"),
                    }
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique_id,
                        "url": url,
                    }
                ],
            }
            objects.append(ap_obj)

        ap_ref = attack_pattern_ids[technique_id]

        # 3. STIX Indicator Object
        ind_id = f"indicator--{uuid5(NAMESPACE_URL, f'{STIX_NAMESPACE_SEED}.{ip}')}"
        ind_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": created_str,
            "modified": now_str,
            "name": f"Malicious Network Traffic from {ip}",
            "description": f"IoTGuard detected {cat} activity from {ip} with anomaly score {score:.2f}.",
            "indicator_types": ["malicious-activity", "anomalous-activity"],
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": created_str,
            "confidence": int(score * 100),
            "created_by_ref": IOTGUARD_IDENTITY_ID,
        }
        objects.append(ind_obj)

        # 4. Relationship (Indicator indicates Attack Pattern)
        rel_id = f"relationship--{uuid4()}"
        rel_obj = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created": created_str,
            "modified": now_str,
            "relationship_type": "indicates",
            "source_ref": ind_id,
            "target_ref": ap_ref,
            "created_by_ref": IOTGUARD_IDENTITY_ID,
        }
        objects.append(rel_obj)

        # 5. Sighting of Indicator by IoTGuard
        hits = int(item.get("hits", item.get("hits_in_window", 1)))
        sighting_id = f"sighting--{uuid4()}"
        sighting_obj = {
            "type": "sighting",
            "spec_version": "2.1",
            "id": sighting_id,
            "created": created_str,
            "modified": now_str,
            "first_seen": created_str,
            "last_seen": now_str,
            "count": max(1, hits),
            "sighting_of_ref": ind_id,
            "where_sighted_refs": [IOTGUARD_IDENTITY_ID],
        }
        objects.append(sighting_obj)

    return {
        "type": "bundle",
        "id": actual_bundle_id,
        "objects": objects,
    }
