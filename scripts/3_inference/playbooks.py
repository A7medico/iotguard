"""
scripts/3_inference/playbooks.py
-----------------------------------------------------------------------------
IoTGuard Component — Multi-Class Attack Taxonomy & Remediation Playbooks

Defines the 9 canonical attack taxonomies and their structured automated
remediation playbooks, providing actionable playbooks for security analysts
and automated response engines.

Taxonomies:
    1. DDoS-SYN
    2. DDoS-UDP
    3. DDoS-HTTP
    4. Mirai-C2
    5. PortScan
    6. SQLInjection
    7. CommandInjection
    8. BruteForce
    9. ZeroDay-Anomaly (for novel/unsupervised detections)
-----------------------------------------------------------------------------
"""

from typing import Any, Optional

# ── Canonical Taxonomies ─────────────────────────────────────────────────────
TAXONOMIES = [
    "DDoS-SYN",
    "DDoS-UDP",
    "DDoS-HTTP",
    "Mirai-C2",
    "PortScan",
    "SQLInjection",
    "CommandInjection",
    "BruteForce",
    "ZeroDay-Anomaly",
]

# ── Official MITRE ATT&CK® (Enterprise & ICS/IoT) Taxonomy Mapping ───────────
MITRE_ATTACK_MAP: dict[str, dict[str, Any]] = {
    "DDoS-SYN": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood",
        "framework": "Enterprise ATT&CK",
        "url": "https://attack.mitre.org/techniques/T1498/001/",
        "matrix": "enterprise",
    },
    "DDoS-UDP": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood",
        "framework": "Enterprise ATT&CK",
        "url": "https://attack.mitre.org/techniques/T1498/001/",
        "matrix": "enterprise",
    },
    "DDoS-HTTP": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T1499.002",
        "technique_name": "Service Exhaustion Flood",
        "framework": "Enterprise ATT&CK",
        "url": "https://attack.mitre.org/techniques/T1499/002/",
        "matrix": "enterprise",
    },
    "Mirai-C2": {
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "ics_technique_id": "T0814",
        "ics_technique_name": "Denial of Control",
        "framework": "Enterprise & ICS/IoT ATT&CK",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "matrix": "enterprise/ics",
    },
    "PortScan": {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "framework": "Enterprise ATT&CK",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "matrix": "enterprise",
    },
    "SQLInjection": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "framework": "Enterprise ATT&CK",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "matrix": "enterprise",
    },
    "CommandInjection": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "framework": "Enterprise ATT&CK",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "matrix": "enterprise",
    },
    "BruteForce": {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "framework": "Enterprise ATT&CK",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "matrix": "enterprise",
    },
    "ZeroDay-Anomaly": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T0814",
        "technique_name": "Denial of View/Control",
        "framework": "ICS/IoT ATT&CK",
        "url": "https://attack.mitre.org/techniques/T0814/",
        "matrix": "ics",
    },
}

DEFAULT_MITRE: dict[str, Any] = {
    "tactic_id": "TA0040",
    "tactic_name": "Impact",
    "technique_id": "T0814",
    "technique_name": "Denial of View/Control",
    "framework": "ICS/IoT ATT&CK",
    "url": "https://attack.mitre.org/techniques/T0814/",
    "matrix": "ics",
}


def get_mitre_attack(category: Optional[str] = None) -> dict[str, Any]:
    """
    Retrieve official MITRE ATT&CK metadata for a given attack taxonomy.

    Args:
        category: Canonical taxonomy name or raw attack label.

    Returns:
        Dictionary with tactic_id, tactic_name, technique_id, technique_name, url, framework.
    """
    canon = normalize_taxonomy(category)
    return MITRE_ATTACK_MAP.get(canon, DEFAULT_MITRE).copy()

# ── Raw Label to Canonical Taxonomy Mapping ──────────────────────────────────
RAW_LABEL_MAP: dict[str, str] = {
    # SYN Floods
    "syn_flood": "DDoS-SYN",
    "ddos_syn": "DDoS-SYN",
    "syn": "DDoS-SYN",
    "ddos: syn flood": "DDoS-SYN",
    "syn-flood": "DDoS-SYN",

    # UDP Floods
    "udp_flood": "DDoS-UDP",
    "ddos_udp": "DDoS-UDP",
    "udp": "DDoS-UDP",
    "ddos: volumetric (mirai/udp)": "DDoS-UDP",
    "udp-flood": "DDoS-UDP",

    # HTTP Floods & Web Exploits
    "ddos_http": "DDoS-HTTP",
    "http_flood": "DDoS-HTTP",
    "http_exploit": "DDoS-HTTP",
    "web attack (http)": "DDoS-HTTP",
    "http": "DDoS-HTTP",

    # Mirai & Botnets
    "mirai": "Mirai-C2",
    "mirai-c2": "Mirai-C2",
    "mirai_c2": "Mirai-C2",
    "backdoor": "Mirai-C2",
    "ransomware": "Mirai-C2",
    "data_exfil": "Mirai-C2",
    "exfiltration / upload": "Mirai-C2",
    "c2": "Mirai-C2",

    # Scans & Reconnaissance
    "port_scan": "PortScan",
    "portscan": "PortScan",
    "vulnerability_scan": "PortScan",
    "os_fingerprint": "PortScan",
    "recon: port scan (rst)": "PortScan",
    "recon: port scan (stealth)": "PortScan",
    "scan": "PortScan",

    # SQL Injection
    "sql_injection": "SQLInjection",
    "sqli": "SQLInjection",
    "sqlinjection": "SQLInjection",
    "sql": "SQLInjection",
    "xss": "SQLInjection",

    # Command Injection & Web Shells
    "command_injection": "CommandInjection",
    "commandinjection": "CommandInjection",
    "upload_attack": "CommandInjection",
    "webshell": "CommandInjection",
    "rce": "CommandInjection",

    # Brute Force
    "bruteforce": "BruteForce",
    "brute_force": "BruteForce",
    "dictionarybruteforce": "BruteForce",
    "password_spray": "BruteForce",

    # Zero-Day & Anomalies
    "mitm": "ZeroDay-Anomaly",
    "unsupervised": "ZeroDay-Anomaly",
    "zeroday": "ZeroDay-Anomaly",
    "zeroday-anomaly": "ZeroDay-Anomaly",
    "zero_day": "ZeroDay-Anomaly",
    "novel anomaly": "ZeroDay-Anomaly",
    "general anomaly": "ZeroDay-Anomaly",
    "anomaly": "ZeroDay-Anomaly",
}

# ── Structured Remediation Playbooks ─────────────────────────────────────────
REMEDIATION_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "DDoS-SYN": {
        "title": "TCP SYN Flood Mitigation Playbook",
        "category": "DDoS-SYN",
        "severity": "CRITICAL",
        "recommended_action": "Enable TCP SYN cookies and rate-limit new inbound half-open TCP handshakes.",
        "port_restrictions": "Enforce SYN backlog limits; inspect TCP flags on port 80/443/8080.",
        "firewall_rule": "netsh advfirewall firewall add rule name=\"IoTGuard_RateLimit_SYN\" dir=in action=block protocol=TCP remoteip={src_ip}",
        "linux_rule": "nft add rule inet iotguard input tcp flags & (syn|ack) == syn limit rate over 25/second drop",
        "rate_limit_policy": "Limit to 25 SYN pkts/sec per host with 50 burst.",
        "payload_inspection_hint": "Verify missing ACK in 3-way handshake; inspect for randomized spoofed source IP pools.",
    },
    "DDoS-UDP": {
        "title": "UDP Volumetric Flood Mitigation Playbook",
        "category": "DDoS-UDP",
        "severity": "CRITICAL",
        "recommended_action": "Drop high-volume stateless UDP streams and isolate affected destination ports.",
        "port_restrictions": "Filter NTP (123), DNS (53), and SSDP (1900) amplification reflection sources.",
        "firewall_rule": "netsh advfirewall firewall add rule name=\"IoTGuard_Drop_UDP\" dir=in action=block protocol=UDP remoteip={src_ip}",
        "linux_rule": "iptables -A INPUT -p udp -m limit --limit 100/s -j ACCEPT",
        "rate_limit_policy": "Strict cap of 100 UDP pkts/sec per IoT endpoint.",
        "payload_inspection_hint": "Check for DNS ANY query floods, NTP monlist replies, or zero-payload UDP bursts.",
    },
    "DDoS-HTTP": {
        "title": "Layer-7 HTTP Flood Mitigation Playbook",
        "category": "DDoS-HTTP",
        "severity": "HIGH",
        "recommended_action": "Apply reverse proxy connection throttling and challenge HTTP clients with rate-limiting.",
        "port_restrictions": "Restrict inbound HTTP (80) and HTTPS (443) concurrency per source IP.",
        "firewall_rule": "netsh advfirewall firewall add rule name=\"IoTGuard_Block_HTTP\" dir=in action=block protocol=TCP localport=80,443 remoteip={src_ip}",
        "linux_rule": "nft add rule inet iotguard input tcp dport {80, 443} ct count over 30 reject",
        "rate_limit_policy": "Maximum 30 concurrent HTTP connections per IP address.",
        "payload_inspection_hint": "Look for repetitive GET/POST requests targeting resource-intensive endpoints (/search, /api, /login).",
    },
    "Mirai-C2": {
        "title": "Mirai / IoT Botnet Command & Control Playbook",
        "category": "Mirai-C2",
        "severity": "CRITICAL",
        "recommended_action": "Instantly quarantine infected IoT host, terminate outbound C2 beaconing, and change default device credentials.",
        "port_restrictions": "Block Telnet (23, 2323) and SSH (22); restrict outbound custom TCP ports (4212, 10101, 48101).",
        "firewall_rule": "netsh advfirewall firewall add rule name=\"IoTGuard_Quarantine_Mirai\" dir=in action=block remoteip={src_ip}",
        "linux_rule": "iptables -A FORWARD -s {src_ip} -j DROP",
        "rate_limit_policy": "Zero tolerance: immediate isolation / quarantine VLAN.",
        "payload_inspection_hint": "Search network capture for Telnet brute-force patterns (admin/admin, root/xc3511) and busybox commands.",
    },
    "PortScan": {
        "title": "Reconnaissance & Port Scanning Playbook",
        "category": "PortScan",
        "severity": "MEDIUM",
        "recommended_action": "Temporarily block reconnaissance source and enable port-knocking or honeypot traps.",
        "port_restrictions": "Block rapid sequential SYN sweeps across 1-1024 port ranges.",
        "firewall_rule": "netsh advfirewall firewall add rule name=\"IoTGuard_Block_Scan\" dir=in action=block remoteip={src_ip}",
        "linux_rule": "iptables -A INPUT -m recent --name portscan --set -j DROP",
        "rate_limit_policy": "Threshold at 10 connection attempts per second across distinct destination ports.",
        "payload_inspection_hint": "Examine TCP flag combinations (NULL scan, XMAS scan, or fast SYN probes with window size 1024).",
    },
    "SQLInjection": {
        "title": "Web Application SQL Injection Playbook",
        "category": "SQLInjection",
        "severity": "HIGH",
        "recommended_action": "Engage WAF SQLi inspection rules, sanitize input parameters, and block attacker IP at edge proxy.",
        "port_restrictions": "Inspect ports 80, 443, 8000, 8080 HTTP request query parameters and body payloads.",
        "firewall_rule": "netsh advfirewall firewall add rule name=\"IoTGuard_Block_SQLi\" dir=in action=block remoteip={src_ip}",
        "linux_rule": "nft add rule inet iotguard input ip saddr {src_ip} drop",
        "rate_limit_policy": "Immediate 1-hour block upon confirmed SQL syntax injection attempt.",
        "payload_inspection_hint": "Check HTTP URI parameters for keywords: UNION, SELECT, OR 1=1, SLEEP, WAITFOR DELAY, schema names.",
    },
    "CommandInjection": {
        "title": "Remote Command Injection & Web Shell Playbook",
        "category": "CommandInjection",
        "severity": "CRITICAL",
        "recommended_action": "Isolate target web server / IoT gateway API, kill spawned reverse shells, inspect firmware cgi-bin.",
        "port_restrictions": "Restrict HTTP/HTTPS endpoints invoking shell executors (/cgi-bin/, /system, /form2).",
        "firewall_rule": "netsh advfirewall firewall add rule name=\"IoTGuard_Block_RCE\" dir=in action=block remoteip={src_ip}",
        "linux_rule": "nft add rule inet iotguard input ip saddr {src_ip} drop",
        "rate_limit_policy": "Instant permanent ban on command injection attempts.",
        "payload_inspection_hint": "Look for payload patterns targeting system binaries: wget, curl, chmod +x, /etc/passwd, nc -e, /bin/sh.",
    },
    "BruteForce": {
        "title": "Credential Brute Force Mitigation Playbook",
        "category": "BruteForce",
        "severity": "HIGH",
        "recommended_action": "Enforce exponential authentication backoff, account lockout, and fail2ban style IP blocking.",
        "port_restrictions": "Guard authentication ports: SSH (22), Telnet (23), HTTP Auth (80/443), FTP (21).",
        "firewall_rule": "netsh advfirewall firewall add rule name=\"IoTGuard_Block_Brute\" dir=in action=block remoteip={src_ip}",
        "linux_rule": "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set",
        "rate_limit_policy": "Block IP for 30 minutes after 5 consecutive failed login attempts within 60 seconds.",
        "payload_inspection_hint": "Check auth service logs for dictionary username sweeps (admin, root, user, test, guest).",
    },
    "ZeroDay-Anomaly": {
        "title": "Zero-Day Anomaly Investigation Playbook",
        "category": "ZeroDay-Anomaly",
        "severity": "HIGH",
        "recommended_action": "Flag for human forensic analysis, isolate host to sandbox VLAN, and capture full packet PCAP.",
        "port_restrictions": "Restrict abnormal protocol mixtures and uncharacteristic outbound volumetric shifts.",
        "firewall_rule": "netsh advfirewall firewall add rule name=\"IoTGuard_Sandbox_ZeroDay\" dir=in action=block remoteip={src_ip}",
        "linux_rule": "nft add rule inet iotguard input ip saddr {src_ip} drop",
        "rate_limit_policy": "Apply conservative soft rate-limit while baseline comparison is conducted.",
        "payload_inspection_hint": "Inspect IsolationForest anomaly features in SHAP XAI: check protocol diversity and mean IAT deviations.",
    },
}

# ── Generic Fallback Playbook ────────────────────────────────────────────────
DEFAULT_PLAYBOOK: dict[str, Any] = {
    "title": "General Security Anomaly Playbook",
    "category": "General-Anomaly",
    "severity": "MEDIUM",
    "recommended_action": "Monitor affected host, log high-frequency traffic bursts, and inspect SHAP feature drivers.",
    "port_restrictions": "Restrict suspicious ports and apply generic traffic shaping.",
    "firewall_rule": "netsh advfirewall firewall add rule name=\"IoTGuard_Block_General\" dir=in action=block remoteip={src_ip}",
    "linux_rule": "nft add rule inet iotguard input ip saddr {src_ip} drop",
    "rate_limit_policy": "Apply moderate rate limits until traffic returns to baseline.",
    "payload_inspection_hint": "Review packet lengths and inter-arrival times for non-standard device communication.",
}


# ── Helper Functions ─────────────────────────────────────────────────────────

def normalize_taxonomy(raw_label: Optional[str], detection_source: Optional[str] = None) -> str:
    """
    Map raw model predictions, heuristics, or detection sources to canonical taxonomy.

    Returns:
        One of the 9 canonical taxonomies, or 'Benign' if normal.
    """
    if detection_source == "unsupervised":
        return "ZeroDay-Anomaly"

    if not raw_label:
        return "ZeroDay-Anomaly" if detection_source == "both" else "DDoS-SYN"

    clean = str(raw_label).strip().lower()
    if clean in ("benign", "normal"):
        return "Benign"

    if clean in RAW_LABEL_MAP:
        return RAW_LABEL_MAP[clean]

    # Partial / substring matching
    for key, canon in RAW_LABEL_MAP.items():
        if key in clean:
            return canon

    return "ZeroDay-Anomaly"


def get_remediation_playbook(category: str, src_ip: Optional[str] = None) -> dict[str, Any]:
    """
    Retrieve structured remediation playbook for a given attack taxonomy.

    Args:
        category: Canonical taxonomy name (e.g. 'DDoS-SYN', 'Mirai-C2')
        src_ip: Optional source IP to format into firewall rules

    Returns:
        Dictionary containing playbook fields.
    """
    canon = normalize_taxonomy(category)
    base = REMEDIATION_PLAYBOOKS.get(canon, DEFAULT_PLAYBOOK).copy()

    ip_str = src_ip or "<TARGET_IP>"
    # Format rules with actual IP
    formatted = {}
    for k, v in base.items():
        if isinstance(v, str) and "{src_ip}" in v:
            formatted[k] = v.replace("{src_ip}", ip_str)
        else:
            formatted[k] = v

    # Attach official MITRE ATT&CK metadata
    formatted["mitre"] = get_mitre_attack(canon)

    return formatted

