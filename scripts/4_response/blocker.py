"""
scripts/blocker.py
-----------------------------------------------------------------------------
IoTGuard Component — Cross-Platform IP Blocking Utility

Position in pipeline
    decision_loop.py (attack detected)
        →  [THIS FILE] (enforce IP block via OS firewall)
        →  Firewall rules (Windows netsh / Linux nft/iptables)

High-level responsibilities
    - Provide platform-agnostic IP blocking primitives for the decision loop.
    - Support multiple firewall backends:
        * Windows: netsh advfirewall (Windows Firewall with Advanced Security)
        * Linux: nftables (preferred) with fallback to iptables
    - Validate IP addresses to prevent command injection attacks.
    - Handle edge cases (loopback, link-local, invalid formats).
    - Provide timeout protection for subprocess calls.

Security Considerations
    - All IP addresses are validated before being passed to shell commands.
    - Dangerous characters that could enable command injection are rejected.
    - Loopback and link-local addresses cannot be blocked (safety measure).
    - Commands have a 10-second timeout to prevent hangs.

Usage
    from blocker import block_ip
    success, message = block_ip("192.168.1.100")
    
    # In dry-run mode (from decision_loop):
    from blocker import block_ip as blocker_block_ip
    success, message = blocker_block_ip(ip)

Note
    - This module is called by decision_loop.py when dry_run=False.
    - For testing, you can run directly: python scripts/blocker.py 1.2.3.4
    - Blocked IPs have rules named "IoTGuardBlock_{ip}" for easy cleanup.
-----------------------------------------------------------------------------
"""
import os
import sys
import subprocess
import shutil
import re
import json
import time
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any
import ipaddress

import importlib

try:
    from ebpf_driver import EBPFBlocker, get_ebpf_blocker
except ImportError:
    try:
        _mod = importlib.import_module("scripts.4_response.ebpf_driver")
        EBPFBlocker = _mod.EBPFBlocker
        get_ebpf_blocker = _mod.get_ebpf_blocker
    except ImportError:
        EBPFBlocker = None
        get_ebpf_blocker = None

ACTIVE_BLOCKS_FILE = Path("data/active_blocks.json")


# ---------- Constants ----------
# Precompiled regex for basic IPv4 validation (fallback if ipaddress fails)
_IP_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

# Characters that could enable shell command injection
_DANGEROUS_CHARS = [';', '&', '|', '$', '`', '\n', '\r', '\\', '"', "'", '<', '>', '(', ')']

# Default timeout for subprocess calls (seconds)
_COMMAND_TIMEOUT = 10


# ---------- Validation ----------
def validate_ip(ip: str) -> Tuple[bool, str]:
    """
    Validate an IP address to prevent command injection and invalid input.
    
    This function performs multiple layers of validation:
    1. Type and emptiness check
    2. Dangerous character detection (security)
    3. IPv4/IPv6 parsing via ipaddress module
    4. Fallback regex validation for edge cases
    5. Safety checks (no loopback, no link-local)
    
    Args:
        ip: The IP address string to validate.
        
    Returns:
        Tuple of (is_valid: bool, error_message: str).
        If valid, error_message is empty string.
        
    Examples:
        >>> validate_ip("192.168.1.1")
        (True, "")
        >>> validate_ip("127.0.0.1")
        (False, "Cannot block loopback address")
        >>> validate_ip("192.168.1.1; rm -rf /")
        (False, "IP contains dangerous character: ';'")
    """
    # Check for empty or invalid type
    if not ip or not isinstance(ip, str):
        return False, "IP address is empty or not a string"
    
    ip = ip.strip()
    
    # Security check: reject dangerous characters that could enable command injection
    # This is critical for preventing shell injection attacks when passing to subprocess
    for char in _DANGEROUS_CHARS:
        if char in ip:
            return False, f"IP contains dangerous character: {repr(char)}"
    
    # Try to parse as valid IPv4 or IPv6 using Python's ipaddress module
    try:
        parsed = ipaddress.ip_address(ip)
        
        # Safety check: don't block localhost (would break the system)
        if parsed.is_loopback:
            return False, "Cannot block loopback address"
        
        # Safety check: don't block link-local (169.254.x.x / fe80::)
        if parsed.is_link_local:
            return False, "Cannot block link-local address"
        
        return True, ""
    except ValueError:
        pass
    
    # Fallback: regex check for IPv4 format
    # This catches some edge cases the ipaddress module might reject
    if _IP_PATTERN.match(ip):
        return True, ""
    
    return False, f"Invalid IP address format: {ip}"


# ---------- Command Execution ----------
def _run(cmd: list, timeout: int = _COMMAND_TIMEOUT) -> Tuple[int, str]:
    """
    Run a command with timeout protection.
    
    This wrapper around subprocess.run provides:
    - Timeout protection to prevent indefinite hangs
    - Combined stdout/stderr output
    - Graceful error handling
    
    Args:
        cmd: List of command arguments (e.g., ["netsh", "advfirewall", ...])
        timeout: Maximum seconds to wait for command completion.
        
    Returns:
        Tuple of (return_code: int, output: str).
        Special return codes:
          - 997: Exception during execution
          - 998: Command timed out
    """
    try:
        p = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=False,
            timeout=timeout
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 998, f"command timed out after {timeout}s"
    except Exception as e:
        return 997, f"exec error: {e}"


# ---------- Platform Detection ----------
def is_wsl() -> bool:
    """
    Check if running inside Windows Subsystem for Linux (WSL).
    
    WSL requires special handling because it runs Linux but may need
    to interact with Windows networking in some scenarios.
    
    Returns:
        True if running in WSL, False otherwise.
    """
    # Check for WSL-specific environment variable
    if "WSL_DISTRO_NAME" in os.environ:
        return True
    
    # Check for "microsoft" in kernel release (works for WSL2)
    if hasattr(os, "uname"):
        return "microsoft" in os.uname().release.lower()
    
    return False


def have(cmd: str) -> bool:
    """
    Check if a command-line tool is available in PATH.
    
    Args:
        cmd: Name of the command (e.g., "nft", "iptables")
        
    Returns:
        True if the command exists in PATH, False otherwise.
    """
    return shutil.which(cmd) is not None


# ---------- Windows Implementation ----------
def block_ip_windows(ip: str) -> Tuple[bool, str]:
    """
    Block an IP address using Windows Firewall (netsh advfirewall).
    
    Creates an inbound firewall rule that blocks all traffic from the
    specified remote IP address. The rule is named "IoTGuardBlock_{ip}"
    for easy identification and cleanup.
    
    Args:
        ip: The validated IP address to block.
        
    Returns:
        Tuple of (success: bool, output: str).
        
    Note:
        Requires Administrator privileges to modify firewall rules.
    """
    # Create a unique rule name for this IP
    rule_name = f"IoTGuardBlock_{ip}"
    
    # Build the netsh command to add an inbound block rule
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",      # Unique rule identifier
        "dir=in",                  # Inbound traffic
        "action=block",            # Block the traffic
        f"remoteip={ip}"           # From this specific IP
    ]
    
    code, out = _run(cmd)
    return (code == 0), out


def unblock_all_windows() -> str:
    """
    Remove all IoTGuard-created firewall rules on Windows.
    
    Searches for all rules with names starting with "IoTGuardBlock_"
    and removes them. Useful for cleanup during testing or reset.
    
    Returns:
        Status message indicating how many rules were removed.
    """
    # Get list of all firewall rules
    code, out = _run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"])
    
    removed = []
    for line in out.splitlines():
        if "IoTGuardBlock_" in line:
            # Extract the rule name and delete it
            name = line.strip().split(":")[-1].strip()
            _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
            removed.append(name)
    
    return f"removed {len(removed)} rules"


# ---------- Linux Implementation ----------
def block_ip_linux(ip: str) -> Tuple[bool, str]:
    """
    Block an IP address using Linux firewall (nftables or iptables).
    
    Prefers nftables (nft) as it's the modern replacement for iptables.
    Falls back to iptables if nft is not available.
    
    nftables approach:
        1. Create table 'inet iotguard' (if not exists)
        2. Create set 'blocked' for storing IPs
        3. Create input chain with drop rule for set members
        4. Add the IP to the blocked set
    
    iptables approach:
        1. Insert a DROP rule for the source IP at the start of INPUT chain
    
    Args:
        ip: The validated IP address to block.
        
    Returns:
        Tuple of (success: bool, output: str).
        
    Note:
        Requires root/sudo privileges to modify firewall rules.
    """
def get_configured_firewall_backend() -> str:
    """Read configured firewall backend from environment or configs/model.yaml."""
    env_backend = os.getenv("IOTGUARD_FIREWALL_BACKEND")
    if env_backend:
        return env_backend.lower().strip()

    cfg_file = Path("configs/model.yaml")
    if cfg_file.exists():
        try:
            import yaml
            cfg = yaml.safe_load(cfg_file.read_text(encoding="utf-8")) or {}
            return str(cfg.get("decision", {}).get("firewall_backend", "auto")).lower().strip()
        except Exception:
            pass
    return "auto"


def get_active_driver(dry_run: bool = False) -> str:
    """
    Determine the active firewall driver mode:
    'dry_run' | 'ebpf_xdp' | 'nftables' | 'iptables' | 'netsh' | 'none'
    """
    if dry_run:
        return "dry_run"

    if os.name == "nt":
        return "netsh"

    backend = get_configured_firewall_backend()
    if backend == "netsh":
        return "netsh"
    if backend in ("ebpf", "xdp"):
        return "ebpf_xdp"
    if backend in ("nftables", "nft"):
        return "nftables"
    if backend == "iptables":
        return "iptables"

    # Auto tier on Linux: ebpf -> nftables -> iptables
    if get_ebpf_blocker:
        try:
            ebpf = get_ebpf_blocker()
            if ebpf and ebpf.is_available():
                return "ebpf_xdp"
        except Exception:
            pass

    if have("nft"):
        return "nftables"
    if have("iptables"):
        return "iptables"

    return "none"


def get_driver_telemetry() -> Dict[str, Any]:
    """Return operational telemetry on the active firewall driver subsystem."""
    driver = get_active_driver(dry_run=False)
    ebpf_avail = False
    ebpf_attached = False
    xdp_iface = "eth0"
    drop_stats: Dict[str, Any] = {}
    total_drops = 0

    if get_ebpf_blocker:
        try:
            ebpf = get_ebpf_blocker()
            if ebpf:
                ebpf_avail = ebpf.is_available()
                ebpf_attached = ebpf.is_attached()
                xdp_iface = ebpf.interface
                drop_stats = ebpf.get_drop_stats()
                total_drops = ebpf.get_total_drops()
        except Exception as e:
            logger.debug(f"Error querying eBPF telemetry: {e}")

    return {
        "active_driver": driver,
        "os": "windows" if os.name == "nt" else "linux",
        "ebpf_available": ebpf_avail,
        "ebpf_attached": ebpf_attached,
        "xdp_interface": xdp_iface,
        "drop_stats": drop_stats,
        "total_xdp_drops": total_drops,
    }


def block_ip_linux(ip: str) -> Tuple[bool, str]:
    """
    Block an IP address on Linux using the highest priority available driver:
      Tier 1: eBPF / XDP In-Kernel Driver Hook (Fastest, drops at NIC)
      Tier 2: nftables (Kernel netfilter table)
      Tier 3: iptables legacy
    """
    backend = get_configured_firewall_backend()

    # Tier 1: Try eBPF / XDP if backend is auto or ebpf
    if backend in ("auto", "ebpf", "xdp") and get_ebpf_blocker:
        try:
            ebpf = get_ebpf_blocker()
            if ebpf and ebpf.is_available():
                ok, msg = ebpf.add_blocked_ip(ip)
                if ok:
                    return True, f"ebpf-xdp-blocked-{ip}: {msg}"
                if backend in ("ebpf", "xdp"):
                    return False, f"ebpf-xdp failed: {msg}"
        except Exception as e:
            if backend in ("ebpf", "xdp"):
                return False, f"ebpf-xdp exception: {e}"

    # Tier 2: Prefer nftables if available
    if (backend in ("auto", "nftables", "nft")) and have("nft"):
        _run(["nft", "add", "table", "inet", "iotguard"])
        _run(["nft", "add", "set", "inet", "iotguard", "blocked", 
              "{", "type", "ipv4_addr", ";", "flags", "interval", ";", "}"])
        _run(["nft", "add", "chain", "inet", "iotguard", "input", 
              "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"])
        _run(["nft", "add", "rule", "inet", "iotguard", "input", 
              "ip", "saddr", "@blocked", "drop"])
        code, out = _run(["nft", "add", "element", "inet", "iotguard", "blocked", f"{ip}"])
        if code == 0:
            return True, f"nftables-blocked-{ip}"
        if backend in ("nftables", "nft"):
            return False, out

    # Tier 3: Fallback to iptables
    if have("iptables"):
        code, out = _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
        if code == 0:
            return True, f"iptables-blocked-{ip}"
        return False, out

    return False, "no firewall tool (ebpf/nft/iptables) available"


# ---------- State & Tracking ----------
def record_block(ip: str, severity: str = "hard", reason: str = "", dry_run: bool = False, *args, **kwargs) -> None:
    """Record an actively blocked IP into persistent storage."""
    try:
        blocks = {}
        if ACTIVE_BLOCKS_FILE.exists():
            blocks = json.loads(ACTIVE_BLOCKS_FILE.read_text(encoding="utf-8")) or {}
        active_driver = get_active_driver(dry_run=dry_run)
        blocks[ip] = {
            "ip": ip,
            "blocked_at": time.time(),
            "severity": str(severity).lower(),
            "reason": str(reason),
            "dry_run": bool(dry_run),
            "driver": active_driver,
        }
        ACTIVE_BLOCKS_FILE.parent.mkdir(parents=True, exist_ok=True)
        ACTIVE_BLOCKS_FILE.write_text(json.dumps(blocks, indent=2), encoding="utf-8")
    except Exception:
        pass

    # Enterprise Dual-Write Contract: Relational Storage Engine
    try:
        try:
            from storage_engine import get_storage_engine
        except ImportError:
            import importlib
            _mod = importlib.import_module("scripts.9_utilities.storage_engine")
            get_storage_engine = _mod.get_storage_engine
        if get_storage_engine is not None:
            get_storage_engine().record_block(
                ip,
                severity=severity,
                reason=reason,
                driver=get_active_driver(dry_run=dry_run)
            )
    except Exception:
        pass


def record_unblock(ip: str, *args, **kwargs) -> None:
    """Remove an IP from the active blocks storage."""
    try:
        if ACTIVE_BLOCKS_FILE.exists():
            blocks = json.loads(ACTIVE_BLOCKS_FILE.read_text(encoding="utf-8")) or {}
            if ip in blocks:
                del blocks[ip]
                ACTIVE_BLOCKS_FILE.write_text(json.dumps(blocks, indent=2), encoding="utf-8")
    except Exception:
        pass

    # Enterprise Dual-Write Contract: Relational Storage Engine
    try:
        try:
            from storage_engine import get_storage_engine
        except ImportError:
            import importlib
            _mod = importlib.import_module("scripts.9_utilities.storage_engine")
            get_storage_engine = _mod.get_storage_engine
        if get_storage_engine is not None:
            get_storage_engine().record_unblock(ip)
    except Exception:
        pass


def get_active_blocks() -> List[Dict[str, Any]]:
    """Return all currently active IP blocks."""
    try:
        if ACTIVE_BLOCKS_FILE.exists():
            blocks = json.loads(ACTIVE_BLOCKS_FILE.read_text(encoding="utf-8")) or {}
            return list(blocks.values())
    except Exception:
        pass
    return []


def is_ip_blocked(ip: str) -> bool:
    """Check if an IP address is currently recorded as blocked."""
    clean_ip = ip.strip() if ip else ""
    try:
        if ACTIVE_BLOCKS_FILE.exists():
            blocks = json.loads(ACTIVE_BLOCKS_FILE.read_text(encoding="utf-8")) or {}
            return clean_ip in blocks
    except Exception:
        pass
    return False


def unblock_ip_windows(ip: str) -> Tuple[bool, str]:
    """Remove a specific blocked IP rule on Windows."""
    rule_name = f"IoTGuardBlock_{ip}"
    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
    code, out = _run(cmd)
    return (code == 0), out


def unblock_ip_linux(ip: str) -> Tuple[bool, str]:
    """
    Remove a specific blocked IP rule on Linux across eBPF/XDP, nftables, and iptables.
    """
    messages = []
    success = False

    # 1. eBPF/XDP map deletion
    if get_ebpf_blocker:
        try:
            ebpf = get_ebpf_blocker()
            if ebpf:
                ok, msg = ebpf.remove_blocked_ip(ip)
                if ok:
                    success = True
                    messages.append(f"xdp: {msg}")
        except Exception:
            pass

    # 2. nftables deletion
    if have("nft"):
        code, out = _run(["nft", "delete", "element", "inet", "iotguard", "blocked", f"{{ {ip} }}"])
        if code == 0:
            success = True
            messages.append("nftables unblocked")

    # 3. iptables deletion
    if have("iptables"):
        code, out = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        if code == 0:
            success = True
            messages.append("iptables unblocked")

    if success:
        return True, "; ".join(messages) or f"unblocked-{ip}"
    return False, "neither ebpf, nft, nor iptables rule removed"


def unblock_ip(ip: Optional[str], dry_run: bool = False) -> Tuple[bool, str]:
    """
    Unblock an IP address and remove its firewall rule.
    """
    if not ip:
        return False, "no ip provided"

    valid, error = validate_ip(ip)
    if not valid:
        return False, f"validation failed: {error}"

    clean_ip = ip.strip()
    record_unblock(clean_ip)

    if dry_run:
        return True, f"dry-run-unblocked-{clean_ip}"

    if os.name == "nt":
        return unblock_ip_windows(clean_ip)

    return unblock_ip_linux(clean_ip)


# ---------- Public API ----------
def block_ip(
    ip: Optional[str],
    severity: str = "hard",
    reason: str = "",
    dry_run: bool = False,
) -> Tuple[bool, str]:
    """
    Block an IP address using the appropriate firewall for the OS.
    
    This is the main entry point for IP blocking. It:
    1. Validates the IP address (security + correctness)
    2. Detects the operating system
    3. Calls the appropriate platform-specific implementation
    4. Records the block in active blocks storage
    
    Args:
        ip: The IP address to block. Can be IPv4 or IPv6.
        severity: Mitigation tier ("soft", "hard", "kill").
        reason: Explanation or attack category.
        dry_run: If True, simulates the block without OS changes.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Handle missing IP
    if not ip:
        return False, "no ip provided"
    
    # Validate IP before attempting to block (security critical!)
    valid, error = validate_ip(ip)
    if not valid:
        return False, f"validation failed: {error}"
    
    clean_ip = ip.strip()
    record_block(clean_ip, severity=severity, reason=reason, dry_run=dry_run)

    if dry_run:
        return True, f"dry-run-blocked-{clean_ip}"

    # Route to platform-specific implementation
    if os.name == "nt":
        return block_ip_windows(clean_ip)
    
    # Linux / WSL / macOS
    return block_ip_linux(clean_ip)


# ---------- CLI Entry Point ----------
if __name__ == "__main__":
    # Small CLI for manual testing: python scripts/blocker.py 1.2.3.4
    ip = sys.argv[1] if len(sys.argv) > 1 else None
    ok, out = block_ip(ip)
    print("OK" if ok else "FAIL", out)
