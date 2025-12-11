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
from typing import Optional, Tuple
import ipaddress


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
    # Prefer nftables if available (modern, more features)
    if have("nft"):
        # Create the iotguard table (idempotent - won't fail if exists)
        _run(["nft", "add", "table", "inet", "iotguard"])
        
        # Create the blocked set for IP addresses
        _run(["nft", "add", "set", "inet", "iotguard", "blocked", 
              "{", "type", "ipv4_addr", ";", "flags", "interval", ";", "}"])
        
        # Create the input chain with filter hook
        _run(["nft", "add", "chain", "inet", "iotguard", "input", 
              "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"])
        
        # Add rule to drop packets from blocked set members
        _run(["nft", "add", "rule", "inet", "iotguard", "input", 
              "ip", "saddr", "@blocked", "drop"])
        
        # Add the IP to the blocked set
        code, out = _run(["nft", "add", "element", "inet", "iotguard", "blocked", f"{ip}"])
        return (code == 0), out
    
    # Fallback to iptables if nft not available
    if have("iptables"):
        # Insert a DROP rule at the beginning of INPUT chain
        code, out = _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
        return (code == 0), out
    
    return False, "no firewall tool (nft/iptables) available"


# ---------- Public API ----------
def block_ip(ip: Optional[str]) -> Tuple[bool, str]:
    """
    Block an IP address using the appropriate firewall for the OS.
    
    This is the main entry point for IP blocking. It:
    1. Validates the IP address (security + correctness)
    2. Detects the operating system
    3. Calls the appropriate platform-specific implementation
    
    Args:
        ip: The IP address to block. Can be IPv4 or IPv6.
        
    Returns:
        Tuple of (success: bool, message: str).
        - success: True if the block rule was created
        - message: Status message or error description
        
    Examples:
        >>> block_ip("192.168.1.100")
        (True, "Rule 'IoTGuardBlock_192.168.1.100' added")
        
        >>> block_ip(None)
        (False, "no ip provided")
        
        >>> block_ip("invalid")
        (False, "validation failed: Invalid IP address format: invalid")
    """
    # Handle missing IP
    if not ip:
        return False, "no ip provided"
    
    # Validate IP before attempting to block (security critical!)
    valid, error = validate_ip(ip)
    if not valid:
        return False, f"validation failed: {error}"
    
    ip = ip.strip()
    
    # Route to platform-specific implementation
    if os.name == "nt":
        return block_ip_windows(ip)
    
    # Linux / WSL / macOS (macOS pfctl not implemented)
    return block_ip_linux(ip)


# ---------- CLI Entry Point ----------
if __name__ == "__main__":
    # Small CLI for manual testing: python scripts/blocker.py 1.2.3.4
    ip = sys.argv[1] if len(sys.argv) > 1 else None
    ok, out = block_ip(ip)
    print("OK" if ok else "FAIL", out)
