# scripts/blocker.py
# -----------------------------------------------------------------------------
# Utility — Cross-platform best-effort IP blocker
#
# Purpose
#   - Provide simple block/unblock primitives used by the decision loop, with
#     Windows (netsh) and Linux (nft/iptables) backends.
#
# When used
#   - Called by decision logic to enforce a temporary block (or in dry-run just
#     log the intent). Can be replaced by more advanced mechanisms.
# -----------------------------------------------------------------------------
import os, sys, subprocess, shutil, re
from typing import Optional
import ipaddress

# Precompiled regex for basic IP validation (fallback)
_IP_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)


def validate_ip(ip: str) -> tuple[bool, str]:
    """
    Validate an IP address to prevent command injection and invalid input.
    Returns (is_valid, error_message).
    """
    if not ip or not isinstance(ip, str):
        return False, "IP address is empty or not a string"
    
    ip = ip.strip()
    
    # Check for dangerous characters that could enable command injection
    dangerous_chars = [';', '&', '|', '$', '`', '\n', '\r', '\\', '"', "'", '<', '>', '(', ')']
    for char in dangerous_chars:
        if char in ip:
            return False, f"IP contains dangerous character: {repr(char)}"
    
    # Try to parse as valid IPv4 or IPv6
    try:
        parsed = ipaddress.ip_address(ip)
        # Don't block localhost or link-local
        if parsed.is_loopback:
            return False, "Cannot block loopback address"
        if parsed.is_link_local:
            return False, "Cannot block link-local address"
        return True, ""
    except ValueError:
        pass
    
    # Fallback regex check for IPv4
    if _IP_PATTERN.match(ip):
        return True, ""
    
    return False, f"Invalid IP address format: {ip}"


def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
    """Run a command with timeout protection."""
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

def is_wsl() -> bool:
    return "WSL_DISTRO_NAME" in os.environ or "microsoft" in (os.uname().release.lower() if hasattr(os, "uname") else "")

# ---------- Windows ----------
def block_ip_windows(ip: str) -> tuple[bool, str]:
    # Add inbound block rule for remoteip
    rule_name = f"IoTGuardBlock_{ip}"
    cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
           f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"]
    code, out = _run(cmd)
    return (code == 0), out

def unblock_all_windows() -> str:
    # Remove all rules we added
    code, out = _run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"])
    removed = []
    for line in out.splitlines():
        if "IoTGuardBlock_" in line:
            name = line.strip().split(":")[-1].strip()
            _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
            removed.append(name)
    return f"removed {len(removed)} rules"

# ---------- Linux / WSL ----------
def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def block_ip_linux(ip: str) -> tuple[bool, str]:
    # Prefer nftables if available
    if have("nft"):
        # add a set and rule (idempotent-ish)
        _run(["nft", "add", "table", "inet", "iotguard"])
        _run(["nft", "add", "set", "inet", "iotguard", "blocked", "{", "type", "ipv4_addr", ";", "flags", "interval", ";", "}"])
        _run(["nft", "add", "chain", "inet", "iotguard", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"])
        _run(["nft", "add", "rule", "inet", "iotguard", "input", "ip", "saddr", "@blocked", "drop"])
        code, out = _run(["nft", "add", "element", "inet", "iotguard", "blocked", f"{ip}"])
        ok = (code == 0)
        return ok, out
    # fallback to iptables
    if have("iptables"):
        code, out = _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
        return (code == 0), out
    return False, "no firewall tool (nft/iptables) available"

# ---------- Public API ----------
def block_ip(ip: Optional[str]) -> tuple[bool, str]:
    """
    Block an IP address using the appropriate firewall for the OS.
    
    Args:
        ip: The IP address to block
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    if not ip:
        return False, "no ip provided"
    
    # Validate IP before attempting to block
    valid, error = validate_ip(ip)
    if not valid:
        return False, f"validation failed: {error}"
    
    ip = ip.strip()
    
    if os.name == "nt":
        return block_ip_windows(ip)
    # Linux / WSL / macOS (macOS: pfctl not implemented here)
    return block_ip_linux(ip)

if __name__ == "__main__":
    # Small CLI for manual test: python scripts/blocker.py 1.2.3.4
    ip = sys.argv[1] if len(sys.argv) > 1 else None
    ok, out = block_ip(ip)
    print("OK" if ok else "FAIL", out)
