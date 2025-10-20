# scripts/blocker.py
import os, sys, subprocess, shutil
from typing import Optional

def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
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
    if not ip:
        return False, "no ip"
    if os.name == "nt":
        return block_ip_windows(ip)
    # Linux / WSL / macOS (macOS: pfctl not implemented here)
    return block_ip_linux(ip)

if __name__ == "__main__":
    # Small CLI for manual test: python scripts/blocker.py 1.2.3.4
    ip = sys.argv[1] if len(sys.argv) > 1 else None
    ok, out = block_ip(ip)
    print("OK" if ok else "FAIL", out)
