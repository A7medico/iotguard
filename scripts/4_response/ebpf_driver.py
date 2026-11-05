"""
scripts/4_response/ebpf_driver.py
=============================================================================
IoTGuard Phase 4 — eBPF / XDP High-Speed In-Kernel Packet Filtering Manager
=============================================================================

Capabilities:
  1. In-Kernel O(1) NIC-Level Blocking:
     Interacts with the compiled XDP program (`xdp_iotguard.o`) and its pinned
     BPF hash map (`iotguard_blocked_ips`), enabling packet drops at the network
     driver RX queue before entering the Linux kernel network stack.
  2. BPF Map Management via bpftool:
     Provides atomic insertion, deletion, and extraction of dropped packet
     telemetry from pinned BPF maps using standard `bpftool -j` (JSON mode).
  3. Network Byte-Order Handlers:
     Handles IPv4 conversion between dotted-decimal strings, 32-bit network
     byte-order integers (big-endian), and raw hexadecimal bytes for bpftool.
  4. Cross-Platform Safe Abstraction:
     Gracefully reports availability status on Linux vs. Windows/macOS. When
     eBPF/XDP is unavailable or unattached, upper layers seamlessly fall back
     to nftables, iptables, or netsh without breaking dry-run or validation.
=============================================================================
"""

import json
import logging
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("iotguard.ebpf")

DEFAULT_BPF_PIN_PATH = Path("/sys/fs/bpf/iotguard_blocked_ips")
DEFAULT_BPF_PROG_PATH = Path("/sys/fs/bpf/xdp_iotguard")
DEFAULT_XDP_OBJ_PATH = Path("scripts/4_response/xdp_iotguard.o")
COMMAND_TIMEOUT = 5


# ============================================================================
# 1. IPv4 Byte Order & BPF Map Formatting Helpers
# ============================================================================

def ip_to_network_u32(ip: str) -> int:
    """
    Convert an IPv4 string to a 32-bit unsigned integer in network byte order.
    Matches the `ip->saddr` representation in the Linux kernel `struct iphdr`.
    """
    clean_ip = ip.strip()
    packed = socket.inet_aton(clean_ip)
    return struct.unpack("!I", packed)[0]


def network_u32_to_ip(val: int) -> str:
    """
    Convert a 32-bit integer in network byte order back to dotted-decimal IPv4.
    """
    packed = struct.pack("!I", val & 0xFFFFFFFF)
    return socket.inet_ntoa(packed)


def ip_to_hex_bytes(ip: str) -> List[str]:
    """
    Convert an IPv4 address to a list of hex strings formatted for bpftool.
    Example: '192.168.1.100' -> ['0xc0', '0xa8', '0x01', '0x64']
    """
    clean_ip = ip.strip()
    raw_bytes = socket.inet_aton(clean_ip)
    return [f"0x{b:02x}" for b in raw_bytes]


def entry_to_hex_bytes(blocked_at_ns: int, drop_count: int = 0) -> List[str]:
    """
    Serialize struct blocked_ip_entry (__u64 blocked_at_ns, __u64 drop_count)
    into 16 bytes formatted for bpftool (little-endian for x86_64/ARM64).
    """
    packed = struct.pack("<QQ", blocked_at_ns, drop_count)
    return [f"0x{b:02x}" for b in packed]


def parse_dump_key(key_data: Any) -> Optional[str]:
    """
    Parse a bpftool map dump key field into a dotted-decimal IPv4 string.
    Supports hex string lists, integer byte lists, and raw integers.
    """
    if not key_data:
        return None

    try:
        if isinstance(key_data, list):
            if all(isinstance(x, str) and (x.startswith("0x") or len(x) <= 4) for x in key_data):
                raw_bytes = bytes([int(x, 16) for x in key_data])
            elif all(isinstance(x, int) for x in key_data):
                raw_bytes = bytes(key_data)
            else:
                return None
            if len(raw_bytes) == 4:
                return socket.inet_ntoa(raw_bytes)
        elif isinstance(key_data, int):
            return network_u32_to_ip(key_data)
        elif isinstance(key_data, str) and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", key_data):
            return key_data
    except Exception as e:
        logger.debug(f"Failed to parse BPF map dump key {key_data}: {e}")

    return None


def parse_dump_value(val_data: Any) -> Tuple[int, int]:
    """
    Parse a bpftool map dump value field into (blocked_at_ns, drop_count).
    """
    blocked_at_ns = 0
    drop_count = 0

    if not val_data:
        return (0, 0)

    try:
        if isinstance(val_data, list):
            if all(isinstance(x, str) and (x.startswith("0x") or len(x) <= 4) for x in val_data):
                raw_bytes = bytes([int(x, 16) for x in val_data])
            elif all(isinstance(x, int) for x in val_data):
                raw_bytes = bytes(val_data)
            else:
                raw_bytes = b""

            if len(raw_bytes) >= 16:
                blocked_at_ns, drop_count = struct.unpack("<QQ", raw_bytes[:16])
        elif isinstance(val_data, dict):
            blocked_at_ns = int(val_data.get("blocked_at_ns", 0))
            drop_count = int(val_data.get("drop_count", 0))
    except Exception as e:
        logger.debug(f"Failed to parse BPF map dump value {val_data}: {e}")

    return (blocked_at_ns, drop_count)


# ============================================================================
# 2. EBPFBlocker Manager Class
# ============================================================================

class EBPFBlocker:
    """
    High-Performance eBPF / XDP In-Kernel Packet Filter Manager.

    Provides control-plane primitives for loading, attaching, updating,
    and monitoring XDP programs and pinned BPF hash maps.
    """

    def __init__(
        self,
        interface: str = "eth0",
        mode: str = "auto",
        map_pin_path: Union[str, Path] = DEFAULT_BPF_PIN_PATH,
        obj_path: Union[str, Path] = DEFAULT_XDP_OBJ_PATH,
        bpftool_bin: str = "bpftool",
    ):
        self.interface = interface
        self.mode = mode
        self.map_pin_path = Path(map_pin_path)
        self.obj_path = Path(obj_path)
        self.bpftool_bin = bpftool_bin
        self._lock = threading.Lock()

        # In-memory shadow state for tracking, simulation, and offline stats
        self._shadow_map: Dict[str, Dict[str, Any]] = {}

        # Testing hooks
        self._force_available: Optional[bool] = None
        self._force_attached: Optional[bool] = None

    # ── Platform & Capability Detection ──────────────────────────────────────

    def is_available(self) -> bool:
        """
        Check if eBPF/XDP subsystem is operational on this host.
        Requires Linux, bpftool in PATH, and accessible /sys/fs/bpf.
        """
        if self._force_available is not None:
            return self._force_available

        # eBPF/XDP is strictly a Linux kernel capability
        if os.name == "nt" or not sys.platform.startswith("linux"):
            return False

        # Check for bpftool binary
        if not shutil.which(self.bpftool_bin):
            return False

        # Check if BPF filesystem is mounted or accessible
        bpf_fs = Path("/sys/fs/bpf")
        if not bpf_fs.exists():
            return False

        return True

    def is_attached(self, interface: Optional[str] = None) -> bool:
        """
        Check whether an XDP program is actively attached to the network interface.
        """
        if self._force_attached is not None:
            return self._force_attached

        if not self.is_available():
            return False

        iface = interface or self.interface
        try:
            # Query bpftool net list
            cmd = [self.bpftool_bin, "net", "list", "-j"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
            if res.returncode == 0:
                data = json.loads(res.stdout or "[]")
                for entry in data:
                    if entry.get("devname") == iface and "xdp" in entry:
                        return True
        except Exception as e:
            logger.debug(f"bpftool net list check failed: {e}")

        # Fallback to ip link
        try:
            res = subprocess.run(
                ["ip", "link", "show", "dev", iface],
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT,
            )
            if res.returncode == 0 and "xdp" in res.stdout:
                return True
        except Exception:
            pass

        return False

    # ── XDP Lifecycle Operations ─────────────────────────────────────────────

    def attach_xdp(
        self,
        interface: Optional[str] = None,
        mode: str = "auto",
        obj_path: Optional[Union[str, Path]] = None,
    ) -> Tuple[bool, str]:
        """
        Load and attach the compiled XDP program to the network interface.
        """
        if not self.is_available():
            return False, "eBPF/XDP is not available on this platform"

        iface = interface or self.interface
        bpf_obj = Path(obj_path or self.obj_path)

        if not bpf_obj.exists():
            return False, f"Compiled XDP object not found at {bpf_obj}"

        # Choose attachment mode flag
        # xdpdrv = native driver hook (fastest), xdpgeneric = skb generic hook
        mode_flag = "xdp" if mode == "native" else "xdpgeneric"

        try:
            cmd = ["ip", "link", "set", "dev", iface, mode_flag, "obj", str(bpf_obj), "sec", "xdp"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
            if res.returncode == 0:
                return True, f"Successfully attached XDP filter to {iface} ({mode_flag})"
            return False, f"Failed to attach XDP filter: {res.stderr.strip()}"
        except Exception as e:
            return False, f"Exception attaching XDP filter: {e}"

    def detach_xdp(self, interface: Optional[str] = None) -> Tuple[bool, str]:
        """
        Detach the XDP program from the network interface.
        """
        if not self.is_available():
            return False, "eBPF/XDP is not available on this platform"

        iface = interface or self.interface
        try:
            cmd = ["ip", "link", "set", "dev", iface, "xdp", "off"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
            if res.returncode == 0:
                return True, f"Successfully detached XDP filter from {iface}"
            return False, f"Failed to detach XDP filter: {res.stderr.strip()}"
        except Exception as e:
            return False, f"Exception detaching XDP filter: {e}"

    # ── Map Control Primitives ───────────────────────────────────────────────

    def add_blocked_ip(
        self,
        ip: str,
        timestamp_ns: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Insert an IPv4 address into the in-kernel pinned BPF hash map.
        Packets from this IP will be dropped at the NIC driver stage.
        """
        if not ip or not isinstance(ip, str):
            return False, "No valid IP provided"

        clean_ip = ip.strip()

        # Basic IP validation
        try:
            socket.inet_aton(clean_ip)
        except socket.error:
            return False, f"Invalid IPv4 format: {clean_ip}"

        ts = timestamp_ns or time.time_ns()

        # Update shadow tracking map
        with self._lock:
            self._shadow_map[clean_ip] = {
                "blocked_at_ns": ts,
                "drop_count": self._shadow_map.get(clean_ip, {}).get("drop_count", 0),
            }

        # If kernel BPF map is not active/available, shadow map operates in simulated mode
        if not self.is_available() or not self.map_pin_path.exists():
            return True, f"Added {clean_ip} to XDP blocklist (shadow/dry-run mode)"

        # Write to pinned BPF hash map via bpftool
        key_hex = ip_to_hex_bytes(clean_ip)
        val_hex = entry_to_hex_bytes(ts, drop_count=0)

        cmd = [
            self.bpftool_bin,
            "map",
            "update",
            "pinned",
            str(self.map_pin_path),
            "key",
            "hex",
            *key_hex,
            "value",
            "hex",
            *val_hex,
        ]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
            if res.returncode == 0:
                return True, f"Added {clean_ip} to in-kernel XDP map ({self.map_pin_path.name})"
            return False, f"bpftool map update failed: {res.stderr.strip()}"
        except Exception as e:
            return False, f"Exception executing bpftool map update: {e}"

    def remove_blocked_ip(self, ip: str) -> Tuple[bool, str]:
        """
        Remove an IPv4 address from the pinned BPF hash map, restoring traffic.
        """
        if not ip or not isinstance(ip, str):
            return False, "No valid IP provided"

        clean_ip = ip.strip()

        # Remove from shadow tracking map
        with self._lock:
            if clean_ip in self._shadow_map:
                del self._shadow_map[clean_ip]

        if not self.is_available() or not self.map_pin_path.exists():
            return True, f"Removed {clean_ip} from XDP blocklist (shadow/dry-run mode)"

        key_hex = ip_to_hex_bytes(clean_ip)
        cmd = [
            self.bpftool_bin,
            "map",
            "delete",
            "pinned",
            str(self.map_pin_path),
            "key",
            "hex",
            *key_hex,
        ]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
            if res.returncode == 0:
                return True, f"Removed {clean_ip} from in-kernel XDP map"
            return False, f"bpftool map delete failed: {res.stderr.strip()}"
        except Exception as e:
            return False, f"Exception executing bpftool map delete: {e}"

    def get_drop_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Dump all entries and per-IP dropped packet counters from the BPF map.
        Returns a dictionary: {ip: {'drop_count': N, 'blocked_at_ns': T}}
        """
        stats: Dict[str, Dict[str, Any]] = {}

        # 1. If kernel BPF map is available, dump via bpftool
        if self.is_available() and self.map_pin_path.exists():
            try:
                cmd = [self.bpftool_bin, "map", "dump", "pinned", str(self.map_pin_path), "-j"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
                if res.returncode == 0:
                    raw_data = json.loads(res.stdout or "[]")
                    for item in raw_data:
                        ip = parse_dump_key(item.get("key"))
                        if ip:
                            blocked_at, drops = parse_dump_value(item.get("value"))
                            stats[ip] = {
                                "drop_count": drops,
                                "blocked_at_ns": blocked_at,
                            }
                            # Sync shadow map
                            with self._lock:
                                self._shadow_map[ip] = stats[ip].copy()
                    return stats
            except Exception as e:
                logger.debug(f"Failed to dump BPF map via bpftool: {e}")

        # 2. Return cached shadow map
        with self._lock:
            return {k: v.copy() for k, v in self._shadow_map.items()}

    def get_total_drops(self) -> int:
        """Calculate aggregate packets dropped across all active XDP rules."""
        stats = self.get_drop_stats()
        return sum(item.get("drop_count", 0) for item in stats.values())

    def clear_all(self) -> Tuple[bool, str]:
        """Clear all active blocks from both shadow map and in-kernel BPF map."""
        with self._lock:
            cached_ips = list(self._shadow_map.keys())
            self._shadow_map.clear()

        if self.is_available() and self.map_pin_path.exists():
            for ip in cached_ips:
                try:
                    self.remove_blocked_ip(ip)
                except Exception:
                    pass

        return True, "Cleared all XDP rules"


# ── Global Singleton Accessor ────────────────────────────────────────────────
_GLOBAL_EBPF_BLOCKER: Optional[EBPFBlocker] = None
_BLOCKER_LOCK = threading.Lock()


def get_ebpf_blocker() -> EBPFBlocker:
    """Retrieve or initialize the global EBPFBlocker manager instance."""
    global _GLOBAL_EBPF_BLOCKER
    with _BLOCKER_LOCK:
        if _GLOBAL_EBPF_BLOCKER is None:
            _GLOBAL_EBPF_BLOCKER = EBPFBlocker()
        return _GLOBAL_EBPF_BLOCKER

