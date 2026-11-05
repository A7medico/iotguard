"""
tests/test_ebpf_blocker.py
-----------------------------------------------------------------------------
Comprehensive Unit Tests for eBPF / XDP In-Kernel Packet Filtering,
Driver Hierarchy, Telemetry, and Fallback Behavior (Phase 4 Verification)
-----------------------------------------------------------------------------
"""

import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

# Ensure repository root and script directories are on sys.path
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "4_response"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "5_dashboard"))

import blocker
import ebpf_driver
from ebpf_driver import (
    EBPFBlocker,
    get_ebpf_blocker,
    ip_to_network_u32,
    network_u32_to_ip,
    ip_to_hex_bytes,
    entry_to_hex_bytes,
    parse_dump_key,
    parse_dump_value,
)
import metrics


@pytest.fixture
def isolated_blocks_file(tmp_path, monkeypatch):
    """Isolate active blocks storage to a clean temporary file."""
    test_file = tmp_path / "test_active_blocks.json"
    monkeypatch.setattr(blocker, "ACTIVE_BLOCKS_FILE", test_file)
    return test_file


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    """Create a test client for the dashboard Flask application."""
    test_blocks = tmp_path / "test_active_blocks_ebpf.json"
    monkeypatch.setattr(blocker, "ACTIVE_BLOCKS_FILE", test_blocks)

    from api_dashboard import app
    app.config["TESTING"] = True
    app.config["DEBUG"] = False

    with app.test_client() as client:
        yield client


# ============================================================================
# 1. IPv4 Byte Order & Conversion Primitives Tests
# ============================================================================

class TestIPv4ByteOrderConversions:
    """Tests for network byte order, endianness, and bpftool serialization."""

    def test_ip_to_network_u32_and_roundtrip(self):
        """IPv4 to network u32 integer conversion must preserve big-endian order."""
        test_ips = ["192.168.1.1", "10.0.0.5", "172.16.254.1", "8.8.8.8", "127.0.0.1"]
        for ip in test_ips:
            u32 = ip_to_network_u32(ip)
            assert isinstance(u32, int)
            assert 0 <= u32 <= 0xFFFFFFFF
            # Verify exact roundtrip conversion
            assert network_u32_to_ip(u32) == ip

    def test_ip_to_hex_bytes(self):
        """Convert IPv4 to hex byte list for bpftool map commands."""
        assert ip_to_hex_bytes("192.168.1.100") == ["0xc0", "0xa8", "0x01", "0x64"]
        assert ip_to_hex_bytes("10.0.0.1") == ["0x0a", "0x00", "0x00", "0x01"]
        assert ip_to_hex_bytes("255.255.255.255") == ["0xff", "0xff", "0xff", "0xff"]

    def test_entry_to_hex_bytes(self):
        """Serialize struct blocked_ip_entry into 16 little-endian bytes."""
        ts = 1_000_000_000
        drops = 42
        hex_bytes = entry_to_hex_bytes(ts, drops)
        assert len(hex_bytes) == 16
        raw = bytes([int(x, 16) for x in hex_bytes])
        unpacked_ts, unpacked_drops = struct.unpack("<QQ", raw)
        assert unpacked_ts == ts
        assert unpacked_drops == drops

    def test_parse_dump_key_formats(self):
        """Parse bpftool map dump key outputs across various kernel/tool versions."""
        # 1. Hex byte list: ['0xc0', '0xa8', '0x01', '0x64']
        assert parse_dump_key(["0xc0", "0xa8", "0x01", "0x64"]) == "192.168.1.100"

        # 2. Integer byte list: [192, 168, 1, 100]
        assert parse_dump_key([192, 168, 1, 100]) == "192.168.1.100"

        # 3. Raw network-order integer
        u32_int = ip_to_network_u32("192.168.1.100")
        assert parse_dump_key(u32_int) == "192.168.1.100"

        # 4. String passthrough
        assert parse_dump_key("10.0.0.1") == "10.0.0.1"

        # 5. Invalid input
        assert parse_dump_key(None) is None
        assert parse_dump_key([]) is None

    def test_parse_dump_value_formats(self):
        """Parse bpftool map dump value into (blocked_at_ns, drop_count)."""
        # 1. Hex byte list (16 bytes)
        raw_val = struct.pack("<QQ", 5000, 120)
        hex_list = [f"0x{b:02x}" for b in raw_val]
        blocked_at, drops = parse_dump_value(hex_list)
        assert blocked_at == 5000
        assert drops == 120

        # 2. Dict format
        blocked_at2, drops2 = parse_dump_value({"blocked_at_ns": 8000, "drop_count": 99})
        assert blocked_at2 == 8000
        assert drops2 == 99

        # 3. Empty/invalid
        assert parse_dump_value(None) == (0, 0)


# ============================================================================
# 2. EBPFBlocker Manager & Lifecycle Tests
# ============================================================================

class TestEBPFBlockerManager:
    """Unit tests for the EBPFBlocker control plane manager."""

    def test_availability_on_windows_by_default(self):
        """On Windows, native eBPF/XDP reports unavailable by default."""
        mgr = EBPFBlocker()
        if os.name == "nt":
            assert mgr.is_available() is False

    def test_availability_mocked_linux(self, monkeypatch, tmp_path):
        """Simulate Linux environment with bpftool and /sys/fs/bpf present."""
        mgr = EBPFBlocker()
        monkeypatch.setattr(os, "name", "posix")
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/sbin/bpftool" if cmd == "bpftool" else None)

        fake_bpf_fs = tmp_path / "bpf"
        fake_bpf_fs.mkdir()
        monkeypatch.setattr(Path, "exists", lambda self: True if "/sys/fs/bpf" in str(self) else False)

        assert mgr.is_available() is True

    def test_attach_and_detach_mocked(self, monkeypatch, tmp_path):
        """Test attach_xdp and detach_xdp command execution."""
        mgr = EBPFBlocker(interface="eth0")
        mgr._force_available = True

        fake_obj = tmp_path / "xdp_iotguard.o"
        fake_obj.write_bytes(b"\x7fELF")  # Fake ELF header

        # Mock successful subprocess.run for ip link
        mock_run = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""))
        monkeypatch.setattr(subprocess, "run", mock_run)

        ok, msg = mgr.attach_xdp(interface="eth0", mode="native", obj_path=fake_obj)
        assert ok is True
        assert "Successfully attached" in msg

        ok, msg = mgr.detach_xdp(interface="eth0")
        assert ok is True
        assert "Successfully detached" in msg

    def test_add_and_remove_blocked_ip_shadow_mode(self):
        """Add and remove IPs from shadow/simulated map when kernel map unpinned."""
        mgr = EBPFBlocker()
        mgr._force_available = False

        # Add valid IP
        ok, msg = mgr.add_blocked_ip("192.168.1.55")
        assert ok is True
        assert "192.168.1.55" in mgr.get_drop_stats()

        # Reject invalid IP
        ok, msg = mgr.add_blocked_ip("invalid-ip")
        assert ok is False

        # Remove IP
        ok, msg = mgr.remove_blocked_ip("192.168.1.55")
        assert ok is True
        assert "192.168.1.55" not in mgr.get_drop_stats()

    def test_add_blocked_ip_pinned_kernel_mode(self, monkeypatch, tmp_path):
        """Test bpftool map update invocation when pinned map exists."""
        pin_file = tmp_path / "iotguard_blocked_ips"
        pin_file.touch()

        mgr = EBPFBlocker(map_pin_path=pin_file)
        mgr._force_available = True

        mock_run = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""))
        monkeypatch.setattr(subprocess, "run", mock_run)

        ok, msg = mgr.add_blocked_ip("10.0.0.99")
        assert ok is True
        assert "Added 10.0.0.99" in msg

        # Verify command line arguments passed to bpftool
        called_cmd = mock_run.call_args[0][0]
        assert "bpftool" in called_cmd[0]
        assert "map" in called_cmd
        assert "update" in called_cmd
        assert "pinned" in called_cmd
        assert "0x0a" in called_cmd  # 10 in hex

    def test_get_drop_stats_from_bpftool_dump(self, monkeypatch, tmp_path):
        """Parse drop counts and timestamps from bpftool map dump JSON output."""
        pin_file = tmp_path / "iotguard_blocked_ips"
        pin_file.touch()

        mgr = EBPFBlocker(map_pin_path=pin_file)
        mgr._force_available = True

        mock_dump_json = json.dumps([
            {
                "key": ["0xc0", "0xa8", "0x01", "0x32"],  # 192.168.1.50
                "value": [
                    "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00",  # ts
                    "0x15", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00",  # drop_count=21
                ],
            },
            {
                "key": ["0x0a", "0x00", "0x00", "0x05"],  # 10.0.0.5
                "value": [
                    "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00",
                    "0x09", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00",  # drop_count=9
                ],
            },
        ])

        mock_run = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_dump_json, stderr=""))
        monkeypatch.setattr(subprocess, "run", mock_run)

        stats = mgr.get_drop_stats()
        assert "192.168.1.50" in stats
        assert stats["192.168.1.50"]["drop_count"] == 21
        assert "10.0.0.5" in stats
        assert stats["10.0.0.5"]["drop_count"] == 9

        assert mgr.get_total_drops() == 30


# ============================================================================
# 3. Blocker Driver Hierarchy & Fallback Tests
# ============================================================================

class TestBlockerDriverHierarchy:
    """Tests for multi-tiered firewall driver selection (eBPF -> nftables -> iptables -> netsh)."""

    def test_active_driver_dry_run(self):
        """When dry_run=True, active driver is always 'dry_run'."""
        assert blocker.get_active_driver(dry_run=True) == "dry_run"

    def test_active_driver_windows(self, monkeypatch):
        """On Windows, active driver is 'netsh'."""
        monkeypatch.setattr(os, "name", "nt")
        assert blocker.get_active_driver(dry_run=False) == "netsh"

    def test_active_driver_linux_ebpf_priority(self, monkeypatch):
        """On Linux, eBPF is selected first when available."""
        monkeypatch.setattr(os, "name", "posix")
        monkeypatch.setattr(sys, "platform", "linux")

        fake_ebpf = MagicMock()
        fake_ebpf.is_available.return_value = True
        monkeypatch.setattr(blocker, "get_ebpf_blocker", lambda: fake_ebpf)
        monkeypatch.setattr(blocker, "get_configured_firewall_backend", lambda: "auto")

        assert blocker.get_active_driver(dry_run=False) == "ebpf_xdp"

    def test_active_driver_linux_nftables_fallback(self, monkeypatch):
        """When eBPF is unavailable, fallback to nftables."""
        monkeypatch.setattr(os, "name", "posix")
        monkeypatch.setattr(sys, "platform", "linux")

        fake_ebpf = MagicMock()
        fake_ebpf.is_available.return_value = False
        monkeypatch.setattr(blocker, "get_ebpf_blocker", lambda: fake_ebpf)
        monkeypatch.setattr(blocker, "have", lambda tool: tool == "nft")
        monkeypatch.setattr(blocker, "get_configured_firewall_backend", lambda: "auto")

        assert blocker.get_active_driver(dry_run=False) == "nftables"

    def test_active_driver_linux_iptables_fallback(self, monkeypatch):
        """When eBPF and nftables are unavailable, fallback to iptables."""
        monkeypatch.setattr(os, "name", "posix")
        monkeypatch.setattr(sys, "platform", "linux")

        fake_ebpf = MagicMock()
        fake_ebpf.is_available.return_value = False
        monkeypatch.setattr(blocker, "get_ebpf_blocker", lambda: fake_ebpf)
        monkeypatch.setattr(blocker, "have", lambda tool: tool == "iptables")
        monkeypatch.setattr(blocker, "get_configured_firewall_backend", lambda: "auto")

        assert blocker.get_active_driver(dry_run=False) == "iptables"

    def test_block_ip_linux_ebpf_execution(self, monkeypatch):
        """Verify block_ip_linux calls ebpf.add_blocked_ip and returns success."""
        fake_ebpf = MagicMock()
        fake_ebpf.is_available.return_value = True
        fake_ebpf.add_blocked_ip.return_value = (True, "added to xdp map")
        monkeypatch.setattr(blocker, "get_ebpf_blocker", lambda: fake_ebpf)
        monkeypatch.setattr(blocker, "get_configured_firewall_backend", lambda: "auto")

        ok, msg = blocker.block_ip_linux("192.168.1.77")
        assert ok is True
        assert "ebpf-xdp-blocked-192.168.1.77" in msg
        fake_ebpf.add_blocked_ip.assert_called_once_with("192.168.1.77")

    def test_get_driver_telemetry_structure(self):
        """get_driver_telemetry returns complete telemetry dict."""
        tel = blocker.get_driver_telemetry()
        assert "active_driver" in tel
        assert "os" in tel
        assert "ebpf_available" in tel
        assert "ebpf_attached" in tel
        assert "xdp_interface" in tel
        assert "drop_stats" in tel
        assert "total_xdp_drops" in tel


# ============================================================================
# 4. API & Metrics Telemetry Integration Tests
# ============================================================================

class TestApiAndMetricsTelemetry:
    """Tests for /api/blocks, /api/topology, and Prometheus /metrics integration."""

    def test_api_blocks_exposes_driver_and_xdp_telemetry(self, app_client, isolated_blocks_file):
        """GET /api/blocks must return active driver and XDP telemetry."""
        resp = app_client.get("/api/blocks")
        assert resp.status_code == 200

        data = resp.get_json()
        assert data["ok"] is True
        assert "driver" in data
        assert "blocks" in data
        assert "driver_telemetry" in data
        assert "xdp_total_drops" in data

    def test_api_topology_exposes_firewall_summary(self, app_client):
        """GET /api/topology summary must include firewall_driver and xdp_drops."""
        resp = app_client.get("/api/topology")
        assert resp.status_code == 200

        data = resp.get_json()
        assert "summary" in data
        summary = data["summary"]
        assert "firewall_driver" in summary
        assert "xdp_drops" in summary

    def test_prometheus_metrics_exports_ebpf_gauges(self, app_client):
        """GET /metrics must export IoTGuard eBPF and firewall driver metrics."""
        resp = app_client.get("/metrics")
        assert resp.status_code == 200

        text = resp.data.decode("utf-8")
        assert "iotguard_firewall_driver_info" in text
        assert "iotguard_xdp_active_blocked_ips" in text

