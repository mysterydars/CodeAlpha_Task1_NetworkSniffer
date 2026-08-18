#!/usr/bin/env python3
"""
CodeAlpha Cybersecurity Task 1: Basic Network Sniffer
Author: CodeAlpha Intern
Description: Python script using Scapy and Raw Sockets to capture, inspect,
and analyze network packets in real-time with threat detection rules.
"""

import sys
import os
import time
import argparse
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, DNS, conf
except ImportError:
    print("[!] Scapy is required. Install using: pip install scapy")
    sys.exit(1)

THREAT_KEYWORDS = ["SELECT", "UNION", "INSERT", "DROP", "<script>", "admin' OR", "eval(", "/etc/passwd"]

def analyze_payload(payload_bytes):
    alerts = []
    try:
        text = payload_bytes.decode('utf-8', errors='ignore')
        for kw in THREAT_KEYWORDS:
            if kw.lower() in text.lower():
                alerts.append(f"[ALERT] Suspicious signature found: '{kw}'")
    except Exception:
        pass
    return alerts

packet_count = 0

def packet_callback(packet):
    global packet_count
    packet_count += 1
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    pkt_size = len(packet)

    src_ip = "N/A"
    dst_ip = "N/A"
    proto_name = "Other"
    details = ""

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ttl = packet[IP].ttl

        if packet.haslayer(TCP):
            proto_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            details = f"Ports: {sport} -> {dport} | Flags: {flags} | TTL: {ttl}"
        elif packet.haslayer(UDP):
            proto_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            details = f"Ports: {sport} -> {dport} | TTL: {ttl}"
            if packet.haslayer(DNS):
                proto_name = "DNS"
                details += " (DNS Query/Response)"
        elif packet.haslayer(ICMP):
            proto_name = "ICMP"
            icmp_type = packet[ICMP].type
            details = f"Type: {icmp_type}"
    elif packet.haslayer(ARP):
        proto_name = "ARP"
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        details = f"Operation: {'Who-has' if packet[ARP].op==1 else 'Is-at'}"

    print("-" * 80)
    print(f"[{packet_count}] {timestamp} | Protocol: {proto_name:<5} | Size: {pkt_size}B")
    print(f"    Source: {src_ip}  ===>  Destination: {dst_ip}")
    if details:
        print(f"    Info: {details}")

    if packet.haslayer(Raw):
        raw_payload = packet[Raw].load
        hex_dump = " ".join(f"{b:02x}" for b in raw_payload[:32])
        print(f"    Payload (Hex 32b): {hex_dump}")
        alerts = analyze_payload(raw_payload)
        for alert in alerts:
            print(f"    \033[91m{alert}\033[0m")

def main():
    parser = argparse.ArgumentParser(description="CodeAlpha Task 1 - Basic Network Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface (e.g. eth0, wlan0, lo)", default=None)
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (0 = infinite)", default=0)
    parser.add_argument("-f", "--filter", help="BPF Filter string (e.g. 'tcp port 80', 'icmp')", default="")

    args = parser.parse_args()

    print("=" * 80)
    print("      CodeAlpha Cybersecurity - Network Sniffer (Task 1)")
    print("=" * 80)
    print(f"[*] Interface: {args.interface or 'Default'}")
    print(f"[*] Filter: {args.filter or 'None (Capturing all)'}")
    print("[*] Press Ctrl+C to stop packet capture.")
    print("=" * 80)

    try:
        sniff(
            iface=args.interface,
            filter=args.filter if args.filter else None,
            prn=packet_callback,
            count=args.count,
            store=0
        )
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")
    except PermissionError:
        print("[!] Error: Root/Admin privileges required for raw packet sniffing.")
        print("[!] Try running with: sudo python3 sniffer.py")

if __name__ == "__main__":
    main()
