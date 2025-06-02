#! /usr/bin/env python3

# A custom network analysis script for SOC analysts that captures live packet traffic and maps key protocol
# headers to their respective OSI layers for inspection event correlation.

from datetime import datetime
# from scapy.all import get_if_list
# print(get_if_list())
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
import re

icmp_message = {

        (0, 0): "Echo Reply",
        (3, 0): "Destination network unreachable",
        (3, 1): "Desintation host unreachable",
        (3, 2): "Destination protocol unreachable",
        (3, 3): "Destination port unreacheable",
        (3, 4): "Fragmentation required, and DF flag set",
        (3, 5): "Source route failed",
        (3, 6): "Destination network unknown",
        (3, 7): "Destination host unknown",
        (3, 8): "SOurce host isolated",
        (3, 9): "Network administravtively prohibited",
        (3, 10): "Host administractively prohibited",
        (3, 11): "Network unreachable for ToS",
        (3, 12): "Host unreachable for ToS",
        (3, 13): "COmmunication administratively prohibited",
        (3, 14): "Host PRecednece VIolation",
        (3, 15): "Precedence cutoff in effect",
        (4, 0): "SOurce quench (congrestion control)",
        (5, 0): "Redirect Datagram for the Network",
        (5, 1): "REdirect Datagram for the HOst",
        (5, 2): "Redirect Datagram for the TOS & Network",
        (5, 3): "Redirect Datagram for the ToS & host",
        (6, 0): "Alternate Host Address",
        (8, 0): "Echo request"

}

# TO-DOs:
# TCP Flags
# Flag suspicous ports
# Save to log
# Filter by port or protocol
# Add DNS
# Add suspicious payload sizes for HTTP traffic

def packet_processor(pkts):
    try:
        for pkt in pkts:
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')
                
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    flags = pkt[TCP].flags
                    payload = pkt[Raw].load.decode(errors="ignore")
                    print(f"[TCP] {timestamp} {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: {flags}")
                    
                    # Formatting output using bold for credentials found
                    BOLD = "\033[1m"
                    RESET = "\033[0m"

                    # HTTP Method extraction
                    if payload.startswith(("GET", "POST", "PUT", "DELETE")):
                        method = payload.splitlines()[0]
                        print(f"\n[HTTP Reuest]: {method}")

                    if "username=" in payload or "password=" in payload:
                        print(f"{BOLD}Credentials found:{RESET}\n")
                        # Splitting based on POST data (&) and headers (newline)
                        params = re.split(r"[&\n]", payload)
                        for param in params:
                            if "username=" in param or "password=" in param:
                                key_val = param.strip()
                                print(f"   {BOLD}{key_val}{RESET}")
                    print("\n")

                elif pkt.haslayer(UDP):
                    print(f"[UDP] {timestamp} {src_ip}:{pkt[UDP].sport} -> {dst_ip}:{pkt[UDP].dport}")
                
                elif pkt.haslayer(ICMP):
                    icmp_type = pkt[ICMP].type
                    icmp_code = pkt[ICMP].code
                    meaning = icmp_message.get((icmp_type, icmp_code), "Unknown ICMP Message")
                    print(f"[ICMP] {timestamp} {src_ip} -> {dst_ip} | Type: {icmp_type}, Code: {icmp_code}, Message: {meaning}")

                elif pkt.haslayer("ARP"):
                      print(f"ARP: {timestamp} {pkt[ARP].psrc} -> {pkt[ARP].pdst}")

    except Exception as e:
        print(f"Packet error while parsing: {e}")


# Run ping 8.8.8.8 or ping google.com, script runs in sudo
#sniff(filter="ip", count=10, prn=packet_processor, iface="eth0", store=True)

# Run ping telnet google.com 80, ctrl+] quit
#sniff(filter="tcp", prn=packet_processor)


# sniff(prn=packet_processor, store=0)

# Testing HTTP capture
sniff(filter= "tcp port 8000", iface= "lo", prn=packet_processor, store=0)
