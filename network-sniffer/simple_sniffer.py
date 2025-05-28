#! /usr/bin/env python3

# A custom network analysis script for SOC analysts that captures live packet traffic and maps key protocol
# headers to their respective OSI layers for inspection event correlation.

from datetime import datetime
# from scapy.all import get_if_list
# print(get_if_list())
from scapy.all import sniff
from  scapy.all import  *



def packet_layers(pkts):
    try:
        for pkt in pkts:
            if pkt.haslayer("IP"):
                src_ip = pkts[IP].src
                dst_ip = pkts[IP].dst
                timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')
            if pkt.haslayer("TCP"):
                src_port = pkts[TCP].sport
                dst_port = pkts[TCP].dport
            print(f"[Timestamp] {timestamp} [IP] {pkts[TCP].flags}  {src_ip} {src_port} -> {dst_ip} {dst_port}")
    except Exception as e:
        print(f"Packet error while parsing: {e}")


# Run ping 8.8.8.8 or ping google.com, script runs in sudo
# sniff(filter="ip", count=10, prn=packet_layers, iface="eth0", store=True)

# Run ping telnet google.com 80, ctrl+] quit
sniff(filter="tcp", prn=packet_layers)
    
