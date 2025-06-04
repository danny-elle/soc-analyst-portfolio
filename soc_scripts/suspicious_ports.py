#! /usr/bin/env python3

'''
suspicious_ports.py

Scans a list of ports that may be IOCs.

SOC Use Case: Detects exposed or unusual open ports that can help analysts identify misconfigured systems, potential attack surfaces,
and early signs of malicious activity.
'''

ports = [22, 80, 443, 3389, 53]

for port in ports:
    if port == 3389 or port == 22:
        print(f"Suspicious Port Detected: {port}")
    else:
        print(f"Port {port} is ok")

