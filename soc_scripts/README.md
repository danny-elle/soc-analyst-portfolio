# SOC Scripts

This folder contains Python scripts developed to simulate tasks performed in a Tier 1 SOC environment. Each script is focused on detection, filtering, or triage techniques that support real-world incident response and threat hunting workflows.

---

##  Scripts Overview

###  `network_sniffer.py`
A Scapy-based network packet sniffer that captures and parses live traffic.

- Parses TCP, UDP, ICMP, ARP
- Extracts HTTP methods and basic auth credentials
- Detects suspicious ports (23, 3389, 5900, 8080)
- Maps traffic to OSI layers
- Filters and limits packet capture via CLI

**Use Case:** Real-time traffic inspection and protocol analysis for suspicious behavior.

---

###  `ioc_ips.py`
Parses alert logs and filters malicious IPs.

- Detects IPs where `threat == True`
- Logs IP, category, and severity to file
- Prints high-level summary

**Use Case:** IOC (Indicator of Compromise) identification and reporting.

---

###  `suspicious_ports.py`
Flags ports commonly used in malicious activity.

- Hardcoded check against ports (e.g., 22, 3389)
- Simple console output

**Use Case:** Quick validation of potentially exposed services.

---

###  `timebased_detection.py`
Filters alerts based on timestamp within the last hour.

- Uses `datetime` to calculate recent activity
- Filters based on `threat` and time
- Counts active alerts

**Use Case:** Time-based alert triage and escalation prep.

---

##  Requirements

- Python 3.x
- [Scapy](https://scapy.net/) for `network_sniffer.py`

```bash
pip install scapy

