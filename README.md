#  SOC Analyst Portfolio

Welcome to my SOC Analyst portfolio. This repository showcases hands-on blue team exercises, write-ups, and python blue team based scripts I’ve completed to build my career as a Tier 1 SOC Analyst.

---

##  Write-Ups

### Learning  
| Title | Description | Link |
|-------|-------------|------|
|  Wireshark Traffic Analysis | Analysis of anomalies and protocol behavior using Wireshark | [View](writeups/wireshark-analysis.md) |
|  Anti-Reverse Engineering  | Techniques malware uses to evade analysis and how to detect/analyze them   |[View](writeups/anti-reverse-engineering.md) |

### CTFs  
| Title | Description | Link |
|-------|-------------|------|
|  Summit | Purple-team challenge simulating malware detection, alerting, and response across IOCs and TTPs | [View](writeups/CTFs/summit) |  

## SOC Scripts

| Title | Description | Link |
|-------|-------------|------|
|  Python Network Sniffer   | A Scapy network packet sniffer that displays source/destination IPs, TCP ports, and TCP flags. Built to simulate real-time traffic inspection in SOC setting | [View](network-sniffer/simple_sniffer.py)  |
| Python IOC IPs |  Detects and logs IP addresses involved in threats. Categorizes them by severity and threat type. | [View](soc_scripts/ioc_ips.py) |
| Python Suspicious Ports | Detects and alerts which ports are used for malicious activity. | [View](soc_scripts/suspicious_ports.py) |
| Python Time-based Threat Detection | Checks alerts for any activity within the past hour. | [View](soc_scripts/timebased_detection.py) |


---

##  Skills Demonstrated

- Packet capture and protocol analysis using Wireshark and Python (Scapy)
- Real-time network traffic inspection (TCP, UDP, IP filtering with Python)
- Threat detection and IOC triage automation through Python scripting
- Suspicious port scanning and alerting logic for early threat identification
- Time-based alert filtering to identify recent and high-priority threats
- IP-based IOC correlation and threat logging for escalation workflows
- Custom tool creation to simulate and streamline SOC analyst tasks
- Understanding of common malicious behaviors (e.g., RDP scanning, SSH brute force)
- Reverse engineering basics using tools like Detect It Easy, IDA Pro, x64dbg, Task Manager, and pestudio
- Detecting and analyzing anti-debugging and VM-detection techniques
- CyberChef decoding and credential hunting
- Identifying Nmap scans, ARP spoofing, DNS tunneling, etc.
- Windows API behavior analysis
- Using base64 decoding, memory inspection, and entropy analysis for malware unpacking

---

##  Future Additions

- HTB Blue Team labs
- Splunk detection rules
- CTFs (TryHackMe)-Eviction, Wireshark, Splunk
- Malware analysis and reverse engineering - malware analysis.net and Practical malware labs
- Add DNS and log to network sniffer program
- CrowdStrike Annual Threat Report
- Security Playbook
- Incident Report
