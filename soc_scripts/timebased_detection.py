#! /usr/bin/env python3
'''
timebased_detection.py

This script analyzes a list of alerts to identify and count threat events
that occurred within the last hour. It parses timestamps, checks severity, 
and prints actionable intelligence.

SOC Use Case: TIme-based threat triage and alert filtering.
'''

from datetime import datetime, timedelta


alerts = [
        {"ip": "192.168.1.10", "threat": True, "timestamp": "2025-05-18 13:40:00"},
        {"ip": "10.0.0.3", "threat": False, "timestamp": "2025-05-18 12:00:00"},
        {"ip": "8.8.8.8", "threat": True, "timestamp": "2025-06-04 12:15:00"}
        ]

now = datetime.now()
an_hour_ago = now - timedelta(hours=1)
count = 0

for alert in alerts:
    alert_time = datetime.strptime(alert["timestamp"], "%Y-%m-%d %H:%M:%S")
    if alert["threat"] and alert_time >  an_hour_ago:
        count += 1
        print(f"Threat detected from {alert['ip']} at {alert_time}")
print(f"Total alerts detected: {count}")


