#! /usr/bin/env python3
import datetime

'''
ioc_ip.py

This Python script analyzes a lit of simulated alert data to identify IP addresses associate with threats.
For each IP flagged as malicious, it prints the details and logs them to a local file for further analysis.

-Filters only alerts marked as threats (IOCs)
-Logs IP addresses, threat categories, and severitities
-Outputs total number of threats detected 

SOC Use Case: Isolate threats based on IP addresses, log results, and escalate relevant alerts to Tier 2 analyst for further investigation.
'''


alerts = [
        {"ip": "192.168.1.10", "threat": True, "category": "Brute Force", "severity": "high"},
        {"ip": "10.0.0.3", "threat": False, "category": "Normal", "severity": "low"},
        {"ip": "8.8.8.8", "threat": True, "category": "DDoS", "severity": "critical"}
        ]

def detect_threat_ips(alertsi, logfile="threat_ips.log"):

    count = 0

    with open(logfile, "a") as log:
        log.write(f"\nScanning started at {datetime.datetime.now()}\n")
        log.write(f"IP, Category, Severity\n")
        log.write("-" * 30 + "\n")

        for alert in alerts:
            if alert["threat"] == True:
                count += 1
                print(f"{alert['severity'].upper()} - {alert['category']} detected from {alert['ip']}")
                log.write(f"{alert['ip']}, {alert['category']}, {alert['severity']}\n")

        print(f"\nTotal number of detected threats: {count}")


def main():

    print("Running IOC threat detection...\n")
    detect_threat_ips(alerts)


if __name__ == "__main__":
    main()





