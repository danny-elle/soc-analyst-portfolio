# Brute Force Login Detection Lab

## Overview

This lab focused on generating Windows authentication events and validating that Wazuh successfully collected and displayed those events for analysis.

## Lab Environment

 System - Purpose:
 Kali Linux - Attack Workstation 
 Windows 11 Home - Target System 
 Ubuntu Server - Wazuh SIEM 

---

## Objectives

- Generate authentication activity.
- Validate Windows event collection.
- Confirm log visibility in Wazuh.
- Practice troubleshooting networking and SIEM issues.

---

## Initial Plan

Originally, the lab was intended to perform a brute force exercise against Remote Desktop Protocol (RDP).

### Challenge

Windows 11 Home does not support acting as an RDP server.

### Lesson Learned

Windows Home editions cannot host incoming RDP connections. Alternative authentication services must be used.

---

## Switching to SMB

The lab was modified to use SMB authentication.

Advantages:

- Works on Windows Home.
- Generates Windows authentication logs.
- Easy to monitor using Wazuh.

---

## Networking Challenges

### Issue

There was confusion regarding the IP address of the created user account.

### Resolution

Learned that user accounts do not have their own IP addresses.

Example:

Windows Machine:
192.168.56.105

Accounts:

- Administrator
- labuser

Both accounts use the Windows machine IP.

---

### Issue

Kali and Windows were not properly communicating.

### Resolution

Compared addressing information using:

```bash
ip a
```

and

```cmd
ipconfig
```

Verified both systems could communicate.

---

## SMB Connectivity Challenges

### Issue

Port 445 initially appeared filtered.

```bash
nmap -p 445 <windows-ip>
```

Output:

```text
445/tcp filtered
```

### Resolution

Changed the Windows network category to Private and enabled SMB-related firewall rules.

Afterward:

```text
445/tcp open microsoft-ds
```

---

## Test User Creation

Created a dedicated lab account:

```cmd
net user labuser Password123 /add
```

---

## Verifying SMB Access

Before using Hydra, SMB access was verified manually:

```bash
smbclient -L //<windows-ip> -U labuser
```

Successful authentication confirmed:

- User account existed.
- Password was correct.
- SMB service was operational.

---

## Hydra Installation

Installed Hydra:

```bash
sudo apt update
sudo apt install hydra -y
```

Verified:

```bash
hydra --version
```

Hydra Version:

```text
9.7
```

---

## Password List

Created:

```bash
nano passwords.txt
```

Example:

```text
123456
password
Password123
bigbooty12!
```

---

## Hydra SMB Compatibility Issue

### Issue

Hydra returned:

```text
debug_connect_ok
invalid reply from target
```

### Investigation

SMB protocol scan showed:

```text
SMB 2.0.2
SMB 2.1
SMB 3.0
SMB 3.0.2
SMB 3.1.1
```

Manual SMB authentication still worked.

### Conclusion

The issue was related to Hydra SMB compatibility rather than authentication failure.

### Lesson Learned

Always verify service functionality independently before assuming a target is misconfigured.

---

## Windows Password Storage Learning

### Question

Can Windows display a previously created password?

### Finding

No.

Windows stores password hashes rather than plaintext passwords.

### Resolution

Passwords must be reset rather than viewed.

```cmd
net user labuser NewPassword123
```

---

## Wazuh Troubleshooting

### Wazuh Indexer Failure

Issue:

Indexer service failed.

Resolution:

```bash
sudo systemctl restart wazuh-indexer
```

---

### API Connectivity Failure

Issue:

```text
No API Connection
```

Verification:

```bash
curl -k https://localhost:55000
```

Returned:

```text
Unauthorized
```

This confirmed the API was operational.

Resolution:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl restart wazuh-dashboard
```

---

### Dashboard 429 Error

Issue:

```text
Request failed with status code 429
```

Resolution:

- Restarted dashboard.
- Restarted manager.
- Logged out and back in.

---

## Event Detection

Within Wazuh, searching for:

```text
4625
```

returned failed logon events.

Searching with the full field name did not return results because of differences in indexed field mappings.

---

## Findings

Detected:

```text
4625 - Failed Logon
```

Observed:

```text
Logon Type: 2
IP Address: 127.0.0.1
Workstation Name: WINDOWS11
```

### Lesson Learned

Logon Type 2 represents interactive logons.

Not all Windows authentication events include the attacker's source IP.

---

## Key Takeaways

### Technical

- Windows Home does not support incoming RDP.
- SMB is a suitable alternative authentication mechanism.
- Wazuh components can fail independently.
- Service validation should occur before tool troubleshooting.

### Detection

- Event ID 4625 = Failed Logon
- Event ID 4624 = Successful Logon
- Authentication events do not always record attacker IPs.
- Logon types provide important context during investigations.

### Troubleshooting Methodology

Always verify:

Network - Service - Authentication - Tool - SIEM

---

## Conclusion

This lab successfully demonstrated authentication event generation, event collection, and event analysis using Kali Linux, Windows 11, and Wazuh.

The exercise reinforced skills in:

- Networking
- Windows security logging
- Wazuh administration
- Authentication monitoring
- Incident troubleshooting
