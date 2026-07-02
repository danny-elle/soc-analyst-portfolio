# SOC Analyst Incident Report

## Incident Title

Brute Force Authentication Detection Validation Lab

---

## Executive Summary

A controlled authentication testing exercise was conducted within a homelab environment to validate Windows Security Event collection and Wazuh detection capabilities.

The primary objective was to generate authentication activity against a Windows 11 endpoint and confirm successful collection and visibility of generated events within the Wazuh SIEM platform.

Testing successfully produced Windows authentication events that were indexed and searchable within Wazuh.

---

## Environment

 Asset : Role 
 Kali Linux : Attack Source 
 Windows 11 Home : Target Endpoint 
 Ubuntu Wazuh Server : SIEM 

---

## Scope

This activity occurred within an isolated homelab environment.

No production assets or external systems were involved.

---

## Attack Activity

Authentication attempts were generated against a dedicated Windows local account.

Account:

```text
labuser
```

Authentication testing was performed through Windows SMB services.

---

## Detection Summary

The following Windows Security Event IDs were observed:

 Event ID : Description 
 4624 : Successful Logon 
 4625 : Failed Logon 

Events were successfully ingested by Wazuh and were searchable through the dashboard.

---

## Event Analysis

### Failed Authentication

Observed:

```text
Event ID: 4625
```

Event Details:

```text
Logon Type: 2
Source Address: 127.0.0.1
Workstation: WINDOWS11
```

The failed authentication events confirmed that Windows security logging and Wazuh collection were operating correctly.

---

## Challenges Encountered

### SMB Connectivity

Issue:

```text
445/tcp filtered
```

Impact:

Authentication testing could not proceed.

Resolution:

- Network profile changed to Private.
- Firewall rules adjusted to permit SMB communications.

Result:

```text
445/tcp open microsoft-ds
```

---

### Hydra SMB Communication Error

Issue:

```text
debug_connect_ok
invalid reply from target
```

Analysis:

Hydra successfully established TCP connectivity but failed during SMB protocol negotiation.

Manual SMB authentication succeeded independently through smbclient.

Conclusion:

Issue attributed to Hydra SMB compatibility rather than authentication failure.

---

### Wazuh Indexer Failure

Issue:

Indexer service unavailable.

Resolution:

```bash
systemctl restart wazuh-indexer
```

Result:

Indexer functionality restored.

---

### Wazuh Dashboard API Failure

Issue:

```text
No API Connection
```

and

```text
HTTP 429
```

Resolution:

```bash
systemctl restart wazuh-manager
systemctl restart wazuh-dashboard
```

Dashboard session refreshed successfully.

---

## Findings

 Finding : Status 
 Windows agent reporting : Confirmed 
 Authentication events collected : Confirmed 
 Failed logons detected : Confirmed 
 Successful logons detected : Confirmed 
 Wazuh indexing operational : Confirmed 
 Source IP visibility : Limited 

---

## Lessons Learned

1. Windows Home does not support inbound RDP services.
2. SMB provides an alternative method for authentication testing.
3. Verification of service functionality should occur prior to attack tool troubleshooting.
4. Authentication events may not always contain source IP information.
5. SIEM components should be validated individually when troubleshooting ingestion issues.

## Conclusion

The exercise successfully validated Windows Security Log collection and detection visibility within Wazuh. Authentication-related events were generated, ingested, indexed, and reviewed. The lab provided practical experience in authentication monitoring, Windows event analysis, Wazuh administration, and incident response troubleshooting.
