# Lab 2 - Wazuh Agent Deployment

## Overview
Deploying and register Wazuh agent on Windows system and succesfully connect it to a Wazuh server running on Ubuntu. Verify communication and ensure agent appears as active on Wazuh.

## Enviroment
- Wazuh server: Ubuntu 22.04 LTS Desktop (All-in-one Wazuh 4.7)
- Windows agent: Windows 11
- Virtualization: VirtualBox
- Network: Host Only Adapter 1
- Server IP: 192.168.56.x
- Windows IP: 192.168.56.x

## Step 1 Network Configuration
Initial Issue
- Both VMs configured to SOC NAT NETWORK
- Windows could not ping Ubuntu
- Errors encountered:
    - Destination host unreachable
    - Request timed out
- Agent enrollment failed due to lack of connectivity

Solution
- Configured both VMs to use Host Only Adapter 1
- IP verification:
  
  On Ubuntu:
  ```ip a```

  On Windows:
  ```ipconfig```
  
- Output:
  Ubuntu: 192.168.56.x
  Windows: 192.168.56.y

Connectivity Test
- Windows:
  ``` ping 192.168.56.x ```

## Step 2 Download Wazuh Agent
On Windows 11 VM (PowerShell as Admin):
```Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='192.168.56.x' WAZUH_REGISTRATION_SERVER='192.68.56.x' ```

Issue:
- No service
  ``` Get-Service wazuhsvc ```
- ossec.conf had old NAT Network IP server address listed
  ``` notepad "C:\Program Files (x86)\ossec-agent\ossec.conf" ```
  
Solution:
- updated .conf manager IP address and registration address to current Ubuntu Host Only IPs
- Restarted service:
  ``` Restart-Service wazuh ```

Verify Ports:
- On Windows:
  ``` Test-NetConnection 192.168.56.x -Port 1514 ```
  ``` Test-NetConnection 192.168.56.x -Port 1515 ```
- Output:
  TcpTestSucceeded : true

## Step 3 Verify Agent on Dashboard
- On Ubuntu:
  - In Wazuh Dashboard:
    Management > Endpoints
  - Status changed from never connected to Active
    
  [Wazuh Dashboard Agent Status]
 
## Lessons Learned
- Host-only networking simpliest for VM labs
- NAT alone cannot support internal VM connection (both Windows and Ubuntu IPs were the same 10.0.2.x)
- Wazuh requires:
    - Port 1515 for enrollment
    - Port 1514 for log data
- Always verify:
    - Network, ports, services, and logs

## Conclusion
The deployment of Wazuh Windows agent was successfully completed after resolving networking and installation issues. The agent is fully
operational and actively communicating with the Wazuh server in a virtual SOC enviroment.

## Next steps
- Add screenshots of Agent deployment setup
- Lab 3 brute force 

  
  
