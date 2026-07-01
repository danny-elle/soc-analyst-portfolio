# Lab 1 - Wazuh Installation

## Overview
Installed Wazuh SIEM enviroment on Ubuntu to support centralized logging, alert monitoring, and security event analysis in a SOC lab.

## Enviroment Setup
- Created Ubuntu 22.04.5 desktop virtual machine in VirtualBox
- Allocated:
  - 8 GB RAM
  - 4 CPUs
  - 60 GB Storage
- Configured NAT networking for internet access
- Installed Ubuntu Desktop for ease of management and visulizaiton.

## System Preparation
- Updated system packages prior to installation:
  ```bash
  sudo apt update
  sudo apt upgrade -y
- Installed required dependencies:
  ```bash
  sudo apt install curl -y

## Wazuh Installation
- Downloaded and executed official Wazuh all-in-one installer:
  ```bash
  curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
  sudo bash wazuh-install.sh -a
- Components installed:
  - Wazuh Manager (event processing and analysis)
  - Wazuh Indexer (data storage and search)
  - Wazuh Dashboard (web interface for monitoring)

## Verification that all Wazuh services were running:
  ```bash
  sudo systemctl status wazuh-manager
  sudo systemctl status wazuh-indexer
  sudo systemctl status wazuh-dashboard
``` 

All services are running:

[Installation Success](../screenshots/wazuh-indexer-active.png)

## Dashboard Access
- Retrieve system IP address:
  ```bash
  ip a
  ``` 
- Accessed server broswer via:
  https://<server-ip>
- Logged in using generated admin credentials
- Successfully reach Wazuh dashboard web interface
  [Login page](../screenshots/wazuh-website-loginpage.png)

  [Wazuh Dashboard](../screenshots/wazuh-successfully-logged-in.png)

## Observations
- Wazuh provides centralized visibility into system and security events
- Default rules detect authentication activity and system changes
- Dashboard offers real time monitoring and alert investigation capabilities

## Analyst Notes
- SIEM platform aggregrate and correlate logs from endpoints
- Proper installation ensures reliable event collection and detection
- This setup forms the foundation for incident detection and response testing

## Lessons Learned
- How to deploy a SIEM stack on Linux
- Importance of preparation before installation
- Basic service validation and service troubleshooting using systemctl

## Next Steps
- Complete lab 1 installation with screenshots 
- Deploy wazuh agents to endpoints
- Generate test alerts
- Perform alert triage and incident analysis
