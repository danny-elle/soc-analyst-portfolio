# Information Stealer (Malware)

## Executive Summary

Kaspersky researchers disclosed a previously undocumented advanced persistent threat actor named Armored Likho, running an active cyberespionage and financially motivated credential theft campaign against government agencies and electric power operators in Russia, Kazakhstan, and Brazil. The group delivers a Python infostealer named BusySnake Stealer via spearphishing emails containing NSIS-based executable droppers or malicious LNK files, exploiting the patched Windows shortcut vulnerability CVE-2025-9491. BusySnake is built to resist detection and reverse engineering by using commercial obfuscation tooling and anti-analysis techniques. It gives the attackers persistent, interactive access to compromised systems through reverse SSH tunnels, deployable remote-access software, and a dedicated command-and-control channel. This report examines the attack chain, the stealer's capabilities, and the detection opportunities it presents for defenders.

## Threat Overview

Armored Likho gains initial access through spearphishing emails carrying either NSIS-based executable droppers or malicious Windows shortcut (LNK) files. This technique exploits a patched vulnerability in how Windows handles shortcut files, identified as CVE-2025-9491. Once executed, the infection chain deploys the campaign's primary paylod: BusySnake Stealer. It's a previously undocumented Python-based infostealer capable of harvesting browser-stored passwords and cookies, clipboard content, cyrptographic keys, messaging, and authentication data. It's also known to harvest Telegram session information from compromised hosts. The malware can establish reverse SSH tunnels or deploy remote-access software to give the attackers persistent interactive access. Furthermore, the malware supports command-and-control channel for issuing further commands. Armored Likho's broader toolkit includes Go2Tunnel tool used for remote access and network tunneling.

BusySnake employs several techniques making detection and reverse engineering difficult. Its code is obfuscated and encrypted using PyArmor Pro version 9.2.0; the malware decrypts its own bytecode only at the moment a function is called, then immediately re-encrypts it limiting the window in which the code is exposed to static analysis. It also runs in the background without opening a visible console window and uses a lock file mechanism to prevent multiple instances from running simultaneously on the same host. Analysts examining the loader components noted coding patterns and comments consistent with LLM assisted development. Utilizing LLM deployments is an emerging trend worth tracking as threat actors incorporate AI tooling into malware development.


## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 |
| Execution | User Execution: Malicious File | T1204.002 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Execution | Command and Scripting Interpreter: Visual Basic | T1059.005 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Defense Evasion | Obfuscated Files or Information: Software Packing | T1027.002 |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 |
| Credential Access | Credentials from Password Stores: Credential from Web Browswers | T1027.003 |
| Credential Access | Steal Web Session Cookie | T1539 |
| Collection | Clipboard Data | T1115 |
| Collection | Screen Capture | T1113 |
| Collection | Data from Local System | T1005 |
| Command and Control | Application Layer Protocol | T1071 |
| Command and Control | Protocol Tunneling (reverse SSH tunnel) | T1572 |
| Command and Control | Remote Access Software | T1219 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |


## Indicators of Compromise (IOCs)

The following indicators are sourced from Kaspersky's Securelist disclosure (July 2026).

### First Stage Malicious Files (MD5)

| Hash | Type |
|---|---|
|  5D5C3E483C5E544260CE98FC29FBF192 | PS1 stager |
| 7141917CBA2EEE2B4D31107FACCF3A39 | EXE stager |
| F5C6434EE5F7578FAA3BC1257E1C9226 | EXE stager |
| C019797A00FD56EDB1F468AC0A598510 | BAT stager |
| A0EC7A8E61EFF3F445A7455B3AEF9FBB | BAT stager |
| 7DB9C688C620E54E8C69B7E52A7579FB | BAT stager |
| 1096268FA2B3D454C86CF851CB782319 | EXE dropper |
| F2AB09D7E7A375A192508A5014AA2EE4 | EXE dropper |
| 0041FD1B2358CD08DBCBC28EA8FC3D20 | EXE dropper |
| 393B498F2114CABC0B29D5FCD9DC6723 | LNK |
| CF74AC018D158EA2C2CFA1B1D71D95BC | LNK |
| 2DFA1D949872C1B2F04952DD3E5F5D8F | LNK |

### BusySnake Stealer (MD5)

| Hash | Type |
|---|---|
| C7622A1EFFA27BBFEE6D6E03D6474343 | PYW BusySnake Stealer |
| 80B7700053E115D65365CE7330383320 | PYW BusySnake Stealer (new version) |
| 6B45DDB39A6E86229348DCBBA3857E7C | RAR archive with BusySnake Stealer |
| 006887732CA4A4A46A97989CF4DEEEF6 | RAR archive with BusySnake Stealer |

### C2 Domains

- winupdate[.]live
- arvax[.]xyz
- varenie[.]live
- lvl99[.]store
- onetoken[.]ink
- winupdate[.]ink
- grked[.]online
- ndrt[.]ink

### C2 IP Addresses

- 159.198.41[.]140
- 159.198.75[.]219
- 159.198.32[.]222
- 69.67.173[.]153

## Detection Oppurtunities

### Initial Access and Execution

- Alert on execution of LNK files or NSIS-packaged executables originating from email attachments or archive downloads
- Monitor for rundll32.exe spawning obfuscated commands that subsequently launch PowerShell (matches Kaspersky detection rule: shell_creation_by_rundll32)
- Flag PowerShell processes downloading and executing remote payloads (matches: suspicious_powershell_cmd_or_script_spawning)
- Detect downloads of Python interpreters (python.zip) and pip installers (get-pip.py) to user AppData directories, which is not normal end-user behavior

### Persistence

- Monitor for new scheduled tasks created via schtasks or the Schedule.Service COM object that execute VBScript (.vbs) files from AppData\WindowsHelper
- Alert on scheduled tasks set to run at high frequency (every 5 minutes) targeting scripts in non-standard directories
- Watch for VBScript files created in AppData\Roaming\WindowsHelper (run.vbs, wh_selfdelete.vbs)

### Defense Evasion

- Flag processes with a .pyw extension running without an associated console window
- Detect file-lock mechanisms on unusual paths such as AppData\Roaming\WindowsHelper\screenshots\.lock
- Alert on self-deletion behavior where a VBScript removes the executable that launched it

### Credential Access and Collection

- Monitor for non-browser processes accessing browser credential stores (Chrome Login Data, Firefox logins.json, key4.db)
- Detect calls to win32crypt.CryptUnprotectData from non-browser processes (indicates DPAPI-based credential decryption)
- Alert on unauthorized browser extensions being installed, particularly those with permissions to access cookies and that communicate with localhost (127.0.0.1:8000)
- Watch for Chrome being launched with command-line arguments that load unpacked extensions from unusual directories
- Flag access to Telegram session data directories (AppData\Roaming\Telegram Desktop\tdata) by non-Telegram processes, especially when preceded by force-termination of telegram.exe
- Monitor clipboard polling at high frequency from processes outside of known productivity applications
- Detect file system scans that filter by extension and search for 64-character hexadecimal strings (regex pattern [0-9a-fA-F]{64}), which indicates cryptographic key harvesting
- Alert on processes scanning for otpauth:// strings in files or clipboard data (2FA secret scraping)
- Watch for enumeration of cryptocurrency wallet JSON files across user directories

### Command and Control

- Flag unexpected outbound SSH connections (port 2222 in this campaign, not standard port 22) from non-administrative endpoints
- Monitor for downloads of RustDesk from GitHub by processes other than a browser or package manager
- Detect RustDesk being force-restarted and immediately followed by a screenshot capture (credential harvesting technique)
- Alert on HTTP/HTTPS requests to known C2 patterns such as /get_task?client_id= or /report_status endpoints
- Monitor for connections to domains on unusual TLDs used by this campaign (.ink, .live, .store, .online)

### Exfiltration

- Flag large JSON files being created in AppData\Roaming\WindowsHelper (chromium_passwords.json, firefox_passwords.json, all_browser_data.json, extracted_cookies.json) and subsequently deleted after transmission
- Monitor for archive creation in screenshot directories followed by outbound data transfer


## Relevant Log Sources

- Email gateway/security logs (attachment delivery, sender reputation, archive file scanning)
- Windows Security Event Logs (Event ID 4688 - process creation, Event ID 4698 - scheduled task creation)
- Sysmon logs (Event ID 1 - process creation, Evernt ID 3 - network connection, Event ID 11 - file creation, Event ID 7 - module loads)
- PowerShell script block logging (captures downloaded and executed payloads)
- Task Scheduler operational logs (Windows-TaskScheduler/Operational - captures scheduled task registration via both schtasks and COM objects)
- Browser extension audit logs (Chrome extension installs from non-web-store sources)
- Web proxy and HTTP/HTTPS logs (C2 traffic to /get_task and /report_status endpoints, GitHub repository downloads)
- Firewall and network flow logs (outbound SSH on port 2222, not just standard port 22)
- DNS query logs (resolution of C2 domains on unusual TLDs: .ink, .live, .store, .online)
- EDR and antivirus alerts

## Investigation Process

1. **Identify the delivery vector.** Search email gateway logs for archive attachments (.zip, .rar) containing executables or LNK files. Check for spearphishing themes matching known Armored Likho lures (government notices, humanitarian aid applications, psychological tests).

2. **Trace initial execution.** Review process creation logs (Windows Event ID 4688, Sysmon Event ID 1) for LNK files spawning rundll32.exe or PowerShell, or for NSIS-based executables writing to $temp directories and injecting code into child processes (pnx.exe).

3. **Check for staging activity.** Look for creation of the AppData\Roaming\WindowsHelper directory. Check for downloads of Python interpreters, get-pip.py, and archive files from GitHub repositories. Review DNS and proxy logs for connections to GitHub during the timeframe.

4. **Identify persistence mechanisms.** Enumerate scheduled tasks for entries named "WindowsHelper" or similar that execute VBScript files from AppData. Check for run.vbs and wh_selfdelete.vbs in the WindowsHelper directory.

5. **Assess credential exposure.** Determine whether browser credential databases were accessed by checking file access logs (Sysmon Event ID 11) for Login Data, logins.json, key4.db, and Cookies files. Check for the existence of chromium_passwords.json, firefox_passwords.json, or all_browser_data.json in the WindowsHelper directory — even if deleted, forensic recovery may be possible.

6. **Check for browser extension installation.** Review Chrome extension directories for unauthorized extensions with cookie-access permissions. Check for evidence of Chrome being launched with extension-loading command-line arguments.

7. **Evaluate data theft scope.** Check whether Telegram session data (tdata directory) was accessed or archived. Look for evidence of clipboard logging (KEYLOG_FILE), screenshot capture, 2FA secret scraping (2fa_secrets.txt), and cryptocurrency wallet file enumeration.

8. **Analyze C2 communications.** Review network flow and proxy logs for connections to known C2 domains and IPs (see IOC section). Look for HTTP requests matching the /get_task and /report_status endpoint patterns. Check for outbound SSH connections on port 2222.

9. **Check for lateral movement risk.** Determine whether harvested credentials were reused elsewhere in the environment. Cross-reference compromised accounts against authentication logs across other systems.

10. **Determine scope of compromise.** Check whether RustDesk was downloaded or installed on the endpoint. If present, assess whether attackers obtained interactive remote access. Review whether the newer BusySnake variant's arbitrary Python script execution capability was used by checking for additional pip installations or in-memory script execution artifacts.

## Containment and Remediation Considerations

### Immediate Containment

- Isolate the affected host from the network to sever C2 communication and any active reverse SSH tunnels (port 2222)
- Terminate any active RustDesk processes and remove the application if it was deployed by the malware
- Kill any running Python processes executing from AppData\Roaming\WindowsHelper
- Disable or remove the "WindowsHelper" scheduled task to stop the payload from re-executing every five minutes

### Credential Remediation

- Reset passwords for all accounts with credentials stored in affected browsers (Chromium-based and Firefox)
- Invalidate active session tokens and cookies for web applications accessed from the compromised host
- Revoke and regenerate any 2FA/OTP secrets that may have been scraped
- If Telegram session data was exfiltrated, terminate all active Telegram sessions from a separate trusted device
- Rotate any cryptographic keys stored on the affected system (SSH keys, API keys, wallet keys)
- Monitor for unauthorized use of harvested credentials across the environment

### Malware Removal

- Delete the AppData\Roaming\WindowsHelper directory and all contents (module.pyw, run.vbs, wh_selfdelete.vbs, inventory_state.db, screenshots, JSON output files)
- Remove the malicious scheduled task created via schtasks or the Schedule.Service COM object
- Check for and remove any unauthorized browser extensions installed by the cookie-extraction module
- Verify that the initial dropper (pnx.exe or LNK file) and any decoy documents have been removed

### Infrastructure-Level Remediation

- Block all C2 domains and IPs listed in the IOC section at the firewall and proxy level
- Block the GitHub repository URLs used for payload staging if identified
- Verify all systems are patched against ZDI-CAN-25373 (Windows shortcut display vulnerability)
- Review and tighten email gateway rules to flag or quarantine archive attachments containing executables or LNK files
- Audit scheduled tasks across other endpoints in the environment for similar naming patterns or execution paths

## Key Lessons Learned

1. **Secondary sources lose critical detail.** The Dark Reading summary omitted roughly half the TTPs, all IOCs, and several key capabilities (browser extension cookie theft, RustDesk deployment, Telegram harvesting, 2FA scraping). Always pull the primary vendor disclosure when writing a threat report — secondary coverage is a starting point, not a source of record.

2. **Patched vulnerabilities remain effective attack vectors.** The campaign exploits ZDI-CAN-25373, a known and patched shortcut vulnerability. A patch existing does not mean it has been applied across all targeted environments — patch verification should be an active, recurring process.

3. **Credential exposure from a single endpoint can be extensive.** BusySnake doesn't just grab passwords — it harvests cookies, clipboard data, 2FA secrets, Telegram sessions, and crypto wallet files from one compromised host. Incident response scoping must account for all of these credential categories, not just password resets.

4. **Persistence mechanisms are evolving to avoid detection.** The shift from calling schtasks directly to using the Schedule.Service COM object in the newer BusySnake version shows the threat actor is actively adapting to avoid command-line-based detection rules. Detection engineering should cover both methods.

5. **Non-standard ports matter.** This campaign uses SSH on port 2222, not the standard port 22. Firewall rules and detection logic that only monitor standard ports would miss the reverse tunnel entirely.

6. **AI-generated malware components complicate attribution.** Kaspersky identified LLM-generated code in the loader components, indicated by verbose comments and formatting patterns atypical of human-written malware. This blurs traditional TTP-based attribution and is an emerging trend worth tracking.

7. **Browser extensions are an undermonitored attack surface.** BusySnake installs a malicious extension to extract cookies by launching Chrome with specific command-line arguments. Organizations that do not audit browser extension installations or monitor Chrome launch parameters would miss this entirely.

8. **Validate service functionality independently from tools.** When a security tool fails against a target, the issue may be tool compatibility rather than target misconfiguration — a lesson reinforced both in this threat analysis and in hands-on lab work.


## References
- - Vijayan, Jai. "'BusySnake' Infostealer Slithers Into Critical Infrastructure Networks." *Dark Reading*, July 6, 2026. https://www.darkreading.com/cyberattacks-data-breaches/busysnake-infostealer-critical-infrastructure-networks
- Kaspersky. "Armored Likho digging a snake pit: inside the covert BusySnake Stealer campaign." *Securelist*, July 3, 2026. https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/