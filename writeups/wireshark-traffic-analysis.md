# THM - Wireshark Traffic Analysis Report (SOC Level 1)

## Objective

Perform network traffic analysis using Wireshark to investigate various network protocol activities, identify potential anomalies or malicious behavior, extract key data, and apply packet inspection techniques to solve each investigative question.

## Tools Used

- **Wireshark**
- **CyberChef**
- **Web browser (for defanged IP lookup)**
- **KeysLogFile.txt (for TLS decryption)**

---
## Nmap Scans

**File Used**": `Desktop/exercise-pcaps/nmap/Exercise.pcapng`

- **What is the total number of the "TCP Connect" scans?
  `1000`
  → Filtered using `tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size <= 1024` and checked Displayed number.

- **Which scan type is used to scan the TCP port 80?**
    `TCP Connect`

- **How many "UDP close port" messages are there?**
  `1083`
  → Filtered using `icmp.type==3 and icmp.code==3` and checking Displayed number.

- **Which UDP port in the 55-70 port range is open?**
  `68`
  → Filtered using `udp.dstport >= 55 and udp.dstport <= 70`

## ARP Poisoning & Man In The Middle!

**File Used**: `Desktop/exercise-pcaps/arp/Exercise.pcapng`

- **What is the number of ARP requests crafted by the attacker?**
  `284`
  → Filtered using `arp.dst.hw_mac == 00:00:00:00:00:00 and (arp.opcode == 1 and arp.src.hw_mac == 00:0c:29:e2:18:b4)` checking Displayed packets.
  
- **What is the number of HTTP packets received by the attacker?**
  `90`
  → Filtered using `http and eth.dst == 00:0c:29:e2:18:b4` checked Displayed packets.

- **What is the number of sniffed username&password entries?**
  `6`
  → Filtered using `urlencoded-form.key == "pass"` check Displayed number.

- **What is the password of the "Client986"?**
  `clientnothere!`
  → Filtered using `http contains "client986"`

- **What is the comment provided by the "Client354"?**
  `Nice work!`
  → Filter using `http contains "client354"` under HTML Form URL Encoded section in details look for "comment".
  
## DHCP, NetBIOS, and Kerberos Analysis

**File Used**: `Desktop/exercise-pcaps/dhcp-netbios-kerberos/dhcp-netbios.pcap`

- **What is the MAC address of the host "Galaxy A30"?**  
  `9a:81:41:cb:96:6c`  
  → Filtered using `dhcp.name.hostname contains "A30"` and checked Ethernet source MAC in the details pane.

- **How many NetBIOS registration requests does the "LIVALJM" workstation have?**  
  `16`  
  → Used `nbns.name contains "LIVALJM"` and added `nbns.flags.opcode == "Registration"` to refine the query.

- **Which host requested the IP address "172.16.13.85"?**  
  `Galaxy-A12`  
  → Filtered with `dhcp.option.requested_ip_address == 172.16.13.85` and viewed DHCP Option 12 for the hostname.

**File Used**: `Desktop/exercise-pcaps/dhcp-netbios-kerberos/kerberos.pcap`

- **What is the IP address of the user "u5"?**  
  `10[.]1[.]12[.]2`  
  → Used `Kerberos.CNameString contains "u5"`, opened packet #19, and defanged the IP.

- **What is the hostname of the available host in the Kerberos packets?**  
  `xp1$`  
  → Filtered with `Kerberos.CNameString contains "$"` and identified the hostname ending with `$`.

---

## DNS and ICMP Tunneling Traffic

**File Used**: `Desktop/exercise-pcaps/dns-icmp/icmp-tunnel.pcap`

- **Which protocol is used in ICMP tunneling?**  
  `ssh`  
  → Used `icmp contains "SSH"` to identify protocol used in payload.

**File Used**: `Desktop/exercise-pcaps/dns-icmp/dns.pcap`

- **What is the suspicious main domain address?**  
  `dataexfil[.]com`  
  → Filtered with `dns.qry.name.len > 15 !mdns` and verified payload in the details pane.

---

## Cleartext Protocol Analysis: FTP

**File Used**: `Desktop/exercise-pcaps/ftp/ftp.pcap`

- **How many incorrect login attempts are there?**  
  `737`  
  → Used `ftp.response.code == 530`.

- **What is the size of the file accessed by the "ftp" account?**  
  `39424 bytes`  
  → Used `ftp.response.code == 213` and reviewed packets around #19770 for size confirmation.

- **What is the uploaded filename?**  
  `resume.doc`  
  → Observed from packet #19770 and surrounding TCP stream activity.

- **What command was used to change permissions of the uploaded file?**  
  `chmod 777`  
  → Traced through TCP stream showing the adversary’s intent to change file permissions.

---

## HTTP Analysis

**File Used**: `Desktop/exercise-pcaps/http/user-agent.cap`

- **How many anomalous "user-agent" types are there?**  
  `6`  
  → Filtered `http.user_agent`, added User-Agent as a column, and counted unique agents.

- **What packet has a subtle typo in the User-Agent?**  
  `52`  
  → Found "Mozlila" (instead of Mozilla).

**File Used**: `Desktop/exercise-pcaps/http/http.pcapng`

- **What is the Log4j attack packet number?**  
  `444`  
  → Filtered using `frame contains "jndi"`.

- **What is the IP contacted by the attacker (decoded from base64)?**  
  `62[.]210[.]130[.]250`  
  → Base64 decoded content from packet #444 using CyberChef.

---

## Encrypted Protocol Analysis: HTTPS

**File Used**: `Desktop/exercise-pcaps/https/Exercise.pcap`

- **What is the frame number of the "Client Hello" to accounts.google.com?**  
  `16`  
  → Filter: `tls.handshake.type == 1 and tls contains "accounts.google.com"`.

- **How many HTTP2 packets after decryption?**  
  `115`  
  → After importing the `KeysLogFile.txt` in TLS preferences, used `http2` filter.

- **What is the authority header in frame 322?**  
  `safebrowsing[.]googleapis[.]com`  
  → Navigated to frame 322 and inspected `:authority:` under HTTP2 headers.

- **What is the flag in the decrypted traffic?**  
  `FLAG{THM-PACKETMASTER}`  
  → Filtered `http contains "flag"` and found it in packet #1644.

---

## Bonus: Cleartext Credential Hunting

**File Used**: `Desktop/exercise-pcaps/bonus/Bonus-exercise.pcap`

- **What is the packet number using HTTP Basic Auth?**  
  `237`  
  → Found using `http` filter, inspected Authorization header in the details pane.

- **What is the packet with an empty password submitted?**  
  `170`  
  → Filtered with `ftp.request.command == "PASS"` and looked for a blank password.

---

## Bonus: Actionable Results with IPFirewall (ipfw) Rules

**File Used**: `Desktop/exercise-pcaps/bonus/Bonus-exercise.pcap`

- **What is the ipfw rule to deny the source IPv4 in packet 99?**  
  `add deny ip from 10.121.70.151 to any in`  
  → Tools → Firewall ACL Rules → Selected IPFirewall (ipfw) from packet #99.

- **What is the ipfw rule to allow the destination MAC in packet 231?**  
  `add allow MAC 00:d0:59:aa:af:80 any in`  
  → Same process, but unselected "Deny" and extracted the "Allow MAC" rule.

---

## Lessons Learned

- **Nmap Scans** learned to filter in WireShark for commands nmap -sT (3-way handshake) and nmap -sU (UDP scan).
- **ARP Poisoning & MITM** identified ARP spoofing activity, analyzed intercepted HTTP traffic to attacker, and extracted credentials and user-submitted data from HTTP requests.
- **Wireshark filters** are powerful when paired with an understanding of protocol structures.
- **Attention to packet details** (like opcodes, headers, payloads) is critical for accurate answers.
- **Decryption setup** using key log files opens deeper inspection layers.
- **Defanged formatting** is essential when documenting findings responsibly.
- **TCP stream inspection** offers valuable insight into session context.
- **CyberChef** simplifies decoding tasks like base64, aiding in malware analysis or C2 discovery.

