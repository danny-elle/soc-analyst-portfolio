## Trooper CTF

## Challenge

A multinational technology company has been the target of several cyber attacks in the past few months. The attackers have been successful in stealing sensitive intellectual property and causing disruptions to the company's operations. A threat advisory report about similar attacks has been shared, and as a CTI analyst, your task is to identify the Tactics, Techniques, and Procedures (TTPs) being used by the Threat group and gather as much information as possible about their identity and motive. For this task, you will utilise the OpenCTI platform as well as the MITRE ATT&CK navigator, linked to the details below. 

---

## Objective

Utilize OpenCTI and Mitre Att&ck Navigator to identify the tactics, techniquesm and procedures (TTPs) used by this malicious threat actor and find out who they are and their motive.


---

## Tools & Techniques

  **OPenCTI**
  **MITRE ATT&CK Navigator**


--

## Analysis


  **Q1. What kind of phishing campaign does APT X use as part of their TTPs?**
        Using the APT X Report the answer is in the introduction paragraph.  
       
        **Answer: spear-phising emails**
     
  
  **Q2. What is the name of the malware used by APT X?**
        Using the APT X Report the answer lies in the second paragraph.
 
        **Answer: USBFerry**


  **Q3. What is the malware's STIX ID?**
        Using OpenCTI, navigate to 'Aresnal' to search for 'USBFerry'. Within 'Overview' under 'Basic Information' is the 'Standard STIX ID'.
        
        **Answer: malware--5d0ea014-1ce9-5d5c-bcc7-f625a07907d0**  


  **Q4. With the use of a USB, what technique did APT X use for initial access?**
        TTPs would be found in MITRE ATT&CK Navigator. View the 'initial access' column to find the technique used.
        
        **Answer: Replication through removable media**  


  **Q5. What is the identity of APT X?**  
        Since this is identity is more of a cyber threat intelligence topic I went to OpenCTI under 'Details' section in 'Overview' tab  to find the threat actor's identity.  
 
        **Answer: Tropic Trooper**

 
  **Q6. On OpenCTI, how many Attack Pattern techniques are associated with the APT?**
        Create a new search by searching 'Tropic Trooper' in top search bar. This is asking for the APT group which we identified as Tropic Trooper. You'll need to select the 'Instruction Set' link for 
        Tropic Trooper. Once at the 'Overview' screen select 'Knowledge' section beside 'Overview'. Next locate the 'Distribution of Relations' tile on the 'Knowledge' screen, and there is the 'Attack Pattern'         number.  
      
        **Answer: 39**
        

  **Q7. What is the name of the tool linked to the APT?**
        Select 'Tools' on right-hand side of 'Knowledge' screen.  
        
        **Answer: BITSadmin**


  **Q8. Load up the Navigator. What is the sub-technique used by the APT under Valid Accounts?**
        Go to MITRE ATT&CK Navigator. You can search 'Valid Accounts' using the magnifying glass on the toolbar. Scroll down through 'Technquies' to find the 'view' option for Valid Accounts and select it.
        It will be under 'Initial Access'; select the '||' bars next to it and there the sub-technique will be highlighted in red.  
       
        **Answer: Local Accounts**

  **Q9. Under what Tactics does the technique above fall?**
        With the search results for 'Valid Accounts' open select 'view' link,  it will bring you to MITRE ATT&CK Framework, within the right-hand side lists the Tactics.  
        
        **Answer: Initial Access, Persistence,  Defense Evasion and Privilege Escalation**

 
  **Q10. What technique is the group known for using under the tactic Collection?**
         Within MITRE ATT&CK Navigator, located 'Collection' tactic column, highlighted in red is the technique.  
        
        **Answer: Automated Collection**


