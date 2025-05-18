# THM - Anti Reverse Engineering Report


## Objective


This write-up covers common anti-debugging, anti-VM, and anti-reverse engineering techniques encountered during malware analysis. It includes insights gathered using a range of tools to detect and counter these techniques.


## Tools Used

  -**Ida Pro**  
  -**x64dbg**  
  -**Detect It Easy (DIE)**  
  -**Task Manager**    
  -**PeStudio**      
  -**Base64 decoding script (Python)**   

---  
## Questions and Analysis


## Anti-Reverse Engineering


  - **What is the name of the Windows API function used in common anti-debugging technique that detects if a debugger is running?**    
    `IsDebuggerPresent`  


## Anti-Debugging Using SuspendThread


  - **What is the Windows API function that enumerates windows on the screen so the malware can check the window name?**    
    `EnumWindows`  


  - **What is the hex value of a nop instruction?**  
    `90`


  - **What is the instruction found at memory location 004011CB?**  
    `add esp, 8`
     
    ![antiReverseEng_004011CB](https://github.com/user-attachments/assets/4cbb7c82-626b-4db4-bf0d-e304b10a0471)  



##  VM Detection


   - **What is the name of the identifiable process used by malware to check if the machine is running inside VirtualBox?**  
     `vboxservice`  


   - **What is the OUI automatically assigned specifically to VMware?**  
     `00:50:56`  
     -> Google search VMware OUI  


   - **Using Task Manager, what process indicates that the machine for this room is an Amazon EC2 Virtual Machine?**  
     `amazon-ssm-agent.exe`  
     -> Open Task Manger on machine and look at the 'Background Process' section.  


## VM Detection By Checking The Temperature


   - **In the C code snippet, what is the full WQL query used to get the temperature from the Win32_TemperatureProbe class?**  
     `SELECT * FROM MSAcpi_ThermalZoneTemperature`  


   - **What register holds the memory address that tells the debugger what instruction to execute next?**  
     `EIP`  
     -> The instruction pointer register (EIP for 32 bit machines, RIP for 64 bit machines) is used in holding the present instruction that is currently being executed or decoded by the CPU.  


   - **Before uReturn is compared to zero, what is the memory location pointed to by [ebp-4]**  
     `0019ff1c`  
     -> Right-click [ebp-4] "follow dump" and dump the first memory address.  


## Packer  


   - **What is the decoded string of the base64 encoded string "VGhpcyBpcyBhIEJBU0U2NCBlbmNvZGVkIHN0cmluZy4="?**  
     `This is a base64 encoded string.`  
     -> I created the python script:  
        
       import base64  

       Base64 string   
       base64Str = "VGhpcyBpcyBhIEJBU0U2NCBlbmNvZGVkIHN0cmluZy4="  

       Decode  
       decoded_bytes = base64.b64decode(base64Str)  
       decoded_string = decoded_bytes.decode('utf-8')  

       print("Decoded String:", decoded_string)  

       On command line run: python3 filename.py  


     - **According to DetectItEasy, what is the version of the Microsoft Linker used for linking packed.exe?**  
       `14.16`

      ![ReverseEng_PackerDIE](https://github.com/user-attachments/assets/987369b2-da2f-487c-b14b-3e85c324622f)  


     - **According to pestudio, what is the entropy of the UPX2 section of packed.exe?**  
       `2.006`  

       ![antiReverseEng_EntropyPEStudio](https://github.com/user-attachments/assets/46e4e048-fa51-4f58-aa5f-427b96cdf9c4)  



## Lessons Learned

### Anti-Debugging Techniques


     - **SuspendThread** can halt threads involved in reverse engineering. It’s useful for malware to freeze analyzers like x64dbg.  
     - **Patching with NOPs** is an essential technique to bypass such checks.  

### VM Detection Techniques


     - Malware often checks for VM tools like `vmtoolsd.exe` or `vboxservice.exe` to determine if it’s running in a sandbox.  
     - It may scan the registry path `SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall` to detect installed analysis tools.  
     - MAC addresses like `00:50:56`, `00:0C:29`, `00:1C:14` are often associated with VMware.  
     - Malware may inspect **Organizationally Unique Identifiers (OUIs)** in MAC addresses to identify virtual environments.  
     - Malware uses **WMI queries** like `SELECT * FROM MSAcpi_ThermalZoneTemperature`.  
     - A "Not Supported" value can reveal a virtual environment.  
     

### Debugger Manipulation


     - Tools like x64dbg allow real-time memory editing, register modification (e.g., `EIP`), and patching to bypass checks or force execution paths.  


### Common Obfuscation Techniques


     - **Encoding** (Base64, XOR).  
     - **Encryption** (symmetric or asymmetric key exchange with C2 servers).  
     - **Code obfuscation** (restructured functions, renamed symbols, scattered logic).  


### Packers
   

     - Packers like **UPX** compress executables and hide real instructions until runtime.  
     - The best way to analyze packed malware is **runtime unpacking**.  



## Prevention Tips

     - **Hide analysis tools** by modifying registry entries and uninstall keys.  
     - **Change MAC addresses** to non-VM OUIs.  
     - **Patch WMI queries** or NOP instructions that expose VM or debugger presence.  
     - **Simulate a real environment** (e.g., run a printer service or enable audio) to trick malware into execution.  

