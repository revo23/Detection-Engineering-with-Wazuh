# Detection-Engineering-with-Wazuh


<img width="1600" height="830" alt="image" src="https://github.com/user-attachments/assets/63177460-509b-49f9-9a5e-424540b7f8ae" />  


**Overview**  
Wazuh is a security platform that provides unified XDR and EDR protection for endpoints and cloud workloads. The solution is composed of a single universal agent and three central components: the Wazuh server, the Wazuh indexer, and the Wazuh dashboard.  

- Install manager and agents  
- Invoke AtomicRedTeam MITRE ATT&CK techniques and view mapped logs  
- Detecting and removing malware automatically using VirusTotal integration  
- Create custom rules for DeerStealer infostealer

**Solution**



**Steps**

1. Download and create Ubuntu VM on VMware Workstation  

2. Install Wazuh central components on Ubuntu VM  

3. ```hostname -I``` to find host IP and log in to dashboard  

<img width="1197" height="671" alt="image" src="https://github.com/user-attachments/assets/fb86aed5-d585-4688-93e5-3a65f1435619" />  

4. Setup new agent

<img width="1637" height="777" alt="image" src="https://github.com/user-attachments/assets/43142925-93d7-4bfe-940b-4a1df184aab7" />  

5. Clone current Ubuntu server VM for new Ubuntu agent VM (wazuh-agent and wazuh-manager cannot coexist on the same machine)  
Install and start wazuh-agent  
```
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.1-1_amd64.deb && sudo WAZUH_MANAGER='192.168.235.139' WAZUH_AGENT_NAME='linux' dpkg -i ./wazuh-agent_4.14.1-1_amd64.deb
    
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```
6. Check agent is running and deployed

<img width="1176" height="570" alt="image" src="https://github.com/user-attachments/assets/75d2f7e1-7146-4c72-a217-5011a0740636" />

<img width="1605" height="666" alt="image" src="https://github.com/user-attachments/assets/1d814de1-c025-4b4f-92e8-1a534ac88fd2" />  

7. Install Windows agent on PC  

<img width="1253" height="574" alt="image" src="https://github.com/user-attachments/assets/29307de1-88c4-4f72-94d6-a62636b698d0" />  

8. Verify Sysmon logs being captured (test me opening notepad)  
Sysmon provides detailed information about process creations, network connections, and changes to file creation time.  

<img width="1526" height="954" alt="image" src="https://github.com/user-attachments/assets/00d9ed13-d257-4362-ad52-4271a14a2b4f" />  

9.  Edit ```ossec.conf``` to add in new capability to get sysmon log
```
  <!-- Sysmon added as a log source -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
```

10. Server management > rules > add new rules file > create rule to detect Cipher.exe usage
Cipher.exe is a command-line tool (included with Windows 2000) that you can use to manage encrypted data by using the Encrypting File System (EFS). Some ransomware such a Vohuk use this LotL tool to encrypt victims.

<img width="1319" height="514" alt="image" src="https://github.com/user-attachments/assets/de60eb9e-2a62-4155-9743-e0a3cb867329" />

12. 


**References**

<!-- [This text will not appear in the rendered] 
https://www.youtube.com/watch?v=nSOqU1iX5oQ  
https://www.youtube.com/watch?v=i68atPbB8uQ  
  README -->

https://documentation.wazuh.com/current/installation-guide/index.html  

https://documentation.wazuh.com/current/quickstart.html  

https://github.com/redcanaryco/invoke-atomicredteam  

https://wazuh.com/blog/detecting-deerstealer-malware-with-wazuh/  

https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html  

https://support.microsoft.com/en-us/topic/cipher-exe-security-tool-for-the-encrypting-file-system-56c85edd-85cf-ac07-f2f7-ca2d35dab7e4  
