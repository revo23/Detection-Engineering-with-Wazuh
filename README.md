# Detection-Engineering-with-Wazuh


<img width="1600" height="830" alt="image" src="https://github.com/user-attachments/assets/63177460-509b-49f9-9a5e-424540b7f8ae" />  


**Overview**  
Wazuh is a security platform that provides unified XDR and EDR protection for endpoints and cloud workloads. The solution is composed of a single universal agent and three central components: the Wazuh server, the Wazuh indexer, and the Wazuh dashboard.  

- Install manager and agents  
- Create custom rules for cipher.exe and DeerStealer infostealer  
- Invoke AtomicRedTeam MITRE ATT&CK techniques and view alerts  
- Detecting and removing malware automatically using VirusTotal integration  

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

<img width="1301" height="446" alt="image" src="https://github.com/user-attachments/assets/4e37c5b3-26ce-4ede-affc-e19df1d8429a" />

11. Run ```cipher.exe``` in Powershell, rule triggers (eventid = 10)

<img width="1186" height="489" alt="image" src="https://github.com/user-attachments/assets/1e65913e-0464-4752-8914-39cbd05d4c24" />  

<img width="718" height="515" alt="image" src="https://github.com/user-attachments/assets/0f4a38c3-524d-4a93-9678-6e07c28da9ca" />  

<img width="1329" height="510" alt="image" src="https://github.com/user-attachments/assets/1a9679d9-0a0c-4532-9a08-57688e0886ed" />  

12. Add DeerStealer custom rules to jenson.xml rules file

```
<group name="deerstealer, stealer-malware,">

<!-- Persistence detection -->
  <rule id="111200" level="12">
    <if_sid>61609</if_sid>
    <field name="win.eventdata.image" type="pcre2">\\\\(Windows|Users)\\\\.+\\\\(skotes|cmd|ActiveISO|sxqnmytm|DllHost|(?!(svchost.exe|powershell.exe))\w+).exe</field>
    <field name="win.eventdata.imageLoaded" type="pcre2">\\\\Windows\\\\SysWOW64.+(mstask|Bichromate|msvcp140|Qt5Core|Qt5Gui|Qt5Network|Qt5PrintSupport|Qt5Widgets|StarBurn|vcruntime140|msvcp140).+dll</field>
    <description>Possible DeerStealer malware detected. New scheduled task: $(win.eventdata.imageLoaded) was created by: $(win.eventdata.image).</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>

<!-- Malicious file creation -->
  <rule id="111201" level="12">
    <if_sid>61613</if_sid>
    <field name="win.eventdata.image" type="pcre2">\\\\(Windows|Users)\\\\.+\\\\(skotes|cmd|(?!(svchost.exe))\w+).exe</field>
    <field name="win.eventdata.targetFilename" type="pcre2">\\\\(Windows|Users)\\\\.+\\\\(skotes|ActiveISO|sxqnmytm|DllHost|CHROME.EXE|ELEVATION_SERVICE.EXE|SKOTES.EXE)(.job|.exe|.pf|.js)</field>
    <description>Possible DeerStealer malware activity detected. Malicious file created at $(win.eventdata.targetFilename) by $(win.eventdata.image).</description>
    <mitre>
      <id>T1059</id>
      <id>T1105</id>
    </mitre>
  </rule>


<!-- Executable dropped in Malicious location -->
  <rule id="111202" level="12">
    <if_sid>92213</if_sid>
    <field name="win.eventdata.image" type="pcre2">\\\\(Windows|Users)\\\\.+\\\\(svchost|skotes|cmd|\w+|\d+).exe</field>
    <field name="win.eventdata.targetFilename" type="pcre2">\\\\Users\\\\.+\\\\AppData\\\\Local\\\\.+(skotes|ActiveISO|sxqnmytm|DllHost)|(.job|.exe|.pf|.js)</field>
    <description>Possible DeerStealer malware activity detected. Executable file dropped in folder commonly used by malware: $(win.eventdata.targetFilename).</description>
    <mitre>
      <id>T1105</id>
      <id>T1059</id>
    </mitre>
  </rule>

<!-- Process creation -->
  <rule id="111203" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">\\\\Users\\.+\\\\AppData\\\\Local\\\\Temp\\\\.+skotes.exe</field>
    <description>Possible DeerStealer malware executable: $(win.eventdata.commandLine) was run.</description>
    <mitre>
      <id>T1543</id>
    </mitre>
  </rule>

<!-- Network connection to C2 server -->
  <rule id="111204" level="12">
    <if_sid>61605</if_sid>
    <field name="win.eventdata.image" type="pcre2">\\\\Users\\\\.+\\\\AppData\\\\Local\\\\Temp\\\\.+\\\\(skotes|\w+).exe</field>
    <field name="win.system.message" type="pcre2">Network connection detected</field>
      <field name="win.eventdata.destinationPort" type="pcre2">80</field>
    <description>Possible DeerStealer network connection to C2 server: $(win.eventdata.destinationIp) on port: $(win.eventdata.destinationPort).</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>

<!-- Registry tampering - targeting HKLM -->
  <rule id="111205" level="12">
    <if_sid>61614, 61615</if_sid>
    <field name="win.eventdata.image" type="pcre2">\\\\(Windows|Users)\\\\.+\\\\(skotes|cmd|karat|(?!(svchost.exe))\w+).exe</field>
    <field name="win.eventdata.eventType" type="pcre2">(CreateKey|SetValue)</field>
    <field name="win.eventdata.targetObject" type="pcre2">HKLM\\\\(System|SOFTWARE)\\\\(CurrentControlSet|Microsoft)\\\\(Control|Windows NT|Services)\\\\(SecurityProviders|CurrentVersion|bam)\\\\.+\\\\(skotes|ActiveISO|sxqnmytm|DllHost|msedge|chrome|cmd).exe</field>
    <description>Possible DeerStealer malware executable, $(win.eventdata.image) performed $(win.eventdata.eventType) on $(win.eventdata.targetObject).</description>
    <mitre>
      <id>T1543</id>
      <id>T1053.005</id>
    </mitre>
  </rule>

<!-- Registry tampering - targeting HKU for persistence on next logon -->
  <rule id="111206" level="12">
    <if_sid>61614, 61615, 92300</if_sid>
    <field name="win.eventdata.image" type="pcre2">\\\\(Windows|Users)\\\\.+\\\\(skotes|cmd|karat(?!(svchost.exe))).exe</field>
    <field name="win.eventdata.eventType" type="pcre2">(CreateKey|SetValue)</field>
    <field name="win.eventdata.targetObject" type="pcre2">HKU\\\\.+\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\.+exe</field>
    <description>Possible DeerStealer malware executable, $(win.eventdata.image) performed $(win.eventdata.eventType) on $(win.eventdata.targetObject).</description>
    <mitre>
      <id>T1547</id>
      <id>T1053.005</id>
    </mitre>
  </rule>

</group>
```

13. Download and execute the infostealer from Anyrun, the rule should trigger

14. Install powershell on ubuntu wazuh-manager and invoke atomic redteam, run T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow), T1003.007 (OS Credential Dumping: Proc Filesystem)  

15. Atomicredteam seen trying to pull /etc/pass and /etc/shadow, as expected and running successful sudo session, elevating privileges to root

<img width="1324" height="503" alt="image" src="https://github.com/user-attachments/assets/292c067b-5810-4501-8354-f3c346832b83" />  

16. Next, we move to do a PoC for Detecting and removing malware using VirusTotal integration  
Use the Wazuh File Integrity Monitoring (FIM) module to monitor a directory for changes and the VirusTotal API to scan the files in the directory

17. Configure Wazuh to monitor near real-time changes in the Downloads directory of the Ubuntu endpoint agent
    - Add an entry within the <syscheck> block to configure a directory to be monitored in near real-time > Downloads folder
<img width="760" height="130" alt="image" src="https://github.com/user-attachments/assets/2585653d-8be3-4877-ba9d-c0f694c7bc29" />
    - Install jq (a utility that processes JSON input )
    - Create /var/ossec/active-response/bin/remove-threat.sh script
    - restart wazuh-agent

```
#!/bin/bash

LOCAL=`dirname $0`;
cd $LOCAL
cd ../

PWD=`pwd`

read INPUT_JSON
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.virustotal.source.file)
COMMAND=$(echo $INPUT_JSON | jq -r .command)
LOG_FILE="${PWD}/../logs/active-responses.log"

#------------------------ Analyze command -------------------------#
if [ ${COMMAND} = "add" ]
then
 # Send control message to execd
 printf '{"version":1,"origin":{"name":"remove-threat","module":"active-response"},"command":"check_keys", "parameters":{"keys":[]}}\n'

 read RESPONSE
 COMMAND2=$(echo $RESPONSE | jq -r .command)
 if [ ${COMMAND2} != "continue" ]
 then
  echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Remove threat active response aborted" >> ${LOG_FILE}
  exit 0;
 fi
fi

# Removing file
rm -f $FILENAME
if [ $? -eq 0 ]; then
 echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Successfully removed threat" >> ${LOG_FILE}
else
 echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Error removing threat" >> ${LOG_FILE}
fi

exit 0;
``` 
18. Add rules to the /var/ossec/etc/rules/local_rules.xml file on the Wazuh server. This rule alert about changes in the Downloads directory that are detected by FIM scans:  

<img width="1221" height="678" alt="image" src="https://github.com/user-attachments/assets/874728a0-4f11-44f6-803d-063895eebc10" />  

19. Add the following configuration to the Wazuh server /var/ossec/etc/ossec.conf file to enable the Virustotal integration



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

https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html  
