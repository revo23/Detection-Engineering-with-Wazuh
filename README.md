# Detection-Engineering-with-Wazuh


<img width="1080" height="690" alt="image" src="https://github.com/user-attachments/assets/417aa321-b75e-4d3f-924b-96decb020096" />


**Overview**  
Wazuh is a security platform that provides unified XDR and SIEM protection for endpoints and cloud workloads. The solution is composed of a single universal agent and three central components: the Wazuh server, the Wazuh indexer, and the Wazuh dashboard.  


**High Level Concept (HLC)**

**Solution**



**Steps**

1. Download and create Ubuntu VM on VMware Workstation  

2. Install Wazuh central components on Ubuntu VM  

3. ```hostname -I``` to find host IP and log in to dashboard  

<img width="1197" height="671" alt="image" src="https://github.com/user-attachments/assets/fb86aed5-d585-4688-93e5-3a65f1435619" />  

4. Setup new agent

<img width="1637" height="777" alt="image" src="https://github.com/user-attachments/assets/43142925-93d7-4bfe-940b-4a1df184aab7" />  

5. Clone current Ubuntu serverVM for new Ubuntu agent VM (wazuh-agent and wazuh-manager cannot coexist on the same machine)  
Install and start wazuh-agent  
```wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.1-1_amd64.deb && sudo WAZUH_MANAGER='192.168.235.139' WAZUH_AGENT_NAME='linux' dpkg -i ./wazuh-agent_4.14.1-1_amd64.deb
    
    sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent```


**References**

<!-- [This text will not appear in the rendered] https://www.youtube.com/watch?v=nSOqU1iX5oQ  
https://www.youtube.com/watch?v=i68atPbB8uQ  
https://wazuh.com/blog/detecting-deerstealer-malware-with-wazuh/  README -->

https://documentation.wazuh.com/current/installation-guide/index.html  

https://documentation.wazuh.com/current/quickstart.html  
