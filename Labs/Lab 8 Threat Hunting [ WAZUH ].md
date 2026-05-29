Wazuh consists of several components, including:

Wazuh Manager: This is the central component of the platform, responsible for receiving and analyzing data from agents and forwarding alerts and events to the Wazuh API or a configured SIEM (Security Information and Event Management) system.

Wazuh Agents: These are lightweight software programs that are installed on hosts to monitor and protect them. Wazuh Agents can detect and report on a wide range of security events, including file changes, system anomalies, and network activity.

Wazuh API: This is a RESTful API that allows users to manage and monitor the Wazuh platform and to integrate its capabilities with other security tools and systems.

Wazuh is built on top of the Elastic Stack (formerly known as the Elastic ELK Stack), which includes Elasticsearch, Logstash, and Kibana. This stack provides a robust set of tools for data collection, analysis, and visualization and allows users to create custom dashboards and alerts based on their security needs.

# Lab Environment

In this lab environment, you will have GUI access to an Ubuntu machine running Wazuh manager. The following credentials can be used to access the Wazuh Dashboard:

```
URL: https://localhost
Username: admin
Password: aXJhivzM.iDE2m5xbip8WXy8BxH5eQ+b
```

**Objective:** Analyze the Windows security events on the Wazuh Dashboard and find the Indicators of Compromise (IOCs).

**NOTE: The date of the incident is 11th Feb 2026.**

# Technical Workload
**Step 1:** Open the lab link to access the Ubuntu machine.
**Step 2:** Open the Wazuh Dashboard and analyze the security events.

Open the Firefox web browser and visit the URL: [https://localhost.] Use the stored credentials to log in.

![[Pasted image 20260507091030.png]]

We can see in the agent summary that one agent is present (disconnected).

![[Pasted image 20260507091144.png]]

We can see it's a Windows agent. Click on it.
![[Pasted image 20260507091226.png]]

Click on "More" >> "MITRE ATT&CK."
![[Pasted image 20260507091424.png]]

Go to the "**Framework**" tab and set the start date to "11th Feb 2026" and toggle the switch to hide techniques with no alerts.
![[Pasted image 20260507092022.png]]

First, we will check the brute-force alerts.
![[Pasted image 20260507092338.png]]

We can see multiple failed logon attempts in the logs. Observe the timestamps and expand the latest event.
![[Pasted image 20260507092357.png]]

We can notice that the attacker's IP address is "3.110.33.3" and the targeted IP address is "192.168.1.120," which is the private IP address of the connected Windows agent.
![[Pasted image 20260507092510.png]]

Next, we can see that the targeted account for these failed logon attempts is the "Administrator" user, indicating that the attacker was specifically attempting to gain access to a high-privilege account.
![[Pasted image 20260507092712.png]]

Next, click on the "Pass the Hash" tab.
![[Pasted image 20260507092747.png]]

In the description, we can notice a successful remote logon detected. Expand the first log.
![[Pasted image 20260507092842.png]]

Again, we can clearly observe that the attacker’s IP address (3.110.33.3) matches the IP previously identified in the brute-force events, confirming that the same source is responsible for both activities.
![[Pasted image 20260507092916.png]]
==Same Attacker's public IP

Here as well, the targeted account is the "Administrator" user, and the log clearly confirms that the login attempt was successful.
![[Pasted image 20260507093011.png]]

We can see that the "Logon Type" is **3**, which is associated with a network logon. 
![[Pasted image 20260507093059.png]]
This indicates that the account was accessed remotely over the network (for example, via SMB or a similar remote service), rather than through an interactive local login.

Next, click on the "SMB/Windows Admin Shares" tab.
![[Pasted image 20260507093642.png]]

Expand the most recent event.

First, we observe that the attacker’s IP address matches the one identified earlier. Next, the logs reveal the targeted network share, along with the user account "Administrator", confirming the focus of the attempted access.
![[Pasted image 20260507093809.png]]
![[Pasted image 20260507093829.png]]

This confirms that the targeted service was SMB (Server Message Block), indicating that the attacker was attempting to access network file-sharing resources.
![[Pasted image 20260507093850.png]]

Next, open the "Account Manipulation" tab.
From the description, we can see that a new user account has been created. To gather more details, expand the last log entry for further analysis.
![[Pasted image 20260507094000.png]]

The logs show that the newly created account is named "evil-user", confirming that a new user was successfully added to the system.
![[Pasted image 20260507094110.png]]

We can see that the "Administrator" account was used to create this new user.
![[Pasted image 20260507094037.png]]

This indicates that the attacker attempted to establish persistence by creating a new user account.
![[Pasted image 20260507094202.png]]

We effectively examined the Windows security events using the Wazuh Dashboard and successfully identified malicious activities.

End of the Lab!

# Conclusion

In this lab, we successfully analyzed the Windows security events and were able to identify malicious activities, including brute-force attempts, successful logins by the attacker, and the creation of a malicious user account. This demonstrates how security logs can be leveraged to detect and investigate potential security breaches.

---