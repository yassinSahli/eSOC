As a SOC Level 1 analyst at Syntrix, you identify a sequence of suspicious alerts related to account creation and potential privilege escalation while reviewing events in the Wazuh dashboard. Your task is to perform an initial triage by analyzing the relevant system and authentication logs, determine the nature and severity of the activity, and document the case in TheHive for escalation to SOC Level 2.

# Lab Environment

In this lab environment, you will have GUI access to two Ubuntu machines, one hosting Wazuh and the other hosting TheHive. 
You can access Wazuh at [https://wazuh.ine.local.] The event date is "24th December 2025." 

You can access the case management platform, TheHive, at [http://localhost:9000,] using the following analyst credentials:

```
Username: soc1@syntrix.com
Password: pass123
```

**Objective:** Perform an initial triage of suspicious system and authentication alerts related to account creation and potential privilege escalation observed in the Wazuh dashboard, and document the findings in TheHive for further investigation.

# Tools

The best tools for this lab are:

- Firefox
- Wazuh
- TheHive

# Technical Workload
**Step 1:** Open the lab link to access the Ubuntu machine.
**Step 2:** Visit the Wazuh dashboard and check the events/alerts.

Open the Firefox web browser and visit the URL: [https://localhost.] Use the stored credentials to log in: 
![[Pasted image 20260507091030.png]]

View the "Agents Summary" and click on disconnected.
![[Pasted image 20260508102826.png]]

Click on the agent with ID 002.
![[Pasted image 20260508102850.png]]

Click on "More." Then go to the "MITRE ATT&CK" dashboard.
![[Pasted image 20260508102950.png]]

Go to the "Framework" and select the date timeline as "24th December 2025" and hide the techniques with no alerts.
![[Pasted image 20260508103040.png]]

First, we can notice that there's an alert for "Create Account." Open it.

Note the timestamp and check the description "New user added to the system." The new user is "eviluser," and the agent name is "ip-10-0-0-100."
![[Pasted image 20260508103203.png]]

Next, open the alert for "Remote Services."

Notice here the timestamp is after the "eviluser" account creation, and the SSH service was used by the "eviluser" from the machine IP 10.0.0.11.
![[Pasted image 20260508103545.png]]

Next, open the alert for "Sudo and Sudo Caching."
![Content Image](https://assets.ine.com/lab/learningpath/db3a59c31d9609308e3576aa1c60e2ebd4833153674628a6ed4f3903e08bf350.jpg)

Note the timestamp. Next, we can see that the "/etc/sudoers" file has been accessed.
![[Pasted image 20260508104159.png]]

We can see it was accessed by the "evil user," and a full log can also be seen.

![[Pasted image 20260508104213.png]]

Our initial investigation concludes that there was a suspicious new user (eviluser) creation on the agent "ip-10-0-0-100." Followed by the remote service access (SSH) and possible privilege escalation attempt. Now, let's document our findings in TheHive.

**Step 3:** Log in to TheHive and document the findings.

Navigate to the 2nd machine, open Firefox, and visit [http://localhost:9000.] Use the following analyst credentials:

**Credentials:**

```
Username: soc1@syntrix.com
Password: pass123
```

![[Pasted image 20260508104229.png]]

Click on Create case.
![[Pasted image 20260508104253.png]]

Select the "Empty case."
![[Pasted image 20260508104308.png]]

Now enter the details given below:

- Title: Suspicious Account Creation Followed by Privileged Access Attempt
    
- Date: Current Date
    
- Severity: HIGH (New local user created, Remote login using that account, Attempt to modify /etc/sudoers)
    
- TLP: TLP:AMBER (Internal security incident, Sensitive system-level activity, Should not be freely shared)
    
- PAP: PAP:AMBER (Active investigation, Actions must follow SOC process, No unrestricted handling)
    
- Tags: privilege-escalation, account-creation, persistence, sudo, ssh
    
- Description: Wazuh detected the creation of a new local user account eviluser on host ip-10-0-0-100. Shortly after account creation, successful SSH authentication was observed for the same account originating from internal IP 10.0.0.11. Subsequent logs indicate that the newly created user executed sudo for the first time and attempted to modify the /etc/sudoers file, suggesting a potential privilege escalation attempt. The sequence of events indicates possible unauthorized persistence and privilege escalation activity. Findings have been documented and escalated for further review.

![[Pasted image 20260508104857.png]]

**What is TLP (Traffic Light Protocol)?**

It is a standard way to classify the sensitivity of information so that recipients know how widely it can be shared.

|**TLP Level**|**Description**|
|---|---|
|**TLP:Clear**|Public information; can be shared freely.|
|**TLP:Green**|For community use; share with trusted peers and partner organizations.|
|**TLP:Amber**|Limited sharing; can be shared within your organization and with its clients on a need-to-know basis.|
|**TLP:Amber+Strict**|Even more restricted; can be shared only within your own organization.|
|**TLP:Red**|Highly sensitive; for named recipients only, no further sharing allowed.|

**What is PAP (Permissible Actions Protocol)?**

It specifies how the received information can be used.

| **PAP Level** | **Description**                                                                                                                                                               |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **PAP:CLEAR** | No restrictions. Can be used freely without operational limitations.                                                                                                          |
| **PAP:GREEN** | Active actions allowed. You can block traffic, ping the target, or actively interact with it.                                                                                 |
| **PAP:AMBER** | Passive checks allowed. You can query third-party services (WHOIS, VirusTotal, etc.). You can set up honeypots to monitor traffic, but no direct interaction with the target. |
| **PAP:RED**   | Non-detectable actions only. Only log review or offline analysis. No active scanning, blocking, or interacting.                                                               |


The case has been created.
![[Pasted image 20260508104928.png]]

Next go to the "Observables" and click on the "+" button.
![[Pasted image 20260508105001.png]]

Add the first observable:

- Type: other
    
- Value: eviluser
    
- TLP: TLP:AMBER
    
- PAP: PAP:AMBER
    
- Is IOC: Yes
    
- Has been sighted: Yes
    
- Sighted at: 2025-12-24 07:41
    
- Tags: new-account, persistence, local-user
    
- Description: Newly created local user account observed prior to remote authentication and privileged command execution.
    

![[Pasted image 20260508105149.png]]

Click on "Save and add another."
![[Pasted image 20260508105207.png]]

Next observable:

- Type: ip
    
- Value: 10.0.0.11
    
- TLP: TLP:AMBER
    
- PAP: PAP:AMBER
    
- Has been sighted: Yes
    
- Sighted at: 2025-12-24 07:59
    
- Tags: ssh, remote-access
    
- Description: Source IP used for successful SSH authentication to the newly created account.
    
![[Pasted image 20260508105323.png]]


Click on "Save and add another."

Next observable:

- Type: hostname
    
- Value: ip-10-0-0-100
    
- TLP: TLP:AMBER
    
- PAP: PAP:AMBER
    
- Has been sighted: Yes
    
- Sighted at: 2025-12-24 08:00
    
- Tags: linux, privilege-escalation
    
- Description: Target Linux host involved in account creation, SSH access, and privileged command execution.
    
![[Pasted image 20260508105451.png]]

Click on "Save and add another."

Next observable:

- Type: filename
- Value: /etc/sudoers
- TLP: TLP:AMBER
- PAP: PAP:AMBER
- Is IOC: Yes
- Has been sighted: Yes
- Sighted at: 2025-12-24 08:00
- Tags: sudo, privilege-escalation, configuration
- Description: The /etc/sudoers file was accessed via sudo by the newly created user eviluser, indicating an attempt to modify privileged configuration for potential privilege escalation.

![[Pasted image 20260508105623.png]]

Click on the "Confirm" button.

Resulting Observables: 
![[Pasted image 20260508105726.png]]

Next, go to the "Tasks" and click on the "+" button.
![[Pasted image 20260508105749.png]]

Add the following task:

- Group: default
    
- Title: Validate legitimacy of privileged access attempt
    
- Mandatory: Yes
    
- Description: Validate whether the account creation and modification attempt of /etc/sudoers was authorized. Confirm if privilege escalation was successful and assess potential impact.
    
- Assignee: SOC 2
    

![[Pasted image 20260508105845.png]]

![[Pasted image 20260508105915.png]]

Next we will go to "TTPs" and click on the "+" button.

Add the following TTPs:

- Catalog: Enterprise Attack
    
- Occur date: 2025-12-24 07:41
    
- Technique: T1136 – Create Account (New user eviluser was created.)
    
- Technique: T1078 – Valid Accounts (Successful SSH login using the newly created account.)
    
- Technique: T1021.004 – Remote Services (Remote SSH access from 10.0.0.11.)
    
- Technique: T1548.003 – Sudo and Sudo Caching (Attempt to modify /etc/sudoers using sudo.)
    

Choose "show selection" after completing the selection part: 
![[Pasted image 20260508110201.png]]
Click on the "Confirm" button.

Result: 
![[Pasted image 20260508110240.png]]

Finally, we will change the assignee to "SOC 2" as shown below:
![[Pasted image 20260508110302.png]]

![[Pasted image 20260508110325.png]]

![[Pasted image 20260508110339.png]]

![[Pasted image 20260508110407.png]]

Click on "Assign to me"
![[Pasted image 20260508110429.png]]

Now click on "Start" & then click on "View Task Details"
![[Pasted image 20260508110544.png]]

![[Pasted image 20260508110621.png]]
# Conclusion

An initial triage was conducted on a sequence of suspicious alerts related to account creation and potential privilege escalation identified in the Wazuh dashboard. Relevant system and authentication logs were analyzed to establish context and assess potential risk. All identified observables and investigation findings have been documented in TheHive, and the case has been escalated to SOC Level 2 for further analysis and validation.

# References

- [https://docs.strangebee.com/thehive/overview/]
- [https://www.misp-project.org/taxonomies.html]