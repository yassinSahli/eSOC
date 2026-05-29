A system belonging to Syntrix experienced a sudden spike in inbound network traffic resembling automated attacks on a Windows service. As a SOC Level 1 analyst, you are tasked with reviewing firewall and security logs to determine the nature and cause of this activity. All findings should be documented in **TheHive** with an appropriate severity rating and escalated for further investigation as needed.

# Lab Environment

In this lab environment, you will have GUI access to two Ubuntu machines, one hosting `Splunk` and the other hosting `TheHive`. You can access `Splunk` at `http://localhost:8000`, where the logs should be visible under the `syntrix` index pattern. You can access the case management platform, `TheHive`, at `http://localhost:9000` using the following analyst credentials:

- **Username:** soc1@syntrix.com
    
- **Password:** pass123
    

**Objective:** Investigate a sudden spike in inbound network traffic and associated firewall and security logs to assess potential malicious activity, determine the cause, and document your findings in TheHive for further investigation. (Analyze the events generated in **December 2025**)

# Tools

The best tools for this lab are:

- Splunk
- TheHive

# Technical Workload

**Step 1:** On the **Splunk** tab, open Firefox and navigate to `http://localhost:8000`.
![[Pasted image 20260508143025.png]]

**Step 2:** Go to **Search & Reporting**.![[Pasted image 20260508143049.png]]

Set the time frame to "All time". Note that the events to be analyzed were generated in **December 2025**.

**Step 3:** Apply the following filter to list all events:

**Filter:**

```
index=syntrix
```
![[Pasted image 20260508144830.png]]

We see many events, but we are interested in those related to the firewall. So, let’s query for Event ID 4947 in Security logs to identify modifications to Windows Firewall rules, if any.

**Filter:**

```
index=syntrix source="WinEventLog:Security" EventCode=4947
```

![[Pasted image 20260508144901.png]]

![[Pasted image 20260508144929.png]]

We observe three firewall rule modification events on `PC02` occurring within seconds of each other. 

These related events are part of a single action in which built-in SMB inbound firewall rules were modified across all profiles. 

Specifically, the rules modified were: "File and Printer Sharing (SMB-In)" and "File Server / SMB inbound rule".

But what were these modifications, and who made them? To find out, let’s filter for Event ID 2005 in the Windows Firewall logs.

==Event ID 2005 typically indicates a "Firewall Rule Modified" event in Windows, showing that a firewall rule has been changed.

**Filter:**

```
index=syntrix source="WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" EventCode=2005
```

![[Pasted image 20260508145046.png]]

We observe some events.
![[Pasted image 20260508145202.png]]

These events can be summarized as follows:

At around 04:35 AM on PC02, the built-in Windows Firewall rules: **"File and Printer Sharing (SMB-In)"** and **"File Server Remote Management (SMB-In)"** were modified. 

The changes were made by the user identified by the SID: `S-1-5-21-3250466395-192540623-711299986-1010` via **WMI (WmiPrvSE.exe)** to **"Allow"** inbound TCP traffic.

Since WMI (WmiPrvSE.exe) was used to modify the firewall rules, it’s likely that the change was executed via a script or automation, such as PowerShell.

==WMI is a Windows component that enables software and scripts to request system information

Let's review the PowerShell logs.

**Filter:**

```
index=syntrix source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
```

![[Pasted image 20260508145533.png]]

We observe a number of events. However, the following two events reveal something interesting:
![[Pasted image 20260508145552.png]]

![[Pasted image 20260508145622.png]]

```
CMD1> Set-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" -RemoteAddress Any

CMD2> Set-NetFirewallRule -DisplayName "File Server Remote Management (SMB-In)" -RemoteAddress Any
```

Summary:

- PowerShell executed commands to update inbound SMB firewall rules:
    
    - "File Server Remote Management (SMB-In)" → Allow **any** remote address
        
    - "File and Printer Sharing (SMB-In)" → Allow **any** remote address
        
- User: S-1-5-21-3250466395-192540623-711299986-1010
    

The SMB service exposure with “Any” remote address presents a potential security risk, as it allows inbound SMB connections from any IP. 

This exposes the SMB service to the public internet. 

Normally, Windows SMB rules are restricted to local subnets or trusted networks, so a setting of ‘Any’ is unusual and potentially unsafe.

This may explain the sudden, unexpected brute-force traffic on a service (SMB). 

Let’s review the SMB logs to investigate further:
**Filter:**

```
index=syntrix source="WinEventLog:Microsoft-Windows-SMBServer/Security"  EventCode=551
```

Event ID 551 logs record failed SMB authentication attempts.
![[Pasted image 20260508145734.png]]
==552 Events

As expected, we observed **a large number of failed SMB authentication events on PC02** from **external IP addresse**s, suggesting a brute-force attack.

For the report, we need a few more details: the username of the account that modified the firewall rules, and the IP address of PC02, which was the target of the brute-force attack. 

These can be identified using the following filters:
- ==Windows Event ID 4103 relates to PowerShell Module Logging
- ==SID found earlier:S-1-5-21-3250466395-192540623-711299986-1010

**Filter:**
```
index=syntrix "S-1-5-21-3250466395-192540623-711299986-1010" EventCode=4103
```

Check the PowerShell logs to identify the user associated with the SID.
![[Pasted image 20260508150111.png]]

The user identified is `brandon`.

**Filter:**

```
index=syntrix source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
```

Review Sysmon logs to identify relevant network connection events.

![[Pasted image 20260508150300.png]]

The destination IP address, `10.0.0.101`, identifies PC02 as the victim.

**Step 4:** Now, switch to **TheHive** tab. Open Firefox and navigate to `http://localhost:9000`. Log in using the following credentials:

- **Username:** soc1@syntrix.com
- **Password:** pass123

![[Pasted image 20260508104229.png]]

Click on Create case.
![[Pasted image 20260508104253.png]]

Select the "Empty case."
![[Pasted image 20260508104308.png]]

Fill in the details.

- **Title:** Suspicious Modification of Windows Firewall Rules Leading to SMB Brute-Force Activity
    
- **Date:** Current date and time.
    
- **Severity:** `High`
    
- **TLP:** `TLP:Amber` (Indicates limited sharing; can be shared within your organization and with its clients on a need-to-know basis.)
    
- **PAP:** `PAP:AMBER` (Indicates that only passive checks are allowed. You can query third-party services (WHOIS, VirusTotal, etc.). You can set up honeypots to monitor traffic, but no direct interaction with the target.)
    
- **Tags:** `windows-firewall`, `smb`, `brute-force`, `powershell`
    
- **Description:** Security log analysis identified a series of Windows Firewall rule modifications on host PC02. Built-in SMB-related inbound firewall rules were altered to allow inbound TCP traffic from any remote address. Shortly after the firewall changes, a significant spike in failed SMB authentication attempts was observed from multiple external IP addresses, consistent with automated brute-force activity. This suggests that the firewall misconfiguration directly exposed the SMB service to the internet, enabling the observed attack traffic.
    

Skip the "Tasks" for now and click **Confirm**. Your case will be created.

![[Pasted image 20260508150340.png]]

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

![[Pasted image 20260508150354.png]]

**Step 6:** Next, go to **Observables** and click the "+" button to add a new observable.

Fill in the details.

**1. System affected due to Firewall Rule Modification**

- **Type:** `ip`
- **Value:** `10.0.0.101`
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** no (Internal victim system)
- **Has been sighted:** yes
- **Sighted at:** 01/12/2025 (04:35:35)
- **Ignore Similarity:** no
- **Tags:** `internal-ip`, `smb`, `firewall-exposure`, `victim`
- **Description:** Internal IP address associated with PC02. Firewall rules were modified to allow inbound SMB traffic from any remote address, exposing this system to external authentication attempts.

![[Pasted image 20260508150413.png]]

Next, click **"Save and add another"**.

**2. PowerShell Command Used to Modify Firewall Rules**

- **Type:** `other`
- **Value:** `Set-NetFirewallRule` (SMB inbound rules modified)
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** no (Legitimate command potentially misused)
- **Has been sighted:** yes (observed in PowerShell Operational logs)
- **Sighted at:** 01/12/2025 (04:35:35)
- **Ignore Similarity:** no
- **Tags:** `powershell`, `living-off-the-land`, `firewall`
- **Description:** PowerShell commands leveraging Set-NetFirewallRule were used to alter inbound SMB firewall rule configuration. While the command itself is legitimate, its use resulted in expanded network exposure.

![[Pasted image 20260508150425.png]]

Similarly, add the other observables:

**3. User Account Associated with Firewall Rule Changes**

- **Type:** `other`
- **Value:** `brandon`
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** no (Legitimate user account; potential misuse or compromise)
- **Has been sighted:** yes (identified via PowerShell and Security logs)
- **Sighted at:** 01/12/2025 (04:35:35)
- **Ignore Similarity:** no
- **Tags:** `user-account`, `firewall-modification`, `powershell`
- **Description:** User account associated with PowerShell activity that modified inbound SMB firewall rules.

**4. Modified SMB Firewall Rules**

- **Type:** `other`
- **Value:** `File and Printer Sharing (SMB-In); File Server Remote Management (SMB-In)`
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** no (Configuration change increasing attack surface)
- **Has been sighted:** yes (Event IDs 4947 and 2005)
- **Sighted at:** 01/12/2025 (04:35:35)
- **Ignore Similarity:** no
- **Tags:** `smb`, `firewall-rule`, `misconfiguration`
- **Description:** Built-in Windows Firewall rules were modified to allow inbound SMB connections from any remote address, significantly increasing exposure to external attacks.

**5. Failed SMB Authentication Attempts**

- **Type:** `other`
- **Value:** `Event ID 551` (SMB authentication failures)
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** no (Attack activity indicator)
- **Has been sighted:** yes (observed in SMB Server Security logs)
- **Sighted at:** 01/12/2025 (04:40:35) (following firewall rule modification)
- **Ignore Similarity:** no
- **Tags:** `smb`, `brute-force`, `authentication-failure`
- **Description:** Large volume of failed SMB authentication attempts originating from external IP addresses, consistent with automated brute-force activity against the exposed SMB service.

After all observables are added, click **"Confirm"**.
![[Pasted image 20260508150439.png]]

**Step 7:** Next, go to **TTPs**. Click the **"+"** button to add TTPs.

- Set the **"Occur date"** to: 01/12/2025 (04:35:35)
- Select the following **Techniques**:
    
    - **Defense Evasion:**
        
        - T1562.004 – Impair Defenses: Disable or Modify System Firewall
        - **_Reason:_** Firewall rules were modified to allow inbound SMB connections from any remote address, weakening host-based network protections.
    - **Execution:**
        
        - T1059.001 – Command and Scripting Interpreter: PowerShell
        - **_Reason:_** PowerShell was used to modify Windows Firewall rules via Set-NetFirewallRule, indicating scripted or automated configuration changes.


After adding the TTPs, click **"Confirm"**

![[Pasted image 20260508150513.png]]

**Step 8:** Next, go to **Tasks**. Click the **"+"** button to add a task.

Fill in the task details, and assign it to an SOC 2 analyst (soc2@syntrix.com).

**Task 1 — Affected Host and User Context**

- **Title:** Context on Affected Host and Associated User Account
    
- **Description:** The host identified as PC02 (IP address 10.0.0.101) was the target of the observed inbound SMB traffic. The firewall modifications were executed under the user account brandon. Reviewing recent activity on this host and account may help establish whether the actions were intentional, misconfigured, or potentially the result of account misuse.
    

![[Pasted image 20260508150530.png]]

Next, click **"Save and add another"**.

**Task 2 — Potential Impact Assessment of Brute-force Activity**

- **Title:** Context on Potential Impact from Observed SMB Brute-force Attempts
    
- **Description:** A sustained volume of failed SMB authentication attempts was observed targeting PC02 following the firewall rule changes. While the events indicate unsuccessful logon attempts, additional review may help determine whether the activity resulted in any measurable impact, such as account compromise or service disruption.
    

After adding all the tasks, click **"Confirm"**.


Finally, escalate the case to SOC level 2 by changing the case owner to an SOC 2 analyst (soc2@syntrix.com), as shown below:

![[Pasted image 20260508150544.png]]

![[Pasted image 20260508150558.png]]

# Conclusion

The investigation of firewall and security logs revealed that inbound SMB firewall rules on PC02 were modified to allow connections from any remote address. These changes were executed via PowerShell under the user account brandon. Shortly after the rule modifications, a significant increase in failed SMB authentication attempts from external IP addresses was observed, consistent with automated brute-force activity targeting the exposed service. All relevant observables have been documented, and the case has been escalated to SOC Level 2 to further assess the intent behind the firewall changes, evaluate potential account or system impact, and determine whether additional containment or remediation actions are required.

# References

- [https://docs.strangebee.com/thehive/overview/]
- [https://www.misp-project.org/taxonomies.html]