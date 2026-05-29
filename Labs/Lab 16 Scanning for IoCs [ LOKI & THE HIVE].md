An endpoint protection alert flagged a Windows workstation at Syntrix for suspicious behavior following a user report of system slowness and unexpected pop-up activity. As a SOC Level 1 analyst, you are tasked with identifying Indicators of Compromise (IOCs).

All identified IOCs must be documented in **TheHive**. Based on the findings, the incident should be assigned an appropriate severity level and escalated to SOC Level 2 for containment and remediation if confirmed malicious activity is present.

# Lab Environment

In this lab environment, you have GUI access to two machines: an Windows victim machine and an Ubuntu machine hosting **TheHive**. The case management platform, **TheHive**, can be accessed at `http://localhost:9000` using the following analyst credentials:

- **Username:** soc1@syntrix.com
- **Password:** pass123

Use the **Loki IOC Scanner** available on the Windows desktop to complete the objective.

**Objective:** Identify Indicators of Compromise (IOCs) on the Windows victim machine using the Loki IOC Scanner and document all relevant findings in TheHive. Based on the analysis, assign an appropriate severity level and escalate the case to SOC Level 2 if malicious activity is confirmed.

# Tools

The best tools for this lab are:

- Loki
- TheHive

# Technical Workload

**Step 1:** On the victim Windows machine, open PowerShell and navigate to the loki directory located on the Desktop.

Use the `--help` flag to review the available options and confirm the tool is functioning correctly.

**Commands:**

```
cd Desktop\loki
.\loki.exe --help
```

![[Pasted image 20260513163224.png]]

**Step 2:** Now, run the following command to scan all the local hard drives.

**Command:**

```
.\loki.exe --allhds
```

This may take approximately 2-3 minutes to display the results. You may stop the scan once the following output is observed:
![[Pasted image 20260513163906.png]]


Let’s review the alerts and warnings one by one.
![[Pasted image 20260513164019.png]]

**Summary:**

- A suspicious executable file (`haha.exe`) was found in **C:\ProgramData**, a location where legitimate programs rarely run from.
- The file has a very high risk score (415), indicating strong malicious indicators.
- It matches a YARA rule for **Mimikatz**, a well-known credential‑stealing and post‑exploitation tool.
- File timestamps show it was modified and accessed on December 2, 2025.
- Hashes (MD5, SHA1, SHA256) are provided for identification and threat intelligence correlation.
- Binary patterns inside the file match known Mimikatz x64 signatures.

```
MD5: 29efd64dd3c7fe1e2b022b7ad73a1ba5
SHA1: e3b6ea8c46fa831cec6f235a5cf48b38a4ae8d69
SHA256: 61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1
```

To cross‑verify, copy the MD5 hash shown in the results and check it against a threat intelligence database such as VirusTotal. On your local machine, navigate to the following URL and search using the MD5 hash:

**URL:** `https://www.virustotal.com/gui/home/search`
![[Pasted image 20260513164205.png]]

The file is confirmed to be Mimikatz, disguised as haha.exe.

Let's review the next alert.
![[Pasted image 20260513164248.png]]

**Summary:**

- A suspicious executable (`winfix.exe`) was found in the Administrator's **Startup folder**, which means it is configured to run automatically at user logon.
- The file has an elevated risk score (130), indicating notable malicious indicators.
- It matches a YARA rule for **Metasploit payloads**, commonly associated with exploitation frameworks and post‑compromise activity.
- File timestamps show it was modified and accessed on December 2, 2025.
- The filename and location strongly indicate persistence behavior, ensuring continued execution after reboots.


Since we have the MD5 hash for this file, let's check it against VirusTotal.
```
MD5: 622e51a67dbe059cc907753da1178b39
SHA1: 390462cb96105528e259cc73bea01a9956e68535
SHA256: afd2a282abcb2d3e8a9d1419fb621b2256d9a47339fd8ed5dedea730780ad6d9
```

![[Pasted image 20260513164344.png]]

No results were returned, likely because the file is either new or not widely reported yet.

Since this is a suspected Metasploit payload located in the startup folder to ensure persistence after system reboots, let’s check whether there is an active network connection associated with it.

In the loki directory, there should be a file containing the scan results. Review this file and look for any processes associated with the `winfix.exe` executable.
![[Pasted image 20260513164417.png]]

![[Pasted image 20260513164537.png]]

==Scan MESSAGE: Listening process PID: 4680 NAME: winfix.exe COMMAND: "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\winfix.exe"  IP: 0.0.0.0 PORT: 4444

A process, winfix.exe (PID 4500), located in the Administrator's Startup folder, was detected by LOKI’s ProcessScan module as **listening on IP 0.0.0.0 and port 4444.** 

This behavior is consistent with a suspected Metasploit payload, as it indicates a potentially malicious process waiting for incoming connections, typical of a bind shell.

Moving on to the next warning.
![[Pasted image 20260513164743.png]]

**Summary:**

- A registry hive file was found in **C:\Users\Public** with a random-looking filename, which is unusual for legitimate registry backups.
- The file matches a YARA rule for a **SAM hive backup**, indicating it is a copy of the Windows Security Account Manager (SAM) database.
- The SAM hive contains local user account information and password hashes, making it highly sensitive.
- The observed date is the same as the ones noted previously, i.e., December 2, 2025.
    

Proceeding to the next alert.
![[Pasted image 20260513164831.png]]

```
MD5: 7d77408e1c6d11bf5623cd777444e8b8
SHA1: c8876ec437b9600767995e18a6e64e809876e36c
SHA256: f238dc9e495fb2a94ac6ba82d27572270113194ea87251eb1d8f0b250272b882
```

**Summary:**

- A PowerShell script (`Disable.ps1`) was found directly in the **C:\Windows** directory, which is an unusual and suspicious location for scripts.
- The file has a high risk score (100) due to strong indicator matches.
- Detection flags indicate script-based activity placed in a system folder, a common technique used to evade user notice and gain elevated execution context.
- The observed date is the same as the ones noted previously, i.e., December 2, 2025.
- While no specific malware family is identified, the name “Disable.ps1” suggests it may be intended to disable security features or system protections.
    

Let's try to check it against VirusTotal.
![[Pasted image 20260513164925.png]]

Looks like it is a well known PowerShell script designed to disable various Windows security features and perform self-replication and self-destruction.

Let's document our findings in TheHive.

**Step 3:** Switch to **TheHive** tab. Open Firefox and navigate to `http://localhost:9000`. Log in using the following credentials:

- **Username:** soc1@syntrix.com
- **Password:** pass123

![[Pasted image 20260508104229.png]]

Click on Create case.
![[Pasted image 20260508104253.png]]

Select the "Empty case."
![[Pasted image 20260508104308.png]]

Fill in the details.

- **Title:** Multiple Malicious Artifacts Detected via LOKI Indicating Post-Compromise Activity
    
- **Date:** Current date and time.
    
- **Severity:** `Critical`
    
- **TLP:** `TLP:Amber` (Indicates limited sharing; can be shared within your organization and with its clients on a need-to-know basis.)
    
- **PAP:** `PAP:AMBER` (Indicates that only passive checks are allowed. You can query third-party services (WHOIS, VirusTotal, etc.). You can set up honeypots to monitor traffic, but no direct interaction with the target.)
    
- **Tags:** `mimikatz`, `persistence`, `backdoor`, `startup-folder`, `sam-hive`, `loki`
    
- **Description:** Multiple high-risk artifacts were identified on a Windows system during a host-based scan using the LOKI IOC scanner. The findings include suspicious executables located in uncommon directories, indicators associated with credential access activity, persistence mechanisms configured to survive reboots, and evidence of a process listening for incoming connections. Additional artifacts suggest sensitive system data was accessed and that security-related settings may have been targeted.
    

Skip the "Tasks" for now and click **Confirm**. Your case will be created.
![[Pasted image 20260513165039.png]]

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


![[Pasted image 20260513165055.png]]

**Step 5:** Next, go to **Observables** and click the "+" button to add a new observable.

Fill in the details.

**1. Suspicious Executable – Credential Theft Tool**

- **Type:** `filename`
- **Value:** `C:\ProgramData\haha.exe`
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** yes (matches known credential theft tooling)
- **Has been sighted:** yes
- **Sighted at:** 02/12/2025 @ 05:59:02
- **Ignore Similarity:** no
- **Tags:** `malware`, `mimikatz`, `post-compromise`
- **Description:** Executable identified in an uncommon directory with a very high risk score. Matches YARA signatures associated with Mimikatz, indicating potential post-exploitation activity.

![[Pasted image 20260513165115.png]]

Next, click **"Save and add another"**.

**2. File Hash – haha.exe (MD5)**

- **Type:** `hash`
- **Value:** `29efd64dd3c7fe1e2b022b7ad73a1ba5`
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** yes (confirmed malicious via threat intelligence)
- **Has been sighted:** yes
- **Sighted at:** 02/12/2025 @ 05:59:02
- **Ignore Similarity:** no
- **Tags:** `hash`, `mimikatz`, `malware`
- **Description:** MD5 hash associated with haha.exe. Cross-referenced with threat intelligence sources and confirmed to be linked to Mimikatz-related activity.
![[Pasted image 20260513165129.png]]


Similarly, add the other observables:

**3. Persistent Startup Executable**

- **Type:** `filename`
- **Value:** `C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\winfix.exe`
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** yes (persistence mechanism)
- **Has been sighted:** yes
- **Sighted at:** 02/12/2025 @ 05:55:31
- **Ignore Similarity:** no
- **Tags:** `persistence`, `startup-folder`, `metasploit`, `backdoor`
- **Description:** Executable located in the Administrator’s Startup folder, configured to execute automatically at logon. Matches YARA rules associated with Metasploit payloads, suggesting persistence behavior.

**4. Listening Process – winfix.exe**

- **Type:** `other`
- **Value:** `winfix.exe listening on 0.0.0.0:4444`
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** yes (backdoor-like behavior)
- **Has been sighted:** yes
- **Sighted at:** 02/12/2025 @ 05:55:31
- **Ignore Similarity:** no
- **Tags:** `backdoor`, `network-listener`, `post-exploitation`
- **Description:** Process identified by LOKI as actively listening on port 4444. This behavior is consistent with backdoor or bind shell payloads commonly used in post-compromise scenarios.

**5. Suspicious Registry Hive Copy**

- **Type:** `filename`
- **Value:** `C:\Users\Public\89852140106261f4bda5e815876583e8`
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** yes (sensitive credential data exposure)
- **Has been sighted:** yes
- **Sighted at:** 02/12/2025 @ 05:57:47
- **Ignore Similarity:** no
- **Tags:** `credential-access`, `sam-hive`, `registry`
- **Description:** Registry hive file detected in a public directory. Matches YARA rules for a SAM database copy, which contains sensitive local account credential data.

**6. Malicious PowerShell Script in System Directory**

- **Type:** `filename`
- **Value:** `C:\Windows\Disable.ps1`
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** yes (defense evasion behavior)
- **Has been sighted:** yes
- **Sighted at:** 02/12/2025 @ 06:00:33
- **Ignore Similarity:** no
- **Tags:** `powershell`, `defense-evasion`, `script`
- **Description:** PowerShell script found in a system directory with a high risk score. The script is associated with disabling security features and performing self-modifying actions, indicating malicious intent.

**7. File Hash – Disable.ps1 (MD5)**

- **Type:** `hash`
- **Value:** `7d77408e1c6d11bf5623cd777444e8b8`
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** yes (confirmed malicious via threat intelligence)
- **Has been sighted:** yes
- **Sighted at:** 02/12/2025 @ 06:00:33
- **Ignore Similarity:** no
- **Tags:** `hash`, `powershell`, `malware`
- **Description:** MD5 hash associated with Disable.ps1. Cross-referenced with threat intelligence sources and confirmed to be linked to disabling security features activity.

After all observables are added, click **"Confirm"**.
![[Pasted image 20260513165145.png]]

**Step 6:** Next, go to **TTPs**. Click the **"+"** button to add TTPs.

- Set the **"Occur date"** to: 02/12/2025 @ 05:55:31
- Select the following **Techniques**:
    
    - **Execution:**
        
        - T1059.001 – Command and Scripting Interpreter: PowerShell
        - **_Reason:_** PowerShell scripts were identified on the system, including a script placed in a system directory (Disable.ps1), indicating script-based execution activity.
    - **Persistence:**
        
        - T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
        - **_Reason:_** An executable (winfix.exe) was located in the Administrator’s Startup folder, ensuring automatic execution upon user logon and persistence across reboots.
    - **Defense Evasion:**
        
        - T1562.001 – Impair Defenses: Disable or Modify Tools
        - **_Reason:_** The PowerShell script Disable.ps1 is associated with disabling security features, consistent with attempts to weaken host-based protections and evade detection.
    - **Credential Access:**
        
        - T1003.002 – OS Credential Dumping: Security Account Manager (SAM)
        - **_Reason:_** A copy of the SAM registry hive was identified in a public directory, indicating access to stored credential material.

![[Pasted image 20260513165203.png]]

After adding the TTPs, click **"Confirm"**

![[Pasted image 20260513165221.png]]

**Step 7:** Next, go to **Tasks**. Click the **"+"** button to add a task.

Fill in the task details, and assign it to an SOC 2 analyst (soc2@syntrix.com).

**Task 1 — Initial Foothold Context**

- **Title:** Context on Potential Initial Foothold and Entry Point
    
- **Description:** Multiple post-compromise artifacts were identified on the system, including credential access tooling, persistence mechanisms, and defense-evasion scripts. Reviewing available telemetry may help determine how initial access to the system was obtained, including whether the activity originated from user execution, external exposure, or another entry vector. Clarifying the initial foothold could assist in understanding the broader attack timeline.
    
![[Pasted image 20260513165244.png]]

Next, click **"Save and add another"**.

**Task 2 — Malicious File and Script Analysis**

**Title:** Context on Identified Executables and Scripts

**Description:** Several suspicious files were identified during host-based scanning, including winfix.exe, Disable.ps1, and haha.exe. Further analysis may help determine the true nature and purpose of these artifacts. Reviewing their functionality and execution context could provide insight into the actions performed on the system.

After adding all the tasks, click **"Confirm"**.

![[Pasted image 20260513165259.png]]

Finally, escalate the case to SOC level 2 by changing the case owner to an SOC 2 analyst (soc2@syntrix.com), as shown below:

![[Pasted image 20260513165316.png]]



# Conclusion

The host-based scan conducted using the LOKI IOC scanner identified multiple high-risk artifacts on the system, indicating post-compromise activity. Findings included executables associated with credential access, files configured to persist across user logons, a process listening for incoming connections, and scripts placed in system directories that may impact security controls. The presence of a copied SAM registry hive further suggests access to sensitive credential-related data. All identified artifacts and related observables have been documented and escalated to SOC Level 2 for deeper analysis to determine the initial foothold, assess the impact of the malicious files, and evaluate the overall extent of the compromise.

# References

- [https://docs.strangebee.com/thehive/overview/]
- [https://www.misp-project.org/taxonomies.html]