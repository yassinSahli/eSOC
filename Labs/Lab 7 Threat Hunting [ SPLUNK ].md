In this lab, you will assume the role of a SOC analyst investigating a series of security alerts triggered by a Splunk SIEM deployment. The alerts indicate a potential intrusion chain — from initial remote access, through credential theft, persistence establishment, and finally account manipulation. You will use Splunk to correlate logs, validate each alert, and piece together the attacker's actions step by step.

# Lab Environment

In this lab environment, you will have GUI access to an Ubuntu machine. Splunk will be accessible at `http://splunk.local:8000`, and the logs can be found under the `blue` index. The Alerts Dashboard will be accessible at `http://alerts.local`.

**Objective:** Analyze the alerts, validate them using Splunk, and answer the following questions:

- **Question 1:** How can you confirm that the authentication was really via WinRM?
- **Question 2:** What is the exact filename of the executable that was downloaded, and from which URL path and port was it downloaded?
- **Question 3:** What is the name of the process that accessed LSASS memory, and what GrantedAccess permission mask was used?
- **Question 4:** What is the full command line executed, and what was the output redirection used to save the stolen credentials?
- **Question 5:** What is the exact filename of the DLL?
- **Question 6:** What is the registry value name that was created/modified, and what is the full path to the DLL that was registered?
- **Question 7:** What command or tool was used to change the password?
- **Question 8:** What are the exact names of the 4 administrative accounts that were deleted?

**Note:** Each question corresponds to one unique alert in the same order as that of the alerts seen on the dashboard.

# Tools

The best tools for this lab are:

- Firefox
- Splunk


**Step 1:** Open Firefox and access the Alerts Dashboard at `http://splunk.local`.
![[Pasted image 20260506145028.png]]

**Step 2:** Access Splunk at `http://splunk.local:8000` and go to **Search & Reporting**.
Make sure you set the time range to **All time**
![[Pasted image 20260506100948.png]]

**Step 3:** Apply the following filter to list all events:

**Filter:**

```
index=blue
```

![Content Image](https://assets.ine.com/lab/learningpath/82f53d672651b190c2255e747a91240260627114c7031d9690f8e5796dc839b8.png)

Now, let's analyze the alerts one by one.

---

## Alert 1: Suspicious WinRM Remote Login Detected

**Step 4:** On the Alerts Dashboard, check the first alert.
![[Pasted image 20260506145301.png]]
The first alert is **"Suspicious WinRM Remote Login Detected"** with **MEDIUM** severity. It indicates a privileged WinRM authentication from source IP **10.0.0.56** to host **ATTACKDEFENSE** using the **Administrator** account. 

![[Pasted image 20260506145414.png]]

Scope narrowed down --> Result: 5 events only 
![[Pasted image 20260506145551.png]]

But this won't confirm anything: 

This maps to MITRE ATT&CK technique **T1021.006 (Remote Services: WinRM)**, which covers lateral movement via Windows Remote Management.

To validate this alert, we need to confirm that the authentication was indeed performed via WinRM. 

WinRM connections spawn `wsmprovhost.exe` (the WinRM host process) on the target machine, and the service communicates over port **5985** (HTTP) or **5986** (HTTPS).

**Step 5:** In Splunk, apply the following filter to search for process creation events related to `wsmprovhost.exe`:

**Filter:**

```
index=blue LogName="Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\wsmprovhost.exe"
```

![[Pasted image 20260506145833.png]]

![[Pasted image 20260506150003.png]]

This Sysmon **EventCode 1** (Process Create) filter looks for any instance of `wsmprovhost.exe` being launched. 

The presence of this process confirms that a WinRM session was established on the target host.

**Step 6:** To further confirm the network connection associated with WinRM, apply the following filter to look for network connection events around the same time:

**Filter:**

```
index=blue LogName="Microsoft-Windows-Sysmon/Operational" EventCode=3
```

This Sysmon **EventCode 3** (Network Connection) filter reveals the network connections made during the time of the alert. 

Look for connections showing destination port **5985**, which is the default WinRM HTTP port. This corroborates that the remote login was indeed performed via WinRM.
![[Pasted image 20260506150329.png]]
> **Question 1:** How can you confirm that the authentication was really via WinRM?
> 
> **Answer:** The presence of `wsmprovhost.exe` (the WinRM host process) in the Sysmon process creation logs (EventCode 1), combined with network connection logs (EventCode 3) showing communication over destination port **5985** (the default WinRM HTTP port), confirms that the authentication was performed via WinRM.

---

## Alert 2: Suspicious File Download Activity

**Step 7:** Go back to the alerts dashboard and examine the second alert.
![[Pasted image 20260506150431.png]]

The second alert is **"Suspicious File Download Activity"** with **HIGH** severity. It indicates that PowerShell was used to download a suspicious executable to `C:\Windows\Temp\`. The source IP is **10.0.0.56**. This maps to MITRE ATT&CK technique **T1105 (Ingress Tool Transfer)**, which describes adversaries transferring tools or files from a remote system into the compromised environment.

**Step 8:** In Splunk, apply the following filter to search for PowerShell script block logs that reference executables in the Temp directory:

**Filter:**

```
index=blue source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 "C:\\Windows\\Temp\\*.exe"
```

This filter targets **EventCode 4104** (PowerShell Script Block Logging), which captures the full content of PowerShell scripts and commands executed on the system. 

By filtering for references to `C:\Windows\Temp\*.exe`, we can identify the exact download command and the filename of the downloaded executable.
![[Pasted image 20260506150607.png]]

Examine the script block content in the results. You should see a PowerShell command run by Administrator (indicated by the **SID 500**) that downloads an executable file from a remote server.

> **Question 2:** What is the exact filename of the executable that was downloaded, and from which URL path and port was it downloaded?
> 
> **Answer:** The executable filename is **gotyou.exe**, and it was downloaded from **http://10.0.0.56:8000/gotyou.exe**.

---

## Alert 3: Suspicious Process Accessing LSASS Memory

**Step 9:** Go back to the alerts dashboard and examine the third alert.
![[Pasted image 20260506150828.png]]

The third alert is **"Suspicious Process Accessing LSASS Memory"** with **CRITICAL** severity. LSASS (Local Security Authority Subsystem Service) stores credentials in memory, and unauthorized access to it is a hallmark of credential dumping attacks. 

This maps to MITRE ATT&CK technique **T1003.001 (OS Credential Dumping: LSASS Memory)**.

**Step 10:** In Splunk, apply the following filter to search for events related to LSASS access by the Administrator account:

**Filter:**

```
index=blue source="WinEventLog:Microsoft-Windows-Sysmon/Operational" *lsass.exe* *Administrator*
```

This filter searches Sysmon logs for any events involving `lsass.exe` in the context of the Administrator account. Look for **EventCode 10** (Process Access) events, which log when one process accesses another. The key fields to examine are:

- **SourceImage** — the process that accessed LSASS (the attacker's tool)
- **GrantedAccess** — the permission mask used to access the process memory

Expand the event details to find the source process and the access mask.
![[Pasted image 20260506151302.png]]

> **Question 3:** What is the name of the process that accessed LSASS memory, and what GrantedAccess permission mask was used?
> 
> **Answer:** The process that accessed LSASS memory is **gotyou.exe**, and the GrantedAccess permission mask used is **0x1010**.

---

## Alert 4: Credential Dumping Keywords Detected

**Step 11:** Go back to the alerts dashboard and examine the fourth alert.
![[Pasted image 20260506151326.png]]

The fourth alert is **"Credential Dumping Keywords Detected"** with **CRITICAL** severity. The alert flagged command-line arguments matching known credential theft tools, specifically the keywords `privilege::debug` and `sekurlsa`. 

These are signature commands used by **Mimikatz**, a well-known credential dumping tool. This maps to MITRE ATT&CK technique **T1003.001 (Credential Access)**.

**Step 12:** In Splunk, apply the following filter to search for PowerShell script block logs containing the `privilege::debug` keyword:

**Filter:**

```
index=blue LogName=Microsoft-Windows-PowerShell/Operational EventCode=4104 "*privilege::debug*"
```

This filter searches PowerShell **EventCode 4104** (Script Block Logging) for any script blocks containing the string `privilege::debug`. This Mimikatz command is used to escalate to debug privileges, which is required before dumping credentials from LSASS memory.

Examine the full script block content to see the complete command line that was executed, including any output redirection.
![[Pasted image 20260506151608.png]]

> **Question 4:** What is the full command line executed, and what was the output redirection used to save the stolen credentials?
> 
> **Answer:** The full command line executed was: `.\gotyou.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > creds.txt`. The output was redirected to a file named **creds.txt** using the `>` operator.

---

## Alert 5: Unsigned DLL Written to System32

**Step 13:** Go back to the alerts dashboard and examine the fifth alert.
![[Pasted image 20260506151714.png]]

The fifth alert is **"Unsigned DLL Written to System32"** with **HIGH** severity. A suspicious unsigned DLL was created in the protected `C:\Windows\System32\` directory. 

Writing malicious DLLs to System32 is a common technique for persistence and execution flow hijacking. This maps to MITRE ATT&CK technique **T1574 (Hijack Execution Flow)**.

**Step 14:** In Splunk, apply the following filter to search for PowerShell command logs referencing DLL files in System32:

**Filter:**

```
index=blue LogName="Windows PowerShell" EventCode=800 "C:\\Windows\\System32\\*.dll"
```

This filter targets **EventCode 800** (Pipeline Execution) from the classic Windows PowerShell log source. 

By searching for references to DLL files in `C:\Windows\System32\`, we can identify which DLL was written to the protected directory and how it was placed there.

Examine the event details to find the exact filename of the DLL.

![[Pasted image 20260506151922.png]]

> **Question 5:** What is the exact filename of the DLL?
> 
> **Answer:** The exact filename of the DLL is **evil_netsh.dll**.

---

## Alert 6: Suspicious Registry Modification Detected

**Step 15:** Go back to the alerts dashboard and examine the sixth alert.
![[Pasted image 20260506152008.png]]

The sixth alert is **"Suspicious Registry Modification Detected"** with **CRITICAL** severity. A critical system registry key under `HKLM\SOFTWARE\Microsoft\NetSh` was modified, which is a known persistence technique. Adversaries can register malicious DLLs as NetSh helper DLLs, which get loaded every time `netsh.exe` is executed. This maps to MITRE ATT&CK technique **T1546.007 (Event Triggered Execution: Netsh Helper DLL)**.

**Step 16:** In Splunk, apply the following filter to search for registry modification events related to NetSh:

**Filter:**

```
index=blue LogName=Microsoft-Windows-Sysmon/Operational EventCode=13 "*NetSh*"
```

This filter targets Sysmon **EventCode 13** (Registry Value Set), which logs whenever a registry value is created or modified. By filtering for entries containing `NetSh`, we can identify the exact registry key that was modified to establish persistence.

Examine the event details to find:
- **TargetObject**: The full registry path including the value name
- **Details**: The data written to the registry value (the path to the malicious DLL)
![[Pasted image 20260506152335.png]]

> **Question 6:** What is the registry value name that was created/modified, and what is the full path to the DLL that was registered?
> 
> **Answer:** The registry value name is **evil_helper**, and the full path to the DLL that was registered is **C:\Windows\System32\evil_netsh.dll**.

---

## Alert 7: Administrator Account Password Changed

**Step 17:** Go back to the alerts dashboard and examine the seventh alert.
![[Pasted image 20260506152525.png]]

The seventh alert is **"Administrator Account Password Changed"** with **HIGH** severity. 
The built-in Administrator account password was modified outside of the normal change window. 

This is a common post-exploitation technique where attackers change passwords to maintain access or lock out legitimate administrators. This maps to MITRE ATT&CK technique **T1098 (Account Manipulation)**.

**Step 18:** In Splunk, first apply the following filter to search for password change events in the Security log:

**Filter:**

```
index=blue LogName=Security EventCode=4724
```

![[Pasted image 20260506152912.png]]

Windows Security **EventCode 4724** logs when an attempt is made to reset an account's password. This confirms that a password reset event occurred for the Administrator account.

**Step 19:** Next, apply the following filter to identify the command or tool that was used to perform the password change:

**Filter:**

```
index=blue source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 CommandLine="*Administrator*"
```

This Sysmon **EventCode 1** (Process Create) filter searches for any processes that were launched with `Administrator` in the command line. 

This helps us identify the exact command or tool that the attacker used to change the password.

Examine the **CommandLine** field in the results to see the full command that was executed.

![[Pasted image 20260506153137.png]]


> **Question 7:** What command or tool was used to change the password?
> 
> **Answer:** The attacker used the **net user** command to change the Administrator account password.

---

## Alert 8: Multiple User Accounts Deleted

**Step 20:** Go back to the alerts dashboard and examine the eighth and final alert.
![[Pasted image 20260506153207.png]]

The eighth alert is **"Multiple User Accounts Deleted"** with **MEDIUM** severity. Several user accounts were removed in quick succession by the Administrator account. This is a destructive action that maps to MITRE ATT&CK technique **T1531 (Account Access Removal)**, where adversaries delete accounts to disrupt operations and remove access for legitimate users.

**Step 21:** In Splunk, apply the following filter to search for account deletion events:

**Filter:**

```
index=blue LogName=Security EventCode=4726
```
Windows Security **EventCode 4726** logs when a user account is deleted. This filter will show all account deletion events recorded in the Security log.

4 events raised:
![[Pasted image 20260506153351.png]]

![[Pasted image 20260506153332.png]]

**Step 22:** To identify the specific accounts that were deleted, refine the search to extract account names:

**Filter:**

```
index=blue EventCode=4726 *Account Name*
```

Examine the results to find the **Target Account Name** field in each event. You should see four separate deletion events, one for each account that was removed.

![Content Image](https://assets.ine.com/lab/learningpath/a50f705fcd6c8cf38a33e6f4587159480d7982f8542b50098d57a1a7010e79ea.png)

or just by looking at the Account Name fields: 
![[Pasted image 20260506153543.png]]


> **Question 8:** What are the exact names of the 4 administrative accounts that were deleted?
> 
> **Answer:** The four administrative accounts that were deleted are: **sysadmin**, **netadmin**, **itadmin**, and **servadmin**.

---

# Conclusion

In this lab, you investigated a complete attack chain by validating 8 SOC alerts using Splunk. The attack followed this sequence:

1. **Initial Access** — The attacker authenticated via WinRM (port 5985) from IP 10.0.0.56 using the Administrator account.
2. **Tool Transfer** — A malicious executable (`gotyou.exe`) was downloaded to `C:\Windows\Temp\` via PowerShell.
3. **Credential Dumping** — The attacker used `gotyou.exe` (a Mimikatz variant) to access LSASS memory and dump credentials.
4. **Credential Theft** — The full Mimikatz command was executed with `privilege::debug` and `sekurlsa::logonpasswords`, with output saved to `creds.txt`.
5. **Persistence Setup** — A malicious DLL (`evil_netsh.dll`) was dropped into `C:\Windows\System32\`.
6. **Persistence via Registry** — The DLL was registered as a NetSh helper by creating the `evil_helper` registry value under `HKLM\SOFTWARE\Microsoft\NetSh`.
7. **Account Manipulation** — The attacker changed the Administrator password using the `net user` command.
8. **Account Removal** — Four administrative accounts (`sysadmin`, `netadmin`, `itadmin`, `servadmin`) were deleted to disrupt operations.

---