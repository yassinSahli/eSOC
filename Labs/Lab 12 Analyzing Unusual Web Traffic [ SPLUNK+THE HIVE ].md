As a SOC Level 1 analyst at the company **Syntrix**, you notice unusual web traffic while reviewing routine logs in the Splunk dashboard. The log entries indicate activity that may be suspicious and require further examination.

Your task is to perform an initial triage by analyzing the relevant web server logs, identifying and extracting the source IP address associated with the activity, and determining whether the behavior represents misuse, or potential signs of compromise. Based on your findings, you must assign an appropriate severity classification and document the case within the **TheHive** platform for escalation.

# Lab Environment

In this lab environment, you will have GUI access to two Ubuntu machines, one hosting `Splunk` and the other hosting `TheHive`. You can access `Splunk` at `http://localhost:8000`, where the logs should be visible under the `syntrix` index pattern. You can access the case management platform, `TheHive`, at `http://localhost:9000` using the following analyst credentials:

- **Username:** soc1@syntrix.com
    
- **Password:** pass123
    

**Objective:** Conduct an initial triage of unusual web traffic observed in Splunk logs to assess potential malicious activity, extract the relevant source IP information, and record your findings in TheHive for further investigation. (Analyze the events generated in **November 2025**)

# Tools

The best tools for this lab are:

- Splunk
- TheHive

# Technical Workload

**Step 1:** On the **Splunk** tab, open Firefox and navigate to `http://localhost:8000`.
![[Pasted image 20260508143025.png]]

**Step 2:** Go to **Search & Reporting**.![[Pasted image 20260508143049.png]]

Set the time frame to "All time". Note that the events to be analyzed were generated in **November 2025**.

**Step 3:** Apply the following filter to list all events:

**Filter:**

```
index=syntrix
```

![[Pasted image 20260508143210.png]]

Click on **source**.
![[Pasted image 20260508143236.png]]

We are interested in web traffic, so the log sources to review are `/var/log/apache2/access.log` and `/var/log/apache2/error.log`, as the web server appears to be Apache running on a Linux machine.

Let's first analyze ONLY the logs in `/var/log/apache2/access.log`.
![[Pasted image 20260508143344.png]]

We see a lot of GET requests to an application (syntrix.com) that appears to be legitimate web traffic.

Let's look for POST requests and see if we can find anything unusual there.

**Filter:**

```
index=syntrix source="/var/log/apache2/access.log" "POST"
```

![[Pasted image 20260508143422.png]]

We see a number of POST requests. However, upon carefully observing the latest POST request, on **Nov 26, 2025 at 06:28:34 AM**, a client at IP `13.203.202.168` sent a POST request to `/codebase/handler.php` from a page `dir.php?type=filenew`. 

The server responded successfully with a 200 OK. Since it’s a POST to `handler.php` with a referrer suggesting `filenew`, this might indicate someone submitting a form to create a new file or resource on the server. 
==Note that the web server is hosted at IP `172.31.10.177`.

Let's look for other events around this time. Make sure you apply the following filter:

**Filter:**

```
index=syntrix source="/var/log/apache2/access.log"
```

Look for events around the date & time: **Nov 26, 2025 at 06:28:34 AM**.
![[Pasted image 20260508143622.png]]

We notice that immediately after the POST request to create a new file or resource on the server, the same client makes a GET request to `/img/bingo.php?cmd=whoami`. We make the following observations:

- `bingo.php` in `/img/` is suspicious, because `/img/` should normally only hold images.
    
- The `?cmd=whoami` query is a classic web shell command to check the server user.
    
- Status 200 OK indicates the server executed the command. The `212 bytes` response likely contains the output of whoami (the server user), so the attacker confirmed the shell works.
    

**What this means:**

- The web server was probed and compromised:
    
    - Vulnerable file upload endpoint (handler.php) was exploited.
    - Malicious script (bingo.php) was uploaded.
    - Attacker confirmed control via "whoami" command.
        

Let's look at other commands the attacker might have executed. Use the following filter:

```
index=syntrix source="/var/log/apache2/access.log" "cmd"
```

![[Pasted image 20260508143752.png]]

We observe a number of other commands that were executed on the web server by the attacker to gather more information about the environment, and the varying response sizes indicate that the output of those commands was returned.

**Step 4:** Now, let's head over to TheHive to document our findings. Switch to **TheHive** tab, open Firefox and navigate to `http://localhost:9000`. Log in using the following credentials:

- **Username:** soc1@syntrix.com
- **Password:** pass123

![[Pasted image 20260508104229.png]]

Click on Create case.
![[Pasted image 20260508104253.png]]

Select the "Empty case."
![[Pasted image 20260508104308.png]]

Fill in the details.

- **Title:** Suspicious Web Activity Suggesting Web Shell Upload and Execution
    
- **Date:** Current date and time.
    
- **Severity:** `High`
    
- **TLP:** `TLP:Amber` (May be shared within the organization and with trusted partners on a need-to-know basis.)
    
- **PAP:** `PAP:AMBER` (Only passive checks are permitted—such as OSINT queries or external reputation lookups. No direct interaction with the suspected attacker infrastructure.)
    
- **Tags:** `webshell`, `file-upload-abuse`, `apache`, `command-execution`, `php`, `intrusion`
    
- **Description:** Splunk analysis of Apache logs revealed suspicious web activity involving a POST request to a file-handling endpoint, followed immediately by the execution of a script located in an unexpected directory. The accessed script accepted system commands through query parameters, and the server returned valid responses, indicating successful remote command execution. This behavior suggests the server may have been compromised through a file upload mechanism and subsequently accessed via a web shell.
    

Skip the "Tasks" for now and click **Confirm**. Your case will be created.
![[Pasted image 20260508144053.png]]

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


![[Pasted image 20260508144108.png]]

**Step 6:** Next, go to **Observables** and click the "+" button to add a new observable.

Fill in the details.

**1. Attacker IP Address**

|Field|Value|
|---|---|
|Type|`ip`|
|Value|`13.203.202.168`|
|TLP|`TLP:Amber`|
|PAP|`PAP:Amber`|
|Is IOC|Yes|
|Has been sighted|Yes (seen in Apache logs)|
|Sighted at|26/11/2025 06:28:34|
|Ignore Similarity|No|
|Tags|`webshell`, `attack-origin`, `apache-logs`, `unauthorized-post`|
|Description|External client IP that uploaded a web shell. Indicates attacker origin for the compromise.|

![[Pasted image 20260508144121.png]]

Next, click **"Save and add another"**.

**2. Victim Web Server IP**

|Field|Value|
|---|---|
|Type|`ip`|
|Value|`172.31.10.177`|
|TLP|`TLP:Amber`|
|PAP|`PAP:Amber`|
|Is IOC|No (victim asset)|
|Has been sighted|Yes|
|Sighted at|26/11/2025 06:28:34|
|Ignore Similarity|Yes|
|Tags|`victim-host`, `webserver`, `apache`|
|Description|Internal IP of the compromised Apache web server hosting syntrix.com. Observed processing malicious POST and GET requests.|
![[Pasted image 20260508144135.png]]

Similarly, add the other observables by referring to the following tables:

**3. Malicious Uploaded File (Web Shell)**

|Field|Value|
|---|---|
|Type|`filename`|
|Value|`bingo.php`|
|TLP|`TLP:Amber`|
|PAP|`PAP:Amber`|
|Is IOC|Yes|
|Has been sighted|Yes|
|Sighted at|26/11/2025 06:28:34|
|Ignore Similarity|No|
|Tags|`webshell`, `php`, `file-upload`, `apache-compromise`|
|Description|PHP-based web shell placed in the /img/ directory.|

**4. API Endpoint Used for Malicious Upload**

|Field|Value|
|---|---|
|Type|`uri_path`|
|Value|`/codebase/handler.php`|
|TLP|`TLP:Amber`|
|PAP|`PAP:Amber`|
|Is IOC|Yes|
|Has been sighted|Yes|
|Sighted at|26/11/2025 06:28:34|
|Ignore Similarity|No|
|Tags|`vulnerable-endpoint`, `file-upload`, `initial-access`|
|Description|File-handling endpoint used by attacker via POST request, likely exploited to upload the PHP web shell.|

**5. Web Shell Execution Path**

|Field|Value|
|---|---|
|Type|`uri_path`|
|Value|`/img/bingo.php?cmd=whoami`|
|TLP|`TLP:Amber`|
|PAP|`PAP:Amber`|
|Is IOC|Yes|
|Has been sighted|Yes|
|Sighted at|26/11/2025 06:28:34|
|Ignore Similarity|No|
|Tags|`webshell-execution`, `remote-command`, `apache-logs`|
|Description|Path used by attacker to execute commands on the server. The presence of cmd= parameter confirms an operational web shell.|

**6. Additional Web Shell Commands**

|Field|Value|
|---|---|
|Type|`other`|
|Value|`cmd=<various_commands>`|
|TLP|`TLP:Amber`|
|PAP|`PAP:Amber`|
|Is IOC|Yes|
|Has been sighted|Yes|
|Sighted at|26/11/2025 06:28:34|
|Ignore Similarity|No|
|Tags|`command-execution`, `webshell`, `recon`|
|Description|Multiple commands executed through the web shell, used for environmental enumeration on the compromised server.|

After all observables are added, click **"Confirm"**.
![[Pasted image 20260508144158.png]]

**Step 7:** Next, go to **TTPs**. Click the **"+"** button to add TTPs.
![[Pasted image 20260508144211.png]]

Fill in the details.

- Set the **"Occur date"** to: 26/11/2025 06:28:34
- Select the following **Techniques**:
    
    - **Initial Access**
        
        - T1190 — Exploit Public-Facing Application
        - **_Reason:_** A POST to a file-handling endpoint (/codebase/handler.php) resulted in placement of an unexpected script in the webroot — consistent with exploitation of a public-facing upload endpoint.
    - **Persistence**
        
        - T1505.003 - Server Software Component: Web Shell
        - **_Reason:_** A PHP file (bingo.php) was uploaded into /img/ (an image folder) and then invoked with ?cmd=whoami and other cmd= queries, which is the canonical observable for an implanted web shell.
    - **Command and Control**
        
        - T1071.001 - Application Layer Protocol: Web Protocols
        - **_Reason:_** The attacker interacted with the implanted shell using HTTP GET requests (e.g., /img/bingo.php?cmd=whoami), indicating use of web protocols for command execution and data return.
    - **Execution**
        
        - T1059.004 — Command and Scripting Interpreter: Unix Shell
        - **_Reason:_** The web shell accepted and executed system commands (whoami and others) on the server — behavior that maps to adversaries invoking command interpreters via a remote interface.

After adding the TTPs, click **"Confirm"**.

![[Pasted image 20260508144236.png]]

**Step 8:** Next, go to **Tasks**. Click the **"+"** button to add a task.

![[Pasted image 20260508144301.png]]

Fill in the task details, and assign it to an SOC 2 analyst (soc2@syntrix.com).

**Task 1 — Web Server Compromise Validation**

- **Title:** Context on Potential File Upload Exploitation and Web Shell Deployment
    
- **Description:** Log review indicates that a client at IP 13.203.202.168 issued a POST request to /codebase/handler.php on Nov 26, 2025, followed shortly by requests to /img/bingo.php?cmd=whoami. The sequence suggests possible exploitation of an upload endpoint followed by execution of a PHP-based web shell. Further assessment may clarify the extent of server interaction via the shell, and any resulting impact on the host.
    
Next, click **"Save and add another"**
![[Pasted image 20260508144316.png]]

Similarly, add the following tasks:

**Task 2 — External Source IP Assessment**

**Title:** Context on Activity Originating from External IP 13.203.202.168

**Description:** All observed activity involving the suspected upload and subsequent command execution originated from a single external client IP (13.203.202.168). Assessing whether this address is associated with known scanning infrastructure, prior malicious activity, or anomalous traffic patterns may help determine whether the interaction reflects targeted exploitation or broader opportunistic probing.

**Task 3 — Application Code Review for Upload Handling**

**Title:** Context on Potential Vulnerability in File Upload Functionality

**Description:** The sequence of events suggests that the file upload mechanism associated with handler.php may have been used to introduce a PHP script into a non-intended directory. Reviewing the relevant application code, particularly how file types, paths, and user input are validated, may help clarify whether a weakness in the upload logic enabled the observed behavior. This could provide insight into the root cause of the unauthorized file placement.

After adding all the tasks, click **"Confirm"**.
![[Pasted image 20260508144415.png]]

Finally, escalate the case to SOC level 2 by changing the case owner to an SOC 2 analyst (soc2@syntrix.com), as shown below:

![[Pasted image 20260508144434.png]]

![[Pasted image 20260508144509.png]]

# Conclusion

The review of Apache access logs in Splunk indicates that the web server at 172.31.10.177 was successfully exploited through its file upload functionality. A POST request from 13.203.202.168 to handler.php appears to have been used to upload a PHP web shell (bingo.php) into the /img/ directory, a location not intended to store executable files. Subsequent GET requests invoking commands such as whoami confirmed that the attacker was able to execute system commands on the server. Additional command executions suggest ongoing reconnaissance activity, consistent with early-stage post-exploitation behavior.

All relevant observables have been documented, and the case has been escalated to SOC Level 2 for a deeper assessment of the compromised host, potential lateral movement, and underlying application vulnerabilities.

# References

- [https://docs.strangebee.com/thehive/overview/]
- [https://www.misp-project.org/taxonomies.html]