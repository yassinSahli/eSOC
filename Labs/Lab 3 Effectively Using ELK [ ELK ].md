# Effectively Using ELK

## LAB 9

# Scenario

The organization you work for is evaluating a customized [ELK stack](https://www.elastic.co/elk-stack) as a SIEM solution to enhance its intrusion detection capabilities. The SOC manager tasked you with getting familiar with the ELK stack and its detection capabilities. He also tasked you with translating common attacker behavior into ELK searches.

**Note**: Credits to [Teymur Kheirkhabarov](https://twitter.com/HeirhabarovT) for the dataset this lab uses and some of the detection techniques covered.

# Learning Objectives

The learning objective of this lab, is to get familiar with ELK stack's architecture and detection capabilities.

# Introduction To ELK

[Elastic](https://www.elastic.co/)'s ELK is an open source stack that consists of three applications (Elasticsearch, Logstash and Kibana) working in synergy to provide users with end-to-end search and visualization capabilities to analyze and investigate log file sources in real time.

ELK's architecture, at a high level, is the following.

![Content Image](https://assets.ine.com/cybersecurity-lab-images/37b8b3a1-190c-4056-95b9-ae9de63cd8d1/image3.png)

On demanding/data-heavy environments, ELK's architecture can be reinforced by Kafka, RabbitMQ and Redis for buffering and resilience and by ngnix for security.

![Content Image](https://assets.ine.com/cybersecurity-lab-images/37b8b3a1-190c-4056-95b9-ae9de63cd8d1/image4.png)

Let's dive into all of ELK's components.

- **Elasticsearch** is a NoSQL database based on the Lucene search engine and built with RESTful APIs. It is essentially the index, store and query application of the ELK stack. It provides users with the capability to perform advanced queries and analytics operations against the log file records processed by Logstash.
    
- **Logstash** is the tool responsible for the collection, transformation and transport of log file records. The great thing about Logstash is that it can unify data from disparate sources and also normalize them. Logstash has three areas of function.
    
- **Process input** of the log file records from remote locations into a machine understandable format. Logstash can receive records through a [variety of ways](https://www.elastic.co/guide/en/logstash/current/input-plugins.html) such as reading from a flat file, reading events from a TCP socket or directly reading syslog messages. When Logstash completes processing input it proceeds to the next function.
    
- [**Transform and enrich log records**](https://www.elastic.co/guide/en/logstash/current/filter-plugins.html). Logstash provides users with numerous methods to make changes to the format (and even content) of a log record. Specifically, filter plugins exist that can perform intermediary processing on an event (most of the times based on a predefined condition). Once a log record is transformed Logstash processes it.
    
- **Send log records** to Elasticsearch by utilizing any of the [output plugins](https://www.elastic.co/guide/en/logstash/current/output-plugins.html).
    
- **Kibana** is the tool used for visualizing the Elasticsearch documents. Through Kibana users can view the data stored in Elasticsearch and perform queries against them. It also facilitates the understanding of query results through tables, charts and custom dashboards.

**Note**: **Beats** is an additional download that should be installed in every remote location for its logs to be shipped to the Logstash component.

**ELK's Search:**

As incident responders, chances are that we will spend the majority of our ELK-time inside Kibana. For this reason, we will focus on submitting searches through Kibana.

![Content Image](https://assets.ine.com/cybersecurity-lab-images/37b8b3a1-190c-4056-95b9-ae9de63cd8d1/image5.png)

- [ ] Kibana searches are usually formatted as _FieldName:SearchTerm_. Fields and search terms are case sensitive.
    
- [ ] Boolean operators like AND, OR are supported (and are sometimes implied).
    
- [ ] Wildcards and free text searches can be used, but use sparingly.
    

In this lab's context, we will focus on basic Kibana operations and searches that will help you to better organize and analyze what ELK has ingested.

# Recommended tools

- ELK
    
- Use a Firefox browser to connect to Kibana [**http://demo.ine.local:5601**](http://demo.ine.local:5601/)


# Tasks

## Task 1: Add any fields you see fit to enhance your understanding of the data

Once you connect to Kibana you will notice that you are presented with a documents table that consists of two columns only. Add any fields you consider helpful so that you gain a better understanding of the events gathered.

## Task 2: Create an actionable visualization

Experiment with Kibana's visualizations. First, identify all users included in the dataset and then try to create a visualization that will enable you to quickly identify suspicious or anomalous behavior. Choose any behavior you want to detect.... (for which you have data of course).

## Task 3: Create a search to identify files that are named like system processes

It is a known fact that attackers try to blend in by naming their malware like legitimate Windows processes. Create an ELK search to identify this behavior.

**Hint**: Obviously such files will not reside where their legitimate counterparts are located, but elsewhere.

## Task 4: Create a search to identify suspicious services interacting with an executable from the Windows folder

The addition of a new service is something worth analyzing. Attackers oftentimes leverage Windows services for both exploitation and persistence purposes.

It is not uncommon to see attacker-derived services interacting with an executable from the Windows folder. Create an ELK search to identify this behavior.

**Hint**: Identify Windows Security Log Event IDs and Windows Event IDs related to service creation. Check the following too. [https://github.com/palantir/windows-event-forwarding/tree/master/AutorunsToWinEventLog](https://github.com/palantir/windows-event-forwarding/tree/master/AutorunsToWinEventLog)

## Task 5: Create a search to identify suspicious code injection

Attackers are known for performing code injection against running processes for exploitation or evasion purposes. Create an ELK search to identify this behavior, leveraging the available data.

**Hint**: Carefully go through the following resource (especially the detection part) [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/). Combine what you read in the aforementioned resource with one related Sysmon Event ID.

## Task 6: Create a search to identify possible privilege escalation via weak service permissions

It is not uncommon in Windows environments to see services running with SYSTEM privileges. It is also not uncommon to see such services having lax permissions. Specifically, oftentimes untrusted groups (or users) have privileged access to a service or permissions over the folder where the binary of the service is stored.

Attackers are known to leverage such lax service permissions to escalate their privileges.

**Hints**:

1. Focus on the **sc** executable (which is related to creating, configuring and deleting Windows services) and the _start_ or _sdshow_ options (used when an attacker wants more granular details about a service's permissions)
    
2. To launch their own executable (with higher privileges) attackers will have to tamper with another **sc** option. Try to think which option is that...
    

## Task 7: Create a search to identify possible Windows session hijacking

By design, a privileged Windows user who can perform command execution with SYSTEM-level privileges can hijack any currently logged in user's RDP session, without being prompted to enter his/her credentials. This behavior and its root cause are described in the following resource [http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html](http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html).

Create a search to identify possible Windows session hijacking through the behavior described above.

**Hint**: The Windows executable that attackers leverage to perform the above is **tscon**.

## Task 8: Create a search to identify the whoami command being executed with System privileges

When attackers gain access to a system they usually execute commands such as _whoami_ to identify their level of access. You can leverage this attacker routine to detect intrusions.

Create a search to detect the _whoami_ command being executed with SYSTEM-level privileges.

## Task 9: Create a search to identify LSASS loading a library not signed by Microsoft

By the time a user logs in to a Windows system the Local Security Authority Subsystem Service (LSASS) process's memory is filled with user and other credentials. As you can imagine, the LSASS process is a process worth monitoring.

Create a search to identify LSASS loading a library not signed by Microsoft.

**Hint**: Sysmon contains an Event ID that can assist in monitoring the DLLs being loaded by a specific process.


# Technical Workload

## **Task 1 – Explore Data & Identify Users**

1. Connect to Kibana:
    `http://172.16.73.100:5601`
2. Change time filter → **Last 5 years**.
3
    ![[Pasted image 20251004114408.png]]
3. Run empty search → add helpful fields (`event_id`, `computer_name`).
    ![[Pasted image 20251004114450.png]]
	![[Pasted image 20251004114507.png]]

Now you can see all users in the dataset.

---

## **Task 2 – Create an actionable visualization**

To identify all users included in the dataset you can start by submitting an empty search, expanding Available Fields and then inspecting the event_data.User field. If you do you so will come across the below.
![[Pasted image 20251004120047.png]]
Do you notice that 500 records message? This is because, by default, results are limited to 500 records. You can change that by going to the Management tab and then clicking **Advanced Settings,** but let’s create a visualization instead.
![[Pasted image 20251004120137.png]]
![[Pasted image 20251004120157.png]]
![[Pasted image 20251004120219.png]]
![[Pasted image 20251004120301.png]]
![[Pasted image 20251004120320.png]]
You can save this visualization if you like by pressing Save on your upper right and specifying a name.

---

## **Task 3 – CREATE A SEARCH TO IDENTIFY FILES THAT ARE NAMED LIKE SYSTEM PROCESSES**

Malware often uses **legitimate process names** (e.g., `svchost.exe`) but runs outside `System32`.

Search:

`( event_data.Image:("*\\rundll32.exe" "*\\svchost.exe" "*\\wmiprvse.exe" "*\\wmiadap.exe" "*\\smss.exe" "*\\wininit.exe" "*\\taskhost.exe" "*\\lsass.exe" "*\\winlogon.exe" "*\\csrss.exe" "*\\services.exe" "*\\svchost.exe" "*\\lsm.exe" "*\\conhost.exe" "*\\dllhost.exe" "*\\dwm.exe" "*\\spoolsv.exe" "*\\wuauclt.exe" "*\\taskhost.exe" "*\\taskhostw.exe" "*\\fontdrvhost.exe" "*\\searchindexer.exe" "*\\searchprotocolhost.exe" "*\\searchfilterhost.exe" "*\\sihost.exe") AND event_data.Image:("*\\system32\\*" "*\\syswow64\\*" "*\\winsxs\\*") ) OR ( event_data.TargetFilename:("*\\rundll32.exe" "*\\svchost.exe" "*\\wmiprvse.exe" "*\\wmiadap.exe" "*\\smss.exe" "*\\wininit.exe" "*\\taskhost.exe" "*\\lsass.exe" "*\\winlogon.exe" "*\\csrss.exe" "*\\services.exe" "*\\svchost.exe" "*\\lsm.exe" "*\\conhost.exe" "*\\dllhost.exe" "*\\dwm.exe" "*\\spoolsv.exe" "*\\wuauclt.exe" "*\\taskhost.exe" "*\\taskhostw.exe" "*\\fontdrvhost.exe" "*\\searchindexer.exe" "*\\searchprotocolhost.exe" "*\\searchfilterhost.exe" "*\\sihost.exe") AND event_data.TargetFilename:("*\\system32\\*" "*\\syswow64\\*" "*\\winsxs\\*") )`

AND -event_data.Image is excluding the expected paths.
`event_data.TargetFilename` is used in case the file included in the event_data.Image field interacted with another file. For example, if PowerShell downloaded a file named 65536.exe you would see the below. 

event_data.Image: `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` event_data.TargetFilename: `C:\Users\PhisedUser\AppData\Local\Temp\65536.exe`

![[Pasted image 20251012121616.png]]

---

## **TASK 4: CREATE A SEARCH TO IDENTIFY SUSPICIOUS SERVICES INTERACTING WITH AN EXECUTABLE FROM THE WINDOWS FOLDER**

When it comes to suspicious service detection the Windows Security Log Event ID 4697 and the Windows Event ID 7045 events will prove useful. The same applies for Autoruns logs.

Search:

`(event_id:("4697" "7045") OR (log_name:Autoruns AND event_data.Category:Services) ) AND event_data.CommandLine.keyword:/.*%[s|S][y|Y][s|S][t|T][e|E][m|M][r|R] [o|O][o|O][t|T]%\\[^\\]*\.exe/ AND -event_data.CommandLine:(*paexe* *psexesvc* *winexesvc* *remcomsvc*)`

`event_id:("4697" "7045")` is used to identify services being installed.
`log_name:Autoruns AND event_data.Category:Services` is used to identify auto start services detected by the Autoruns MS tool. `event_data.Category:Services` is used to limit the Autorun-derived documents to those only related to services
`-event_data.CommandLine:(*paexe* *psexesvc* *winexesvc* *remcomsvc*)` excludes services that interact with expected Windows executables inside the Windows folder.

![[Pasted image 20251012122303.png]]
---

## **TASK 5: CREATE A SEARCH TO IDENTIFY SUSPICIOUS CODE INJECTION**

Sysmon contains a CreateRemoteThread event (Event ID 8) that detects when a process creates a thread in another process. Malware usually do that so that the target process can load a malicious DLL (whose path is written in the virtual address space of the target process) or a malicious portable executable.
![[Pasted image 20251012122636.png]]
Search:

`event_id:8 AND source_name:"Microsoft-Windows-Sysmon"  AND -(event_data.SourceImage:"*\\VBoxTray.exe" AND event_data.TargetImage:"*\\csrss.exe")  AND -(event_data.StartFunction:EtwpNotificationThread AND event_data.SourceImage:"*\\rundll32.exe")`

![[Pasted image 20251012122830.png]]

---

## **TASK 6: CREATE A SEARCH TO IDENTIFY POSSIBLE PRIVILEGE ESCALATION VIA WEAK SERVICE PERMISSIONS**

As mentioned in this task’s description attackers will interact with the **sc** Windows executable in order to identify if a service has weak permissions and if they have any kind of privileged access over it.

If they have enough privileges, attackers may also attempt to specify an executable of their own to be executed by the insufficiently secure service. This can be done again through the sc executable and the config option (binPath =
Search:

`event_data.Image:"*\\sc.exe"  AND (event_data.CommandLine:(*start* *sdshow*) OR  (event_data.CommandLine:*config* AND event_data.CommandLine:*binPath*))  AND event_data.IntegrityLevel:Medium`

`event_data.IntegrityLevel:Medium` ensures that we don’t get results from privileged users (such as admins) performing legitimate service tasks.

![[Pasted image 20251012123153.png]]

---

## **TASK 7: CREATE A SEARCH TO IDENTIFY POSSIBLE WINDOWS SESSION HIJACKING**

As already mentioned in this task’s description we can focus on any `tscon` invocation. More specifically, we are interested in any tscon invocation with SYSTEM-level privileges. 

A viable search to identify possible Windows session hijacking via the described attacker technique is the below.

Search:

`event_data.Image:"*\\tscon.exe" AND event_data.User:"NT AUTHORITY\\SYSTEM"`

Alternatively, you can use the following search : 
`event_data.Image:"*\\tscon.exe" AND (event_data.LogonId:0x3e7 OR event_data.SubjectLogonId:0x3e7 OR event_data.User:"NT AUTHORITY\\SYSTEM")`

![[Pasted image 20251012123814.png]]
---

## **TASK 8: CREATE A SEARCH TO IDENTIFY THE WHOAMI COMMAND BEING EXECUTED WITH SYSTEM PRIVILEGES**

It is quite trivial to create a search to detect the whoami command being executed with SYSTEM-level privileges.

Search:

`event_data.Image:"*\\whoami.exe" AND (event_data.LogonId:0x3e7 OR event_data.SubjectLogonId:0x3e7 OR event_data.User:"NT AUTHORITY\\SYSTEM")`

The LogonIds used in this and the previous tasks are usually met when SYSTEM-level access is involved.
![[Pasted image 20251012123932.png]]

---
## **TASK 9: CREATE A SEARCH TO IDENTIFY LSASS LOADING A LIBRARY NOT SIGNED BY MICROSOFT**

Sysmon’s Event ID 7: Image loaded can be used to monitor the DLLs being loaded by a specific process. Thankfully this event contains information about the library’s signature in its data (Signature entry).

Search:

`event_id:7 AND event_data.Image:"*\\lsass.exe" AND event_data.Signature:*Microsoft*`

![[Pasted image 20251012124044.png]]
## **Outcome**

By completing these tasks, analysts gain:

- Mastery of **ELK search syntax**.
    
- Ability to map attacker TTPs to log events.
    
- Practical detection rules for:
    
    - Failed logins.
        
    - Process masquerading.
        
    - Service abuse.
        
    - Code injection.
        
    - Privilege escalation.
        
    - RDP hijacking.
        
    - Credential dumping.
        

---

## **Conclusion**

ELK is a powerful SIEM stack enabling analysts to:

- Collect and normalize diverse logs.
- Detect attacker behaviors via search queries.
- Visualize activity for faster incident response.


This lab demonstrated how to **translate adversary behavior into ELK searches** aligned with MITRE ATT&CK techniques, strengthening intrusion detection capabilities.