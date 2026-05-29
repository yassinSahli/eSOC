As a SOC Level 1 analyst at the company Syntrix, you notice an unusual brute-force event while reviewing routine logs in the Wazuh dashboard. Your task is to perform an initial triage by analyzing the relevant brute-force logs on the Wazuh dashboard. Based on your findings, you must assign an appropriate severity classification and document the case within the TheHive platform for escalation.

# Lab Environment

In this lab environment, you will have GUI access to two Ubuntu machines, one hosting Wazuh and the other hosting TheHive. You can access Wazuh at [https://wazuh.ine.local.] The event date is "7th December 2025." You can access the case management platform, TheHive, at [http://localhost:9000,] using the following analyst credentials:

```
Username: soc1@syntrix.com
Password: pass123
```

**Additional information:** The IP address of the Syntrix administrator’s workstation is **10.0.0.11**.

**Objective:** Conduct an initial triage of unusual brute-force alerts on the Wazuh dashboard and record your findings in TheHive for further investigation.

# Tools

The best tools for this lab are:

- Firefox
- Wazuh
- TheHive


**Step 1:** Open the lab link to access the Ubuntu machine.
**Step 2:** Visit the Wazuh dashboard and check the events/alerts.

Open the Firefox web browser and visit the URL: [https://localhost.] Use the stored credentials to log in: 
![[Pasted image 20260507091030.png]]

View the "Agents Summary" and click on disconnected (we have only 1 agent).

![[Pasted image 20260507151007.png]]
Click on the agent with ID 001.
![[Pasted image 20260507151032.png]]

Click on "More."
Then go to the "MITRE ATT&CK" dashboard --> And then go to the "Framework" and select the date timeline as "7th December 2025" and hide the techniques with no alerts.
![[Pasted image 20260507151322.png]]

We can see there is an alert for "Brute Force." We'll investigate it based on the information and the objective of the lab.

Click on the "Brute Force" alert and expand it to dig in further. Firstly, we can see a description message that suggests that there was a brute force attempt, as the user missed the password multiple times.
![[Pasted image 20260507151346.png]]

The targeted IP address is 10.0.0.100, which corresponds to the agent. The source IP, 10.0.0.11, belongs to the Syntrix administrator’s workstation, as stated in the lab description. 

A closer review of the full logs shows several SSH login attempts targeting the root user originating from this workstation. 

**Since these attempts came from the administrator’s system, they are likely part of routine system maintenance activities rather than a malicious attack. **
![[Pasted image 20260507151555.png]]
==False Positive==

Scroll down to note the timestamp for this event.
![[Pasted image 20260507151653.png]]

Now that the initial triage is complete and we have determined that the brute-force alert is a **false positive**, we can document our findings in TheHive for record-keeping and any further investigation.

**Step 3:** Log in to TheHive and document the findings.

Navigate to the 2nd machine, open Firefox, and visit [http://localhost:9000.] Use the following analyst credentials:

**Credentials:**
```
Username: soc1@syntrix.com
Password: pass123
```

![[Pasted image 20260507165416.png]]

Click on Create case.
![[Pasted image 20260507152300.png]]

Select the "Empty case."

![[Pasted image 20260507165431.png]]

Now enter the details given below:

- Title: Failed SSH Brute-Force Login Attempt from Internal Admin Host (False Positive)
    
- Date: Current date and time.
    
- Severity: LOW (No compromise, Internal trusted source, Confirmed false positive)
    
- TLP: TLP:CLEAR (Internal operational alert, No sensitive intel, Safe to share within organization)
    
- PAP: PAP:CLEAR (No restrictions on handling, No containment or response actions required, Informational documentation only)
    
- Tags: brute-force, false-positive, ssh, internal-activity
    
- Description: Investigation confirmed the source IP 10.0.0.11 is a trusted internal administrative workstation. The failed login attempt was associated with legitimate system maintenance activities.
    
![[Pasted image 20260507152716.png]]
![[Pasted image 20260507152731.png]]

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


Click on the "Confirm" button.

Your case has been created.
![[Pasted image 20260507152757.png]]
Next, go to Observables and click the "+" button to add a new observable.
![[Pasted image 20260507152817.png]]

Fill in the details:

- Type: ip
- Value: 10.0.0.11
- TLP: TLP:CLEAR
- PAP: PAP:CLEAR
- Has been sighted: Yes
- Sighted at: 07/12/2025 18:13
- Tags: internal, admin-workstation, false-positive, brute-force
- Description: Source IP associated with failed authentication attempt. Validated as a trusted internal administrative workstation performing legitimate maintenance.

![[Pasted image 20260507152856.png]]

Click on the "Confirm" button.

![[Pasted image 20260507165459.png]]

Next, go to Tasks. Click the "+" button to add a task.
![[Pasted image 20260507152926.png]]

Fill in the task details, and assign it to an SOC 2 analyst (soc2@syntrix.com).

- Group: default
- Title: Cross-verify False Positive SSH Brute-Force Login Attempt from internal admin host
- Mandatory: YES
- Description: Cross-verify failed SSH authentication attempts originating from internal administrative workstation 10.0.0.11. Validate that the activity aligns with approved maintenance activity and confirm no indicators of compromise are present. If findings confirm legitimate behavior, close the case as a false positive.
- Assignee: SOC2
    
![[Pasted image 20260507152953.png]]

Click on the confirm button.
![[Pasted image 20260507153014.png]]

Finally, escalate the case to SOC level 2 by changing the case owner to an SOC 2 analyst (soc2@syntrix.com), as shown below:

![[Pasted image 20260507153051.png]]

![[Pasted image 20260507153105.png]]

# Conclusion

In this lab, "False Positive Validation: Trusted Admin Brute-Force Detection," we conducted an initial triage of a suspected brute-force alert involving a trusted administrator account. The investigation confirmed the activity to be a false positive resulting from legitimate administrative actions. All relevant observables and findings have been documented, and the case has been escalated to SOC Level 2 for deeper assessment and formal validation.

# References

- [https://docs.strangebee.com/thehive/overview/]
- [https://www.misp-project.org/taxonomies.html]