As a SOC Level 1 analyst at the company **Syntrix**, you receive a report from an employee who may have clicked a link in an email with a subject similar to _'Urgent Invoice – Payment Required'_, before realizing it might be suspicious. Since no SIEM alerts were triggered, your team captured a PCAP file from the user’s workstation identified by the IP address 10.0.0.103. Your task is to perform an initial triage by analyzing the PCAP to determine whether the activity indicates a phishing attempt and to record the case in the **TheHive** platform for further investigation.

# Lab Environment

In this lab environment, you will have GUI access to an Ubuntu machine. The PCAP file for analysis, `net_capture.pcapng`, is located on the Desktop. You can access the case management platform, `TheHive`, at `http://localhost:9000` using the following analyst credentials:

- **Username:** soc1@syntrix.com
    
- **Password:** pass123
    

**Objective:** Perform initial triage of a potential phishing incident by analyzing the provided PCAP file and document the findings in the TheHive platform for further investigation.

# Tools

The best tools for this lab are:

- Wireshark
- TheHive

# Technical Workload

**Step 1:** Access the Ubuntu machine.

**Step 2:** Start Wireshark and open the `net_capture.pcapng` file located on the Desktop.
![[Pasted image 20260514090322.png]]

**Step 3:** To specifically focus on email-related traffic, we can search for SMTP, IMAP, or POP3 protocols, as phishing emails may be sent or received over these channels. Use the following Wireshark filter:

**Filter:**

```
smtp || imap || pop
```

- `||` represents the logical OR operator. It displays packets that are SMTP or IMAP or POP traffic.
![[Pasted image 20260514090454.png]]

We observe IMAP (Internet Message Access Protocol) traffic between the victim workstation (10.0.0.103) and 13.229.210.143, which appears to be a mail server. 

IMAP is a protocol used by email clients such as Apple Mail, Mozilla Thunderbird, Microsoft Outlook, etc., to retrieve and manage emails from a mail server.

**Step 4:** Right-click the first frame, then select **Follow > TCP Stream**.
![[Pasted image 20260514090657.png]]

This shows the content of an email being fetched from a mail server. The email was received by one of the Syntrix employee: `millybrown@syntrix.com`. 
![[Pasted image 20260514091317.png]]

By looking at the "Subject" field, it is clear that this is the email we are looking for as per the report. 

The "Date" field shows when the email was received. This can be considered the incident occurrence date and time (**Tuesday, November 11, 2025, at 6:24:32 AM UTC**).

**Step 5:** Let's try to gather as much evidence as possible to confirm whether it is a phishing email.
![[Pasted image 20260514091659.png]]

**1. Typosquatted Domain**

- **Sender address:** `billing@paypa1.com`
- At first glance it looks like “paypal.com,” but the attacker replaced the letter “l” with the number “1” a typosquatted domain (paypa1.com).
- The “Received:” header also show the message originated from an AWS EC2 instance (`ec2-52-221-249-45.ap-southeast-1.compute.amazonaws.com`), and probably not from PayPal’s legitimate infrastructure.
- **Conclusion:** Clear attempt to deceive the recipient.
![[Pasted image 20260514092000.png]]

**2. Suspicious Email header**

- **X-Mailer:** `sendEmail-1.56`
- "sendEmail" is a command-line email-sending utility written in perl. It’s not a professional mail client used by large companies. Attackers frequently use "sendEmail" or "PHPMailer" in phishing toolkits to distribute mass scam emails.
- **Conclusion:** Clear red flag that the email was sent using a script by an unauthorized or malicious sender.

![[Pasted image 20260514092019.png]]

**3. Urgency in Subject (with poor grammar or random capitalization)**

- **Subject:** _'Urgent invoice - PAYMENT required now!'_
- Words like “Urgent” and “required now!” are classic signs of urgency and pressure tactics used in phishing to make users act quickly.
- The random capitalization of "PAYMENT" and awkward phrasing show poor grammar and formatting typical of scams.
- **Conclusion:** The subject line creates a false sense of urgency to trick the victim into taking an action.

![Content Image](https://assets.ine.com/lab/learningpath/1309e1c3a208552cff8f71d34a12c70ebb6ef31a0cb6af4574e0042cf3b1a39d.png)

Part 1 Findings:  
![[Pasted image 20260514092034.png]]

Let's focus on the 2nd part now:
![[Pasted image 20260514092615.png]]

**4. Generic Greetings, Spelling Errors, and Odd Tone in the Body**

- **Greeting:** _'Hello Valued Customer'_ is not personalized. Legitimate emails usually address the user by their full registered name.
- **Grammar/spelling issues:**
    - “We noticed problem with your account payment.”
    - “It is very important fix fast,”
    - “...your service will be suspend imediately.
- The odd tone and spelling errors suggest the message is not from a professional corporate sender.
- **Conclusion:** Generic greeting + numerous language errors = impersonal and suspicious tone common in phishing messages.

**5. Shortened Links Starting with HTTP**

- The message contains a shortened URL: `http://bit.ly/paypal-pay-now`
- Bitly and other URL shorteners are often used by attackers to hide the true destination of a malicious link.
- Additionally, the link is not HTTPS-secured, which is highly unusual for a financial service like PayPal that always uses HTTPS for encrypted connections.
- **Conclusion:** The shortened, insecure HTTP link is a major phishing red flag.

**6. Unusual Sender Signature (Missing Official Contact Info or Using Personal Numbers)**

- Legitimate corporate emails include official branding, disclaimers, contact links, and sometimes digital signatures.
- This email ends with a generic “Billing Team” and a fake-looking personal-style phone number.
- No PayPal branding, no corporate address, no legitimate contact links.
- **Conclusion:** An unprofessional, incomplete signature, typical of phishing.

![[Pasted image 20260514092537.png]]


**7. Suspicious Attachments That Don’t Make Sense**

- **Attached file:** `Invoice_5550199.hta`
- .hta (HTML Application) files are not standard invoice formats. Legitimate invoices are typically .pdf or .docx.
- **Conclusion:** Attachment type is suspicious and may contain malicious code.

Part 2 Findings: 
![[Pasted image 20260514092629.png]]

**Step 6:** Now that we have confirmed the email to be a phishing email, let's document it in TheHive platform for further investigation.

Log in to TheHive at [http://localhost:9000] using the following credentials:

- **Username:** soc1@syntrix.com
- **Password:** pass123

![[Pasted image 20260508104229.png]]

Click on Create case.
![[Pasted image 20260508104253.png]]

Select the "Empty case."
![[Pasted image 20260508104308.png]]

Fill in the details.

- **Title:** Phishing Email Impersonating PayPal
    
- **Date:** Current date and time.
    
- **Severity:** `High`
    
- **TLP:** `TLP:Amber` (Look at the description below to understand what they mean)
    
- **PAP:** `PAP:AMBER` (Look at the description below to understand what they mean)
    
- **Tags:** `phishing`, `paypal`, `typosquatted-domain`, `malicious-attachment`, `hta`, `shortened-url`, `social-engineering`
    
- **Description:** A phishing email impersonating PayPal was identified, originating from a typosquatted domain and sent via a non-professional email utility. The message used urgency in the subject line, generic greetings, and displayed suspicious tone and errors in the email body, along with a malicious attachment disguised as an invoice. Indicators confirm a high-severity phishing attempt intended to steal credentials or deploy malware.
    

Skip the "Tasks" for now and click **Confirm**. Your case will be created.
![[Pasted image 20260514093100.png]]

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
![[Pasted image 20260514093512.png]]

**Step 8:** Next, go to **Observables** and click the "+" button to add a new observable.

Fill in the details.

**1. Typosquatted Domain**

- **Type:** `domain`
- **Value:** `paypa1.com`
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** (yes — directly indicates malicious infrastructure)
- **Has been sighted:** yes (seen in phishing email)
- **Sighted at:** 11/11/2025 (06:24:33)
- **Ignore Similarity:** no (This toogle can be turned on if you don't want to include the observable in the algorithm used to identify similar alerts and cases based on observables.)
- **Tags:** `phishing`, `typosquatted-domain`, `paypal`
- **Description:** Typosquatted domain used in phishing email pretending to be PayPal. Replaces letter “l” with number “1”. Originated from AWS EC2 host.

![[Pasted image 20260514093745.png]]

Next, click **"Save and add another"**.

**Observable A — IP**

- **Type:** `ip`
- **Value:** `52.221.249.45`
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** (yes — actionable infrastructure indicator)
- **Has been sighted:** yes
- **Sighted at:** 11/11/2025 (06:24:33)
- **Ignore Similarity:** no
- **Tags:** `phishing`, `aws`, `ec2`, `mail-source`
- **Description:** Public IP observed in "Received:" header of the phishing email. Reverse-resolves to an AWS EC2 hostname; likely temporary/attacker-controlled infrastructure used to send phishing messages.

Next, click **"Save and add another"**

**Observable B — Hostname / FQDN**

- **Type:** `hostname` or `fqdn`
- **Value:** `ec2-52-221-249-45.ap-southeast-1.compute.amazonaws.com`
- **TLP:** `TLP:Amber`
- **PAP:** `PAP:Amber`
- **Is IOC:** yes
- **Has been sighted:** yes
- **Sighted at:** 11/11/2025 (06:24:33)
- **Ignore Similarity:** no
- **Tags:** `phishing`, `aws-ec2`, `mail-source`
- **Description:** Hostname observed in "Received:" header of the phishing email. Maps to the observed IP and indicates the email originated from an EC2 instance in AWS Singapore region.

Similarly, add the other observables by referring to the following tables:

**2. Suspicious Email Header**

|Field|Value|
|---|---|
|**Type**|`other`|
|**Value**|`X-Mailer: sendEmail-1.56`|
|**TLP**|`TLP:Amber`|
|**PAP**|`PAP:Green`|
|**Is IOC**|_(optional — not a strong IOC but contextual indicator)_|
|**Has been sighted**|yes|
|**Sighted at:**|11/11/2025 (06:24:33)|
|**Ignore Similarity**|no|
|**Tags**|`email-header`, `sendemail`, `phishing`, `script-mailer`|
|**Description**|Email generated using sendEmail-1.56 CLI utility, often used in phishing campaigns to send spoofed messages.|

**3. Urgent Subject Line**

|Field|Value|
|---|---|
|**Type**|`mail-subject`|
|**Value**|`Urgent invoice - PAYMENT required now!`|
|**TLP**|`TLP:Amber`|
|**PAP**|`PAP:Green`|
|**Is IOC**|_(not directly actionable, behavioral indicator)_|
|**Has been sighted**|yes|
|**Sighted at:**|11/11/2025 (06:24:33)|
|**Ignore Similarity**|yes _(common text, avoid noise)_|
|**Tags**|`phishing`, `email-subject`, `urgency`, `social-engineering`|
|**Description**|Subject line exhibits urgency and poor grammar to trick the user into taking immediate action.|

**4. Generic Greeting and Odd Tone**

|Field|Value|
|---|---|
|**Type**|`other`|
|**Value**|`Hello Valued Customer`|
|**TLP**|`TLP:Amber`|
|**PAP**|`PAP:Green`|
|**Is IOC**|no|
|**Has been sighted**|yes|
|**Sighted at:**|11/11/2025 (06:24:33)|
|**Ignore Similarity**|yes|
|**Tags**|`phishing`, `social-engineering`, `generic-greeting`, `email-body`|
|**Description**|Generic greeting and broken grammar used instead of personalized name — common in phishing emails.|

**5. Shortened Link**

|Field|Value|
|---|---|
|**Type**|`url`|
|**Value**|`http://bit.ly/paypal-pay-now`|
|**TLP**|`TLP:Amber`|
|**PAP**|`PAP:Amber`|
|**Is IOC**|yes|
|**Has been sighted**|yes|
|**Sighted at:**|11/11/2025 (06:24:33)|
|**Ignore Similarity**|no|
|**Tags**|`phishing`, `shortened-url`, `malicious-link`, `bitly`|
|**Description**|Shortened HTTP link used to disguise malicious redirection, not HTTPS-secured. Possible phishing payload delivery.|

**6. Unusual Sender Signature**

|Field|Value|
|---|---|
|**Type**|`other`|
|**Value**|`Billing Team\nPhone: +1-212-555-0199`|
|**TLP**|`TLP:Amber`|
|**PAP**|`PAP:Green`|
|**Is IOC**|no|
|**Has been sighted**|yes|
|**Sighted at:**|11/11/2025 (06:24:33)|
|**Ignore Similarity**|no|
|**Tags**|`phishing`, `email-signature`, `social-engineering`, `fake-contact`|
|**Description**|Unprofessional email signature with fake phone number and no branding or official contact info.|

**7. Suspicious Attachment**

|Field|Value|
|---|---|
|**Type**|`filename`|
|**Value**|`Invoice_5550199.hta`|
|**TLP**|`TLP:Amber+Strict`|
|**PAP**|`PAP:Amber`|
|**Is IOC**|yes _(possibly malicious attachment)_|
|**Has been sighted**|yes|
|**Sighted at:**|11/11/2025 (06:24:33)|
|**Ignore Similarity**|no|
|**Tags**|`phishing`, `malicious-attachment`, `hta`, `script`, `invoice-scam`|
|**Description**|HTA attachment masquerading as an invoice. Potential script-based malware delivery file.|

After all observables are added, click **"Confirm"**.
![[Pasted image 20260514093824.png]]

**Step 9:** Next, go to **TTPs**. Click the **"+"** button to add TTPs.

- Set the **"Occur date"** to: 11/11/2025 (06:24:33)
- Select the following **Techniques**:
    
    - **Initial Access:**
        
        - T1566.001 – Spearphishing Attachment (the `.hta` invoice attachment)
        - T1566.002 – Spearphishing Link (the shortened HTTP link)
        - **_Justification:_** The attacker attempted to trick the victim into visiting a malicious link or opening a malicious attachment to gain an initial foothold.
    - **Execution:**
        
        - T1204.002 – User Execution: Malicious File
        - **_Justification:_** The `.hta` file is possibly designed to execute script-based payloads once opened by the user.

![[Pasted image 20260514093852.png]]

![[Pasted image 20260514093931.png]]

After adding the TTPs, click **"Confirm"**
![[Pasted image 20260514093909.png]]

**Step 10:** Next, go to **Tasks**. Click the **"+"** button to add a task.

Fill in the task details, and assign it to an SOC 2 analyst (soc2@syntrix.com).

**Task 1 — Identified IP and Hostname**

- **Title:** Context on Identified IP and Hostname
    
- **Description:** An IP address (`52.221.249.45`) and associated hostname (`ec2-52-221-249-45.ap-southeast-1.compute.amazonaws.com`) were observed in the email header, indicating possible AWS-based infrastructure used for email delivery. Preliminary review suggests non-corporate origin. Further assessment may clarify whether the infrastructure has links to known phishing or spam activity.
    
![[Pasted image 20260514093952.png]]

Next, click **"Save and add another"**

**Task 2 — Shortened Link Review**

- **Title:** Information on Reported Shortened URL
    
- **Description:** The email body includes a shortened link (`http://bit.ly/paypal-pay-now`) using an unsecured HTTP scheme. It may warrant further review to understand the redirect chain and destination domain characteristics.
    
![[Pasted image 20260514094003.png]]

Next, click **"Save and add another"**

**Task 3 — Email Attachment Overview**

- **Title:** Details on Suspicious Attachment
    
- **Description:** The email contains an attachment named `Invoice_5550199.hta`, which is not a standard invoice format. Context suggests it may have been included to trigger unwanted execution, though confirmation is pending deeper analysis.
    
![[Pasted image 20260514094018.png]]

After adding all the tasks, click **"Confirm"**.

![[Pasted image 20260514094034.png]]

Finally, escalate the case to SOC level 2 by changing the case owner to an SOC 2 analyst (soc2@syntrix.com), as shown below:

![[Pasted image 20260513165316.png]]


![[Pasted image 20260514094130.png]]

# Conclusion

The analysis confirmed that the reported email was a phishing attempt impersonating PayPal, designed to deceive recipients into clicking a fraudulent payment link or opening a malicious attachment. Header review revealed that the message originated from an instance hosted on AWS and was sent using a non-professional email utility, further supporting its illegitimacy. Multiple indicators, including a typosquatted sender domain, urgent and poorly formatted subject line, generic greeting, shortened insecure link, and a suspicious attachment, align with common phishing characteristics. The identified observables have been documented and escalated for further investigation of associated infrastructure, URLs, and file behavior.

# References

- [https://docs.strangebee.com/thehive/overview/]
- [https://www.misp-project.org/taxonomies.html]