This lab demonstrates how modern AI techniques can enhance traditional security monitoring by integrating a Security Information and Event Management (SIEM) platform with an LLM for intelligent threat analysis.

At the core of the lab is Wazuh, an open-source security monitoring platform used for log collection, file integrity monitoring, vulnerability detection, and compliance monitoring. Wazuh continuously generates security alerts based on activity across endpoints, servers, and network devices. These alerts contain valuable threat intelligence but often require manual analysis to extract actionable insights.

To improve efficiency, this lab integrates Wazuh with a Large Language Model (LLM). In this implementation, we use Mistral running locally via Ollama to interpret security alerts and respond in natural language.
![[Pasted image 20260514111423.png]]

By combining alert data with embeddings and similarity search techniques (a Retrieval-Augmented Generation approach), the system enables AI-assisted threat hunting. Instead of manually reviewing raw JSON logs, analysts can interact with a chatbot interface and ask questions about alerts, suspicious behaviors, or attack patterns. The LLM retrieves relevant alert context and generates clear, human-readable explanations.

---
# Lab Environment

In this lab environment, you will have GUI access to a Debian machine running Wazuh manager. The following credentials can be used to access the Wazuh Dashboard:

```
URL: https://localhost
Username: admin
Password: oA6d*?yiPOzS7Q5m?RdCY4cIkU+JJTfe
```

Additionally, you will have access to an LLM-powered chatbot that is integrated with Wazuh at **http://wazuhbot.ine.local/**. This will allow you to query and analyze security alerts in a conversational manner.

**Objective:** To explore how threat detection and analysis can be improved by combining AI with security monitoring platforms like Wazuh.

**NOTE: The date of the incident is 15th Feb 2026.**

# Technical Workload

**Step 1:** Open the lab link to access the Debian machine.

**Step 2:** Open the Wazuh Dashboard.

Open the Firefox web browser and visit the URL: [https://localhost.] Use the stored credentials to log in.

**NOTE: It may take a couple of minutes for the Wazuh dashboard to fully load. If you see a loading or initialization message, please wait 1–2 minutes and then refresh the page.**
![[Pasted image 20260515110120.png]]

We can see in the agent summary that one agent is present (disconnected).
![[Pasted image 20260515110146.png]]

Here we can observe the agent's IP address and operating system type. Click on it.
![[Pasted image 20260515110213.png]]

Click on "More" >> "MITRE ATT&CK."
![[Pasted image 20260515110242.png]]

Go to the "Events" tab and set the start date to "15th Feb 2026" and click on the "Refresh" button.
![[Pasted image 20260515110406.png]]

Here, you can observe multiple security events, including SSH-related activities and new user creation events. We will ask the questions related to these events to our chatbot.
![[Pasted image 20260515110451.png]]

**Step 3:** Open the chatbot in a new tab.

Visit: **http://wazuhbot.ine.local in the same browser.
![[Pasted image 20260515110520.png]]

Let's first ask the chatbot about the SSH brute-force attempts.

**Query:**

```
Were there any SSH brute-force attempts? Give me all the details.
```

We can observe that the LLM chatbot responds in a conversational manner, clearly identifying key details such as the** attacker’s IP address, the ports involved, the targeted user account, and the corresponding security event message.**

**Note:** You may observe slightly different responses from the chatbot even when using the same prompt. This is expected behavior, as LLM-generated outputs can vary while still conveying the same underlying information.
![[Pasted image 20260515110743.png]]

![[Pasted image 20260515110726.png]]

==Attacker IP: 10.160.0.113

Next, let’s query the chatbot about the newly created user on the monitored agent to analyze the associated security event and understand the context of the user creation activity.

**Query:**

```
Is there any new account creation on "ubuntu-machine"? Give me all the details.
```

The chatbot responds by identifying the newly created user "bob", along with the associated group, UID, and GID, presenting the information clearly in a conversational format based on the corresponding alert data.
![[Pasted image 20260515110833.png]]
==New User Created: Bob UID=1005 GID=1006

**Step 4:** Explore the alerts on the Wazuh dashboard to verify and validate the findings provided by the LLM chatbot.

Go to "MITRE ATT&CK" >> "Framework." Set the date range (15th Feb 2026) and toggle the switch to hide the techniques with no alerts.

Click on the "Brute Force" tab.
![[Pasted image 20260515110942.png]]

Expand the log, and you will see that the details clearly align with the information provided by the chatbot.
![[Pasted image 20260515111047.png]]

==Attacker IP: 10.160.0.113 Verified. 

Next, click on the "Create Account" tab.
![[Pasted image 20260515111721.png]]

Expand the logs one by one.
![[Pasted image 20260515111201.png]]
==New User Verified: Bob UID=1005 GID=1006

Lets try to check if there was any Account Manipulation / Changes now:
```
Was there any Account Manipulation Attempts ?
```

![[Pasted image 20260515111450.png]]
==Password Change For user bob


![[Pasted image 20260515111630.png]]

![[Pasted image 20260515111609.png]]
==Password Change For user bob Verified

End of the Lab!

# Conclusion

In this lab, we learned how integrating AI with a security monitoring platform like Wazuh can significantly enhance threat detection and analysis. By leveraging the LLM-powered chatbot, we were able to query and interpret security alerts in a more intuitive and conversational manner.

---