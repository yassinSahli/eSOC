# Introduction

In this lab, you'll take a look at logs that have already been sent to the Splunk instance, performing analysis on them in an attempt to build actionable intelligence for next steps. 

All required IPs and credentials for this lab are listed below.

| Server   | IP             |
| -------- | -------------- |
| DC01     | 172.31.115.100 |
| SERVER01 | 172.31.115.110 |
| LINUX01  | 172.31.115.111 |

| Location/Purpose | Username     | Password         |
| ---------------- | ------------ | ---------------- |
| Domain Admin     | ine\labadmin | K5+peE#5q+&WJ^c# |
| Linux Server     | labadmin     | TTnxyAn5=jRd3R   |

# Tasks

You have been tasked with analyzing existing logs on a Splunk platform to identify the origin of suspicious activity on a Linux server. Your objective is to build a story regarding what has occured on the server, and use that information to plan out required next steps.

1. Perform searches in Splunk to identify potential suspicious or malicious activity
2. Based on the data found, identify any gaps in logging that may exist
3. Plan out next steps, which should be determined by the results of the log analysis

## Technical Workload

**Step 1 - Start the initial search in Splunk:**

Open up Splunk and type the following into the search bar to return all events for the Linux server:

`index=* host=linux01`

Make sure you set the time range to **All time**
![[Pasted image 20260506100948.png]]

![[Pasted image 20260506101041.png]]

We want to narrow down the type of logs we're looking at to only _syslog_ types. On the left-hand side, click on _sourcetype_ and then click _syslog_ to further filter the search.
![[Pasted image 20260506101117.png]]

Next, we want to further narrow the search to only authentication/authorization logs (to begin with). Click on _source_ on the left, and then select **source**  and then _/var/log/auth.log_ to filter even further.
![[Pasted image 20260506101227.png]]
Look through the logs to see if you can identify anything "malicious".

You should see at least one entry referencing an account named **maliciousaccount**
![[Pasted image 20260506101310.png]]

![[Pasted image 20260506101347.png]]

If you expand this event, you will notice that there is no individual field that references this account name. This would be our first identified hole in our logging that should be corrected.

However, we can still easily filter based on this account name. Simply click on _maliciousaccount_ in the entry, and click on _Add to search_. Alternatively, you can append _maliciousaccount_ to the end of the search query, so that it would look like this:

`index=* host=linux01 sourcetype=syslog source="/var/log/auth.log" maliciousaccount`

Either method will accomplish the same result

![[Pasted image 20260506101439.png]]
Again, look through the log entries. We want to identify where this account came from. Who created it?

We can see an event where another user named _newadmin_ used the command _adduser_ to create _maliciousaccount_
![[Pasted image 20260506101604.png]]
Before you move on, look through the rest of the log entries to identify what _maliciousaccount_ may have done and where this account may have logged in from.

After you have identified those items, let's adjust the search to see what _newadmin_ has been doing, and where that account came from as well. Edit your search to look like the following:

`index=* host=linux01 sourcetype=syslog source="/var/log/auth.log" newadmin`

After this search completes, we should see several interesting entries:
![[Pasted image 20260506101902.png]]
These 4 entries begin to tell a story:
- The account _labadmin_ created _newadmin_
- _labadmin_ gave _newadmin_ sudo permissions, by adding them to the sudo group
- _labadmin_ then switched users to _newadmin_, 
- Then _labadmin_ created the _maliciousaccount_ account

This leads us to believe that the _labadmin_ account has been **compromised** and the attacker was attempting to cover their tracks by creating chained users.

If we go back to the results for _maliciousaccount_, we can also see that this account successfully logged in to LINUX01 using SSH from 172.31.115.100, which is our domain controller!
![[Pasted image 20260506102051.png]]
At this point, we have identified that there are several possible points of compromise:
- labadmin
- newadmin
- maliciousaccount
- DC01

**Step 2 - Identify any other suspicious activity related to _maliciousaccount_:**

Now, let's adjust our search timeframe to reflect anything within 5 minutes before and after _maliciousaccount_ logged in to the server. To do this, find that entry in the list and click on the _Time_. Adjust the filter to show **+/- 5 minutes**
![[Pasted image 20260506102225.png]]
Since we want to look at _any_ logs around that time, let's also remove _maliciousaccount_ from the search query, so it should now look like this:

`index=* host=linux01 sourcetype=syslog source="/var/log/auth.log"`

Look through the resulting events and see if you can identify any additional useful information. Remember, the goal here is to gather **actionable** information.

We're not seeing a lot of new information here, so let's expand our search to show us other types of logs. Remove _source="/var/log/auth.log"_ from the search query. It should now look like this:
==Remember, we're still narrowed down to logs within 5 minutes before and after the _maliciousaccount_ logged in from DC01.

`index=* host=linux01 sourcetype=syslog`

We will naturally see a lot more unrelated data in our logs, since we have widened our search terms - this is expected and desired. 

We are trying to identify any other general information that can expand or support the story we are building.

If you don't see any additional information to support your efforts, try removing the _sourcetype_ from the query as well. Let's also add in _maliciousaccount_ to the query again. 

We're doing this because we've expanded the types of logs we're seeing, so we want to narrow down on that specific term again.
==Remember, we're still narrowed down to logs within 5 minutes before and after the _maliciousaccount_ logged in from DC01.

`index=* host=linux01 maliciousaccount`

Not seeing any new information? Let's remove _maliciousaccount_ from the query then. 

`index=* host=linux01`

We're still not overwhelemed by the logs at this point, because of that narrowed timeframe in the search. However, **NOW** we're seeing some interesting information:
![[Pasted image 20260506102535.png]]

![[Pasted image 20260506102720.png]]

![Content Image](https://assets.ine.com/content/labs/ptp/BrianOlliff/VOD-4529/LAB-4741/15.png)

Our attacker made this pretty obvious didn't they?

At this point, we've put together an interesting timeline of events:

1. _labadmin_ (possibly compromised) created _newadmin_
2. _labadmin_ switched users to act as _newadmin_
3. _newadmin_ then created _maliciousaccount_
4. _maliciousaccount_ logged in from DC01 using SSH (DC01 possibly compromised)
5. _maliciousaccount_ created/uploaded some form of malware on LINUX01

We also have some possible next steps based on this information:

- Disable _labadmin_, _newadmin_, and _maliciousaccount_ accounts
- Evaluate which of those accounts are legitimate and are needed. Change passwords and secure as necessary.
- If possible, take DC01 offline for further investigation. This is only possible if there are other, redundant domain controllers. If we can't disconnect it from the network, then **IMMEDIATE** further investigation is required.
- Do the same with LINUX01, since it is possibly compromised with malware

Feel free to investigate further to see if you can identify any other activity that may have taken place on this server. Experiment with different search criteria, including using some wildcards in your searches (*).