In this lab, you'll configure 2 servers to send log data to a Splunk instance that resides on SERVER01. 
- DC01 will need specified Windows event logs, including some AD information sent 
- LINUX01 will need specific auth log files sent. 

All required IPs and credentials for this lab are listed below:

| Server   | IP             |
| -------- | -------------- |
| DC01     | 172.31.115.100 |
| SERVER01 | 172.31.115.110 |
| LINUX01  | 172.31.115.111 |

| Location/Purpose | Username     | Password         |
| ---------------- | ------------ | ---------------- |
| Domain Admin     | ine\labadmin | K5+peE#5q+&WJ^c# |
| Linux Server     | labadmin     | TTnxyAn5=jRd3R   |


You have been tasked with collecting log information from two servers in the organization. Your director has asked for security event logs and basic AD information to be collected from DC01 and sent to the Splunk server on SERVER01. In addition, you have been asked to have authorization logs from the Linux server indexed into Splunk as well.

1. Configure Splunk (and Windows Firewall) to receive logs on port 9997
2. Install and configure the Splunk Forwarder to send _Security_ event logs and Active Directory information from DC01 to SERVER01
3. Install and configure the Splunk Forwarder on the linux server to send /var/log/auth.log to SERVER01


**Step 1 - Configure Splunk and SERVER01 to receive logs:**

Open Splunk from the desktop and navigate to _Settings_, then _Forwarding and receiving_
![[Pasted image 20260430142710.png]]

Click on _Add new_ next to **Configure receiving** to add a new receiver. Enter port _9997_ and click _Save_
![[Pasted image 20260430142731.png]]

![[Pasted image 20260430142758.png]]

Next, open up Windows Firewall settings to allow traffic on port 9997 through the local firewall.

Go to _inbound rules_ and create a new rule
![[Pasted image 20260430142911.png]]

Choose the following options to create the rule: - Port - TCP, on port 9997 only - Allow the connection - Enable for all profiles - Name: **Splunk Forwarder**
![[Pasted image 20260430142955.png]]

![[Pasted image 20260430143007.png]]

![[Pasted image 20260430143044.png]]

**Step 2 - Install and configure the Splunk Forwarder on DC01:**

Open up RDP to connect to DC01. Use the Domain Admin credentials listed in the lab summary
![[Pasted image 20260430143200.png]]
Open up the _Tools_ folder on the desktop of DC01 and launch the Splunk Forwarder installer
![[Pasted image 20260430143827.png]]

Check the box at the top to accept the license agreement, and ensure that **An on-premises Splunk Enterprise instance is selected**, then choose _Customize Options

![[Pasted image 20260430143914.png]]
![[Pasted image 20260430144205.png]]

Accept the default installation location, and accept all the defaults on the SSL certificate screen
![[Pasted image 20260430144336.png]]

Ensure **Local System** is selected for the account that Splunk Forwarder will be installed as
![[Pasted image 20260430144400.png]]

On the following screen, select **Security Logs** and **Enable AD monitoring** and choose _Next_
![[Pasted image 20260430144440.png]]

Enter a username for the Splunk administrator account, and then either enter a password or let the installer generate a random password
![[Pasted image 20260430144513.png]]

**Leave the Deployment Server information empty**

On the **Receiving Indexer** screen, enter the IP address for SERVER01, and the port that you previously configured for the receiver on Splunk (9997)
![[Pasted image 20260430144620.png]]

![[Pasted image 20260430145247.png]]

Return to SERVER01 (we're done on DC01 for now) and go back to Splunk. 

Click on *Splunk>Enterprise* at the top, and then choose *Search & Reporting* from the navigation bar
![Content Image](https://assets.ine.com/content/labs/ptp/BrianOlliff/VOD-4529/LAB-4740/15.png)

Enter the following search query in the search bar to verify you're receiving logs. Ensure you change the time frame on the right of the search bar to **All time**

`index=* host=DC01`
![[Pasted image 20260430150428.png]]
In my case, I couldn't find any results. It takes time for logs to be generated and the lab will expire soon so I moved on to the next task.  

But its supposed to look something like this:
![[Pasted image 20260430151351.png]]

After a moment, you should see results returned. If you do not see any events after the search completes, go back and double-check your configuration to ensure all settings are correct.

**Step 3 - Install Splunk Forwarder on LINUX01 and configure to send logs to SERVER01:**

Use Putty to SSH to the Linux server. Use the credentials for the Linux server listed in the lab information to connect.

Once connected via SSH, there are a few prerequisites to complete before installing the forwarder:

- Create a new user to be the owner for the installation:

```bash
sudo useradd -m splunk
```

- Create a variable to easily store the installation location:

```bash
export SPLUNK_HOME="/opt/splunkforwarder"
```

- Create the folder

```bash
sudo mkdir $SPLUNK_HOME
```

With the prerequisites completed, we can install the forwarder now

```bash
sudo dpkg -i splunkforwarder-9.0.4-de405f4a7979-linux-2.6-amd64.deb
```
![[Pasted image 20260505113100.png]]
Now that the forwarder is installed, change the ownership of the folder to the user we created earlier:

```bash
sudo chown splunk:splunk $SPLUNK_HOME -R
```

Now change directories into the **$SPLUNK_HOME/bin** directory. **The rest of the commands will not work if this step is not completed**

```bash
cd $SPLUNK_HOME/bin
```

Start the Splunk Forwarder (accepting the license agreement):

```bash
sudo ./splunk start --accept-license
```

![[Pasted image 20260505113121.png]]

You will be prompted to create a new administrator for this forwarder. Enter a username and password when prompted. **You will need this information again in a moment**
![[Pasted image 20260505113136.png]]

The forwarder will take a moment to start, and then it will show its completed startup:
![[Pasted image 20260505113154.png]]

Next, we need to tell Splunk where to send its logs. Enter the following command to configure the forwarding. Enter the username/password you just created when prompted.

```bash
sudo ./splunk add forward-server 172.31.115.110:9997
```

![[Pasted image 20260505113230.png]]

Next, we need to tell Splunk what logs to monitor. In our case, we need to monitor the file **/var/log/auth.log**. Use the following command to configure this. If done within a few minutes of the last command, you should not be prompted for the username again.

```bash
sudo ./splunk add monitor /var/log/auth.log
```

![[Pasted image 20260505113316.png]]

Now, for good measure, restart the Splunk Forwarder to ensure all the new settings are applied

```bash
sudo ./splunk restart
```

Once the restart is complete (should only take a few seconds), return to the Splunk search console and repeat our previous search, but replacing the host with _ip-172-31-115-111_ this time.

![[Pasted image 20260505113339.png]]

Now that we have all of the logs being sent to the Splunk server, feel free to perform various searches to see what type of data we are capturing.

We'll perform additional analysis on these logs (and more) in the _Log Analysis_ lab.