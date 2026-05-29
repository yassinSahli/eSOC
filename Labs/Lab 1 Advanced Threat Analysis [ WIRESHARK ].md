This lab focuses on analyzing malicious network traffic associated with a certain C2 (Command and Control) framework. The objective is to perform packet analysis on a PCAP file to identify indicators of compromise, identify the C2 framework involved, extract cryptographic keys, and decrypt encrypted C2 communications. The lab demonstrates real-world techniques used by security analysts to investigate suspected malware infections and understand attacker activities through network forensics.

# Lab Environment

In this lab environment, you will have GUI access to a Windows machine. The PCAP file for analysis, `mal01.pcapng`, is located on the Desktop.

**Objective:** Analyze network traffic to identify and decrypt suspected C2 (Command and Control) communications.

# Tools

The best tools for this lab are:

- Wireshark
- CyberChef

# Technical Workload


**Step 1:** Access the Windows machine.
**Step 2:** Start Wireshark and open the `mal01.pcapng` file located on the Desktop.
**Step 3:** Filter for HTTP traffic to investigate potential C2 activity, as HTTP is a common channel used by malware for command and control communications.

**Filter:**

```
http
```

We immediately notice a suspicious GET request to `/checkmate.exe` from 10.0.0.156 to 10.0.0.155. Downloading an executable file over HTTP is unusual.

![[Pasted image 20260430094521.png]]

Right-click on the frame and go to **Follow > HTTP Stream**.
![[Pasted image 20260430094742.png]]

Based on this HTTP stream, we can identify several key indicators:

1. **PowerShell as User-Agent:** The request is coming from `WindowsPowerShell/5.1.17763.1432`, which means this executable is being downloaded via a PowerShell command (likely Invoke-WebRequest or wget). This is a common technique in attack scenarios.
    
2. **Python SimpleHTTP Server:** The server hosting the executable is `SimpleHTTP/0.6 Python/3.12.8`, which is a lightweight, temporary web server often used for quick file transfers rather than legitimate software distribution.
    
3. **Executable File Type:** The content-type `application/x-msdos-program` confirms this is a Windows executable (.exe file).
    
4. **Internal Network Communication:** The communication is between two internal IPs (10.0.0.156 requesting from 10.0.0.155:8000), suggesting lateral movement or internal file distribution.
    
5. **Non-standard Port:** Port 8000 is being used instead of standard HTTP port 80, which is typical for ad-hoc Python SimpleHTTP servers.
    

**Step 4:** Let's extract the `checkmate.exe` executable, calculate its hash, and check it against a threat intelligence database like **VirusTotal** to confirm whether it is malicious.

Go to **File > Export Objects > HTTP**.
![[Pasted image 20260430094922.png]]
Select the `checkmate.exe` file and click on Save. Save it to the desktop.
![[Pasted image 20260430095014.png]]

Next, open PowerShell and caluclate the MD5 hash of the executable.

**Commands:**

```
cd Desktop

Get-FileHash -Algorithm MD5 checkmate.exe
```

![[Pasted image 20260430095121.png]]

Copy the MD5 hash and search for it on VirusTotal at `https://www.virustotal.com`.
![[Pasted image 20260430095228.png]]

The hash returns no results on VirusTotal, indicating this may be a previously unknown or custom-built executable.

**Step 5:** Back in Wireshark, we can observe that after the initial request to download the executable, there are multiple HTTP POST requests and 200 OK response exchanges between 10.0.0.156 and 10.0.0.155.
![[Pasted image 20260430095504.png]]

Right-click on these requests and follow the HTTP stream. Notice that they either contain encrypted content, unusual data, or empty responses.

![[Pasted image 20260430095716.png]]

![[Pasted image 20260430095637.png]]

Let's visualize this traffic pattern. First, apply the following filter to narrow down the HTTP traffic involving only 10.0.0.156 and 10.0.0.155.

**Filter:**

```
http && ip.addr==10.0.0.155 && ip.addr==10.0.0.156
```
![[Pasted image 20260430111226.png]]

Next, go to **Statistics > I/O Graphs**.
Make sure the graph only visualizes the filtered packets. Uncheck the remaining boxes as shown below:
![[Pasted image 20260430111503.png]]
We observe beaconing activity occurring approximately every 2 seconds, which is indicative of potential C2 activity. Beaconing is when a compromised system periodically (Every 1 minute) sends automated requests to a C2 server to check for new commands or maintain the connection.

Now the key questions arise: **What kind of C2 are we dealing with? How do we identify the C2 framework? Is it a well-known framework or something custom?**

The solution is to gather evidences that may point us to a known C2 framework.

**Step 6:** Examine the first POST request from the victim machine after the executable is downloaded and possibly executed.
![[Pasted image 20260430111727.png]]

Upon closer inspection, the first few bytes read `dead beef`. This is a well know magic byte value associated with **Havoc C2**.

This can be confirmed by checking the `Defines.h` file in the Havoc C2 github repository.
![[Pasted image 20260430111743.png]]

**Link:** `https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/include/common/Defines.h`

**Step 7:** Now that we have identified the framework as Havoc C2, we can apply known reverse-engineering and traffic analysis techniques to recover the AES key and IV used for encryption and decryption. 

While threat intelligence write-ups and automated scripts are available online for reference, the following section provides a concise, practical cheat sheet for analyzing Havoc C2 traffic.

**Understanding AES Key and IV:**

- **AES Key:** The Advanced Encryption Standard (AES) key is the secret cryptographic key used to encrypt and decrypt the C2 communication between the implant and the server. In Havoc C2, this key is embedded in both the implant and server to secure the traffic.
    
- **IV (Initialization Vector):** The IV is a random value used alongside the AES key to ensure that identical plaintext messages produce different ciphertext outputs. This prevents pattern recognition in encrypted traffic.
    
- **Why they matter:** Without the AES key and IV, the encrypted POST request data appears as random bytes. Extracting these values allows us to decrypt the C2 traffic and understand what commands are being sent and what data is being exfiltrated.
    

Select the first POST request, copy the packet bytes as a Hex Dump as shown below and paste it on notepad:
![[Pasted image 20260430112136.png]]

![[Pasted image 20260430112159.png]]

```
0000   02 55 6a 9e 55 49 02 a5 f2 86 c8 b5 08 00 45 00
0010   01 11 36 b0 40 00 80 06 00 00 0a 00 00 9c 0a 00
0020   00 9b c4 bf 00 50 f1 e2 41 43 bf 83 ff ba 50 18
0030   20 14 16 3a 00 00 00 00 00 e5 de ad be ef 08 75
0040   c2 54 00 00 00 63 00 00 00 00 08 da 26 84 0e c4
0050   d8 c2 3e 32 5e ea e6 ea e6 48 f6 5a 2c d0 48 50
0060   6e 64 32 dc d2 c4 76 86 d6 8a 9a f8 84 b0 68 dc
0070   38 d0 2c a6 b2 ca 2c 8e 96 82 8f d3 51 ad 66 c7
0080   7c 4c 95 3f a4 a0 44 a1 bd 93 16 ff 56 13 32 13
0090   6a 92 7c 7c d5 db 7f 68 5c c9 b7 24 5c 2d b4 c3
00a0   ba 16 2b 5d 37 78 3e 8b fc 1a a2 eb f0 03 05 e8
00b0   81 05 c0 ac 9f 69 91 5d d3 15 e9 43 b2 f9 03 7f
00c0   7e 91 dc 2c b3 c5 f1 bf 41 76 a8 b6 ff 07 a7 d1
00d0   7e 57 13 c2 7b d8 16 12 43 08 4e e7 2e be 9f 99
00e0   a0 4d 93 30 fb de 37 27 30 9e 54 f8 46 b3 52 6b
00f0   59 37 99 6d 73 0a ec b6 36 9b 3e 31 6b 78 b6 36
0100   aa ce fe fb 23 71 95 74 a7 b3 03 1c 5d d4 f5 fb
0110   93 6f c7 b3 40 9c 0d f3 cf 8d 13 67 f0 b7 d9
```

In the above hex dump, locate the magic bytes `de ad be ef`, skip the next 12 bytes, and then extract the following 32 bytes, which represent the AES key:

```
08 da 26 84 0e c4 d8 c2 3e 32 5e ea e6 ea e6 48 f6 5a 2c d0 48 50 6e 64 32 dc d2 c4 76 86 d6 8a
```

Note that 1 byte = 2 hexadecimal characters.

Removing the white spaces, the **AES Key** is:

```
08da26840ec4d8c23e325eeae6eae648f65a2cd048506e6432dcd2c47686d68a
```

The next 16 bytes is the **IV**:

```
9af884b068dc38d02ca6b2ca2c8e9682
```

To summarize, the key extraction process for Havoc C2 is as follows:

==**Find deadbeef → skip 12 bytes → next 32 bytes = AES key → next 16 bytes = AES IV**

**Step 8:** Next, observe that after the first POST request, the subsequent POST requests and responses are of fixed lengths:

![Content Image](https://assets.ine.com/lab/learningpath/99c69a4072837f2198c6b24df7345dad465a95a3345b91e18082acf177b549e8.png)

After a few of these exchanges, notice that there is a sudden and significant change in the length of the POST request. This likely indicates the output of a command executed by the C2 implant.
![[Pasted image 20260430112630.png]]
Double-click on that frame and expand "Hypertext Transfer Protocol".
![[Pasted image 20260430112617.png]]
Right-click on **File Data** and select **Copy > Value**.

Go to **CyberChef** (`https://gchq.github.io/CyberChef/`) and paste it in the **Input** box:

We now have an AES-encrypted input that needs to be decrypted using the keys we discovered.

To do this, first drag & drop the **AES Decrypt** operation in the **Recipe** box.
![[Pasted image 20260430112844.png]]

Paste the **AES Key** and the **IV** in their respective fields.
![[Pasted image 20260430112823.png]]
Havoc C2 uses the **CTR (Counter)** block cipher mode for encrypting/decrypting data. This can be confirmed by examining the **AesCrypt.h** file in the Havoc C2 repository.
![[Pasted image 20260430112906.png]]

**Link**: `https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/include/crypt/AesCrypt.h`

Set the mode to **CTR** in the recipe.

![Content Image](https://assets.ine.com/lab/learningpath/540a1b8bf3b501358bcb364f98ac0f168b76c348193bf0981df83c906ba3307d.png)

![[Pasted image 20260430112935.png]]

Notice that we still see garbage in the **Output**. This is because the input content contains headers that need to be removed.

**Remove exactly 20 bytes (40 characters) from the beginning of the input.**
![[Pasted image 20260430113117.png]]

Success! We can now see the decrypted content! 

![[Pasted image 20260430113223.png]]
It appears to be the output of the **"whoami /all"** command, indicating that the attacker has administrative-level access on the compromised machine at 10.0.0.156.

Similarly, you can try decrypting other command outputs seen in the capture as well.

# Conclusion

In this lab, through systematic packet analysis, we identified malicious executable downloads, identified C2 communication patterns, recognized the C2 framework through magic byte signatures (`deadbeef`), extracted cryptographic parameters (AES key and IV), and decrypted encrypted communications to reveal the attacker's commands and access level.

Key findings from this analysis include:

1. **Confirmed Compromise:** The system at 10.0.0.156 was compromised and downloaded `checkmate.exe` from an internal host at 10.0.0.155.
    
2. **C2 Framework Identification:** The traffic was positively identified as Havoc C2 through the characteristic `deadbeef` magic bytes.
    
3. **Beaconing Pattern:** Regular beaconing activity occurred every 2 seconds, indicating an active C2 connection with persistent communication.
    
4. **Encryption Analysis:** Successfully extracted the AES key and IV from the initial POST request, enabling decryption of all subsequent C2 communications.
    
5. **Administrative Access:** The decrypted command output revealed that the attacker executed `whoami /all` and gained administrative-level privileges on the compromised system.
    

# References

- [https://github.com/HavocFramework/Havoc]
- [https://gchq.github.io/CyberChef/]