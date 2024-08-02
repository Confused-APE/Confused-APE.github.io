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

