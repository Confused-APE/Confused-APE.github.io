---
layout:	post
title:  "Reversing WannaCry Ransomware Internals"
date:   2023-05-11 11:11:11 +0200
categories: [Reversing Malware Internals]
tags: [WannaCry, Ransomware, YARA]
---

## Overview

In my early days into malware analysis, I had analyzed WannaCry ransomware but without delving into reverse engineering due to my limited proficiency in that area. But now with couple of months into malware analysis amd armed with new found expertise in reverse engineering, I decided to reverse the WannaCry ransomware to gain deeper understanding of its internals.

WannaCry ransomware (also known as WCry, WannaCrypt or WannaCrypt0r) appeared on May 12, 2017 and quickly propagate over the internet with its worm feature by  exploiting vulnerability in Microsoft SMB (MS17-010).

<br>

## Sample Identification

**Sample Source:** [Triage](https://tria.ge/200320-7j5lhpc5fj)

**SHA256:** 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c

![VirusTotal Result](/images/2023-11-11-Reversing-WannaCry-Ransomware/1.png)

<br>

## WannaCry Ransomware Execution Flow


<br>

## Ransom Note

**WannaCry** drops a ransom note named *@Please_Read_Me@.txt in every folder that it encrypts. 

    Q:  What's wrong with my files?
    
    A:  Ooops, your important files are encrypted. It means you will not be able to access them anymore until they are decrypted.
    If you follow our instructions, we guarantee that you can decrypt all your files quickly and safely!
    Let's start decrypting!
    
    Q:  What do I do?
    
    A:  First, you need to pay service fees for the decryption.
    Please send $300 worth of bitcoin to this bitcoin address: 13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94

    Next, please find an application file named "@WanaDecryptor@.exe". It is the decrypt software.
    Run and follow the instructions! (You may need to disable your antivirus for a while.)
    
    Q:  How can I trust? 
     
    A:  Don't worry about decryption.
    We will decrypt your files surely because nobody will trust us if we cheat users. 
     
    *   If you need our assistance, send a message by clicking <Contact Us> on the decryptor window.
 
<br>

## Reversing WannaCry Ransomware

### Loader (mssecsvc.exe)

Lets dive straight into reversing WannaCry by loading in IDA. The IDA point out the main function of this program so lets start reversing from there. 

#### Kill Switch

![Main Function](/images/2023-11-11-Reversing-WannaCry-Ransomware/3.png)

Under the main function, first some variables can be seen initialized.

Then sub esp, 50 instruction is allocating space in stack for arguments and values.

After that there are couple of instructions for preparing rep movsd, which will move double word (32-bits) value from esi to edi till the ecx is 0.

- The esi and ebi are pushed onto the stack to save their value.
- The value 0xE (14) is moved to ecx as counter.
- The offset of a kill switch URL somewhere under .data section is moved to esi.
- With lea instruction, the beginning offset under stack segment where the kill switch URL is to be stored is moved to edi.
- There is xor eax, eax which will result to eax being 0.
- Finally the rep movsd instruction will move 32-bits (4 bytes) of kill switch URL from esi to edi each time till ecx is 0 (14 times).

![KillSwitch URL](/images/2023-11-11-Reversing-WannaCry-Ransomware/4.png)

Following it, there is movsb which will move just a byte from esi to edi.

Then there are couple of mov instructions where eax value (0) is moved to stack, which offset are just after the end of kill switch URL.

![Check KillSwitch](/images/2023-11-11-Reversing-WannaCry-Ransomware/5.png)


After that there is call to InternetOpenA to initialize WinINet functions.

Immediately after it, there is call to InternetOpenUrlA, where value of ecx is pushed as argument for lpszUrl, which store the kill switch URL. 

From the call to InternetOpenURLA, if the kill switch URL could be reached:

- The return will be a handle, meaning eax will be a non-zero value.
- Then the eax value is moved to edi.
- The test edi, edi will perform bitwise AND operation and the result of AND operation between non-zero and non-zero will be a non-zero value, clearing the zero flag (ZF=0).
- The next instruction jnz will jump if zero flag is not zero/set (ZF=0). Since the ZF=0 in this case, it will take the jump to loc_4081BC.
- It will close the handle and then exists.
- This capability of WannaCry could be to evade sandbox environment, which normally simulates the URL that the malware is trying to connect. By trying to reach out to a gibberish non-existence domain, the WannaCry will know if it’s running in sandbox environment. If it connects to the kill switch URL, it will then exit without doing anything.

From the call to InternetOpenURLA, if the kill switch URL could not be reached:

- The return value will be null, meaning eax=0.
- Then the eax value is moved to edi.
- The test edi, edi will perform bitwise AND operation and the result of AND operation between 0 and 0 will be 0, setting up the zero flag (ZF=1).
- The next instruction jnz will jump if zero flag is not zero/set (ZF=0). Since the ZF=1 in this case, it will not take the jump.
- After that it will close the handle and call sub_408090.

#### Service Mode

Lets now analyze sub_408090.

![Check parameters](/images/2023-11-11-Reversing-WannaCry-Ransomware/6.png)

Under the sub_408090, there is call to GetModuleFileNameA that retrieves the path for the image of current process. 

Then it calls the __p__argc to check the number of parameters which will be returned in eax.

Immediately after the call there is cmp instruction which checks if the number of parameter is 2.

- If true
    - The instruction jge will jump to loc_4080B9.
    - Since no parameter is passed until now, lets not jump to that execution flow. We will come to this part later on after some parameters is appended.
- If false
    - The instruction jge will jump to loc_4080B9. Since no parameter is passed to this binary, it will not take the jump and call sub_507F20.

Under the sub_507F20, there is call to 2 functions, sub_407C40 and sub_407CE0 as can be seen below.

![Function calls](/images/2023-11-11-Reversing-WannaCry-Ransomware/7.png)

Lets now dive into sub_407C40.


### Second Stager (tasksche.exe)


### Final Payload (kbdlv.dll)



<br>

## MITRE ATT&CK

|  Tactics|Techniques  |
|--|--|
| Initial Access | T0866 Exploitation of Remote Services |
| Persistence | T1543.003 Create or Modify System Process:  Windows Service |
| Defense Evasion | T1222.001 File and Directory Permissions Modification:  Windows File and Directory Permissions Modification |
|  | T1564.001 Hide Artifacts:  Hidden Files and Directories |
|  | T1036.005 Masquerading: Match Legitimate Name or Location |
| Discovery | T1018 Remote System Discovery |
|  | T1120 Peripheral Device Discovery |
|  | T1016 System Network Configuration Discovery |
| Lateral Movement | T1210 Exploitation of Remote Services |
| Command and Control | T1573.002 Encrypted Channel:  Asymmetric Cryptography |
|  | T1090.003 Proxy: Multi-hop Proxy |
| Impact | T1486 Data Encrypted for Impact |
|  | T1490 Inhibit System Recovery |

<br>

## YARA Rule


<br>