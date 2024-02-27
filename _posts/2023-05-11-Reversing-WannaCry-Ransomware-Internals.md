---
layout:	post
title:  "Reversing WannaCry Ransomware Internals"
date:   2023-05-11 11:11:11 +0200
categories: [Reversing Malware Internals]
tags: [WannaCry, Ransomware, Reverse Engineering, YARA]
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

### First Stager



### Second Stager


### Final Stager

<br>

## MITRE ATT&CK


<br>

## YARA Rule


<br>