---
layout:	post
title:  "Analysis of 'MalDoc in PDF'"
date:   2023-08-21 11:11:11 +0200
categories: [Malware Analysis]
tags: [MalDoc in PDF, YARA]
---

## Introduction:

This year, in July, a new “MalDoc in PDF” attack which could evade detection and analysis was shared by  [JPCERT](https://www.bleepingcomputer.com/news/security/maldoc-in-pdfs-hiding-malicious-word-docs-in-pdf-files/#:~:text=Japan%27s%20computer%20emergency%20response%20team%20%28JPCERT%29%20is%20sharing,open%20it%20as%20a%20regular%20Word%20document%20%28.doc%29.). This malware was polyglot, meaning a file that combine two or more file formats in a way that it could be executed as more than one file type by different application without error to evade detection and hinder analysis tools. In this case, the malware sample could be opened either as Word or as PDF and had embedded MHT (MIME HTML) that encoded macro in its ActiveMime.

<br>

## Identification:

**Source:**  [Triage](https://tria.ge/230829-clz17ahd83)

**FileName:**  0723Request.pdf

**SHA256:**  ef59d7038cfd565fd65bae12588810d5361df938244ebad33b71882dcf683058

**AV-Detection:**  22/59 ([VirusTotal](https://www.virustotal.com/gui/file/ef59d7038cfd565fd65bae12588810d5361df938244ebad33b71882dcf683058))

![](https://miro.medium.com/v2/resize:fit:700/1*PEyslpp2OfHfVsPRDMIHuw.png)

<br>

## Analysis:

### **Static Analysis:**

The sample collected was a PDF file, which are normally initial stager. Let's start with static analysis of this sample by loading this file in VSCode. Initially, its contents looked legitimate with PDF header and objects as shown below.

![](https://miro.medium.com/v2/resize:fit:700/1*jipSdIw8eQwFepoLd4pEdA.png)

But scrolling through the contents, there is MIME version declaration as shown below. From this part, the MHT (MIME HTML) content starts. Since this sample is polyglot and can be executed as Word file, the Word file can render this MHT contents.

![](https://miro.medium.com/v2/resize:fit:700/1*emYwCRrjZ_avUe_zFI2HLA.png)

The <link rel=’Edit-Time-Date’> object inside the MHT content point to ActiveMime. Here, ActiveMime is an undocumented Microsoft file format that is often used to encode the macro.

![](https://miro.medium.com/v2/resize:fit:700/1*jqqtgwxmlE_hw_L8AFCScw.png)

Also in above figure, note that the referenced location (href) to the ActiveMime of ‘Edit-Time-Date’ object is encoded, which was decoded using CyberChef as:

![](https://miro.medium.com/v2/resize:fit:700/1*tb21jSsPNlAv2qKQjhJ3ZQ.png)

Using decoded location path name ‘lonhzFH_files/image7891805.jpg’, it was searched in VScode and jumped to that part as shown below. The content (ActiveMime) is obfuscated text with lots of spaces.

![](https://miro.medium.com/v2/resize:fit:700/1*JTdYgkEriPdNiHttQLKEYQ.png)

![](https://miro.medium.com/v2/resize:fit:700/1*IvXuRexvQli5wNPUdMrfRw.png)

The contents from above were copied to CyberChef where it revealed that those spaces were actually created by CR (Carriage Return)’.

![](https://miro.medium.com/v2/resize:fit:700/1*vdDtzGYfyGH1-NHrmf1AyA.png)

The content was then decoded from Base64 revealing it to be ActiveMime, which encode the macro. So, it was then saved as macro.bin.

![](https://miro.medium.com/v2/resize:fit:700/1*X7ByHMYU3MjkRsDDUvjfvQ.png)

To search for the embedded macro inside the decoded content, binwalk was used.

    binwalk macro.bin

![](https://miro.medium.com/v2/resize:fit:700/1*mUcophOlKOn-oQyPOaG-Qg.png)

The binwalk revealed a compressed data, which is part of the ActiveMime format that encode the macro. It was again extracted using binwalk.

    binwalk -D='.*' macro.bin

After extracting, it revealed a file named 32, as shown below.

![](https://miro.medium.com/v2/resize:fit:646/1*bYVI72MsN-93DJGqJqOZAQ.png)

The above extracted file should be the decoded malicious macro. So, it was checked using the Oletools. First, Oleid was used to check for any macro.

    oleid 32

![](https://miro.medium.com/v2/resize:fit:700/1*quyfon1TH05vxcsGLyWdXQ.png)

The Oleid tool found VBA macros within it.

To extract the VBA macro inside it, Olevba tool was used.

    olevba 32

![](https://miro.medium.com/v2/resize:fit:700/1*nqx4tuLwHwGoU3C4vJmkEA.png)

Here, from the output of olevba tool, it can be found that the macro will download a msi file from its C2 server (hxxps[:]//cloudmetricsapp[.]com/wp-content/uploads/docs/addin[.]msi). Then, it will execute the downloaded msi file with Office.InstallProduct. Also, this macro will be executed as soon as the Word file is opened through AutoExec, and download and install that msi file.

This further verify that this pdf sample file is an initial stager that will bypass detection and download another payload, which is the msi file.

Using the URL obtained from the macro, it was checked in  [Browserling](https://www.browserling.com/)  sandbox if it acts as downloader. But it was unreachable as shown below.

![](https://miro.medium.com/v2/resize:fit:700/1*i6oObcCBDoxAAuz0cOLj9A.png)

<br>

### **Dynamic Analysis:**

Let's now further analyze this sample through dynamic analysis. The PDF file was saved as Word file and opened. Notice the ‘Enable Content’ is still there. Although this sample was able to bypass detection, it was not able to bypass this protection measure.

![](https://miro.medium.com/v2/resize:fit:700/1*KOFqfeJztMVT1L_Gq1ikiw.png)

When the ‘Enable Content’ is enabled, the Word will render the MHT contents, which will decode the macro from the ActiveMime blob and execute it to download the msi file as discovered during static analysis.

In the Wireshark capture, it can be seen that it is resolving the domain cloudmetricsapp[.]com to IP address of 179[.]60[.]147[.]105. After that the infected host tried to initiate connection over 443 to download the msi file but get no reply from server as shown below.

![](https://miro.medium.com/v2/resize:fit:700/1*UAHxPE7WR2vhdh8ecTWu-Q.png)

It is clear now that this ‘MalDoc in PDF’ is an initial stager that will download its final payload by bypassing detection. And there have been many scenarios where one malware family has been used as initial stager for other malware families. So, in near future, this malware could probably be used by other malware families to act as their initial stager. So, the next section will include YARA rule for detecting these kind of malware samples.

<br>

## Detection with YARA:

    rule MaldocinPDF{  
      meta:  
            description= "Detecting MalDocs in PDF"  
        strings:  
            $mht0 = "mime" ascii nocase  
            $mht1 = "content-location:" ascii nocase  
            $mht2 = "content-type:" ascii nocase  
            $mht3 = "Edit-Time-Data" ascii nocase  
            $doc = "<w:WordDocument>" ascii nocase  
            $xls = "<x:ExcelWorkbook>" ascii nocase  
         condition:  
            (uint32(0) == 0x46445025) and  
            (2 of ($mht*)) and   
            ( (1 of ($doc)) or   
              (1 of ($xls)) )  
    }

<br>

## IoC:

Explore IoC of ‘MalDoc in PDF’ from Virus Total Graph as they have great visualization.

**Link:**  [VirusTotal Graph](https://www.virustotal.com/graph/gf02630da298546129218c8f0577ea4a751c3137cfcb54c56b785a69b33d5372f)

![](https://miro.medium.com/v2/resize:fit:700/1*o9OgwHTT2Y5wp00yn_Zhgg.png)