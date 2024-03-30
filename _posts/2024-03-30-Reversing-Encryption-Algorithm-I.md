---
layout:	post
title:  "Reversing Encryption Algorithms (I): Intro"
date:   2024-03-30 11:11:11 +0200
categories: [Reversing Encryption Algorithms]
tags: [Encryption]
---

## Overview

Encryption serves as a sophisticated mechanism employing algorithms to convert plaintext into ciphertext, establishing as a stalwart guardian to safeguard sensitive information from unauthorized access. Yet, in the intricate game of cat and mouse between defenders and adversaries, encryption has also found an unwelcome application in the realm of malware.

Malware leverage encryption algorithm for anti-defense and anti-analysis. There are two approaches that malware author can take to leverage encryption, which are:

- Using APIs
- Coding encryption algorithms

In case of samples using API for encryption, it can be easily identified because Microsoft has documented most of those APIs.

- [Wincrypt.h header — Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/)
- [BCryptEncrypt function (bcrypt.h) — Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt)

**Example**

Consider a sample that has functionality to decrypt obfuscated strings during run time. And for this, it uses **CryptGenKey** API from **WinCrypt** to generate cryptographic key, which handle will be passed to **CryptDecrypt** to decrypt those obfuscated strings

Following the [Microsoft documentation on **CryptGenKey**](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdecrypt) as shown below, the second parameter it takes is Algorithm ID

![CryptDecrypt](/images/2024-03-30-Reversing-Encryption-Algorithm-I/CryptDecrypt.png)

By checking the [value of Algorithm ID](https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id) that is passed as second parameter to the CryptGenKey API, the encryption algorithm can be identified easily.

![AlgorithmID](/images/2024-03-30-Reversing-Encryption-Algorithm-I/AlgorithmID.png)

The usage of API made it easier to detect. But what if malware author do not use API for cryptographic algorithm?

One way is by through the **constants** used in cryptographic algorithm.
- Constants are hardcoded value required by cryptographic algorithm to output correct data.
    - Those constant can be substitution box, magic numbers or certain value used in algorithm.
- Tools like KANAL and CAPA can detect encryption algorithm through constants.

Again what if those tools did not pickup those constants of encryption algorithm? 
- In such cases, malware analyst needs to understand the **flow** of cryptographic algorithm in order to identify them. 

So, this blog series will focus on identifying encryption algorithms. Following encryption algorithms will be covered.

**Symmetric Encryption Algorithm**
- **Stream Cipher**
    - RC4
    - Salsa20/ChaCha20
- **Block Cipher**
    - AES
    - Blowfish
    - Serpent
    - 3DES
**Asymmetric Encryption Algorithm**
- RSA
- ECDH