---
layout:	post
title:  "Reversing Encryption Algorithms (II): RC4"
date:   2024-03-29 11:11:11 +0200
categories: [Reversing Encryption Algorithms]
tags: [Encryption, RC4]
---

## Introduction

RC4 is symmetric stream cipher developed by Ronald Rivest in 1987. It is one of the most encountered cryptographic algorithms in malware because of its simplicity and efficiency. It is widely used by malware for activities like:

- To encrypt network communication to its C2.
- To decrypt obfuscated strings and 2nd stager binary.

RC4 was popular with malwares like Raccoon Stealer v2, Revil, IceID, Dridex, and more.

<br>

## Implementation in C

```c
    #include <stdio.h>
    #include <stdlib.h>
    
    void swap(unsigned char* a, unsigned char* b) {
        unsigned char temp = *a;
        *a = *b;
        *b = temp;
    }
    
    void rc4(unsigned char* key, unsigned char* plaintext, unsigned char* ciphertext, int len) {
        unsigned char SBox[256];
        int i, j = 0, k;
    
        // Key scheduling algorithm
        for (i = 0; i < 256; i++) {
            SBox[i] = i;  //Initializing 256-byte array substitution box
        }
    
        for (i = 0; i < 256; i++) {
            j = (j + SBox[i] + key[i % len]) % 256;  //Scrambling initialized substitution box with key
            swap(&SBox[i], &SBox[j]); //Swap SBox[i] and SBox[j]
        }
    
        // Pseudo-random generation algorithm
        i = j = 0;
        for (int l = 0; l < len; l++) {
            i = (i + 1) % 256;
            j = (j + SBox[i]) % 256;
            swap(&SBox[i], &SBox[j]);  //Swap SBox[i] and SBox[j]
            k = SBox[(SBox[i] + SBox[j]) % 256]; //Generating key stream
            ciphertext[l] = plaintext[l] ^ k; // XOR operation
        }
    }
    
    int main() {
        unsigned char key[] = "mysecretkey";
        unsigned char plaintext[] = "Hello, world!";
        int len = sizeof(plaintext) - 1; // exclude null terminator
    
        // Dynamically allocate memory for ciphertext
        unsigned char* ciphertext = (unsigned char*)malloc(len * sizeof(unsigned char));
        if (ciphertext == NULL) {
            printf("Memory allocation failed.\n");
            return 1;
        }
    
        rc4(key, plaintext, ciphertext, len);
    
        printf("Plaintext: %s\n", plaintext);
        printf("Ciphertext: ");
        for (int i = 0; i < len; i++) {
            printf("%02X ", ciphertext[i]);
        }
        printf("\n");
        free(ciphertext); // Free dynamically allocated memory
    
        return 0;
    }
```

<br>

## Algorithm Breakdown

RC4 algorithm consist of 3 stages (code for each stage from above implementation):

**KSA (Key Scheduling Algorithm)**
   
-   In this phase, a 256-byte array substitution box is first initialized.
-   Then, using the key, the initialized substitution box is scrambled.

```c  
    for (i = 0; i < 256; i++) {
        SBox[i] = i;  //Initializing 256-byte array substitution box
    }
    for (i = 0; i < 256; i++) {
        j = (j + SBox[i] + key[i % len]) % 256;  //Scrambling initialized substitution box with key
        swap(&SBox[i], &SBox[j]);  //Swap SBox[i] and SBox[j]             
    }

```
    
**PRGA (Pseudo Random Generation Algorithm)** and **XOR**
    
  -   In PRGA phase, the scrambled substitution box created in KSA stage is used to generate keystream.
  -   Then, in XOR phase, each byte of plaintext/ciphertext is XOR with each byte of key stream generated in previous PRGA stage to get ciphertext/plaintext respectively.

```c
      for (int l = 0; l < len; l++) {
        i = (i + 1) % 256;
        j = (j + SBox[i]) % 256;
        swap(&SBox[i], &SBox[j]);  //Swap SBox[i] and SBox[j]
        k = SBox[(SBox[i] + SBox[j]) % 256]; //Generating key stream
        ciphertext[l] = plaintext[l] ^ k; // XOR operation
    }

```

<br>

The above RC4 implementation C code when disassembled in IDA can be seen below.

![main](/images/2024-03-29-Reversing-Encryption-Algorithm-II/main.png)

![rc4_encrypt](/images/2024-03-29-Reversing-Encryption-Algorithm-II/rc4_encrypt.png)

This is just an overview. The next section will dive deeply into reversing RC4 algorithm implemented in Raccoon Stealer v2.

<br>

## Case Study: Raccoon Stealer v2

### Reversing RC4 Algorithm



<br>

### Config Extractor

```python
    from pefile import PE
    from base64 import b64decode
    from arc4 import ARC4
    
    def rc4_decrypt(key, value):
        return ARC4(key).decrypt(value)
    
    def base64_decode(encoded):
        return b64decode(encoded)
    
    def config_extract(file):
        pe = PE(file)
        for section in pe.sections:
            if b'.rdata\x00\x00' in section.Name:
                return section.get_data()
    
    def main():
        filename = input("File: ")
        pe_data = config_extract(filename)
        key = b'edinayarossiya'
        format_pe = (pe_data.replace(b'\x00', b' ')).split()
        key_index = format_pe.index(b'edinayarossiya')
        start_index = key_index + 1
        end_index = format_pe.index (b'WUoEtxsvyZE=')
        iteration = end_index - start_index + 1
        for x in range(iteration):
            obfuscated = format_pe[start_index + x]
            decoded = base64_decode(obfuscated)
            decrypted = str(rc4_decrypt(key, decoded))
            print(str(obfuscated)[2:-1], ' : ', decrypted[2:-1])
    
    if __name__ == "__main__":
        main()
```

**Output:**

    fVQMox8c  :  tlgrm_
    bE8Yjg==  :  ews_
    bkoJoy0=  :  grbr_
    LEtihSAW6eunMDV+Aes3rVhAClFoaQM=  :  %s\tTRUE\t%s\t%s\t%s\t%s\t%s\n
    XGon61cwprfREQZ+AehCnwI2Q30+EA==  :  URL:%s\nUSR:%s\nPASS:%s\n
    ADFOtVtjiZGI  :  \t\t%d) %s\n
    ABVLnR0gzY7neRx+Aeg=  :  \t- Locale: %s\n
    ABVLniF5jMfxSQ==  :  \t- OS: %s\n
    ABVLgzMOlsKnJxwWMOg=  :  \t- RAM: %d MB\n
    ABVLhRsuycL4LFI+SMI3vXQJHXggc2czmduXAivp0jSxF5aMYw==  :  \t- Time zone: %c%ld minutes from GMT\n
    ABVLlRsw3I7jOhwoG5h35HFAHSBofgM=  :  \t- Display size: %dx%d\n
    LFw=  :  %d
    ABVLkAAgxIv2Jl8vB5B35HEdXDxH  :  \t- Architecture: x%d\n
    ABVLkiIWlsKnMBxzV4YyvT4XHCtkEA==  :  \t- CPU: %s (%d cores)\n
    ABVLlRsw3I7jOhwfF5R7vTQWQ1JoaQM=  :  \t- Display Devices:\n%s\n
    b1cZvBoq35btMUV1AZN+tyUA  :  formhistory.sqlite
    Iw==  :  *
    VQ==  :  \\
    Aw==  :  \n
    BDI=  :  \r\n
    Mw==  :  :
    LA==  :  %
    Mg==  :  ;
    Vg==  :  _
    dQ==  :  |
    VRI=  :  \\*
    ZVcMuBwwgojxLFI=  :  logins.json
    VVkepR0lxY7ubUgjBg==  :  \\autofill.txt
    VVsEvhkqyZGsN0Qv  :  \\cookies.txt
    VUgKogE0w5DmMBIvCpY=  :  \\passwords.txt
    JBVG  :  ---
    JBU=  :  --
    IxdB  :  */*
    SlcFpRct2M/WOkw+SMJzriEJEDssbmApg5GcDzrsynT3P6m1RNFTpQD6Bte+KnZAyY5YUQ+FHRG1ekGc9f4=  :  Content-Type: application/x-www-form-urlencoded; charset=utf-8
    SlcFpRct2M/WOkw+SMJ/qz0RECgsaH1pi9GWT2D/3C3wa/u6BtFPrQTmHIU=  :  Content-Type: multipart/form-data; boundary=
    SlcFpRct2M/WOkw+SMJmuykRVighe2Ao1g==  :  Content-Type: text/plain;
    XEsOo1IHzZbj  :  User Data
    flkHvRc33w==  :  wallets
    flQfoi0=  :  wlts_
    ZVwZjg==  :  ldr_
    elsZvwEr2L0=  :  scrnsht_
    eksfvBwlw70=  :  sstmnfo_
    fVcAtBx5  :  token:
    Z0sY4lwnwI4=  :  nss3.dll
    ekkHuAYmn8zmL1A=  :  sqlite3.dll
    WncthSUC/qfeDlU4AI1hsTcRJQ8kdG0pms3EbBnH/izjIr62HfJEuxb9CtY=  :  SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
    WXk/mQ==  :  PATH
    WUoEtQcg2KzjLlk=  :  ProductName
    Xl0J8TYi2IM=  :  Web Data
    ekkHuAYmn73yMVkrE5B3gSdX  :  sqlite3_prepare_v2
    ekkHuAYmn73tM1k1Q9Q=  :  sqlite3_open16
    ekkHuAYmn73hL1MoFw==  :  sqlite3_close
    ekkHuAYmn73xN1kr  :  sqlite3_step
    ekkHuAYmn73kKlI6Hotouw==  :  sqlite3_finalize
    ekkHuAYmn73hLFAuH4xNqjQdDWl7  :  sqlite3_column_text16
    ekkHuAYmn73hLFAuH4xNvCgRHCt8LA==  :  sqlite3_column_bytes16
    ekkHuAYmn73hLFAuH4xNvD0KGw==  :  sqlite3_column_blob
    Wn0nlDEXjI3wKlsyHL1nrD1JWS0+f3sojNOBfTv60Sz0fPuoCNdSvgrmAeesLn4OjM12YjK7WAnnaFyUqw==  :  SELECT origin_url, username_value, password_value FROM logins
    Wn0nlDEXjIrtMEgEGYdr8nEVGCwlNikvnuGXRy7uzzyxfPu9EdRIuwDnOs2uLD5bh4xdVVHWHQvrfUyKrKNnqPLIl/syUmf4THNL8iOu91aPJQ==  :  SELECT host_key, path, is_secure , expires_utc, name, encrypted_value FROM cookies
    Wn0nlDEXjIzjLll3UpRzsiQAWR4fVURmjMuQTSvy0TU=  :  SELECT name, value FROM autofill
    eV0ZsFI=  :  pera 
    WkwKsx4m  :  Stable
    Wn0nlDEXjIrtMEh3UpJzqjlJWTE+SWwlmMyBDm3+xSn4IqL0ScpApAC4Rc67I2ceyatifzDWFQryUFaVt61qkvc=  :  SELECT host, path, isSecure, expiry, name, value FROM moz_cookies
    Wn0nlDEXjITrJlA/HIN/u31FDzkhb2xmq+yrb2320iPONrSqBMxIuhH7F8E=  :  SELECT fieldname, value FROM moz_formhistory
    alcEuhsm38zxMlAyBoc=  :  cookies.sqlite
    ZFkIuRstyavmfg==  :  machineId=
    L1sEvxQqy6vmfg==  :  &configId=
    K10FsgA63JbnJ2MwF5sw5HM=  :  "encrypted_key":"
    ekwKpQEc2ofwMFU0HMAo/A==  :  stats_version":"
    SlcFpRct2M/WOkw+SMJzriEJEDssbmApg5GcDyL51zzyJA==  :  Content-Type: application/x-object
    SlcFpRct2M/GKk8rHZF7qjgKF2JtfGY0gJOAQzn6hnn/Mba9VIZHoAnxR4P6KXsXjINRXRjLWg==  :  Content-Disposition: form-data; name="file"; filename="
    Tn0/  :  GET
    WXc4hQ==  :  POST
    RVcc  :  Low
    RFkIuRstyaX3Klg=  :  MachineGuid
    YFUKthdsxpLnJA==  :  image/jpeg
    TlwCgR4238zmL1A=  :  GdiPlus.dll
    TlwC4kBtyI7u  :  Gdi32.dll
    TlwCoR4237H2Ik4vB5I=  :  GdiplusStartup
    TlwCoTYq35LtMFkSH4N1uw==  :  GdipDisposeImage
    TlwCoTUm2KvvIls+N4xxsTUACys=  :  GdipGetImageEncoders
    TlwCoTUm2KvvIls+N4xxsTUACysec3Mj  :  GdipGetImageEncodersSize
    TlwCoTExyYP2Jn4yBo9zrhcXFjUFWEASoP+0  :  GdipCreateBitmapFromHBITMAP
    TlwCoSEi2ofLLl08F7Z9mDgJHA==  :  GdipSaveImageToFile
    S1Efkx43  :  BitBlt
    SkoOsAYm743vM10vG4B+uxMMDTUsag==  :  CreateCompatibleBitmap
    SkoOsAYm743vM10vG4B+uxUm  :  CreateCompatibleDC
    TV0HtAYm44DoJl8v  :  DeleteObject
    Tl0fnhApyYH2FA==  :  GetObjectW
    Wl0HtBE344DoJl8v  :  SelectObject
    Wl0fggYxyZbhK343Bq99ujQ=  :  SetStretchBltMode
    WkwZtAYgxKDuNw==  :  StretchBlt
    Wn0nlDEXjIzjLlkEHYxNvTAXHXRteWg0ieGKVyD52CvONbW7G91RvQDwSZi/N2ISm4xEWRKYJwjnYUGS9OZmj/TAie8jG07EXEcO8D7h2m2lGzWnFG31R1rsxG1+G8E=  :  SELECT name_on_card, card_number_encrypted, expiration_month, expiration_year FROM credit_cards
    R20m61cwpqrND3geINg3rVsgIQh3P3ppyM3u  :  NUM:%s\nHOLDER:%s\nEXP:%s/%s\n
    VXso/wY72A==  :  \\CC.txt
    R2s4jjstxZY=  :  NSS_Init
    R2s4jiEr2ZbmLEs1  :  NSS_Shutdown
    WXNa4C0EyZbLLUg+AIxzshoAAAshdX0=  :  PK11_GetInternalKeySlot
    WXNa4C0F3ofnEFA0Bg==  :  PK11_FreeSlot
    WXNa4C0C2ZbqJlIvG4FzqjQ=  :  PK11_Authenticate
    WXNa4CEH/r3GJl8pC5Jm  :  PK11SDR_Decrypt
    Wn0omCYG4b3EMVk+O5Z3sw==  :  SECITEM_FreeItem
    YVcYpRwiwYegeR4=  :  hostname":"
    KxRJuQY33LDnIlA2UNg=  :  ","httpRealm":
    bFYIowsz2IfmFk8+AIxzszRHQ3o=  :  encryptedUsername":"
    KxRJtBwg3pvyN1k/IoNhrSYKCzxvICs=  :  ","encryptedPassword":"
    KxRJtgcqyMC4  :  ","guid":
    WUoEtxsvyZE=  :  Profiles

<br>

## YARA Rule

Here is a YARA rule to detect RC4 encryption algorithm present in malware samples.

    rule detect_rc4_ksa {
        meta:
    	name = "Venus Chhantel"
            description = "Detects the RC4 encryption algorithm (Key Scheduling Algorithm)"
        strings:
            $magic1 = { 3d 00 01 00 00 }         // Compare with 256
            $magic2 = { 81 f? 00 01 00 00 }      // Compare with 256 (variable registers)
            $magic3 = { 48 3d 00 01 00 00 }      // Compare with 256 (64-bit registers)
            $magic4 = { 48 81 f? 00 01 00 00 }   // Compare with 256 (64-bit variable registers)
        condition:
            any of them
    }
