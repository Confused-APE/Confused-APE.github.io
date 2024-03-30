---
layout:	post
title:  "Reversing Encryption Algorithms (II): RC4"
date:   2024-03-30 11:11:11 +0200
categories: [Reversing Encryption Algorithms]
tags: [Encryption, RC4]
---

## Introduction

RC4 is symmetric stream cipher developed by Ronald Rivest in 1987. It is one of the most encountered cryptographic algorithms in malware because of its simplicity and efficiency. It is widely used by malware for activities like:

- To encrypt network communication to its C2.
- To decrypt obfuscated strings and 2nd stager binary.

RC4 was popular with malwares like Raccoon Stealer v2, Revil, IceID, Dridex, and more.

## Implementation in C

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
            swap(&SBox[i], &SBox[j]); #Swap SBox[i] and SBox[j]
        }
    
        // Pseudo-random generation algorithm
        i = j = 0;
        for (int l = 0; l < len; l++) {
            i = (i + 1) % 256;
            j = (j + SBox[i]) % 256;
            swap(&SBox[i], &SBox[j]);  //#Swap SBox[i] and SBox[j]
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


## Algorithm Breakdown

RC4 algorithm consist of 3 stages (code for each stage from above implementation):

1.  **KSA (Key Scheduling Algorithm)**
    
    -   In this phase, a 256-byte array substitution box is first initialized.
    -   Then, using the key, the initialized substitution box is scrambled.
    
    ```
    for (i = 0; i < 256; i++) {
        SBox[i] = i;  //Initializing 256-byte array substitution box
    }
    for (i = 0; i < 256; i++) {
        j = (j + SBox[i] + key[i % len]) % 256;  //Scrambling initialized substitution box with key
        swap(&SBox[i], &SBox[j]);  //#Swap SBox[i] and SBox[j]             
    }
    
    ```
    
2.  **PRGA (Pseudo Random Generation Algorithm)**
    
    -   In this phase, the scrambled substitution box created in KSA stage is used to generate keystream.
    
    ```
    for (int l = 0; l < len; l++) {
        i = (i + 1) % 256;
        j = (j + SBox[i]) % 256;
        swap(&SBox[i], &SBox[j]);  //#Swap SBox[i] and SBox[j]
        k = SBox[(SBox[i] + SBox[j]) % 256]; //Generating key stream
        ciphertext[l] = plaintext[l] ^ k; // XOR operation
    }
    
    ```
    
3.  **XOR**
    
    -   In this phase, each byte of plaintext/ciphertext is XOR with each byte of key stream generated in previous PRGA stage to get ciphertext/plaintext respectively.
    
    ```
    ciphertext[l] = plaintext[l] ^ k; // XOR operation
    
    ```

## Reversing




## Case Study: Raccoon Stealer v2


