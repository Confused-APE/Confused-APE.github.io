---
layout:	post
title:  "AD: Kerberos Authentication"
date:   2024-07-16 11:11:11 +0200
categories: [Active Directory]
tags: [Active Directory]
---

Kerberos is default network authentication protocol in Windows

Kerberos comes from Cerebrus (a three headed dog), where each head represent core component of Kerberos

- Principal
    - Refer to user principal or service principal that want to authenticate.
- Resource
    - Asset or service principal want to access.
- KDC (Key Distribution Center)
    - Created by default when domain is created and manages Kerberos authentication.
    - Inside it, there is AS (Authentication Server) and TGS (Ticket Granting Server).

<br>

## Kerberos Authentication: In-Depth

**Step 1:** User that want to authenticate first sends an unecrypted message to the AS.

![Step 1](/images/2024-07-16-AD_Kerberos_Authentication/1.png)

<br>

**Step 2:** Since AS is part of KDC, it has access to list of all user and their secret. The AS first looks at User Name/ID of message sent by user and then verifies if that user exists by comparing to that list. If that user exist, it sends back two messages. It also randomly generates TGS Session Key and add them into both of the messages.

- The first message is encrypted with user’s secret.
- The second message is Ticket Granting Ticket (TGT) which is encrypted with TGT Secret Key. The TGT Secret Key is derived from krbtgt account password.

![Step 2](/images/2024-07-16-AD_Kerberos_Authentication/2.png)

<br>

**Step 3:** At this time, user will be prompt to enter their password. From the entered password, user’s secret is generated as follows.

    password + salt (name@domain) + key version number ——hashing algorithm——> User’s Secret Key 

If the password is correct, using the User’s Secret Key, the first message is decrypted to retrieve TGS Session Key.

Since users do not have access to TGT Secret Key, the TGT is then forwarded to TGS. Along with TGT, it sends additional two messages to TGS.

- The first message is unencrypted.
- The second message is User Authenticator which is encrypted with TGS Session Key, which is retrieved previously.

![Step 3](/images/2024-07-16-AD_Kerberos_Authentication/3.png)

<br>

**Step 4:** Since TGS is also part of KDC, it has list of all services and their secrets. The TGS first checks the first message and verifies the Service Name/ID. 

Also, TGS has access to TGT secret key, TGS decryptes the TGT. Inside the TGT is the TGS Session Key. And by using that TGS Session key, it decryptes the User Authenticator message. 

The TGS then validates the data in those messages:

- Validates if user Name/ID and Timestamp between TGT and User Authenticator matches.
    - Typically, Kerberos is configured to tolerate upto 5 minutes difference in Timestamp.
- Validates the IP address from TGT with the IP address it recieved the messages from.
- Validates if TGT is not expired.

If the validation is successful, TGS create two message and send back to User.

![Step 4](/images/2024-07-16-AD_Kerberos_Authentication/4.png)

<br>

**Step 5:** Since user already recieved the TGS Session key from AS, it decrypts the first message. After decrypting it receives Service Session Key.

The user cannot decrypt the Service Ticket as it does not have access to Service Secret Key so the user forwards that message along User Authenticator message to the Service, which is encrypted with Service Session Key.

![Step 5](/images/2024-07-16-AD_Kerberos_Authentication/5.png)

<br>

**Step 6:** The Service first decrypts the Service Ticket using its Service Session Key. After decrypting, it get access to Service Session Key and using that, it decrypts the User Authenticator message.

The Service then validates the data in those messages:

- Validates if User Name/ID and Timestamp between Service Ticket and User Authenticator matches.
- Validates the IP address from Service Ticket with the IP address it recieved the messages from.
- Validates if Service Ticket is not expired.

If the validation is successful, Service send back Service Authenticator message to User by encrypting with Service Session Key.

![Step 6](/images/2024-07-16-AD_Kerberos_Authentication/6.png)

<br>

**Step 7:** Since User had already recieved Service Session Key from TGS, it decrypts the Service Authenticator.

The Client then verifies: 

- The Service Name/ID in the Service Authenticator message is the one it requested for, and hence mutual authentication.
- The Client also verifies the timestamp is within tolerable few minutes.

With this the kerberos authentication is complete, and user can access the service.

<br>

## Kerberos Authentication: In-short

![in-short](/images/2024-07-16-AD_Kerberos_Authentication/7.png)

