---
layout:	post
title:  "AD: Fundamentals"
date:   2024-07-15 11:11:11 +0200
categories: [Active Directory]
tags: [Active Directory]
---

***Objects*** are any resource in the network. 

***Directory*** is a herirachy structure that store information about the objects on network. 

***Directory service*** is responsible for storing and providing those information across the network. 

Microsoft have created a set of such directory services for domain-based network which is known as ***Active Directory*** (AD). 

One of the most popular directory service of AD is ***Active Directory Domain Service*** (AD DS). 

The server running the AD DS is known as ***Domain Controller*** (DC). 

The first DC server that gets promoted to AD DS becomes forest by default.

![AD Environment](/images/2024-07-15-AD:Fundamentals/1.png)

<br>

***Forest*** is security boundary and is group of trees.

- Security boundary because all domains within the same forest have by default two-way transitive trust; meaning If domain A trusts domain B and domain B trusts domain C, domain A will automatically trust domain C (covered later).

**Tree** is hierarchical (parent-child) structure of domains that share common namespace. 

***Domain*** is logical group of objects which may contain multiple Organizational Unit (OU) and share an AD database.

***OU*** is container that store similar objects.

<br>

Special roles are assigned to DCs in AD environment known as ***Flexible Single Master Operator*** (FSMO) Roles:

- Schema Master
- Domain Naming Master
- RID Master
- PDC Emulator Master
- Infrastructure Master

![FSMO](/images/2024-07-15-AD:Fundamentals/2.png)

<br>

**(1) Schema Master**

- Schema Master is forest-based role.
    - One DC with Schema Master role per each forest.
- ***Schema*** is blue-print of AD that stores objects and attributes.
    - Objects are any AD resource like user, computer, dnsZone, etc.
    - Attribute is characteristics of object.
        - Example: user object attributes are firstName, lastName, employeeId, employeeType, etc.
- Only DC with Schema Master role can make modification to schema. So, any modification made to the schema go via DC with Schema Master role, which is then replicated to schema of all other DC in the AD network.

<br>

**(2) Domain Naming Master**

- Domain Naming Master is also forest-based role.
    - One DC with Domain Naming Master role per each forest.
- Domain Naming Master manages domain names ensuring unique domain name, to avoid collision of same domain names.

<br>

**(3) RID (Relative Identifier) Master**

- RID Master is domain-based role
    - One DC with RID Master role per each domain.
- RID Master is responsible for assinging unique identifier to objects.
- When any objects are created, they recieve same Domain SID. This results to all objects having the same Domain SID.
    - So, to the Domain SID, RID is appended to created unique SID.

    ![Domain SID](/images/2024-07-15-AD:Fundamentals/3.png)

- For each domain 500 RIDs pool are assigned and if 50% RIDs pool are used up, they will be assigned additional 500 RIDs pool. 

<br>

**(4) PDC (Primary Domain Controller) Emulator Master** 

- PDC Emulator Master is domain-based role.
    - One DC with PDU role per each domain.
- DC with PDC Master Emulator role is also known as authoritative DC because:
    - When password is changed, its replicated to DC with this role and routinely replicated across the other DC.
        - If user recently changes password and tries to login to DC where the change is not replicated, the failed login request is then forwarded to the DC with PDC Emulator Master role, which will verify and grant/deny the request.
    - Since all failed authentication requests from other DC as sent to the DC with this role, it is also responsible for account lookouts. Account lockouts are urgently replicated across the DC.
    - DC with this role is also responsible for synchronizing time, which is critically important for various processes, including Kerberos authentication.

<br>

**(5) Infrastructure Master**

- Infrastructure Master is domain-based role.
    - One DC with Infrastructure Master role per each domain.
- When an object in one domain is referenced by another object in another domain, it represents the reference by using Global Unique Identifier (GUID) , Security Identifier (SID) or Distinguished Name (DN).
    - ***GUID*** is a 128-bit integer to uniquely an object which remains **constant** even if the object is moved or renamed.
        - Example: `c2402276-32cd-4db3-aac2-43a7d4d806e1`
    - ***SID*** is Domain SID + RID, which uniquely identify a security principal (user account/service account).
        - Example: `S-1-5-21-3400425380-2729127854-3074111659-500`
    - ***DN*** is complete path to the object through the hierarchy of containers, which uniquely identify an object.
        - Example: `CN=APE, OU=Team,OU=Users Diretory, DC=WindowsTechno,DC=local`
- DC with Infrastructure Master role is responsible for updating an object's SID and DN in a cross-domain object reference.
- DC with this role compares its data with that of Global Catalog (GC) and if found outdated, it fetches updated data from the GC and replicates it to the other domain controllers in a domain.
    - ***Global Catalog (GC)*** is distributed data store that contain partial replica of every objects in entire forest. GC provides searchable catalog of all objects in multi-domain forest.
- Infrastructure Master role is not given to DC that has GC enabled because it will stop updating object information. Because of this, the cross-domain object references in that domain will not be updated.

<br>

By default there will be following important privileged groups, when a server is promoted to a DC:

- **Enterprise Admin** - Forest-based that can make changes to any domain under that forest.
- **Schema Admin** - Forest-based that can make changes to schema.
- **Domain Admin** - Domain-based that can make changes only to that particular domain.

<br>

In AD, domain (non-admin) users can be granted fairly granular level permission to perform some AD management task without adding them to privileged domain group which is known as ***delegation***. 

- Example: Delegate Helpdesk to grant permissions to add users to groups, create new users in AD, and reset the account passwords.

It is recommendated to delegate controls to group and add users to that group, not directly delegate users.

<br>

***Service Accounts*** are accounts used to provide security contex for services, which determines the service ability to access local and network resources. 

Initially, user accounts were used as Service Accounts. There are risk associated with both operational and security aspect because that service account uses user provided password. 

Later in 2008, ***Managed Service Accounts*** (MSA) were introduced, which are service account that are managed by AD and provides automatic password management , simplified SPN management and ability to delegate management to other administrator. 

- ***Security Principal Name (SPN)*** is unique identifier of service instance, which Kerberos authentication uses to associate service instance with service sign-in account.
- SPN must be unique in forest where its registered otherwise authentication will fail.

MSA only run on a single server so also known as ***standalone Managed Service Accounts*** (sMSA). 

MSA functionality was extended over multiple servers, which is known as ***Group Managed Service Accounts*** (gMSA).

<br>

***Kerberos*** is the default authentication protocol in AD (will be covered in detail in next blog)

<br>

Also, by default, 

- The database and logs are stored under `C:\Windows\NTDS` .
- The SYSVOL is stored under `C:\Windows\SYSVOL`.

<br>

Under the NTDS folder, there are NTDS.DIT (database file) and other log files which are shown below.

![NTDS and logs](/images/2024-07-15-AD:Fundamentals/4.png)

<br>

The NTDS.DIT database has following partitions.

![NTDS partitions](/images/2024-07-15-AD:Fundamentals/5.png)

- ***Schema partition*** stores the schema.
    - This parition is replicated forest-wide.
- ***Configuration partition*** stores AD topology, including DCs, sites and services.
    - This partition is replicated forest-wide.
- ***Domain partition*** stores information about every objects of domain.
    - This partition is replicated domain-wide.
- ***Application partition*** stores information about applications in AD such as AD-Integrated DNS zones.
    - This partition can be setup to replicate forest-wide or domain-wide.

<br>

To enable centralized configuration and management of computers and users setting, there is a feature called ***Group Policy***. 

Virtual collection of Group Policy setting is ***Group Policy Object*** (GPO). 

Group Policy settings are created and edited using Group Policy Object Editor.  

<br>

In AD environment, the availability of resource sharing is goverened by trust. ***Trust*** is secure authenticated communication bridge between domain/forest.

Additionally trust can be categorized as following:   

- Based on direction
    - One-way
        - Provide access from trusted domain to trusting domain.
        - Trust direction will be opposite to access direction.

        ![One-way Trust](/images/2024-07-15-AD:Fundamentals/6.png)

    - Two-way
        - Provide access to both trusting partner domain.
        - Both access and trust direction is bi-directional.
- Based on characteristics
    - Transitive
        - Trust extends beyond domain any other domain that trusting partner domain trusts.
    - Non-transitive
        - Trust exist only between two trusting partner domain

<br>

When trust is created, SID filtering is enabled by default. ***SID filtering*** is a security mechanism that filter out any SID from user’s Acces Token that are not part of trusted domain to ensure only SID from trusted domain are used while accessing a resource over a trust.

- If a user is member of five group, it will recieve a SID for each of those five groups. The SID that are not part of trusted domain gets removed by SID filtering when that user try to access resource over a trust.

Whenever user access resource over trust, the user SID will be added to ***Foreign Security Principals***, which is represents security principals from foreign another domain.
